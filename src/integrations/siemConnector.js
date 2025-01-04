// src/integrations/siemConnector.js
import { fetchEventSource } from '@microsoft/fetch-event-source';

class SIEMConnector {
    constructor(config) {
        this.config = {
            splunkUrl: config.splunkUrl || '',
            splunkToken: config.splunkToken || '',
            wazuhUrl: config.wazuhUrl || '',
            wazuhToken: config.wazuhToken || '',
            refreshInterval: config.refreshInterval || 300000 // 5 minutes
        };
        this.lastCheck = null;
        this.activeConnections = new Set();
        this.alertHandlers = new Set();
        this.eventStream = null;
    }

    async connect() {
        try {
            if (this.config.splunkUrl) {
                await this.connectToSplunk();
            }
            if (this.config.wazuhUrl) {
                await this.connectToWazuh();
            }

            // Start real-time event streams if available
            await this.startEventStreams();
            return true;
        } catch (error) {
            console.error('SIEM Connection Error:', error);
            return false;
        }
    }

    async connectToSplunk() {
        try {
            const response = await fetch(`${this.config.splunkUrl}/services/auth/login`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.config.splunkToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`Splunk connection failed: ${response.statusText}`);
            }

            this.activeConnections.add('splunk');
            console.log('Connected to Splunk');
        } catch (error) {
            throw new Error(`Splunk connection failed: ${error.message}`);
        }
    }

    async connectToWazuh() {
        try {
            const response = await fetch(`${this.config.wazuhUrl}/security/user/authenticate`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.config.wazuhToken}`
                }
            });

            if (!response.ok) {
                throw new Error(`Wazuh connection failed: ${response.statusText}`);
            }

            this.activeConnections.add('wazuh');
            console.log('Connected to Wazuh');
        } catch (error) {
            throw new Error(`Wazuh connection failed: ${error.message}`);
        }
    }

    async startEventStreams() {
        if (this.activeConnections.has('splunk')) {
            this.startSplunkEventStream();
        }
        if (this.activeConnections.has('wazuh')) {
            this.startWazuhEventStream();
        }
    }

    async startSplunkEventStream() {
        try {
            const controller = new AbortController();
            await fetchEventSource(`${this.config.splunkUrl}/services/collector/event`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.config.splunkToken}`,
                    'Accept': 'text/event-stream'
                },
                signal: controller.signal,
                onmessage: (event) => {
                    const alert = this.parseSplunkAlert(JSON.parse(event.data));
                    this.notifyAlertHandlers(alert);
                },
                onerror: (error) => {
                    console.error('Splunk event stream error:', error);
                    controller.abort();
                    // Attempt to reconnect after delay
                    setTimeout(() => this.startSplunkEventStream(), 5000);
                }
            });
        } catch (error) {
            console.error('Failed to start Splunk event stream:', error);
        }
    }

    async startWazuhEventStream() {
        try {
            const controller = new AbortController();
            await fetchEventSource(`${this.config.wazuhUrl}/alerts/event-stream`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.config.wazuhToken}`,
                    'Accept': 'text/event-stream'
                },
                signal: controller.signal,
                onmessage: (event) => {
                    const alert = this.parseWazuhAlert(JSON.parse(event.data));
                    this.notifyAlertHandlers(alert);
                },
                onerror: (error) => {
                    console.error('Wazuh event stream error:', error);
                    controller.abort();
                    // Attempt to reconnect after delay
                    setTimeout(() => this.startWazuhEventStream(), 5000);
                }
            });
        } catch (error) {
            console.error('Failed to start Wazuh event stream:', error);
        }
    }

    async fetchAlerts(timeRange = '15m') {
        const alerts = [];
        const promises = [];

        if (this.activeConnections.has('splunk')) {
            promises.push(this.fetchSplunkAlerts(timeRange));
        }
        if (this.activeConnections.has('wazuh')) {
            promises.push(this.fetchWazuhAlerts(timeRange));
        }

        const results = await Promise.allSettled(promises);
        results.forEach(result => {
            if (result.status === 'fulfilled') {
                alerts.push(...result.value);
            }
        });

        this.lastCheck = new Date();
        return this.normalizeAlerts(alerts);
    }

    async fetchSplunkAlerts(timeRange) {
        try {
            const query = this.buildSplunkQuery(timeRange);
            const response = await fetch(`${this.config.splunkUrl}/services/search/jobs/export`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.config.splunkToken}`,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    search: query,
                    output_mode: 'json'
                })
            });

            if (!response.ok) {
                throw new Error(`Splunk API error: ${response.statusText}`);
            }

            const data = await response.json();
            return data.results.map(result => this.parseSplunkAlert(result));
        } catch (error) {
            console.error('Error fetching Splunk alerts:', error);
            return [];
        }
    }

    async fetchWazuhAlerts(timeRange) {
        try {
            const params = this.buildWazuhParams(timeRange);
            const response = await fetch(`${this.config.wazuhUrl}/alerts`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.config.wazuhToken}`
                },
                params
            });

            if (!response.ok) {
                throw new Error(`Wazuh API error: ${response.statusText}`);
            }

            const data = await response.json();
            return data.data.affected_items.map(item => this.parseWazuhAlert(item));
        } catch (error) {
            console.error('Error fetching Wazuh alerts:', error);
            return [];
        }
    }

    parseSplunkAlert(rawAlert) {
        return {
            id: rawAlert.id || crypto.randomUUID(),
            source: 'Splunk',
            severity: this.mapSplunkSeverity(rawAlert.severity || rawAlert.urgency),
            timestamp: new Date(rawAlert.time || rawAlert._time).toISOString(),
            description: rawAlert.message || rawAlert.description,
            type: rawAlert.event_type || rawAlert.type,
            sourceIp: rawAlert.src_ip || rawAlert.source_ip,
            destinationIp: rawAlert.dest_ip || rawAlert.destination_ip,
            rawData: rawAlert
        };
    }

    parseWazuhAlert(rawAlert) {
        return {
            id: rawAlert.id || crypto.randomUUID(),
            source: 'Wazuh',
            severity: this.mapWazuhSeverity(rawAlert.rule?.level),
            timestamp: new Date(rawAlert.timestamp).toISOString(),
            description: rawAlert.rule?.description,
            type: rawAlert.rule?.groups?.[0],
            sourceIp: rawAlert.agent?.ip,
            destinationIp: rawAlert.data?.dstip,
            rawData: rawAlert
        };
    }

    mapSplunkSeverity(severity) {
        const severityMap = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'informational': 5
        };
        return severityMap[severity?.toLowerCase()] || 5;
    }

    mapWazuhSeverity(level) {
        // Wazuh levels are 1-15, map to our 1-5 scale
        if (!level) return 5;
        if (level >= 13) return 1; // Critical
        if (level >= 10) return 2; // High
        if (level >= 7) return 3;  // Medium
        if (level >= 4) return 4;  // Low
        return 5; // Info
    }

    buildSplunkQuery(timeRange) {
        return `search index=* earliest=-${timeRange} 
                | where severity IN ("critical", "high", "medium", "low") 
                | fields id, severity, timestamp, message, src_ip, dest_ip, event_type`;
    }

    buildWazuhParams(timeRange) {
        const now = new Date();
        const past = new Date(now - this.parseTimeRange(timeRange));
        
        return {
            limit: 100,
            sort: '-timestamp',
            q: `timestamp>=${past.toISOString()}`
        };
    }

    parseTimeRange(timeRange) {
        const value = parseInt(timeRange);
        const unit = timeRange.slice(-1);
        const multiplier = {
            's': 1000,
            'm': 60000,
            'h': 3600000,
            'd': 86400000
        }[unit] || 60000; // Default to minutes
        
        return value * multiplier;
    }

    normalizeAlerts(alerts) {
        return alerts.map(alert => ({
            ...alert,
            severity: typeof alert.severity === 'number' ? 
                     alert.severity : 
                     this.normalizeSeverity(alert.severity)
        }));
    }

    normalizeSeverity(severity) {
        const severityMap = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5
        };
        return severityMap[severity?.toLowerCase()] || 5;
    }

    onNewAlert(handler) {
        this.alertHandlers.add(handler);
    }

    removeAlertHandler(handler) {
        this.alertHandlers.delete(handler);
    }

    notifyAlertHandlers(alert) {
        this.alertHandlers.forEach(handler => {
            try {
                handler(alert);
            } catch (error) {
                console.error('Error in alert handler:', error);
            }
        });
    }

    disconnect() {
        this.activeConnections.clear();
        if (this.eventStream) {
            this.eventStream.close();
            this.eventStream = null;
        }
    }
}

export default SIEMConnector;