// src/integrations/siemConnector.js
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
    }

    async connect() {
        try {
            if (this.config.splunkUrl) {
                await this.connectToSplunk();
            }
            if (this.config.wazuhUrl) {
                await this.connectToWazuh();
            }
            return true;
        } catch (error) {
            console.error('SIEM Connection Error:', error);
            return false;
        }
    }

    async connectToSplunk() {
        try {
            // Implement Splunk connection logic
            this.activeConnections.add('splunk');
            console.log('Connected to Splunk');
        } catch (error) {
            throw new Error(`Splunk connection failed: ${error.message}`);
        }
    }

    async connectToWazuh() {
        try {
            // Implement Wazuh connection logic
            this.activeConnections.add('wazuh');
            console.log('Connected to Wazuh');
        } catch (error) {
            throw new Error(`Wazuh connection failed: ${error.message}`);
        }
    }

    async fetchAlerts(timeRange = '15m') {
        const alerts = [];
        
        if (this.activeConnections.has('splunk')) {
            const splunkAlerts = await this.fetchSplunkAlerts(timeRange);
            alerts.push(...splunkAlerts);
        }
        
        if (this.activeConnections.has('wazuh')) {
            const wazuhAlerts = await this.fetchWazuhAlerts(timeRange);
            alerts.push(...wazuhAlerts);
        }

        this.lastCheck = new Date();
        return this.normalizeAlerts(alerts);
    }

    async fetchSplunkAlerts(timeRange) {
        // Placeholder for Splunk API integration
        return [];
    }

    async fetchWazuhAlerts(timeRange) {
        // Placeholder for Wazuh API integration
        return [];
    }

    normalizeAlerts(alerts) {
        return alerts.map(alert => ({
            id: alert.id || crypto.randomUUID(),
            source: alert.source,
            severity: this.normalizeSeverity(alert.severity),
            timestamp: new Date(alert.timestamp).toISOString(),
            description: alert.description,
            rawData: alert
        }));
    }

    normalizeSeverity(severity) {
        // Normalize severity levels across different SIEM platforms
        const severityMap = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5
        };
        return severityMap[severity.toLowerCase()] || 5;
    }

    onNewAlert(handler) {
        this.alertHandlers.add(handler);
    }

    removeAlertHandler(handler) {
        this.alertHandlers.delete(handler);
    }
}

export default SIEMConnector;