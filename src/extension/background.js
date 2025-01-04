// background.js
import SIEMConnector from '../integrations/siemConnector.js';

class SecurityMonitor {
    constructor() {
        this.state = {
            isMonitoring: false,
            lastCheck: null,
            alertCount: 0,
            activeConnections: new Set(),
            alerts: [], // Store recent alerts
            config: null // Will store SIEM configuration
        };
        
        // Initialize SIEM connector
        this.siemConnector = null;
        
        // Initialize with saved state if it exists
        this.loadState();
        this.initializeSIEM();
    }

    async loadState() {
        const saved = await chrome.storage.local.get([
            'isMonitoring',
            'lastCheck',
            'alertCount',
            'alerts',
            'siemConfig'
        ]);
        
        if (saved) {
            this.state = { ...this.state, ...saved };
            if (saved.siemConfig) {
                this.initializeSIEM(saved.siemConfig);
            }
        }
    }

    async initializeSIEM(config = null) {
        if (config) {
            this.state.config = config;
        }
        
        this.siemConnector = new SIEMConnector({
            splunkUrl: this.state.config?.splunkUrl,
            splunkToken: this.state.config?.splunkToken,
            wazuhUrl: this.state.config?.wazuhUrl,
            wazuhToken: this.state.config?.wazuhToken,
            refreshInterval: 300000 // 5 minutes
        });

        // Set up alert handler
        this.siemConnector.onNewAlert(this.handleNewAlert.bind(this));
    }

    async startMonitoring() {
        if (!this.state.isMonitoring) {
            console.log('Starting security monitoring...');
            
            if (!this.siemConnector) {
                throw new Error('SIEM connector not initialized');
            }

            // Connect to SIEM platforms
            const connected = await this.siemConnector.connect();
            if (!connected) {
                throw new Error('Failed to connect to SIEM platforms');
            }

            this.state.isMonitoring = true;
            
            // Set up regular checks
            chrome.alarms.create('securityCheck', {
                periodInMinutes: 5
            });
            
            await this.checkSecurityAlerts(); // Initial check
            await this.saveState();
        }
    }

    async handleNewAlert(alert) {
        // Add alert to our state
        this.state.alerts.unshift(alert);
        // Keep only recent alerts (last 100)
        this.state.alerts = this.state.alerts.slice(0, 100);
        this.state.alertCount = this.state.alerts.length;
        
        // Notify on high severity
        if (alert.severity <= 2) {
            await this.notifyHighSeverityAlert(alert);
        }
        
        await this.saveState();
    }

    async notifyHighSeverityAlert(alert) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon-48.png',
            title: `High Severity Alert - ${alert.source}`,
            message: alert.description,
            priority: 2
        });
    }

    async checkSecurityAlerts() {
        try {
            console.log('Checking for new security alerts...');
            if (!this.siemConnector) {
                throw new Error('SIEM connector not initialized');
            }

            const alerts = await this.siemConnector.fetchAlerts('5m');
            this.state.lastCheck = new Date().toISOString();
            
            // Process new alerts
            alerts.forEach(alert => this.handleNewAlert(alert));
            
            await this.saveState();
            
        } catch (error) {
            console.error('Error checking security alerts:', error);
            // Update state to reflect error
            this.state.lastCheck = new Date().toISOString();
            await this.saveState();
        }
    }

    async saveState() {
        await chrome.storage.local.set({
            isMonitoring: this.state.isMonitoring,
            lastCheck: this.state.lastCheck,
            alertCount: this.state.alertCount,
            alerts: this.state.alerts,
            siemConfig: this.state.config
        });
    }

    getStatus() {
        return {
            isMonitoring: this.state.isMonitoring,
            lastCheck: this.state.lastCheck,
            alertCount: this.state.alertCount,
            alerts: this.state.alerts,
            connectedPlatforms: Array.from(this.siemConnector?.activeConnections || [])
        };
    }

    async updateConfig(newConfig) {
        this.state.config = newConfig;
        await this.initializeSIEM(newConfig);
        await this.saveState();
    }
}

// Create our security monitor instance
const securityMonitor = new SecurityMonitor();

// Set up event listeners
chrome.runtime.onInstalled.addListener(async () => {
    console.log('Security Operations Extension installed');
    await securityMonitor.startMonitoring();
});

// Handle alarm events
chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'securityCheck') {
        await securityMonitor.checkSecurityAlerts();
    }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case 'getStatus':
            sendResponse(securityMonitor.getStatus());
            break;
        case 'updateConfig':
            securityMonitor.updateConfig(message.config)
                .then(() => sendResponse({ success: true }))
                .catch(error => sendResponse({ success: false, error: error.message }));
            break;
        case 'toggleMonitoring':
            if (message.start) {
                securityMonitor.startMonitoring()
                    .then(() => sendResponse({ success: true }))
                    .catch(error => sendResponse({ success: false, error: error.message }));
            } else {
                securityMonitor.stopMonitoring()
                    .then(() => sendResponse({ success: true }))
                    .catch(error => sendResponse({ success: false, error: error.message }));
            }
            break;
    }
    return true; // Required for async response
});