// popup.js

class PopupManager {
    constructor() {
        this.initializeElements();
        this.setupEventListeners();
        this.loadConfiguration();
        this.updateStatus();
    }

    initializeElements() {
        // Status elements
        this.statusIndicator = document.querySelector('.status-indicator');
        this.statusText = document.getElementById('statusText');
        this.lastCheckTime = document.getElementById('lastCheckTime');
        
        // Configuration form elements
        this.configForm = document.getElementById('siemConfigForm');
        this.splunkUrl = document.getElementById('splunkUrl');
        this.splunkToken = document.getElementById('splunkToken');
        this.wazuhUrl = document.getElementById('wazuhUrl');
        this.wazuhToken = document.getElementById('wazuhToken');
        this.configMessage = document.getElementById('configMessage');

        // Tab elements
        this.tabs = document.querySelectorAll('.tab');
        this.tabContents = document.querySelectorAll('.tab-content');
    }

    setupEventListeners() {
        // Tab switching
        this.tabs.forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
        });

        // Configuration form submission
        this.configForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveConfiguration();
        });
    }

    async loadConfiguration() {
        try {
            const config = await chrome.storage.local.get('siemConfig');
            if (config.siemConfig) {
                this.splunkUrl.value = config.siemConfig.splunkUrl || '';
                this.splunkToken.value = config.siemConfig.splunkToken || '';
                this.wazuhUrl.value = config.siemConfig.wazuhUrl || '';
                this.wazuhToken.value = config.siemConfig.wazuhToken || '';
            }
        } catch (error) {
            this.showConfigMessage('Error loading configuration', true);
        }
    }

    async saveConfiguration() {
        try {
            const config = {
                splunkUrl: this.splunkUrl.value.trim(),
                splunkToken: this.splunkToken.value.trim(),
                wazuhUrl: this.wazuhUrl.value.trim(),
                wazuhToken: this.wazuhToken.value.trim()
            };

            // Validate URLs
            if (!this.validateUrls(config)) {
                this.showConfigMessage('Please enter valid URLs', true);
                return;
            }

            // Send configuration to background script
            const response = await chrome.runtime.sendMessage({
                action: 'updateConfig',
                config
            });

            if (response.success) {
                this.showConfigMessage('Configuration saved successfully');
                // Restart monitoring with new configuration
                await chrome.runtime.sendMessage({
                    action: 'toggleMonitoring',
                    start: true
                });
                this.updateStatus();
            } else {
                this.showConfigMessage(response.error || 'Failed to save configuration', true);
            }
        } catch (error) {
            this.showConfigMessage('Error saving configuration: ' + error.message, true);
        }
    }

    validateUrls(config) {
        try {
            if (config.splunkUrl) new URL(config.splunkUrl);
            if (config.wazuhUrl) new URL(config.wazuhUrl);
            return true;
        } catch {
            return false;
        }
    }

    showConfigMessage(message, isError = false) {
        this.configMessage.textContent = message;
        this.configMessage.className = isError ? 'error-message' : 'success-message';
        setTimeout(() => {
            this.configMessage.textContent = '';
        }, 5000);
    }

    switchTab(tabName) {
        this.tabs.forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });

        this.tabContents.forEach(content => {
            content.classList.toggle('active', content.id === `${tabName}Tab`);
        });
    }

    async updateStatus() {
        try {
            const status = await chrome.runtime.sendMessage({ action: 'getStatus' });
            
            this.statusIndicator.className = 'status-indicator ' + 
                (status.isMonitoring ? 'status-active' : 'status-inactive');
            
            this.statusText.textContent = status.isMonitoring ? 'Active' : 'Inactive';
            
            this.lastCheckTime.textContent = status.lastCheck ? 
                new Date(status.lastCheck).toLocaleString() : 
                'Never';

            // Update alerts display
            this.updateAlerts(status.alerts || []);
            
        } catch (error) {
            console.error('Error updating status:', error);
        }
    }

    updateAlerts(alerts) {
        const container = document.getElementById('alertContainer');
        if (!alerts.length) {
            container.innerHTML = '<div class="loading">No alerts to display</div>';
            return;
        }

        container.innerHTML = alerts.map(alert => `
            <div class="alert-item" style="margin-bottom: 8px; padding: 8px; border: 1px solid #e0e0e0; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between;">
                    <strong>${alert.source}</strong>
                    <span style="color: ${this.getSeverityColor(alert.severity)}">
                        ${this.getSeverityText(alert.severity)}
                    </span>
                </div>
                <div style="margin-top: 4px;">${alert.description}</div>
                <div style="color: #666; font-size: 12px; margin-top: 4px;">
                    ${new Date(alert.timestamp).toLocaleString()}
                </div>
            </div>
        `).join('');
    }

    getSeverityColor(severity) {
        const colors = {
            1: '#d32f2f', // Critical - Red
            2: '#f57c00', // High - Orange
            3: '#ffd600', // Medium - Yellow
            4: '#4caf50', // Low - Green
            5: '#757575'  // Info - Gray
        };
        return colors[severity] || colors[5];
    }

    getSeverityText(severity) {
        const texts = {
            1: 'Critical',
            2: 'High',
            3: 'Medium',
            4: 'Low',
            5: 'Info'
        };
        return texts[severity] || 'Info';
    }
}

// Initialize the popup manager when the document is loaded
document.addEventListener('DOMContentLoaded', () => {
    const popup = new PopupManager();
    
    // Set up periodic status updates
    setInterval(() => popup.updateStatus(), 5000);
});