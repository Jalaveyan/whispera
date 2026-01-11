// Advanced Features Module
// Handles Kill Switch, ASN Bypass, Transport Selection, and Obfuscation Profiles

import { invoke } from '@tauri-apps/api/core';

class AdvancedFeaturesManager {
    constructor() {
        this.killSwitchEnabled = false;
        this.currentTransport = 'auto';
        this.currentObfsProfile = 'stealth';
        this.asnBypassStrategy = 'direct';
    }

    async init() {
        console.log('[AdvancedFeatures] Initializing...');
        await this.loadTransports();
        await this.loadObfsProfiles();
        await this.loadAsnStrategies();
        this.setupListeners();
        console.log('[AdvancedFeatures] Initialized');
    }

    // Kill Switch controls
    async enableKillSwitch(allowLan = true) {
        try {
            await invoke('enable_kill_switch', { allowLan });
            this.killSwitchEnabled = true;
            this.updateKillSwitchUI(true);
            console.log('[AdvancedFeatures] Kill switch enabled');
            return true;
        } catch (err) {
            console.error('[AdvancedFeatures] Failed to enable kill switch:', err);
            return false;
        }
    }

    async disableKillSwitch() {
        try {
            await invoke('disable_kill_switch');
            this.killSwitchEnabled = false;
            this.updateKillSwitchUI(false);
            console.log('[AdvancedFeatures] Kill switch disabled');
            return true;
        } catch (err) {
            console.error('[AdvancedFeatures] Failed to disable kill switch:', err);
            return false;
        }
    }

    async getKillSwitchStatus() {
        try {
            const status = await invoke('get_kill_switch_status');
            this.killSwitchEnabled = status;
            return status;
        } catch (err) {
            console.error('[AdvancedFeatures] Failed to get kill switch status:', err);
            return false;
        }
    }

    updateKillSwitchUI(enabled) {
        const toggle = document.getElementById('kill-switch-toggle');
        const status = document.getElementById('kill-switch-status');

        if (toggle) toggle.checked = enabled;
        if (status) status.textContent = enabled ? 'Активен' : 'Отключён';
    }

    // Transport selection
    async loadTransports() {
        try {
            const transports = await invoke('get_available_transports');
            this.populateTransportSelector(transports);
            return transports;
        } catch (err) {
            console.error('[AdvancedFeatures] Failed to load transports:', err);
            return [];
        }
    }

    populateTransportSelector(transports) {
        const selector = document.getElementById('transport-selector');
        if (!selector) return;

        selector.innerHTML = '';
        transports.forEach(t => {
            const option = document.createElement('option');
            option.value = t.id;
            option.textContent = `${t.name} - ${t.description}`;
            option.disabled = !t.available;
            selector.appendChild(option);
        });
    }

    // Obfuscation profiles
    async loadObfsProfiles() {
        try {
            const profiles = await invoke('get_obfuscation_profiles');
            this.populateObfsSelector(profiles);
            return profiles;
        } catch (err) {
            console.error('[AdvancedFeatures] Failed to load obfs profiles:', err);
            return [];
        }
    }

    populateObfsSelector(profiles) {
        const selector = document.getElementById('obfs-profile-selector');
        if (!selector) return;

        selector.innerHTML = '';
        profiles.forEach(p => {
            const option = document.createElement('option');
            option.value = p.id;
            option.textContent = `${p.name} (уровень: ${p.threat_level})`;
            option.title = p.description;
            selector.appendChild(option);
        });
    }

    // ASN Bypass strategies
    async loadAsnStrategies() {
        try {
            const strategies = await invoke('get_asn_bypass_strategies');
            this.populateAsnSelector(strategies);
            return strategies;
        } catch (err) {
            console.error('[AdvancedFeatures] Failed to load ASN strategies:', err);
            return [];
        }
    }

    populateAsnSelector(strategies) {
        const selector = document.getElementById('asn-strategy-selector');
        if (!selector) return;

        selector.innerHTML = '';
        strategies.forEach(s => {
            const option = document.createElement('option');
            option.value = s.id;
            option.textContent = s.name;
            option.title = s.description;
            selector.appendChild(option);
        });
    }

    // Extended status
    async getExtendedStatus() {
        try {
            return await invoke('get_extended_status');
        } catch (err) {
            console.error('[AdvancedFeatures] Failed to get extended status:', err);
            return null;
        }
    }

    // Setup event listeners
    setupListeners() {
        // Kill switch toggle
        const killSwitchToggle = document.getElementById('kill-switch-toggle');
        if (killSwitchToggle) {
            killSwitchToggle.addEventListener('change', async (e) => {
                if (e.target.checked) {
                    const allowLan = document.getElementById('allow-lan-toggle')?.checked ?? true;
                    await this.enableKillSwitch(allowLan);
                } else {
                    await this.disableKillSwitch();
                }
            });
        }

        // Transport selector
        const transportSelector = document.getElementById('transport-selector');
        if (transportSelector) {
            transportSelector.addEventListener('change', (e) => {
                this.currentTransport = e.target.value;
                console.log('[AdvancedFeatures] Transport changed to:', this.currentTransport);
            });
        }

        // Obfuscation profile selector
        const obfsSelector = document.getElementById('obfs-profile-selector');
        if (obfsSelector) {
            obfsSelector.addEventListener('change', (e) => {
                this.currentObfsProfile = e.target.value;
                console.log('[AdvancedFeatures] Obfs profile changed to:', this.currentObfsProfile);
            });
        }

        // ASN strategy selector
        const asnSelector = document.getElementById('asn-strategy-selector');
        if (asnSelector) {
            asnSelector.addEventListener('change', (e) => {
                this.asnBypassStrategy = e.target.value;
                console.log('[AdvancedFeatures] ASN strategy changed to:', this.asnBypassStrategy);
            });
        }
    }

    // Get current settings for connection
    getConnectionSettings() {
        return {
            transport: this.currentTransport,
            obfsProfile: this.currentObfsProfile,
            asnStrategy: this.asnBypassStrategy,
            killSwitch: this.killSwitchEnabled,
            allowLan: document.getElementById('allow-lan-toggle')?.checked ?? true,
        };
    }
}

export const advancedFeaturesManager = new AdvancedFeaturesManager();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => advancedFeaturesManager.init());
} else {
    advancedFeaturesManager.init();
}
