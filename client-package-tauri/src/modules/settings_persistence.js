// Saves and loads user preferences to localStorage

import { invoke } from '@tauri-apps/api/core';

const STORAGE_KEY = 'whispera_settings';

// Default settings
const defaultSettings = {
    mode: 'global',           // 'rule' or 'global'
    proxyEnabled: false,
    tunEnabled: true,
    lastProfile: null,
    theme: 'dark',
    language: 'ru',
    customSites: []           // User-added sites for ping testing
};

// Current settings in memory
let currentSettings = { ...defaultSettings };

// Load settings from localStorage
export function loadSettings() {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            currentSettings = { ...defaultSettings, ...JSON.parse(stored) };
        }
        console.log('[Settings] Loaded:', currentSettings);
    } catch (e) {
        console.error('[Settings] Failed to load:', e);
        currentSettings = { ...defaultSettings };
    }
    return currentSettings;
}

// Save settings to localStorage
export function saveSettings() {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(currentSettings));
        console.log('[Settings] Saved:', currentSettings);
    } catch (e) {
        console.error('[Settings] Failed to save:', e);
    }
}

// Get a setting value
export function getSetting(key) {
    return currentSettings[key];
}

// Set a setting value and save
export function setSetting(key, value) {
    currentSettings[key] = value;
    saveSettings();
    return value;
}

// Apply settings to UI elements
export function applySettingsToUI() {
    // Mode tabs
    const modeTabs = document.querySelectorAll('.mode-tab');
    modeTabs.forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.mode === currentSettings.mode) {
            tab.classList.add('active');
        }
    });

    // Proxy toggle
    const proxyToggle = document.getElementById('proxy-toggle');
    if (proxyToggle) {
        proxyToggle.checked = currentSettings.proxyEnabled;
    }

    // TUN toggle
    const tunToggle = document.getElementById('tun-toggle');
    if (tunToggle) {
        tunToggle.checked = currentSettings.tunEnabled;
    }

    console.log('[Settings] Applied to UI');
}

// Setup event listeners for UI elements
export function setupSettingsListeners() {
    // Mode tabs
    const modeTabs = document.querySelectorAll('.mode-tab');
    modeTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            modeTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            setSetting('mode', tab.dataset.mode);
            console.log('[Settings] Mode changed to:', tab.dataset.mode);
        });
    });

    // Proxy toggle
    const proxyToggle = document.getElementById('proxy-toggle');
    if (proxyToggle) {
        proxyToggle.addEventListener('change', async (e) => {
            const enabled = e.target.checked;
            setSetting('proxyEnabled', enabled);
            console.log('[Settings] Proxy:', enabled ? 'ON' : 'OFF');

            // Could trigger actual proxy enable/disable here
            if (enabled) {
                // Start proxy mode
            } else {
                // Stop proxy mode
            }
        });
    }

    // TUN toggle
    const tunToggle = document.getElementById('tun-toggle');
    if (tunToggle) {
        tunToggle.addEventListener('change', async (e) => {
            const enabled = e.target.checked;
            setSetting('tunEnabled', enabled);
            console.log('[Settings] TUN:', enabled ? 'ON' : 'OFF');

            // Could trigger actual TUN enable/disable here
        });
    }

    // Connect button - now uses connection key
    const connectBtn = document.getElementById('connect-btn');
    if (connectBtn) {
        connectBtn.addEventListener('click', async () => {
            const isConnected = connectBtn.classList.contains('connected');

            if (isConnected) {
                // Disconnect
                try {
                    await invoke('disconnect');
                    connectBtn.textContent = 'Подключиться';
                    connectBtn.classList.remove('connected');
                    console.log('[Settings] Disconnected');
                } catch (err) {
                    console.error('[Settings] Disconnect error:', err);
                }
            } else {
                // Get connection key from input
                const keyInput = document.getElementById('connection-key');
                const key = keyInput ? keyInput.value.trim() : '';

                if (!key) {
                    alert('Вставьте ключ подключения (whispera://...)');
                    return;
                }

                if (!key.startsWith('whispera://')) {
                    alert('Неверный формат ключа');
                    return;
                }

                connectBtn.textContent = 'Подключение...';
                connectBtn.disabled = true;

                try {
                    const result = await invoke('connect_with_key', { key: key });
                    console.log('[Settings] Connected:', result);

                    connectBtn.textContent = 'Отключиться';
                    connectBtn.classList.add('connected');
                    connectBtn.disabled = false;

                    // Show connection info
                    const infoServer = document.getElementById('info-server');
                    const infoTransport = document.getElementById('info-transport');
                    const infoObfs = document.getElementById('info-obfs');
                    const infoDiv = document.getElementById('connection-info');

                    if (infoServer && result.server) infoServer.textContent = result.server;
                    if (infoTransport) infoTransport.textContent = result.transport || 'auto';
                    if (infoObfs) infoObfs.textContent = result.obfuscation || 'stealth';
                    if (infoDiv) infoDiv.style.display = 'block';

                } catch (err) {
                    console.error('[Settings] Connect error:', err);
                    alert('Ошибка подключения: ' + (err.message || err));
                    connectBtn.textContent = 'Подключиться';
                    connectBtn.disabled = false;
                }
            }
        });
    }

    // Footer buttons
    setupFooterButtons();

    console.log('[Settings] Listeners setup complete');
}

// Footer buttons functionality
function setupFooterButtons() {
    const footerBtns = document.querySelectorAll('.footer-btn');

    footerBtns.forEach((btn, index) => {
        btn.addEventListener('click', () => {
            const title = btn.getAttribute('title');

            switch (title) {
                case 'Выход':
                    if (confirm('Вы уверены, что хотите выйти?')) {
                        window.close();
                    }
                    break;

                case 'Язык':
                    // Toggle language (for now just show alert)
                    alert('Доступные языки:\n• Русский\n• English');
                    break;

                case 'Обновить':
                    location.reload();
                    break;
            }
        });
    });
}

// Initialize settings module
export function initSettings() {
    loadSettings();
    applySettingsToUI();
    setupSettingsListeners();
}

// Auto-initialize
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSettings);
} else {
    initSettings();
}

export { currentSettings };
