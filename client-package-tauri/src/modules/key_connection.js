// Key Connection Module
// Handles whispera:// key-based VPN connection

import { invoke } from '@tauri-apps/api/core';

class KeyConnectionManager {
    constructor() {
        this.connected = false;
        this.connecting = false;
        this.currentKey = null;
    }

    init() {
        console.log('[KeyConnection] Initializing...');
        this.setupListeners();
    }

    setupListeners() {
        // Connection key input and button
        const keyInput = document.getElementById('connection-key');
        const connectKeyBtn = document.getElementById('connect-key-btn');
        const disconnectBtn = document.getElementById('disconnect-btn');

        if (connectKeyBtn) {
            connectKeyBtn.addEventListener('click', () => this.connectWithKey());
        }

        if (disconnectBtn) {
            disconnectBtn.addEventListener('click', () => this.disconnect());
        }

        // Auto-connect on paste
        if (keyInput) {
            keyInput.addEventListener('paste', (e) => {
                setTimeout(() => {
                    const key = keyInput.value.trim();
                    if (key.startsWith('whispera://')) {
                        this.parseAndShowKeyInfo(key);
                    }
                }, 100);
            });

            keyInput.addEventListener('input', () => {
                const key = keyInput.value.trim();
                if (key.startsWith('whispera://')) {
                    this.parseAndShowKeyInfo(key);
                }
            });
        }

        console.log('[KeyConnection] Listeners setup complete');
    }

    parseAndShowKeyInfo(key) {
        try {
            let data = {};

            // Check for URL format: whispera://host:port?param=val
            if (key.includes('?')) {
                const urlBody = key.replace('whispera://', '').replace('wpn://', '');
                const [server, query] = urlBody.split('?');

                data.server = server;

                if (query) {
                    const params = new URLSearchParams(query);
                    if (params.has('pub')) data.pub = params.get('pub');
                    if (params.has('key')) data.psk = params.get('key');
                    // Add other params if needed
                }

                data.transport = 'auto'; // Default for URL keys
                data.obfs = 'stealth';   // Default
                data.name = 'Quick Connect';
            } else {
                // Parse whispera://base64...
                const base64 = key.replace('whispera://', '').replace('wpn://', '');
                // Basic cleanup if user pasted some whitespace
                const cleaned = base64.trim();

                // Try decoding
                const decoded = atob(cleaned);
                data = JSON.parse(decoded);
            }

            // Show parsed info
            const infoDiv = document.getElementById('connection-info');
            const infoServer = document.getElementById('info-server');
            const infoTransport = document.getElementById('info-transport');
            const infoObfs = document.getElementById('info-obfs');
            const infoName = document.getElementById('info-name');

            if (infoServer) infoServer.textContent = data.server || data.server_tcp || '-';
            if (infoTransport) infoTransport.textContent = data.transport || 'auto';
            if (infoObfs) infoObfs.textContent = data.obfs || data.obfsPreset || 'stealth';
            if (infoName) infoName.textContent = data.name || 'Whispera VPN';

            // Check if we got valid data
            if (!data.server && !data.server_tcp) {
                console.warn('[KeyConnection] No server found in key');
            }

            if (infoDiv) infoDiv.style.display = 'block';

            console.log('[KeyConnection] Parsed key:', data);
        } catch (e) {
            console.warn('[KeyConnection] Failed to parse key:', e);
        }
    }

    async safeInvoke(command, args) {
        try {
            // Try importing invoke from @tauri-apps/api/core
            if (typeof invoke === 'function') {
                return await invoke(command, args);
            }
        } catch (e) {
            console.error('[KeyConnection] Invoke failed:', e);
            throw e; // Rethrow the actual error (e.g. "command not found" or "permission denied")
        }

        // Fallbacks for older Tauri or global definition
        if (window.__TAURI__?.core?.invoke) {
            return await window.__TAURI__.core.invoke(command, args);
        }

        if (window.__TAURI__?.invoke) {
            return await window.__TAURI__.invoke(command, args);
        }

        console.error('[KeyConnection] Tauri API not found. contexts:', {
            hasImport: typeof invoke === 'function',
            hasWindowCore: !!window.__TAURI__?.core,
            hasWindow: !!window.__TAURI__
        });
        throw new Error('Tauri API not available - ensure you are running in tauri dev mode');
    }

    async connectWithKey() {
        const keyInput = document.getElementById('connection-key');
        const key = keyInput ? keyInput.value.trim() : '';

        if (!key) {
            alert('Вставьте ключ подключения (whispera://...)');
            return;
        }

        if (!key.startsWith('whispera://') && !key.startsWith('wpn://')) {
            alert('Неверный формат ключа. Ключ должен начинаться с whispera://');
            return;
        }

        const btn = document.getElementById('connect-key-btn');
        const statusText = document.getElementById('status-text');
        const statusDetails = document.getElementById('status-details');
        const statusIndicator = document.getElementById('status-indicator');

        this.connecting = true;

        if (btn) {
            btn.disabled = true;
            btn.textContent = '⏳ Подключение...';
        }

        if (statusText) statusText.textContent = 'Подключение...';
        if (statusDetails) statusDetails.textContent = 'Установка соединения';
        if (statusIndicator) statusIndicator.className = 'status-indicator connecting';

        try {
            console.log('[KeyConnection] Connecting with key...');
            const result = await this.safeInvoke('connect_with_key', { key: key });

            console.log('[KeyConnection] Connected:', result);

            this.connected = true;
            this.connecting = false;
            this.currentKey = key;

            if (btn) {
                btn.textContent = '✅ Подключено';
                btn.classList.add('connected');
            }

            if (statusText) statusText.textContent = 'Подключено';
            if (statusDetails) statusDetails.textContent = result.server || 'VPN активен';
            if (statusIndicator) statusIndicator.className = 'status-indicator connected';

            // Show disconnect button
            const disconnectBtn = document.getElementById('disconnect-btn');
            if (disconnectBtn) disconnectBtn.style.display = 'block';

        } catch (err) {
            console.error('[KeyConnection] Connection failed:', err);
            this.connecting = false;

            if (btn) {
                btn.disabled = false;
                btn.textContent = '🚀 Подключиться';
            }

            if (statusText) statusText.textContent = 'Ошибка';
            if (statusDetails) statusDetails.textContent = err.message || String(err);
            if (statusIndicator) statusIndicator.className = 'status-indicator error';

            alert('Ошибка подключения: ' + (err.message || err));
        }
    }

    async disconnect() {
        const btn = document.getElementById('connect-key-btn');
        const disconnectBtn = document.getElementById('disconnect-btn');
        const statusText = document.getElementById('status-text');
        const statusDetails = document.getElementById('status-details');
        const statusIndicator = document.getElementById('status-indicator');

        try {
            console.log('[KeyConnection] Disconnecting...');
            await this.safeInvoke('disconnect');

            this.connected = false;
            this.currentKey = null;

            if (btn) {
                btn.disabled = false;
                btn.textContent = '🚀 Подключиться';
                btn.classList.remove('connected');
            }

            if (disconnectBtn) disconnectBtn.style.display = 'none';
            if (statusText) statusText.textContent = 'Отключено';
            if (statusDetails) statusDetails.textContent = 'Готов к подключению';
            if (statusIndicator) statusIndicator.className = 'status-indicator disconnected';

            console.log('[KeyConnection] Disconnected');

        } catch (err) {
            console.error('[KeyConnection] Disconnect failed:', err);
        }
    }

    getStatus() {
        return {
            connected: this.connected,
            connecting: this.connecting,
            key: this.currentKey
        };
    }
}

export const keyConnectionManager = new KeyConnectionManager();

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => keyConnectionManager.init());
} else {
    keyConnectionManager.init();
}
