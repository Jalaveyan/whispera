// Whispera API Client (аналогично 3x-ui)

class WhisperaAPI {
    constructor() {
        // Always try real API first
        this.fallbackToDemo = false;  // Only enabled after connection failure

        // Determine API URL
        if (window.location.protocol === 'file:') {
            // For file:// protocol, enable demo mode immediately
            this.fallbackToDemo = true;
            this.baseURL = 'http://localhost:8080';
            console.log('[Whispera] File protocol detected, Demo Mode enabled immediately');
        } else {
            // Use current origin (protocol + hostname + port)
            // This works automatically for any IP/port combination
            this.baseURL = window.location.origin;
        }

        this.token = localStorage.getItem('whispera_token') || null;

        // Demo mode data storage (persists during session)
        this.mockUsers = [
            { id: 1, username: 'demo_user', privateKey: 'wsp_demo_123456abcdef', upload: 1073741824, download: 2147483648, trafficLimit: 10737418240, expiryDate: '2026-12-31', status: 'active' },
            { id: 2, username: 'test_user', privateKey: 'wsp_test_789012ghijkl', upload: 536870912, download: 1073741824, trafficLimit: 5368709120, expiryDate: '2026-06-30', status: 'active' },
            { id: 3, username: 'premium_user', privateKey: 'wsp_prem_345678mnopqr', upload: 2147483648, download: 4294967296, trafficLimit: 0, expiryDate: '2027-01-01', status: 'active' },
        ];
        this.mockSessions = [
            { id: 'sess_001', user: 'demo_user', ip: '192.168.1.100', connected_at: new Date().toISOString(), traffic: 52428800 },
            { id: 'sess_002', user: 'premium_user', ip: '10.0.0.55', connected_at: new Date(Date.now() - 3600000).toISOString(), traffic: 104857600 },
        ];
        this.nextUserId = 4;

        // Check server connectivity on init
        this.checkServerConnection();
    }

    // Check if server is available
    async checkServerConnection() {
        try {
            const response = await fetch(`${this.baseURL}/health`, {
                method: 'GET',
                timeout: 3000
            });
            if (response.ok) {
                this.fallbackToDemo = false;
                console.log('[Whispera] Connected to server at', this.baseURL);
            } else {
                throw new Error('Server not healthy');
            }
        } catch (error) {
            this.fallbackToDemo = true;
            console.warn('[Whispera] Server unavailable, demo mode enabled as fallback');
        }
    }

    // Установка токена авторизации
    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('whispera_token', token);
        } else {
            localStorage.removeItem('whispera_token');
        }
    }

    // Выполнение запроса к API
    async request(endpoint, options = {}) {
        // If we know server is down, use demo data
        if (this.fallbackToDemo) {
            return this.getMockData(endpoint, options);
        }

        const url = `${this.baseURL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            if (response.status === 401) {
                // Не авторизован - редирект на логин
                this.setToken(null);
                window.location.reload();
                throw new Error('Unauthorized');
            }

            // Проверяем Content-Type перед парсингом JSON
            const contentType = response.headers.get('content-type');
            let data;

            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                // Если ответ не JSON, читаем как текст
                const text = await response.text();
                throw new Error(text || `HTTP ${response.status}: ${response.statusText}`);
            }

            if (!response.ok) {
                // Извлекаем сообщение об ошибке
                const errorMsg = data.error || data.message || `HTTP ${response.status}: ${response.statusText}`;
                const error = new Error(errorMsg);
                error.status = response.status;
                error.data = data;
                throw error;
            }

            return data;
        } catch (error) {
            // Network error - enable fallback mode for future requests
            if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
                console.warn('[Whispera] Network error, switching to demo mode');
                this.fallbackToDemo = true;
                return this.getMockData(endpoint, options);
            }
            console.error('API Error:', error);
            throw error;
        }
    }

    // Авторизация
    async login(username, password) {
        const response = await this.request('/api/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        if (response.token) {
            this.setToken(response.token);
        }

        return response;
    }

    // Выход
    logout() {
        this.setToken(null);
    }

    // Mock data for demo mode
    getMockData(endpoint, options = {}) {
        // Route mock responses
        if (endpoint === '/api/login') {
            return { success: true, token: 'demo_token_' + Date.now() };
        }
        if (endpoint === '/api/users') {
            return this.mockUsers;
        }
        if (endpoint === '/api/sessions') {
            return this.mockSessions;
        }
        if (endpoint === '/api/stats') {
            return {
                total_users: 3,
                active_sessions: 2,
                total_upload: 3758096384,
                total_download: 7516192768,
                traffic: {
                    upload: 3758096384,
                    download: 7516192768
                },
                recentActivity: [
                    { type: 'connect', user: 'demo_user', ip: '192.168.1.100', time: new Date().toISOString() },
                    { type: 'connect', user: 'premium_user', ip: '10.0.0.55', time: new Date(Date.now() - 3600000).toISOString() },
                    { type: 'disconnect', user: 'test_user', ip: '172.16.0.25', time: new Date(Date.now() - 7200000).toISOString() }
                ]
            };
        }
        if (endpoint === '/api/system/info') {
            return {
                version: '1.0.0-demo',
                uptime: 259200,
                go_version: 'go1.21.5',
                server_ip: '127.0.0.1',
                public_key: 'WsdemoXpublicXkey123456789abcdefghijklmno='
            };
        }
        if (endpoint === '/api/system/status') {
            return { status: 'running', healthy: true };
        }
        if (endpoint === '/health') {
            return { status: 'ok' };
        }
        if (endpoint === '/api/logs') {
            return {
                logs: [
                    '[2026-01-06 13:00:00] [INFO] Server started',
                    '[2026-01-06 13:00:01] [INFO] Demo mode active',
                    '[2026-01-06 13:00:02] [INFO] Listening on :51820'
                ]
            };
        }
        if (endpoint === '/api/routing/rules') {
            return {
                rules: [
                    { id: 1, type: 'domain', condition: 'geosite:ru', outbound: 'direct', priority: 1, enabled: true },
                    { id: 2, type: 'domain', condition: 'geosite:google', outbound: 'proxy', priority: 2, enabled: true },
                    { id: 3, type: 'ip', condition: 'geoip:private', outbound: 'direct', priority: 0, enabled: true },
                    { id: 4, type: 'domain', condition: 'ads.example.com', outbound: 'block', priority: 3, enabled: false }
                ]
            };
        }
        if (endpoint === '/api/subscriptions') {
            return {
                subscriptions: [
                    { id: 1, name: 'Основная подписка', url: 'https://example.com/sub/abc123', interval: '24h', lastUpdate: new Date(Date.now() - 3600000).toISOString(), serverCount: 15, enabled: true },
                    { id: 2, name: 'Резервные серверы', url: 'https://backup.example.com/nodes', interval: '12h', lastUpdate: new Date(Date.now() - 86400000).toISOString(), serverCount: 8, enabled: true },
                    { id: 3, name: 'Тестовая подписка', url: 'https://test.example.com/proxy', interval: '6h', lastUpdate: null, serverCount: 0, enabled: false }
                ]
            };
        }
        if (endpoint === '/api/outbounds') {
            return {
                outbounds: [
                    { tag: 'direct', type: 'direct', address: '-', protocol: 'direct', latency: 0, availability: 100, enabled: true },
                    { tag: 'proxy-nl', type: 'whispera', address: 'nl.example.com:51820', protocol: 'Whispera', latency: 45, availability: 99.5, enabled: true },
                    { tag: 'proxy-de', type: 'whispera', address: 'de.example.com:51820', protocol: 'Whispera', latency: 62, availability: 98.2, enabled: true },
                    { tag: 'proxy-us', type: 'whispera', address: 'us.example.com:51820', protocol: 'Whispera', latency: 120, availability: 97.8, enabled: true },
                    { tag: 'block', type: 'blackhole', address: '-', protocol: 'block', latency: 0, availability: 100, enabled: true }
                ]
            };
        }
        if (endpoint === '/api/geo/status') {
            return {
                geoip: { loaded: true, entries: 12500, path: '/etc/whispera/geoip.dat', size: '4.2 MB' },
                geosite: { loaded: true, entries: 8400, path: '/etc/whispera/geosite.dat', size: '2.8 MB' },
                lastUpdate: new Date(Date.now() - 172800000).toISOString(),
                autoUpdate: true,
                updateInterval: '7d'
            };
        }
        if (endpoint === '/api/adblock/stats') {
            return { total_blocked: 1547, dns_blocked: 892, https_blocked: 423, ml_blocked: 232 };
        }
        if (endpoint.includes('/api/logs')) {
            const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
            return {
                logs: [
                    `[${now}] [INFO] System: Whispera started in demo mode`,
                    `[${now}] [INFO] API: Mock data initialized`,
                    `[${now}] [INFO] WireGuard: Interface wg0 up and running`,
                    `[${now}] [INFO] Stats: Traffic monitoring enabled`
                ]
            };
        }
        if (endpoint === '/api/adblock/rules') {
            return { rules: [] };
        }
        if (endpoint.includes('/api/stats/traffic')) {
            return {
                total_upload: 3758096384,
                total_download: 7516192768,
                active_users: 2,
                history: []
            };
        }
        if (endpoint === '/api/certificate/status') {
            return { has_certificate: false, domain: '', expiry: null };
        }

        // Key generation endpoints (critical for user creation)
        if (endpoint === '/api/keys/generate') {
            // Generate mock WireGuard-style keys (base64 encoded)
            const mockPrivateKey = this.generateMockBase64Key();
            const mockPublicKey = this.generateMockBase64Key();
            return {
                success: true,
                privateKey: mockPrivateKey,
                publicKey: mockPublicKey
            };
        }
        if (endpoint === '/api/keys/generate-server') {
            return {
                success: true,
                privateKey: this.generateMockBase64Key(),
                publicKey: this.generateMockBase64Key()
            };
        }
        if (endpoint === '/api/keys/derive') {
            return {
                success: true,
                publicKey: this.generateMockBase64Key()
            };
        }

        // Demo mode: Handle POST actions
        const method = (options.method || 'GET').toUpperCase();

        // Add user - persist to mockUsers
        if (endpoint === '/api/users/add' && method === 'POST') {
            const body = options.body ? JSON.parse(options.body) : {};
            const newId = this.nextUserId++;
            const privateKey = body.privateKey || this.generateMockBase64Key();
            const publicKey = body.publicKey || this.generateMockBase64Key();

            const newUser = {
                id: newId,
                name: body.username || body.name || 'new_user',
                key: privateKey,
                privateKey: privateKey, // Required for UI
                publicKey: publicKey,
                upload: 0,
                download: 0,
                limit: body.trafficLimit || body.limit || 0,
                expiry: body.expiryDate || body.expiry || '2027-01-01',
                enabled: true
            };

            // Add to persistent list
            this.mockUsers.push(newUser);
            console.log('[Demo] Added user:', newUser.name, 'Total users:', this.mockUsers.length);

            return {
                success: true,
                user: newUser,
                privateKey: privateKey,
                publicKey: publicKey,
                message: 'Пользователь создан (demo)'
            };
        }

        if (endpoint === '/api/users/delete' && method === 'POST') {
            const body = options.body ? JSON.parse(options.body) : {};
            console.log('[API Mock] Delete request body:', body);
            const userId = body.id || body.userId;
            console.log('[API Mock] Deleting user with ID:', userId, 'Current users:', this.mockUsers.length);
            const initialLength = this.mockUsers.length;
            this.mockUsers = this.mockUsers.filter(u => String(u.id) !== String(userId));
            console.log('[API Mock] New users count:', this.mockUsers.length, 'Deleted:', initialLength - this.mockUsers.length);
            return { success: true, message: 'Пользователь удален (demo)' };
        }

        // Generate key for existing user
        if (endpoint.includes('/generate-key') && method === 'POST') {
            const newKey = this.generateMockBase64Key();
            // Try to extract user id from endpoint like /api/users/123/generate-key
            const match = endpoint.match(/\/api\/users\/(\d+)\/generate-key/);
            if (match) {
                const userId = parseInt(match[1]);
                const user = this.mockUsers.find(u => u.id === userId);
                if (user) {
                    user.key = newKey;
                }
            }
            return { success: true, key: newKey, privateKey: newKey, publicKey: this.generateMockBase64Key(), message: 'Ключ сгенерирован (demo)' };
        }

        // Reset traffic
        if (endpoint.includes('/reset-traffic') && method === 'POST') {
            return { success: true, message: 'Трафик сброшен (demo)' };
        }

        // Let's Encrypt certificate
        if (endpoint === '/api/certificate/letsencrypt' && method === 'POST') {
            return {
                success: true,
                message: 'В demo-режиме сертификаты Let\'s Encrypt недоступны. Запустите реальный сервер.'
            };
        }

        // Upload certificate
        if (endpoint === '/api/certificate/upload' && method === 'POST') {
            return { success: true, message: 'Сертификат загружен (demo)' };
        }

        // Routing rules
        if (endpoint === '/api/routing/rules' && method === 'POST') {
            return { success: true, message: 'Правило добавлено (demo)' };
        }
        if (endpoint === '/api/routing/rules/add' && method === 'POST') {
            return { success: true, message: 'Правило маршрутизации добавлено (demo)' };
        }
        if (endpoint === '/api/routing/rules/delete' && method === 'POST') {
            return { success: true, message: 'Правило маршрутизации удалено (demo)' };
        }

        // Subscriptions
        if (endpoint === '/api/subscriptions/add' && method === 'POST') {
            return { success: true, message: 'Подписка добавлена (demo)' };
        }
        if (endpoint === '/api/subscriptions/update' && method === 'POST') {
            return { success: true, message: 'Подписка обновлена (demo)' };
        }
        if (endpoint === '/api/subscriptions/delete' && method === 'POST') {
            return { success: true, message: 'Подписка удалена (demo)' };
        }
        if (endpoint === '/api/subscriptions/enable' && method === 'POST') {
            return { success: true, message: 'Статус подписки изменен (demo)' };
        }
        if (endpoint === '/api/subscriptions/update-all' && method === 'POST') {
            return { success: true, message: 'Все подписки обновлены (demo)' };
        }

        // Outbounds
        if (endpoint === '/api/outbounds/add' && method === 'POST') {
            return { success: true, message: 'Сервер добавлен (demo)' };
        }
        if (endpoint === '/api/outbounds/update' && method === 'POST') {
            return { success: true, message: 'Сервер обновлен (demo)' };
        }
        if (endpoint === '/api/outbounds/delete' && method === 'POST') {
            return { success: true, message: 'Сервер удален (demo)' };
        }

        // Geo databases
        if (endpoint === '/api/geo/update' && method === 'POST') {
            return { success: true, message: 'Geo базы данных обновлены (demo)' };
        }
        if (endpoint === '/api/geo/reload' && method === 'POST') {
            return { success: true, message: 'Geo базы данных перезагружены (demo)' };
        }
        if (endpoint === '/api/geo/settings' && method === 'POST') {
            return { success: true, message: 'Настройки Geo сохранены (demo)' };
        }

        // System reload
        if (endpoint === '/api/system/reload' && method === 'POST') {
            return { success: true, message: 'Конфигурация перезагружена (demo)' };
        }

        // Setup wizard save
        if (endpoint === '/api/setup/wizard' && method === 'POST') {
            return { success: true, message: 'Настройки сохранены (demo)' };
        }

        // Update user
        if (endpoint.startsWith('/api/users/') && method === 'PUT') {
            return { success: true, message: 'Пользователь обновлен (demo)' };
        }

        // Enable/disable user
        if (endpoint.includes('/enable') || endpoint.includes('/disable')) {
            return { success: true, message: 'Статус изменен (demo)' };
        }

        // Default mock response
        return { success: true, demo: true };
    }

    // Generate mock base64 key (WireGuard-style 32 bytes = 44 chars base64)
    generateMockBase64Key() {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        // Convert to base64
        let binary = '';
        bytes.forEach(b => binary += String.fromCharCode(b));
        return btoa(binary);
    }

    // System API
    async getSystemInfo() {
        return this.request('/api/system/info');
    }

    async getSystemStatus() {
        return this.request('/api/system/status');
    }

    async reloadConfig() {
        return this.request('/api/system/reload', { method: 'POST' });
    }

    // Users API
    async getUsers() {
        return this.request('/api/users');
    }

    async getUser(id) {
        return this.request(`/api/users/${id}`);
    }

    async addUser(userData) {
        return this.request('/api/users/add', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    async updateUser(id, userData) {
        return this.request(`/api/users/${id}`, {
            method: 'PUT',
            body: JSON.stringify(userData)
        });
    }

    async deleteUser(id) {
        return this.request('/api/users/delete', {
            method: 'POST',
            body: JSON.stringify({ id: id })
        });
    }

    async generateKeys() {
        return this.request('/api/keys/generate', { method: 'POST' });
    }

    async generateServerKeys() {
        return this.request('/api/keys/generate-server', { method: 'POST' });
    }

    async resetUserTraffic(id) {
        return this.request(`/api/users/${id}/reset-traffic`, {
            method: 'POST'
        });
    }

    // Sessions API
    async getSessions() {
        return this.request('/api/sessions');
    }

    async getSession(id) {
        return this.request(`/api/sessions/${id}`);
    }

    async killSession(id) {
        return this.request(`/api/sessions/${id}/kill`, {
            method: 'POST'
        });
    }

    // Stats API
    async getStats() {
        return this.request('/api/stats');
    }

    async getTrafficStats() {
        return this.request('/api/stats/traffic');
    }

    // Logs API
    async getLogs(limit = 100) {
        return this.request(`/api/logs?limit=${limit}`);
    }

    // Health check
    async healthCheck() {
        try {
            return await this.request('/health');
        } catch {
            return { status: 'unavailable' };
        }
    }

    // Keys API - генерация ключей
    async generateKeys() {
        return this.request('/api/keys/generate', {
            method: 'POST'
        });
    }

    async generateServerKeys() {
        return this.request('/api/keys/generate-server', {
            method: 'POST'
        });
    }

    // Certificate management API
    async getCertificateStatus() {
        return this.request('/api/certificate/status', {
            method: 'GET'
        });
    }

    async obtainCertificate(domain, email) {
        return this.request('/api/certificate/obtain', {
            method: 'POST',
            body: JSON.stringify({ domain, email })
        });
    }

    async renewCertificate() {
        return this.request('/api/certificate/renew', {
            method: 'POST'
        });
    }

    async derivePublicKey(privateKey) {
        return this.request('/api/keys/derive', {
            method: 'POST',
            body: JSON.stringify({ privateKey })
        });
    }

    // Firewall API
    async getFirewallRules() {
        return this.request('/api/firewall/rules');
    }

    async addFirewallRule(rule) {
        return this.request('/api/firewall/rules/add', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async removeFirewallRule(ruleId) {
        return this.request('/api/firewall/rules/delete', {
            method: 'POST',
            body: JSON.stringify({ id: ruleId })
        });
    }

    async configureFirewall(ports) {
        return this.request('/api/firewall/configure', {
            method: 'POST',
            body: JSON.stringify({ ports })
        });
    }

    // Ports API
    async getPorts() {
        return this.request('/api/ports');
    }

    async addPort(portInfo) {
        return this.request('/api/ports/add', {
            method: 'POST',
            body: JSON.stringify(portInfo)
        });
    }

    async removePort(port) {
        return this.request('/api/ports/delete', {
            method: 'POST',
            body: JSON.stringify({ port })
        });
    }

    // Traffic API
    async getUserTraffic(userId) {
        return this.request(`/api/stats/user/${userId}`);
    }

    async getTrafficHistory(period = '24h') {
        return this.request(`/api/stats/traffic/history?period=${period}`);
    }

    // Ports validation API
    async checkPortAvailability(port, protocol = 'tcp') {
        return this.request(`/api/ports/check?port=${port}&protocol=${protocol}`);
    }

    async getUsedPorts() {
        return this.request('/api/ports/used');
    }

    // AdBlocker API
    async getAdblockStats() {
        return this.request('/api/adblock/stats');
    }

    async getAdblockRules() {
        return this.request('/api/adblock/rules');
    }

    async addAdblockRule(rule) {
        return this.request('/api/adblock/rules/add', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async removeAdblockRule(ruleId) {
        return this.request('/api/adblock/rules/delete', {
            method: 'POST',
            body: JSON.stringify({ id: ruleId })
        });
    }

    async updateAdblockSettings(settings) {
        return this.request('/api/adblock/settings', {
            method: 'POST',
            body: JSON.stringify(settings)
        });
    }

    // Routing API
    async getRoutingRules() {
        return this.request('/api/routing/rules');
    }

    async addRoutingRule(rule) {
        return this.request('/api/routing/rules/add', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async deleteRoutingRule(ruleId) {
        return this.request('/api/routing/rules/delete', {
            method: 'POST',
            body: JSON.stringify({ id: ruleId })
        });
    }

    // Subscriptions API
    async getSubscriptions() {
        return this.request('/api/subscriptions');
    }

    async addSubscription(subscription) {
        return this.request('/api/subscriptions/add', {
            method: 'POST',
            body: JSON.stringify(subscription)
        });
    }

    async updateSubscription(id, subscription) {
        return this.request('/api/subscriptions/update', {
            method: 'POST',
            body: JSON.stringify({ id, ...subscription })
        });
    }

    async deleteSubscription(id) {
        return this.request('/api/subscriptions/delete', {
            method: 'POST',
            body: JSON.stringify({ id })
        });
    }

    async enableSubscription(id, enabled) {
        return this.request('/api/subscriptions/enable', {
            method: 'POST',
            body: JSON.stringify({ id, enabled })
        });
    }

    async updateAllSubscriptions() {
        return this.request('/api/subscriptions/update-all', {
            method: 'POST'
        });
    }

    // Outbounds API
    async getOutbounds() {
        return this.request('/api/outbounds');
    }

    async addOutbound(outbound) {
        return this.request('/api/outbounds/add', {
            method: 'POST',
            body: JSON.stringify(outbound)
        });
    }

    async updateOutbound(tag, outbound) {
        return this.request('/api/outbounds/update', {
            method: 'POST',
            body: JSON.stringify({ tag, ...outbound })
        });
    }

    async deleteOutbound(tag) {
        return this.request('/api/outbounds/delete', {
            method: 'POST',
            body: JSON.stringify({ tag })
        });
    }

    // Outbound Groups API
    async getOutboundGroups() {
        return this.request('/api/outbound-groups');
    }

    async addOutboundGroup(group) {
        return this.request('/api/outbound-groups/add', {
            method: 'POST',
            body: JSON.stringify(group)
        });
    }

    async updateOutboundGroup(tag, group) {
        return this.request('/api/outbound-groups/update', {
            method: 'POST',
            body: JSON.stringify({ tag, ...group })
        });
    }

    async deleteOutboundGroup(tag) {
        return this.request('/api/outbound-groups/delete', {
            method: 'POST',
            body: JSON.stringify({ tag })
        });
    }

    // Geo databases API
    async getGeoStatus() {
        return this.request('/api/geo/status');
    }

    async updateGeoDatabases() {
        return this.request('/api/geo/update', {
            method: 'POST'
        });
    }

    async reloadGeoDatabases() {
        return this.request('/api/geo/reload', {
            method: 'POST'
        });
    }

    async getGeoSettings() {
        return this.request('/api/geo/settings');
    }

    async updateGeoSettings(settings) {
        return this.request('/api/geo/settings', {
            method: 'POST',
            body: JSON.stringify(settings)
        });
    }
}

// Создаем глобальный экземпляр API
const api = new WhisperaAPI();

