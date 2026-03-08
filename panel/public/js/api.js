
class WhisperaAPI {
    constructor() {
        this.baseURL = window.location.origin;
        this.token = localStorage.getItem('whispera_token');
    }

    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('whispera_token', token);
        } else {
            localStorage.removeItem('whispera_token');
        }
    }

    async request(endpoint, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const response = await fetch(`${this.baseURL}${endpoint}`, {
            ...options,
            headers,
        });

        if (response.status === 401) {
            this.setToken(null);
            window.location.href = '/';
            throw new Error('Unauthorized');
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || data.message || `HTTP ${response.status}`);
            }
            return data;
        }
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return response.text();
    }

    async login(username, password) {
        const data = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });
        if (data.token) {
            this.setToken(data.token);
            if (data.user && data.user.id) localStorage.setItem('whispera_user_id', data.user.id);
            if (data.user && data.user.username) localStorage.setItem('whispera_email', data.user.username);
        }
        return data;
    }

    logout() {
        this.setToken(null);
        localStorage.removeItem('whispera_user_id');
        localStorage.removeItem('whispera_email');
    }

    async getUsers() {
        return this.request('/api/users');
    }

    async createUser(email, password, trafficLimitGB = 0, expiryDate = null, options = {}) {
        const trafficLimit = trafficLimitGB * 1024 * 1024 * 1024;

        return this.request('/api/users', {
            method: 'POST',
            body: JSON.stringify({
                email,
                password,
                traffic_limit: trafficLimit,
                valid_until: expiryDate,
                obfs_profile: options.obfsProfile || 'http2',
                marionette_profile: options.marionetteProfile || 'browser',
                russian_service: options.russianService || 'vk'
            }),
        });
    }

    async updateUser(id, data) {
        return this.request(`/api/users/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    async deleteUser(id) {
        return this.request(`/api/users/${id}`, { method: 'DELETE' });
    }

    async generateConnectionKey(opts = {}) {
        return this.request('/api/keys/connection', {
            method: 'POST',
            body: JSON.stringify(opts),
        });
    }

    async getSessions() {
        return this.request('/api/sessions');
    }

    async killSession(id) {
        return this.request(`/api/sessions/${id}/kill`, { method: 'POST' });
    }

    async getInbounds() {
        return this.request('/api/inbounds');
    }

    async addInbound(inbound) {
        return this.request('/api/inbounds', {
            method: 'POST',
            body: JSON.stringify(inbound)
        });
    }

    async deleteInbound(tag) {
        return this.request(`/api/inbounds/${tag}`, { method: 'DELETE' });
    }

    async getInboundPublicKey(port) {
        return this.request(`/api/publickey/${port}`);
    }

    async getOutbounds() {
        return this.request('/api/outbounds');
    }

    async addOutbound(outbound) {
        return this.request('/api/outbounds', {
            method: 'POST',
            body: JSON.stringify(outbound)
        });
    }

    async deleteOutbound(tag) {
        return this.request('/api/outbounds/delete', {
            method: 'POST',
            body: JSON.stringify({ tag })
        });
    }

    async getRoutingRules() {
        return this.request('/api/routing/rules');
    }

    async addRoutingRule(rule) {
        return this.request('/api/routing/rules', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async updateRoutingRule(id, rule) {
        return this.request(`/api/routing/rules/${id}`, {
            method: 'PUT',
            body: JSON.stringify(rule)
        });
    }

    async deleteRoutingRule(id) {
        return this.request(`/api/routing/rules/${id}`, { method: 'DELETE' });
    }

    async getSubscriptions() {
        return this.request('/api/subscriptions');
    }

    async addSubscription(sub) {
        return this.request('/api/subscriptions/add', {
            method: 'POST',
            body: JSON.stringify(sub)
        });
    }

    async updateSubscription(id, sub) {
        return this.request('/api/subscriptions/update', {
            method: 'POST',
            body: JSON.stringify({ id, ...sub })
        });
    }

    async deleteSubscription(id) {
        return this.request('/api/subscriptions/delete', {
            method: 'POST',
            body: JSON.stringify({ id })
        });
    }

    async updateAllSubscriptions() {
        return this.request('/api/subscriptions/update-all', { method: 'POST' });
    }

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

    async deleteAdblockRule(id) {
        return this.request('/api/adblock/rules/delete', {
            method: 'POST',
            body: JSON.stringify({ id })
        });
    }

    async updateAdblockSettings(settings) {
        return this.request('/api/adblock/settings', {
            method: 'POST',
            body: JSON.stringify(settings)
        });
    }

    async getBridges() {
        return this.request('/api/bridges');
    }

    // Прямой запрос к Go backend — возвращает полные BridgeInfo (is_alive, latency_ms, trust_level и т.д.)
    async getBridgesAdmin() {
        return this.request('/api/bridge-admin');
    }

    async getBridgeStats() {
        return this.request('/api/bridge-stats');
    }

    async checkBridge(id) {
        return this.request('/api/bridge-check', {
            method: 'POST',
            body: JSON.stringify({ id })
        });
    }

    async getBridgeToken() {
        return this.request('/api/bridge-token');
    }

    async regenerateBridgeToken() {
        return this.request('/api/bridge-token-regenerate', { method: 'POST' });
    }

    async addBridge(bridge) {
        return this.request('/api/bridge-add', {
            method: 'POST',
            body: JSON.stringify(bridge)
        });
    }

    async deleteBridge(id) {
        return this.request('/api/bridge-delete', {
            method: 'POST',
            body: JSON.stringify({ id })
        });
    }

    async getBridgeCloudInit() {
        return this.request('/api/bridge-cloudinit', {
            headers: { 'Accept': 'text/plain' }
        });
    }

    async getSessions() {
        return this.request('/api/sessions');
    }

    async killSession(id) {
        return this.request(`/api/sessions/${id}/kill`, { method: 'POST' });
    }

    async getStats() {
        return this.request('/api/stats');
    }

    async getTrafficStats(period = '24h') {
        return this.request(`/api/stats/traffic?period=${period}`);
    }

    async getUserTraffic() {
        return this.request('/api/stats/users');
    }

    async getChartData(period = '24h') {
        return this.request(`/api/stats/chart?period=${period}`);
    }

    async getSystemInfo() {
        return this.request('/api/system/info');
    }

    async reloadConfig() {
        return this.request('/api/system/reload', { method: 'POST' });
    }

    async getHealth() {
        return this.request('/api/health');
    }

    async getDashboard() {
        return this.request('/api/dashboard');
    }

    async updateServerSettings(settings) {
        const config = {
            server: {
                port: parseInt(settings.port) || 0
            },
        };
        return this.request('/api/v1/config/update', {
            method: 'POST',
            body: JSON.stringify(config)
        });
    }

    async getProbeStats() {
        return this.request('/api/probe/stats');
    }

    async probeBlockIP(ip, reason) {
        return this.request('/api/probe/block', {
            method: 'POST',
            body: JSON.stringify({ ip, reason })
        });
    }

    async probeUnblockIP(ip) {
        return this.request('/api/probe/unblock', {
            method: 'POST',
            body: JSON.stringify({ ip })
        });
    }

    async updateStealthMode(mode) {
        return this.request('/api/v1/config/update', {
            method: 'POST',
            body: JSON.stringify({ stealth_mode: mode })
        });
    }

    async getStealthMode() {
        const cfg = await this.request('/api/v1/config');
        return cfg.stealth_mode || '';
    }

    async renewCertificate() {
        return this.request('/api/v1/config/renew-cert', { method: 'POST' });
    }

    async updateAdminProfile(username, password) {
        return this.request('/api/admin/update', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });
    }

    async getLogs(limit = 200) {
        return this.request(`/api/logs?limit=${limit}`);
    }

    async getBackup() {
        return this.request('/api/backup', { method: 'GET' });
    }

    async restoreBackup(file) {
        const text = await file.text();
        const backup = JSON.parse(text);
        return this.request('/api/backup/restore', {
            method: 'POST',
            body: JSON.stringify(backup),
        });
    }
}

window.api = new WhisperaAPI();
