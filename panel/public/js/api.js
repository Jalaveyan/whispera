
class WhisperaAPI {
    constructor() {
        this.baseURL = window.location.origin;
        this.token = sessionStorage.getItem('whispera_token');
        this._tokenExpiry = parseInt(sessionStorage.getItem('whispera_token_expiry') || '0', 10);
        if (this.token && this._tokenExpiry && Date.now() > this._tokenExpiry) {
            this.token = null;
            sessionStorage.removeItem('whispera_token');
            sessionStorage.removeItem('whispera_token_expiry');
        }
    }

    setToken(token, expiresIn) {
        this.token = token;
        if (token) {
            sessionStorage.setItem('whispera_token', token);
            const expiry = Date.now() + (expiresIn || 1800) * 1000;
            this._tokenExpiry = expiry;
            sessionStorage.setItem('whispera_token_expiry', String(expiry));
        } else {
            sessionStorage.removeItem('whispera_token');
            sessionStorage.removeItem('whispera_token_expiry');
            this._tokenExpiry = 0;
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
            if (this.token) {
                this.setToken(null);
                window.location.href = '/';
            }
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
            this.setToken(data.token, data.expires_in || 1800);
            if (data.user && data.user.id) sessionStorage.setItem('whispera_user_id', data.user.id);
            if (data.user && data.user.username) sessionStorage.setItem('whispera_email', data.user.username);
        }
        return data;
    }

    async logout() {
        try {
            await this.request('/api/auth/logout', { method: 'POST' });
        } catch (_) {}
        this.setToken(null);
        sessionStorage.removeItem('whispera_user_id');
        sessionStorage.removeItem('whispera_email');
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


    async getBridges() {
        return this.request('/api/bridges');
    }

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

    async getWhiteBridges() {
        return this.request('/api/bridge-white');
    }

    async getBridgeMap() {
        return this.request('/api/bridge-map');
    }

    async connectToBridge(bridgeId) {
        return this.request('/api/bridge-connect', {
            method: 'POST',
            body: JSON.stringify({ bridge_id: bridgeId })
        });
    }

    async scanBridges() {
        return this.request('/api/bridge-scan', { method: 'POST' });
    }

    async pingBridge(id, count = 5) {
        return this.request('/api/bridge-ping', {
            method: 'POST',
            body: JSON.stringify({ id, count, mode: 'tcp' })
        });
    }

    async setBridgeLabel(id, blacklisted) {
        return this.request('/api/bridge-label', {
            method: 'POST',
            body: JSON.stringify({ id, blacklisted })
        });
    }

    async setAdminSSHKey(sshKey) {
        return this.request('/api/bridge-ssh-admin', {
            method: 'POST',
            body: JSON.stringify({ ssh_key: sshKey })
        });
    }

    async issueAccessKey(bridgeId, userId, oneTime = true, ttlHours = 24) {
        return this.request('/api/bridge-access-key', {
            method: 'POST',
            body: JSON.stringify({ bridge_id: bridgeId, user_id: userId, one_time: oneTime, ttl_hours: ttlHours })
        });
    }

    async revokeAccessKey(keyId) {
        return this.request('/api/bridge-access-revoke', {
            method: 'POST',
            body: JSON.stringify({ key_id: keyId })
        });
    }

    async getWhiteBridgeCloudInit(opts = {}) {
        const params = new URLSearchParams();
        if (opts.server) params.set('server', opts.server);
        if (opts.country) params.set('country', opts.country);
        if (opts.city) params.set('city', opts.city);
        if (opts.bandwidth) params.set('bandwidth', opts.bandwidth);
        if (opts.maxUsers) params.set('max_users', opts.maxUsers);
        return this.request(`/api/bridge-white-cloudinit?${params}`, {
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

    async updatePublicURL(url) {
        return this.request('/api/v1/config/update', {
            method: 'POST',
            body: JSON.stringify({ server: { public_url: url } })
        });
    }

    async getPublicURL() {
        const cfg = await this.request('/api/v1/config');
        return cfg.public_url || '';
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
