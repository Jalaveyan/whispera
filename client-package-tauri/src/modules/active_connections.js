// Active Connections Manager
// Fetches and displays real active TCP/UDP connections

import { invoke } from '@tauri-apps/api/core';

class ActiveConnectionManager {
    constructor() {
        this.updateInterval = null;
        this.connectionsList = null;
        this.emptyState = null;
    }

    init() {
        // Initialize when connections page is active
        this.connectionsList = document.querySelector('.connection-list');
        this.emptyState = document.querySelector('.empty-state');

        // Check if current page is connections (on load/refresh)
        const activePage = document.querySelector('.page.active');
        if (activePage && activePage.id === 'page-connections') {
            this.startMonitoring();
        }

        // Listen for navigation to connections page
        document.addEventListener('click', (e) => {
            if (e.target.closest('.nav-item[data-page="connections"]') ||
                e.target.closest('.stat-item[data-page="connections"]')) {
                this.startMonitoring();
            } else if (e.target.closest('.nav-item:not([data-page="connections"])')) {
                this.stopMonitoring();
            }
        });

        // Search functionality
        const searchInput = document.querySelector('.connection-search input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filterConnections(e.target.value);
            });
        }
    }

    startMonitoring() {
        if (this.updateInterval) return;

        // Initial fetch
        this.fetchConnections();

        // Poll every 3 seconds
        this.updateInterval = setInterval(() => this.fetchConnections(), 3000);
        console.log('[ActiveConnections] Monitoring started');
    }

    stopMonitoring() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
            console.log('[ActiveConnections] Monitoring stopped');
        }
    }

    closeAll() {
        this.stopMonitoring();
        this.showEmptyState('Все соединения закрыты пользователем');
        this.updateCount(0);
        this.logDebug('Connections closed by user');
    }

    logDebug(msg) {
        // Console only, no on-screen spam
        console.log('[ActiveConnections]', msg);
    }

    async safeInvoke(command, args) {
        // Try imported invoke
        try {
            if (typeof invoke === 'function') {
                return await invoke(command, args);
            }
        } catch (e) { console.warn('[ActiveConnections] Imported invoke failed:', e); }

        // Try global Tauri v2
        if (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function') {
            console.log('[ActiveConnections] Using window.__TAURI__.core.invoke');
            return await window.__TAURI__.core.invoke(command, args);
        }

        // Try global Tauri v1
        if (window.__TAURI__ && typeof window.__TAURI__.invoke === 'function') {
            console.log('[ActiveConnections] Using window.__TAURI__.invoke');
            return await window.__TAURI__.invoke(command, args);
        }

        throw new Error('Tauri API not found (invoke is undefined)');
    }

    async fetchConnections() {
        try {
            // this.logDebug('Fetching data...');
            const result = await this.safeInvoke('get_active_connections');

            if (result.success) {
                // this.logDebug(`Got ${result.connections ? result.connections.length : 0} items`);
                this.renderConnections(result.connections);
                this.updateCount(result.total);
            } else {
                this.logDebug('Rust returned success=false');
            }
        } catch (error) {
            console.error('[ActiveConnections] Failed to fetch:', error);
            this.logDebug('Error: ' + (error.message || error));
            this.showEmptyState('Ошибка: ' + (error.message || error));
        }
    }

    renderConnections(connections) {
        if (!this.connectionsList) {
            this.connectionsList = document.querySelector('.connection-list');
        }

        const emptyState = document.querySelector('.empty-state');

        if (!connections || connections.length === 0) {
            this.logDebug('No connections to display (length=0)');
            if (emptyState) emptyState.style.display = 'flex';
            if (this.connectionsList) this.connectionsList.innerHTML = '';
            return;
        }

        if (emptyState) emptyState.style.display = 'none';

        if (this.connectionsList) {
            const html = connections.map(conn => this.createConnectionCard(conn)).join('');
            this.connectionsList.innerHTML = html;
        } else {
            this.logDebug('ERROR: .connection-list not found!');
        }
    }

    createConnectionCard(conn) {
        const typeClass = this.getTypeClass(conn.type);
        const stateClass = this.getStateClass(conn.state);

        return `
            <div class="connection-item">
                <div class="active-indicator ${stateClass}"></div>
                <div class="connection-info">
                    <div class="connection-host">
                        <span class="host-name" title="${conn.remoteAddress}">${conn.host || conn.remoteAddress}</span>
                        <span class="connection-tag ${typeClass}">${conn.type}</span>
                    </div>
                    <div class="connection-details">
                        <span class="detail-item">Protocol: ${conn.protocol}</span>
                        <span class="detail-item">PID: ${conn.pid}</span>
                        <span class="detail-item">${conn.localAddress} → ${conn.port}</span>
                    </div>
                </div>
                <div class="connection-actions">
                    <span class="connection-state ${stateClass}">${conn.state}</span>
                    <button class="action-btn-small" title="Закрыть (Недоступно)">✕</button>
                </div>
            </div>
        `;
    }

    getTypeClass(type) {
        switch (type) {
            case 'HTTPS': return 'tag-secure';
            case 'HTTP': return 'tag-warning';
            case 'DNS': return 'tag-info';
            default: return 'tag-neutral';
        }
    }

    getStateClass(state) {
        switch (state) {
            case 'ESTABLISHED': return 'state-active';
            case 'TIME_WAIT': return 'state-waiting';
            case 'CLOSE_WAIT': return 'state-closing';
            default: return 'state-neutral';
        }
    }

    updateCount(count) {
        const countEl = document.getElementById('connections-count');
        if (countEl) countEl.textContent = count;
    }

    showEmptyState(msg) {
        if (this.emptyState) {
            this.emptyState.style.display = 'flex';
            if (msg) this.emptyState.querySelector('span').textContent = msg;
        }
        if (this.connectionsList) {
            this.connectionsList.innerHTML = '';
        }
    }

    filterConnections(query) {
        if (!query) {
            const items = document.querySelectorAll('.connection-item');
            items.forEach(item => item.style.display = 'flex');
            return;
        }

        const lowerQuery = query.toLowerCase();
        const items = document.querySelectorAll('.connection-item');

        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            item.style.display = text.includes(lowerQuery) ? 'flex' : 'none';
        });
    }
}

export const activeConnectionManager = new ActiveConnectionManager();

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => activeConnectionManager.init());
} else {
    activeConnectionManager.init();
}
