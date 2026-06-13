import { api } from '../services/api.js';

export const routingPage = {
    async handleAddRoutingRule() {
        const form = document.getElementById('add-routing-form');
        const data = Object.fromEntries(new FormData(form));

        const rule = {
            type: data.type,
            condition: data.value,
            outbound: data.outboundTag,
            priority: 0
        };

        try {
            await api.addRoutingRule(rule);
            this.closeModals();
            this.loadRouting();
            this.showNotification('Правило добавлено', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    },
    async loadRouting() {
        const tbody = document.getElementById('routing-table-body');
        try {
            const data = await api.getRoutingRules();
            const rules = data.rules || data || [];

            if (rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет правил маршрутизации</td></tr>';
                return;
            }

            const tagBadge = tag => {
                if (tag === 'direct') return `<span style="background:rgba(74,222,128,0.15);color:#4ade80;padding:2px 8px;border-radius:4px;font-size:0.85em;">▶ direct</span>`;
                if (tag === 'block')  return `<span style="background:rgba(248,113,113,0.15);color:#f87171;padding:2px 8px;border-radius:4px;font-size:0.85em;">✕ block</span>`;
                if (tag === 'proxy')  return `<span style="background:rgba(167,139,250,0.15);color:#a78bfa;padding:2px 8px;border-radius:4px;font-size:0.85em;">⇢ proxy</span>`;
                return `<span style="background:rgba(251,191,36,0.15);color:#fbbf24;padding:2px 8px;border-radius:4px;font-size:0.85em;">⇢ ${tag}</span>`;
            };
            const typeLabel = t => t === 'domain' ? '🌐 домен' : t === 'ip' ? '📡 IP' : t;
            tbody.innerHTML = rules.map(r => `
    <tr>
                    <td>${typeLabel(r.type)}</td>
                    <td style="font-family:monospace;font-size:0.9em;">${r.domain || r.ip || '-'}</td>
                    <td>${tagBadge(r.outboundTag)}</td>
                    <td style="opacity:0.6;">${r.priority || 0}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" data-act="deleteRoutingRule" data-arg="${escapeHtml(String(r.id))}">Удалить</button>
                    </td>
                </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    },
    async deleteRoutingRule(id) {
        if (!(await this.showConfirm('Удалить правило?'))) return;
        try {
            await api.deleteRoutingRule(id);
            this.loadRouting();
            this.showNotification('Правило удалено', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }
};
