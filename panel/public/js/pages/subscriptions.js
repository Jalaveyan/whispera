import { api } from '../services/api.js';

export const subscriptionsPage = {
    async handleAddSubscription() {
        const form = document.getElementById('add-subscription-form');
        const raw = Object.fromEntries(new FormData(form));
        const data = {
            name: raw.name,
            transports: raw.transports
                ? raw.transports.split(',').map(s => s.trim()).filter(Boolean)
                : []
        };

        try {
            await api.addSubscription(data);
            this.closeModals();
            this.loadSubscriptions();
            this.showNotification('Подписка добавлена', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    },
    async loadSubscriptions() {
        const tbody = document.getElementById('subscriptions-table-body');
        try {
            const data = await api.getSubscriptions();
            const subs = data.subscriptions || data || [];

            if (subs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" class="text-center"><div style="display:flex;flex-direction:column;align-items:center;gap:12px"><i class="fas fa-rss" style="font-size:32px;opacity:.3"></i><span>Нет подписок</span></div></td></tr>`;
                return;
            }

            this._subById = {};
            subs.forEach(s => { this._subById[s.id] = s; });

            tbody.innerHTML = subs.map(s => {
                const esc = v => String(v || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
                const url = s.sub_url || '';
                const transports = (s.transports || []).join(', ') || '—';
                const userCount = (s.user_ids || []).length || '—';
                return `<tr>
                    <td>${esc(s.name)}</td>
                    <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        <span title="${esc(url)}">${esc(url) || '-'}</span>
                    </td>
                    <td>${esc(transports)}</td>
                    <td>${esc(userCount)}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm sub-copy-btn" data-id="${esc(s.id)}">Копировать</button>
                        <button class="btn btn-danger btn-sm sub-del-btn" data-id="${esc(s.id)}">Удалить</button>
                    </td>
                </tr>`;
            }).join('');

            tbody.querySelectorAll('.sub-copy-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const s = this._subById[btn.dataset.id];
                    if (s?.sub_url) navigator.clipboard.writeText(s.sub_url).then(() => this.showNotification('URL скопирован', 'success'));
                });
            });
            tbody.querySelectorAll('.sub-del-btn').forEach(btn => {
                btn.addEventListener('click', () => this.deleteSubscription(btn.dataset.id));
            });
        } catch (error) {
            const msg = error?.message || 'Ошибка соединения с сервером';
            tbody.innerHTML = `<tr><td colspan="5" class="text-center" style="color:var(--md-sys-color-error,#f87171)"><i class="fas fa-exclamation-circle"></i> ${msg}</td></tr>`;
        }
    },
    async deleteSubscription(id) {
        if (!(await this.showConfirm('Удалить подписку?'))) return;
        try {
            await api.deleteSubscription(id);
            this.loadSubscriptions();
            this.showNotification('Подписка удалена', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }
};
