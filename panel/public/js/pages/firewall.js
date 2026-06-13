import { api } from '../services/api.js';

export const firewallPage = {
    async showFirewallModal() {
        const modal = document.createElement('div');
        modal.className = 'modal-backdrop active';
        modal.style.zIndex = '10000';
        modal.innerHTML = `
        <div class="modal" style="max-width:680px;">
            <div class="modal-header">
                <h3><i class="fas fa-fire-alt" style="margin-right:8px;color:#f59e0b;"></i>Управление Firewall (UFW)</h3>
                <button class="modal-close modal-close-icon" onclick="this.closest('.modal-backdrop').remove()"><i class="fas fa-times"></i></button>
            </div>
            <div class="modal-body" style="display:flex;flex-direction:column;gap:20px;">

                <div id="fw-status-bar" style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:8px;border-left:3px solid var(--border,#333);background:rgba(255,255,255,0.03);border:1px solid var(--border,rgba(255,255,255,0.08));">
                    <span id="fw-status-text" style="flex:1;font-size:0.9em;opacity:0.7;">Загрузка...</span>
                    <button id="fw-toggle-btn" class="btn btn-sm" style="display:none;"></button>
                </div>

                <div>
                    <div style="font-size:0.75em;text-transform:uppercase;letter-spacing:0.08em;opacity:0.45;margin-bottom:10px;font-weight:600;">Правила</div>
                    <div id="fw-rules-table" style="overflow-x:auto;border-radius:8px;border:1px solid rgba(255,255,255,0.07);">
                        <table style="width:100%;border-collapse:collapse;font-size:0.87em;">
                            <thead>
                                <tr style="background:rgba(255,255,255,0.03);">
                                    <th style="text-align:left;padding:9px 12px;font-weight:500;opacity:0.5;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em;">#</th>
                                    <th style="text-align:left;padding:9px 12px;font-weight:500;opacity:0.5;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em;">Назначение</th>
                                    <th style="text-align:left;padding:9px 12px;font-weight:500;opacity:0.5;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em;">Действие</th>
                                    <th style="text-align:left;padding:9px 12px;font-weight:500;opacity:0.5;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em;">Откуда</th>
                                    <th style="padding:9px 12px;"></th>
                                </tr>
                            </thead>
                            <tbody id="fw-rules-body">
                                <tr><td colspan="5" style="text-align:center;padding:20px;opacity:0.4;font-size:0.9em;">Загрузка...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div style="border-top:1px solid rgba(255,255,255,0.07);padding-top:18px;">
                    <div style="font-size:0.75em;text-transform:uppercase;letter-spacing:0.08em;opacity:0.45;margin-bottom:12px;font-weight:600;">Добавить правило</div>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
                        <div class="form-group" style="margin-bottom:0;display:flex;flex-direction:column;gap:5px;">
                            <label style="font-size:0.78em;opacity:0.6;font-weight:500;">Действие</label>
                            <select id="fw-new-action" style="width:110px;height:38px;font-size:13px;padding:0 32px 0 12px;">
                                <option value="allow">ALLOW</option>
                                <option value="deny">DENY</option>
                            </select>
                        </div>
                        <div class="form-group" style="margin-bottom:0;display:flex;flex-direction:column;gap:5px;">
                            <label style="font-size:0.78em;opacity:0.6;font-weight:500;">Порт</label>
                            <input id="fw-new-port" type="text" placeholder="80 или 8080:9090" style="width:155px;height:38px;font-size:13px;padding:0 12px;">
                        </div>
                        <div class="form-group" style="margin-bottom:0;display:flex;flex-direction:column;gap:5px;">
                            <label style="font-size:0.78em;opacity:0.6;font-weight:500;">Протокол</label>
                            <select id="fw-new-proto" style="width:95px;height:38px;font-size:13px;padding:0 32px 0 12px;">
                                <option value="any">any</option>
                                <option value="tcp">tcp</option>
                                <option value="udp">udp</option>
                            </select>
                        </div>
                        <div class="form-group" style="margin-bottom:0;display:flex;flex-direction:column;gap:5px;">
                            <label style="font-size:0.78em;opacity:0.6;font-weight:500;">Откуда (опц.)</label>
                            <input id="fw-new-from" type="text" placeholder="Anywhere" style="width:155px;height:38px;font-size:13px;padding:0 12px;">
                        </div>
                        <button id="fw-add-btn" class="btn btn-primary btn-sm" style="white-space:nowrap;align-self:flex-end;">
                            <i class="fas fa-plus"></i> Добавить
                        </button>
                    </div>
                </div>

            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary btn-sm" onclick="this.closest('.modal-backdrop').remove()">Закрыть</button>
            </div>
        </div>`;
        document.body.appendChild(modal);

        const renderRules = (status) => {
            const statusBar = modal.querySelector('#fw-status-bar');
            const statusText = modal.querySelector('#fw-status-text');
            const toggleBtn = modal.querySelector('#fw-toggle-btn');
            const tbody = modal.querySelector('#fw-rules-body');

            if (status.active) {
                statusBar.style.cssText = 'display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:8px;background:rgba(74,222,128,0.05);border:1px solid rgba(74,222,128,0.2);';
                statusText.innerHTML = '<i class="fas fa-circle" style="color:#4ade80;margin-right:8px;font-size:9px;"></i><span style="font-weight:500;">UFW активен</span>';
                toggleBtn.className = 'btn btn-sm btn-danger';
                toggleBtn.innerHTML = '<i class="fas fa-power-off" style="margin-right:5px;"></i>Отключить';
            } else {
                statusBar.style.cssText = 'display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:8px;background:rgba(248,113,113,0.05);border:1px solid rgba(248,113,113,0.2);';
                statusText.innerHTML = '<i class="fas fa-circle" style="color:#f87171;margin-right:8px;font-size:9px;"></i><span style="font-weight:500;">UFW неактивен</span>';
                toggleBtn.className = 'btn btn-sm btn-primary';
                toggleBtn.innerHTML = '<i class="fas fa-power-off" style="margin-right:5px;"></i>Включить';
            }
            toggleBtn.style.display = '';

            if (!status.rules || status.rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;opacity:0.4;font-size:0.9em;">Правил нет</td></tr>';
            } else {
                tbody.innerHTML = status.rules.map(r => `
                    <tr style="border-top:1px solid rgba(255,255,255,0.05);transition:background 0.15s;" onmouseover="this.style.background='rgba(255,255,255,0.03)'" onmouseout="this.style.background=''">
                        <td style="padding:10px 12px;opacity:0.4;font-size:0.85em;">${r.number}</td>
                        <td style="padding:10px 12px;font-family:monospace;font-size:0.88em;">${r.to}${r.ipv6 ? ' <span style="opacity:0.4;font-size:0.8em;margin-left:4px;">v6</span>' : ''}</td>
                        <td style="padding:10px 12px;">
                            <span style="padding:3px 10px;border-radius:20px;font-size:0.78em;font-weight:600;letter-spacing:0.04em;${r.action.includes('ALLOW') ? 'background:rgba(34,197,94,0.12);color:#4ade80;border:1px solid rgba(34,197,94,0.2);' : 'background:rgba(239,68,68,0.12);color:#f87171;border:1px solid rgba(239,68,68,0.2);'}">
                                ${r.action}
                            </span>
                        </td>
                        <td style="padding:10px 12px;opacity:0.7;font-size:0.88em;">${r.from}</td>
                        <td style="padding:10px 12px;text-align:right;">
                            <button onclick="app._firewallDeleteRule(${r.number})" class="btn btn-danger btn-sm">Удалить</button>
                        </td>
                    </tr>`).join('');
            }
        };

        this._firewallModal = modal;
        this._firewallRenderRules = renderRules;

        try {
            const status = await api.request('/api/firewall/status');
            renderRules(status);
            if (status.error) {
                modal.querySelector('#fw-rules-body').innerHTML = `<tr><td colspan="5" style="text-align:center;padding:16px;color:#f59e0b;font-size:0.85em;opacity:0.8;">${status.error}</td></tr>`;
            }
        } catch (e) {
            modal.querySelector('#fw-rules-body').innerHTML = '<tr><td colspan="5" style="text-align:center;padding:16px;color:#ef4444;">Ошибка загрузки</td></tr>';
        }

        modal.querySelector('#fw-toggle-btn').addEventListener('click', async () => {
            const isActive = !modal.querySelector('#fw-status-text').textContent.includes('неактивен');
            try {
                const res = await api.request('/api/firewall/toggle', { method: 'POST', body: JSON.stringify({ enable: !isActive }) });
                renderRules(res.status);
                this.showNotification(res.message || 'Готово', 'success');
            } catch (e) {
                this.showNotification('Ошибка: ' + e.message, 'error');
            }
        });

        modal.querySelector('#fw-add-btn').addEventListener('click', async () => {
            const port = modal.querySelector('#fw-new-port').value.trim();
            if (!port) { this.showNotification('Укажите порт', 'error'); return; }
            const body = {
                action: modal.querySelector('#fw-new-action').value,
                port,
                proto: modal.querySelector('#fw-new-proto').value,
                from: modal.querySelector('#fw-new-from').value.trim(),
            };
            try {
                const res = await api.request('/api/firewall/rules', { method: 'POST', body: JSON.stringify(body) });
                renderRules(res.status);
                modal.querySelector('#fw-new-port').value = '';
                modal.querySelector('#fw-new-from').value = '';
                this.showNotification(res.message || 'Правило добавлено', 'success');
            } catch (e) {
                this.showNotification('Ошибка: ' + e.message, 'error');
            }
        });
    },
    async _firewallDeleteRule(number) {
        if (!(await this.showConfirm(`Удалить правило #${number}?`))) return;
        try {
            const res = await api.request('/api/firewall/rules', { method: 'DELETE', body: JSON.stringify({ number }) });
            if (this._firewallRenderRules) this._firewallRenderRules(res.status);
            this.showNotification(res.message || 'Правило удалено', 'success');
        } catch (e) {
            this.showNotification('Ошибка: ' + e.message, 'error');
        }
    }
};
