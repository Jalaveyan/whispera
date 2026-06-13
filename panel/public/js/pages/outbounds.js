import { api } from '../services/api.js';

export const outboundsPage = {
    async handleAddOutbound() {
        const form = document.getElementById('add-outbound-form');
        const data = Object.fromEntries(new FormData(form));
        data.port = parseInt(data.port) || 0;
        data.chain = data.chain ? data.chain.split(',').map(s => s.trim()).filter(Boolean) : [];

        try {
            await api.addOutbound(data);
            this.closeModals();
            this.loadOutbounds();
            this.showNotification('Сервер добавлен', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    },
    async _loadBridgesForChainPicker() {
        const datalist = document.getElementById('outbound-chain-datalist');
        const badgeBox = document.getElementById('outbound-chain-bridges');
        const chainInput = document.getElementById('outbound-chain-input');
        if (!datalist || !badgeBox) return;
        try {
            const data = await api.getBridges();
            const bridges = Array.isArray(data) ? data : (data.bridges || []);
            datalist.innerHTML = '';
            badgeBox.innerHTML = '';
            bridges.forEach(b => {
                const id = b.id || b.ID;
                const addr = b.address || b.Address || '';
                const region = b.region || b.Region || '';
                const alive = b.is_alive ?? b.IsAlive ?? true;
                if (!id) return;
                const opt = document.createElement('option');
                opt.value = `bridge:${id}`;
                opt.label = `${region || addr}`;
                datalist.appendChild(opt);
                const badge = document.createElement('button');
                badge.type = 'button';
                badge.style.cssText = `background:rgba(0,229,255,${alive ? '0.12' : '0.04'});color:${alive ? '#00e5ff' : '#555'};
                    border:1px solid ${alive ? '#00e5ff44' : '#333'};border-radius:4px;padding:2px 8px;
                    font-size:11px;cursor:pointer;white-space:nowrap;`;
                badge.title = addr;
                badge.textContent = `${alive ? '●' : '○'} ${region || id.slice(0, 8)}`;
                badge.addEventListener('click', () => {
                    const cur = chainInput.value.split(',').map(s => s.trim()).filter(Boolean);
                    const key = `bridge:${id}`;
                    if (!cur.includes(key)) {
                        cur.push(key);
                        chainInput.value = cur.join(', ');
                    }
                });
                badgeBox.appendChild(badge);
            });
        } catch (_) { }
    },
    async loadOutbounds() {
        const tbody = document.getElementById('outbounds-table-body');
        try {
            const data = await api.getOutbounds();
            const outbounds = data.outbounds || data || [];

            if (outbounds.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center">Нет исходящих серверов</td></tr>';
                return;
            }

            tbody.innerHTML = outbounds.map(o => {
                const chain = Array.isArray(o.chain) && o.chain.length
                    ? o.chain.map(h => `<span style="background:rgba(0,229,255,0.1);color:#00e5ff;padding:1px 6px;border-radius:3px;font-size:11px;margin:1px;">${escapeHtml(h)}</span>`).join(' → ')
                    : '<span style="color:#555;">—</span>';
                return `<tr>
                    <td>${escapeHtml(o.tag)}</td>
                    <td>${escapeHtml(o.protocol)}</td>
                    <td>${escapeHtml(o.address || '-')}</td>
                    <td>${chain}</td>
                    <td>${o.latency ? o.latency + 'ms' : '-'}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" data-act="deleteOutbound" data-arg="${escapeHtml(o.tag)}">Удалить</button>
                    </td>
                </tr>`;
            }).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">Ошибка загрузки</td></tr>';
        }
    },
    async deleteOutbound(tag) {
        if (!(await this.showConfirm('Удалить сервер?'))) return;
        try {
            await api.deleteOutbound(tag);
            this.loadOutbounds();
            this.showNotification('Сервер удален', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }
};
