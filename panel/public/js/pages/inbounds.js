import { api } from '../services/api.js';

export const inboundsPage = {
    onInboundTransportChange(transport) {
        const clientOnlyTransports = new Set([]);
        let warnEl = document.getElementById('inbound-transport-warn');
        if (!warnEl) {
            warnEl = document.createElement('div');
            warnEl.id = 'inbound-transport-warn';
            warnEl.style.cssText = 'color:#f59e0b;font-size:0.82em;margin-top:4px;display:none;';
            warnEl.innerHTML = '⚠ Серверный режим этого транспорта не реализован — inbound создастся, но подключения принимать не будет.';
            const sel = document.querySelector('[name="transport"]')?.closest('.form-group');
            if (sel) sel.appendChild(warnEl);
        }
        warnEl.style.display = clientOnlyTransports.has(transport) ? '' : 'none';

        const paramsTransports = {
            shadowtls:   { label: 'ShadowTLS параметры', hint: 'password, sni, version', placeholder: '{"password":"secret","sni":"www.apple.com","version":3}' },
            shadowsocks: { label: 'Shadowsocks параметры', hint: 'password, method (aes-256-gcm / chacha20-poly1305)', placeholder: '{"password":"secret","method":"aes-256-gcm"}' },
            obfs4:       { label: 'obfs4 параметры', hint: 'node_id, public_key, private_key (генерируются автоматически если пусто)', placeholder: '{}' },
            tuic:        { label: 'TUIC параметры', hint: 'uuid, password, sni, congestion_control', placeholder: '{"uuid":"...","password":"secret","sni":"example.com"}' },
            meek:        { label: 'Meek параметры', hint: 'url, front', placeholder: '{"url":"https://ajax.aspnetcdn.com/","front":"ajax.microsoft.com"}' },
            domainfront: { label: 'Domain Fronting параметры', hint: 'front_domain, real_host', placeholder: '{"front_domain":"cdn.example.com","real_host":"real.example.com"}' },
            tgbot:       { label: 'Telegram Bot параметры', hint: 'token, chat_id', placeholder: '{"token":"123:ABC...","chat_id":12345}' },
            vkbot:       { label: 'VK Bot параметры', hint: 'token, group_id', placeholder: '{"token":"vk1.a...","group_id":12345}' },
            vkwebrtc:    { label: 'VK WebRTC параметры', hint: 'token, group_id', placeholder: '{"token":"vk1.a...","group_id":12345}' },
            okwebrtc:    { label: 'OK WebRTC параметры', hint: 'token', placeholder: '{"token":"..."}' },
            yacloud:     { label: 'Yandex Cloud параметры', hint: 'bucket, folder_id, service_account_key', placeholder: '{"bucket":"my-bucket"}' },
            yadisk:      { label: 'Yandex Disk параметры', hint: 'token, path', placeholder: '{"token":"y0_...","path":"/whispera"}' },
            yatelemost:  { label: 'Yandex Telemost параметры', hint: 'conference_id', placeholder: '{"conference_id":"..."}' },
            snowflake:   { label: 'Snowflake параметры', hint: 'broker_url, front_domain', placeholder: '{"broker_url":"https://snowflake-broker.torproject.net/"}' },
            torsocks:    { label: 'Tor SOCKS параметры', hint: 'proxy_addr (обычно 127.0.0.1:9050)', placeholder: '{"proxy_addr":"127.0.0.1:9050"}' },
            mirage:      { label: 'Mirage параметры', hint: 'password, fingerprint (chrome/firefox/safari/ios/android/random), dest (fallback TLS-хост)', placeholder: '{"password":"secret","fingerprint":"chrome","dest":"www.google.com:443"}' },
        };
        const paramsGroup = document.getElementById('inbound-params-group');
        const paramsLabel = document.getElementById('inbound-params-label');
        const paramsHint = document.getElementById('inbound-params-hint');
        const paramsTA = document.querySelector('[name="params_json"]');
        const info = paramsTransports[transport];
        if (info) {
            paramsGroup.style.display = '';
            paramsLabel.textContent = info.label;
            paramsHint.textContent = info.hint;
            if (paramsTA) paramsTA.placeholder = info.placeholder;
        } else {
            paramsGroup.style.display = 'none';
        }
    },
    collectTransportConfig() {
        const result = {};
        document.querySelectorAll('.tcfg-field').forEach(el => {
            const v = el.value.trim();
            if (v) result[el.dataset.key] = isNaN(v) ? v : (v.includes('.') ? parseFloat(v) : parseInt(v));
        });
        return Object.keys(result).length > 0 ? result : null;
    },
    async handleAddInbound() {
        const form = document.getElementById('add-inbound-form');
        const raw = Object.fromEntries(new FormData(form));
        const transport = raw.transport || 'tcp';
        let params = {};
        if (raw.params_json) {
            try { params = JSON.parse(raw.params_json); } catch { params = {}; }
        }
        const data = {
            tag: raw.tag,
            protocol: raw.protocol,
            port: parseInt(raw.port),
            stream_settings: {
                network: transport,
                security: 'none',
                params: Object.keys(params).length > 0 ? params : undefined
            }
        };

        try {
            await api.addInbound(data);
            this.closeModals();
            this.loadInbounds();
            this.showNotification('Входящее подключение создано', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    },
    async loadInbounds() {
        const tbody = document.getElementById('inbounds-table-body');
        try {
            const data = await api.getInbounds();
            const inbounds = data.inbounds || data || [];

            if (inbounds.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет входящих подключений</td></tr>';
                return;
            }

            tbody.innerHTML = inbounds.map(i => {
                const allPorts = i.ports?.length
                    ? [...new Set([i.port, ...i.ports].filter(p => p > 0))].join(', ')
                    : i.port;
                const network = i.stream_settings?.network || i.streamSettings?.network || 'tcp';
                return `<tr>
                    <td>${escapeHtml(i.tag)}</td>
                    <td>${escapeHtml(i.protocol)}</td>
                    <td>${allPorts}</td>
                    <td>${network}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" data-act="deleteInbound" data-arg="${escapeHtml(i.tag)}">Удалить</button>
                    </td>
                </tr>`;
            }).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    },
    async deleteInbound(tag) {
        if (!(await this.showConfirm('Удалить входящее подключение?'))) return;
        try {
            await api.deleteInbound(tag);
            this.loadInbounds();
            this.showNotification('Подключение удалено', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }
};
