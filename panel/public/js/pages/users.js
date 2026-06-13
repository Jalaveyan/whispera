import { api } from '../services/api.js';

export const usersPage = {
    async handleAddUser() {
        const email = document.getElementById('new-user-email').value;
        const password = document.getElementById('new-user-password').value;
        const trafficLimit = parseInt(document.getElementById('new-user-traffic').value) || 0;
        const expiryDate = document.getElementById('new-user-expiry').value || null;

        const obfsProfile = document.getElementById('new-user-obfs').value;
        const marionetteProfile = document.getElementById('new-user-marionette').value;
        const russianService = document.getElementById('new-user-russian').value;
        const transport = Array.from(document.querySelectorAll('input[name="transport-cb"]:checked')).map(i => i.value).join(',') || 'tcp';
        const portVal = parseInt(document.getElementById('new-user-port')?.value) || 0;

        try {
            const res = await api.createUser(email, password, trafficLimit, expiryDate, {
                obfsProfile,
                marionetteProfile,
                russianService
            });
            this.closeModals();
            document.getElementById('add-user-form')?.reset();
            document.querySelectorAll('input[name="transport-cb"]').forEach(cb => { cb.checked = cb.value === 'tcp'; });
            this.loadUsers();

            const createdInboundTags = [];
            if (portVal > 0) {
                const serverTransports = new Set(['tcp', 'udp', 'ws', 'httpupgrade', 'h2c', 'grpc', 'shadowtls', 'shadowsocks']);
                const existingInbounds = this._cachedInbounds || [];
                const transportSecurity = {
                    shadowtls: 'shadowtls', shadowsocks: 'shadowsocks',
                };
                const transports = transport.split(',').map(t => t.trim()).filter(t => serverTransports.has(t));
                for (const tr of transports) {
                    const alreadyExists = existingInbounds.some(ib => {
                        const p = parseInt(ib.port || ib.Port);
                        const net = (ib.stream_settings?.network || ib.StreamSettings?.Network || 'tcp').toLowerCase();
                        return p === portVal && net === tr;
                    });
                    if (!alreadyExists) {
                        const security = transportSecurity[tr] || 'none';
                        const tag = transports.length > 1 ? `inbound-${portVal}-${tr}` : `inbound-${portVal}`;
                        try {
                            await api.addInbound({
                                tag,
                                protocol: 'whispera',
                                port: portVal,
                                stream_settings: {
                                    network: tr,
                                    security,
                                }
                            });
                            createdInboundTags.push(tag);
                        } catch (e) {
                            console.warn(`Auto-create inbound ${tag} failed:`, e.message);
                        }
                    } else {
                        // Inbound уже существует — всё равно записываем тег для последующей очистки.
                        const tag = transports.length > 1 ? `inbound-${portVal}-${tr}` : `inbound-${portVal}`;
                        createdInboundTags.push(tag);
                    }
                }
                this._cachedInbounds = null;
            }

            const privKey = res.privateKey || res.user?.privateKey;
            if (privKey) {
                try {
                    const keyOpts = {
                        psk: privKey,
                        name: email,
                        transport,
                        russianService,
                    };
                    if (portVal > 0) keyOpts.port = portVal;
                    const tc = this.collectTransportConfig();
                    if (tc) keyOpts.transportConfig = tc;
                    const keyRes = await api.generateConnectionKey(keyOpts);
                    const userId = res.user?.id;
                    if (userId && keyRes.key) {
                        const updatePayload = { connectionURI: keyRes.key };
                        if (createdInboundTags.length > 0) updatePayload.inboundTags = createdInboundTags;
                        api.updateUser(userId, updatePayload).catch(() => {});
                    }
                    this.showKeyModal(res.user?.username || email, privKey, keyRes.key);
                } catch {
                    this.showKeyModal(res.user?.username || email, privKey);
                }
            } else {
                this.showNotification('Пользователь создан', 'success');
            }
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    },
    _updateUserPort() {
        const portField = document.getElementById('new-user-port');
        if (!portField || !portField.dataset.autoSet) return;
        const inbounds = this._cachedInbounds || [];
        if (!inbounds.length) return;
        const selected = new Set(
            Array.from(document.querySelectorAll('input[name="transport-cb"]:checked')).map(i => i.value)
        );
        const match = inbounds.find(ib => {
            const net = (ib.stream_settings?.network || ib.StreamSettings?.Network || 'tcp').toLowerCase();
            return selected.has(net);
        });
        if (match) {
            const port = match.port || match.Port;
            if (port) portField.value = port;
        }
    },
    onKeyTransportChange(transport) {
        const TRANSPORT_FIELDS = {
            vkwebrtc: {
                title: 'VK WebRTC — параметры',
                hint: 'Требуется токен VK-группы и TURN-сервер',
                fields: [
                    { key: 'vk_token',    label: 'Токен VK-группы',  placeholder: 'vk1.a.xxxx...', help: 'Токен сообщества с правом "Сообщения". Настройки → API → Ключи доступа.' },
                    { key: 'vk_group_id', label: 'ID группы VK',     placeholder: '123456789',       help: 'Числовой ID сообщества (без минуса).' },
                    { key: 'vk_peer_id',  label: 'Peer ID (опц.)',   placeholder: '',                 help: 'ID собеседника/peer. Оставьте пустым для нового вызова.' },
                ]
            },
            okwebrtc: {
                title: 'OK WebRTC — параметры',
                hint: 'Требуется OAuth-токен OK.ru',
                fields: [
                    { key: 'ok_token',      label: 'OK OAuth Token',       placeholder: 'tokXXX...',  help: 'Получить: developers.ok.ru → Мои приложения → Токены.' },
                    { key: 'ok_app_id',     label: 'App ID',                placeholder: '12345678',   help: 'ID вашего приложения на OK.ru.' },
                    { key: 'ok_app_secret', label: 'App Secret Key',        placeholder: 'XXXXXXXXXX', help: 'Секретный ключ приложения из настроек на OK.ru.' },
                ]
            },
            yadisk: {
                title: 'Яндекс Диск — параметры',
                hint: 'Требуется OAuth-токен с доступом к Диску',
                fields: [
                    { key: 'ya_token',     label: 'Яндекс OAuth Token', placeholder: 'y0_AgAAAA...', help: 'Получить: oauth.yandex.ru → Создать токен для приложения с правом cloud_api:disk.read+write.' },
                    { key: 'session_id',   label: 'Session ID',          placeholder: 'my-vpn-01',    help: 'Произвольный ID сессии — одинаковый у сервера и клиента. Например UUID или "my-vpn-01".' },
                ]
            },
            yacloud: {
                title: 'Яндекс Cloud API Gateway — параметры',
                hint: 'WebSocket через Яндекс API Gateway (WSS)',
                fields: [
                    { key: 'gateway_url', label: 'WSS Gateway URL', placeholder: 'wss://xxxxx.apigw.yandexcloud.net/ws', help: 'URL WebSocket-интеграции в Яндекс API Gateway. Создать: console.cloud.yandex.ru → API Gateway → Добавить интеграцию WebSocket.' },
                ]
            },
            yatelemost: {
                title: 'Яндекс Телемост — параметры',
                hint: 'Туннель через WebRTC-конференцию Телемоста',
                fields: [
                    { key: 'ya_session_id', label: 'Яндекс Session_id cookie', placeholder: '3:xxx...', help: 'Зайти на yandex.ru → DevTools (F12) → Application → Cookies → Session_id.' },
                    { key: 'conference_url', label: 'URL конференции (опц.)',   placeholder: 'https://telemost.yandex.ru/j/xxx', help: 'Для клиента — вставьте URL конференции который выдал сервер. Для сервера — оставьте пустым (создастся автоматически).' },
                ]
            },
            tgbot: {
                title: 'Telegram Bot — параметры',
                hint: 'Туннель через Telegram supergroup',
                fields: [
                    { key: 'tg_bot_token',  label: 'Bot Token',       placeholder: '123456789:ABCdef...', help: 'Получить у @BotFather → /newbot. Оба конца (сервер и клиент) должны использовать разные боты в одной супергруппе.' },
                    { key: 'tg_chat_id',    label: 'Group Chat ID',    placeholder: '-1001234567890',      help: 'ID супергруппы. Добавить @userinfobot в группу → он напишет ID.' },
                    { key: 'tg_session_id', label: 'Session ID (опц.)', placeholder: 'vpn-session-01',    help: 'Позволяет запускать несколько туннелей в одной группе.' },
                ]
            },
            vkbot: {
                title: 'VK Bot — параметры',
                hint: 'Туннель через VK Сообщества (Long Poll)',
                fields: [
                    { key: 'vk_group_token', label: 'Токен сообщества',  placeholder: 'vk1.a.xxx...',  help: 'Токен с правом "Сообщения". Нужен для серверной стороны.' },
                    { key: 'vk_user_token',  label: 'Токен пользователя', placeholder: 'vk1.a.yyy...', help: 'Пользовательский токен. Нужен для клиентской стороны.' },
                    { key: 'vk_group_id',    label: 'ID сообщества',      placeholder: '123456789',     help: 'Числовой ID VK-сообщества.' },
                ]
            },
        };

        const cfgDiv = document.getElementById('new-user-transport-config');
        const fieldsDiv = document.getElementById('new-user-tcfg-fields');
        const titleEl = document.getElementById('new-user-tcfg-title');
        const hintEl = document.getElementById('new-user-tcfg-hint');

        const transports = Array.isArray(transport) ? transport : [transport];
        const spec = transports.map(t => TRANSPORT_FIELDS[t]).find(Boolean);
        if (!spec) {
            cfgDiv.style.display = 'none';
            return;
        }

        cfgDiv.style.display = '';
        titleEl.textContent = spec.title;
        hintEl.textContent = spec.hint;

        fieldsDiv.innerHTML = spec.fields.map(f => `
            <div class="form-group" style="margin-bottom:8px;">
                <label style="font-size:0.82em;">${f.label}</label>
                <input type="text" class="form-control tcfg-field" data-key="${f.key}"
                    placeholder="${f.placeholder}" style="font-size:0.85em;">
                <small style="color:#888;font-size:0.75em;margin-top:2px;display:block;">${f.help}</small>
            </div>`).join('');
    },
    async loadUsers() {
        const tbody = document.getElementById('users-table-body');
        try {
            const data = await api.getUsers();
            const users = data.users || [];
            this._usersById = {};
            users.forEach(u => { this._usersById[u.id] = u; });

            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет пользователей</td></tr>';
                return;
            }

            tbody.innerHTML = users.map(user => `
    <tr>
          <td>${this.escapeHtml(user.username || '-')}</td>
          <td>${user.trafficLimit ? (user.trafficLimit / 1073741824).toFixed(0) + ' GB' : 'Free'}</td>
          <td>${this.formatBytes(user.upload || 0)} / ${this.formatBytes(user.download || 0)}</td>
          <td><span class="status ${user.status === 'active' ? 'active' : 'inactive'}">${user.status === 'active' ? 'Активен' : 'Неактивен'}</span></td>
          <td>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
                ${user.privateKey ? `<button class="btn btn-secondary btn-sm" onclick="app.generateKeyForUser(${user.id})">Ключ</button>` : ''}
                <button class="btn btn-secondary btn-sm" onclick="app.showEditUserModal(${user.id})">Изменить</button>
                <button class="btn btn-danger btn-sm" data-act="deleteUser" data-arg="${escapeHtml(String(user.id))}">Удалить</button>
            </div>
          </td>
        </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    },
    async generateKeyForUser(userId) {
        const user = this._usersById?.[userId];
        if (!user?.privateKey) {
            this.showNotification('Ключ недоступен', 'error');
            return;
        }
        if (user.connectionURI) {
            this.showKeyModal(user.username, user.privateKey, user.connectionURI);
            return;
        }
        try {
            const keyRes = await api.generateConnectionKey({ psk: user.privateKey, name: user.username });
            if (keyRes.key) {
                api.updateUser(userId, { connectionURI: keyRes.key }).catch(() => {});
                user.connectionURI = keyRes.key;
            }
            this.showKeyModal(user.username, user.privateKey, keyRes.key);
        } catch {
            this.showKeyModal(user.username, user.privateKey);
        }
    },
    showEditUserModal(userId) {
        const user = this._usersById?.[userId];
        if (!user) { this.showNotification('Пользователь не найден', 'error'); return; }

        const trafficGB = user.trafficLimit ? (user.trafficLimit / 1073741824) : 0;

        const field = (label, body) => `
            <div class="form-group">
                <label style="font-size:0.8em;text-transform:uppercase;opacity:0.7;letter-spacing:0.05em;">${label}</label>
                ${body}
            </div>`;

        const modal = document.createElement('div');
        modal.className = 'modal-backdrop active';
        modal.style.zIndex = '10000';
        modal.innerHTML = `
        <div class="modal" style="max-width:460px;">
            <div class="modal-header">
                <h3>Редактировать пользователя</h3>
                <button class="modal-close modal-close-icon" onclick="this.closest('.modal-backdrop').remove()"><i class="fas fa-times"></i></button>
            </div>
            <div class="modal-body" style="display:flex;flex-direction:column;gap:14px;max-height:70vh;overflow-y:auto;padding-right:4px;">
                ${field('Email', `<input id="eu-username" class="form-control" type="text" value="${escapeHtml(user.username || '')}">`)}
                ${field('Статус', `
                    <select id="eu-status" class="form-control">
                        <option value="active"    ${user.status === 'active'    ? 'selected' : ''}>Активен</option>
                        <option value="disabled"  ${user.status === 'disabled'  ? 'selected' : ''}>Отключён</option>
                    </select>`)}
                ${field('Лимит трафика', `
                    <div style="display:flex;gap:8px;align-items:center;">
                        <input id="eu-traffic" class="form-control" type="number" min="0" step="0.1" value="${trafficGB}" style="flex:1;">
                        <span style="opacity:0.6;font-size:0.9em;white-space:nowrap;">GB &nbsp;(0 = ∞)</span>
                    </div>`)}
                ${field('Дата истечения', `<input id="eu-expiry" class="form-control" type="date" value="${user.expiryDate || ''}" placeholder="бессрочно">`)}
                <div style="border-top:1px solid rgba(255,255,255,0.08);padding-top:10px;margin-top:-2px;">
                    <div style="font-size:0.72em;text-transform:uppercase;opacity:0.45;letter-spacing:0.07em;margin-bottom:10px;">Обфускация и маршрутизация</div>
                    ${field('Профиль обфускации', `
                        <select id="eu-obfs" class="form-control">
                            <option value=""    ${!user.obfsProfile                  ? 'selected' : ''}>По умолчанию</option>
                            <option value="vk"  ${user.obfsProfile === 'vk'          ? 'selected' : ''}>VK</option>
                            <option value="ok"  ${user.obfsProfile === 'ok'          ? 'selected' : ''}>OK</option>
                            <option value="yt"  ${user.obfsProfile === 'yt'          ? 'selected' : ''}>YouTube</option>
                        </select>`)}
                    ${field('ASN bypass (рос. сервисы)', `
                        <select id="eu-russian" class="form-control">
                            <option value=""           ${!user.russianService                    ? 'selected' : ''}>Авто</option>
                            <option value="vk"         ${user.russianService === 'vk'            ? 'selected' : ''}>VK</option>
                            <option value="ok"         ${user.russianService === 'ok'            ? 'selected' : ''}>Одноклассники</option>
                            <option value="yandex"     ${user.russianService === 'yandex'        ? 'selected' : ''}>Яндекс</option>
                            <option value="wildberries"${user.russianService === 'wildberries'   ? 'selected' : ''}>Wildberries</option>
                        </select>
                        <span style="font-size:11px;opacity:0.5;">Маршрутизация трафика через ASN указанного сервиса</span>`)}
                    ${field('Marionette (имитация трафика)', `
                        <select id="eu-marionette" class="form-control" size="1">
                            <option value="" ${!user.marionetteProfile ? 'selected' : ''}>— нет —</option>
                            <optgroup label="─── Мессенджеры (Android) ───">
                                <option value="telegram"    ${user.marionetteProfile === 'telegram'    ? 'selected' : ''}>Telegram</option>
                                <option value="vk"          ${user.marionetteProfile === 'vk'          ? 'selected' : ''}>VK Мессенджер</option>
                                <option value="vkvideo"     ${user.marionetteProfile === 'vkvideo'     ? 'selected' : ''}>VK Видео</option>
                                <option value="instagram"   ${user.marionetteProfile === 'instagram'   ? 'selected' : ''}>Instagram</option>
                                <option value="max"         ${user.marionetteProfile === 'max'         ? 'selected' : ''}>MAX (Mail.ru)</option>
                                <option value="wechat"      ${user.marionetteProfile === 'wechat'      ? 'selected' : ''}>WeChat</option>
                                <option value="facebook"    ${user.marionetteProfile === 'facebook'    ? 'selected' : ''}>Facebook Messenger</option>
                            </optgroup>
                            <optgroup label="─── Мессенджеры (iOS) ───">
                                <option value="telegram_ios"  ${user.marionetteProfile === 'telegram_ios'  ? 'selected' : ''}>Telegram iOS</option>
                                <option value="vk_ios"        ${user.marionetteProfile === 'vk_ios'        ? 'selected' : ''}>VK iOS</option>
                                <option value="instagram_ios" ${user.marionetteProfile === 'instagram_ios' ? 'selected' : ''}>Instagram iOS</option>
                                <option value="wechat_ios"    ${user.marionetteProfile === 'wechat_ios'    ? 'selected' : ''}>WeChat iOS</option>
                                <option value="facebook_ios"  ${user.marionetteProfile === 'facebook_ios'  ? 'selected' : ''}>Facebook iOS</option>
                            </optgroup>
                            <optgroup label="─── Музыка ───">
                                <option value="spotify"      ${user.marionetteProfile === 'spotify'      ? 'selected' : ''}>Spotify</option>
                                <option value="yandex_music" ${user.marionetteProfile === 'yandex_music' ? 'selected' : ''}>Яндекс Музыка</option>
                                <option value="vk_music"     ${user.marionetteProfile === 'vk_music'     ? 'selected' : ''}>VK Музыка</option>
                            </optgroup>
                            <optgroup label="─── Видео ───">
                                <option value="youtube"          ${user.marionetteProfile === 'youtube'          ? 'selected' : ''}>YouTube</option>
                                <option value="vk_video_stream"  ${user.marionetteProfile === 'vk_video_stream'  ? 'selected' : ''}>VK Video Stream</option>
                            </optgroup>
                        </select>
                        <span style="font-size:11px;opacity:0.5;">Имитирует TLS-паттерны указанного приложения</span>`)}
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="this.closest('.modal-backdrop').remove()">Отмена</button>
                <button class="btn btn-primary" onclick="app.saveUserEdit(${userId}, this.closest('.modal'))">Сохранить</button>
            </div>
        </div>`;
        document.body.appendChild(modal);
    },
    async saveUserEdit(userId, modal) {
        const username = modal.querySelector('#eu-username').value.trim();
        const status   = modal.querySelector('#eu-status').value;
        const trafficGB = parseFloat(modal.querySelector('#eu-traffic').value) || 0;
        const expiryDate = modal.querySelector('#eu-expiry').value;
        const obfsProfile = modal.querySelector('#eu-obfs').value;
        const russianService = modal.querySelector('#eu-russian').value;
        const marionetteProfile = modal.querySelector('#eu-marionette')?.value || '';

        if (!username) { this.showNotification('Email не может быть пустым', 'error'); return; }

        try {
            await api.updateUser(userId, {
                username,
                status,
                trafficLimit: Math.round(trafficGB * 1073741824),
                expiryDate: expiryDate || '',
                obfsProfile,
                russianService,
                marionetteProfile,
            });
            modal.remove();
            this.showNotification('Пользователь обновлён', 'success');
            this.loadUsers();
        } catch (err) {
            this.showNotification('Ошибка: ' + err.message, 'error');
        }
    },
    async deleteUser(id) {
        if (!(await this.showConfirm('Удалить пользователя?'))) return;
        try {
            await api.deleteUser(id);
            this.loadUsers();
            this.showNotification('Пользователь удален', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    },
    showKeyModal(email, privKey, connectionURI) {
        const modal = document.createElement('div');
        modal.className = 'modal-backdrop active';
        modal.style.zIndex = '10000';

        const uri = connectionURI || privKey;
        const uriEsc = uri.replace(/'/g, "\\'").replace(/"/g, '&quot;');
        const pkEsc = privKey.replace(/'/g, "\\'").replace(/"/g, '&quot;');

        const copyField = (value, label, onCopy) => `
            <div class="field-group">
                <label>${label}</label>
                <div class="copy-row">
                    <input type="text" value="${value}" readonly>
                    <button class="btn btn-primary btn-sm" onclick="${onCopy}"><i class="fas fa-copy"></i> Копировать</button>
                </div>
            </div>`;

        modal.innerHTML = `
    <div class="modal" style="max-width:520px;">
        <div class="modal-header">
            <h3>Пользователь создан</h3>
            <button class="modal-close modal-close-icon" onclick="this.closest('.modal-backdrop').remove()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
            <p style="margin:0 0 12px;">Пользователь: <strong>${email}</strong></p>
            ${connectionURI
                ? copyField(uriEsc, 'Ключ подключения (импортируйте в клиент)', `navigator.clipboard.writeText('${uriEsc}').then(()=>app.showNotification('Скопировано','success'))`)
                : copyField(pkEsc, 'Приватный ключ', `navigator.clipboard.writeText('${pkEsc}').then(()=>app.showNotification('Скопировано','success'))`)
            }
            <div id="key-modal-qr-wrap" style="display:none;flex-direction:column;align-items:center;gap:6px;margin:8px 0 12px;">
                <img id="key-modal-qr" style="border-radius:8px;background:#fff;padding:8px;width:200px;height:200px;" />
                <span class="field-hint">Сканируйте QR-кодом в клиенте</span>
            </div>
            ${connectionURI && privKey ? `
            <div class="field-group" style="padding:10px 12px;background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.25);border-radius:var(--radius);">
                <label><i class="fas fa-brain" style="color:#6366f1;margin-right:4px;"></i>ML Токен (для режима ML в клиенте)</label>
                <div class="copy-row">
                    <input type="text" value="${pkEsc}" readonly>
                    <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${pkEsc}').then(()=>app.showNotification('ML токен скопирован','success'))"><i class="fas fa-copy"></i> Копировать</button>
                </div>
                <span class="field-hint">Вставьте в поле «ML Токен» в разделе Режим ML клиента whisp</span>
            </div>` : ''}
            <p class="field-hint" style="margin-top:8px;">
                <i class="fas fa-info-circle"></i> Ключ содержит все параметры подключения. Сохраните — он больше не будет показан.
            </p>
        </div>
        <div class="modal-footer">
            <button class="btn btn-primary" onclick="this.closest('.modal-backdrop').remove()">Готово</button>
        </div>
    </div>`;
        document.body.appendChild(modal);

        if (connectionURI) {
            const qrWrap = modal.querySelector('#key-modal-qr-wrap');
            const img = modal.querySelector('#key-modal-qr');
            if (img && qrWrap) {
                fetch('/api/qr?data=' + encodeURIComponent(connectionURI))
                    .then(r => r.json())
                    .then(d => {
                        if (d.url) {
                            img.src = d.url;
                            qrWrap.style.display = 'flex';
                        }
                    })
                    .catch(() => {});
            }
        }
    }
};
