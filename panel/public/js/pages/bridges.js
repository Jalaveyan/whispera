import { api } from '../services/api.js';

export const bridgesPage = {
    async loadBridges() {
        this._stopBridgeAutoRefresh();
        await Promise.all([this._fetchBridgeStats(), this._fetchBridgeList(), this._fetchBridgeToken()]);
        this._startBridgeAutoRefresh();
    },
    _startBridgeAutoRefresh() {
        this._stopBridgeAutoRefresh();
        let countdown = 30;
        const badge = document.getElementById('bridges-auto-refresh-badge');
        this._bridgeRefreshTimer = setInterval(async () => {
            countdown--;
            if (badge) badge.textContent = `авто-обновление через ${countdown}с`;
            if (countdown <= 0) {
                countdown = 30;
                await Promise.all([this._fetchBridgeStats(), this._fetchBridgeList()]);
            }
        }, 1000);
        if (badge) badge.textContent = `авто-обновление через ${countdown}с`;
    },
    _stopBridgeAutoRefresh() {
        if (this._bridgeRefreshTimer) {
            clearInterval(this._bridgeRefreshTimer);
            this._bridgeRefreshTimer = null;
        }
    },
    async _fetchBridgeStats() {
        try {
            const s = await api.getBridgeStats();
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
            set('bstat-total',   s.total   ?? '—');
            set('bstat-alive',   s.alive   ?? '—');
            set('bstat-dead',    s.dead    ?? '—');
            set('bstat-latency', s.avg_latency ? s.avg_latency + ' мс' : '—');
        } catch {}
    },
    async _fetchBridgeList() {
        const tbody = document.getElementById('bridges-tbody');
        if (!tbody) return;
        try {
            const data = await api.getBridgesAdmin();
            const bridges = Array.isArray(data) ? data : (data.bridges || []);
            if (!bridges.length) {
                tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:#555;padding:32px;">Мостов нет. Добавьте первый мост.</td></tr>';
                return;
            }
            tbody.innerHTML = bridges.map(b => this._renderBridgeRow(b)).join('');
            tbody.querySelectorAll('.bridge-check-btn').forEach(btn => {
                btn.addEventListener('click', () => this._checkBridge(btn.dataset.id, btn));
            });
            tbody.querySelectorAll('.bridge-delete-btn').forEach(btn => {
                btn.addEventListener('click', () => this._deleteBridge(btn.dataset.id));
            });
            tbody.querySelectorAll('.bridge-ping-btn').forEach(btn => {
                btn.addEventListener('click', () => this._pingBridge(btn.dataset.id, btn));
            });
            tbody.querySelectorAll('.bridge-label-btn').forEach(btn => {
                btn.addEventListener('click', () => this._toggleBridgeLabel(btn.dataset.id, btn.dataset.blacklisted === 'true'));
            });
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="10" style="text-align:center;color:#f87171;padding:32px;">Ошибка загрузки: ${e.message}</td></tr>`;
        }
    },
    _renderBridgeRow(b) {
        const alive = b.is_alive ?? b.IsAlive ?? false;
        const latency = Number(b.latency_ms ?? b.Latency ?? 0) || 0;
        const trust = Number(b.trust_level ?? b.TrustLevel ?? 0) || 0;
        const region = this.escapeHtml(b.region || b.Region || '—');
        const type = this.escapeHtml(b.type || b.Type || '—');
        const address = this.escapeHtml(b.address || b.Address || '—');
        const rawId = String(b.id || b.ID || '');
        const id = this.escapeHtml(rawId);
        const shortID = this.escapeHtml(rawId.length > 8 ? rawId.slice(0, 8) + '…' : rawId);
        const lastCheck = b.last_check || b.LastCheck;
        const lastCheckStr = lastCheck ? this._relativeTime(new Date(lastCheck)) : '—';
        const blacklisted = b.blacklisted || b.Blacklisted || false;
        const mlScore = Number(b.ml_score || b.MLScore || 0) || 0;

        const statusDot = alive
            ? '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#4ade80;" title="Онлайн"></span>'
            : '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#f87171;" title="Недоступен"></span>';

        const latencyColor = latency === 0 ? '#555' : latency < 100 ? '#4ade80' : latency < 300 ? '#facc15' : '#f87171';
        const latencyStr = latency > 0 ? `<span style="color:${latencyColor}">${latency} мс</span>` : '<span style="color:#555">—</span>';

        const typeBadge = {
            operator:  '<span style="background:rgba(99,102,241,0.2);color:#a5b4fc;padding:2px 7px;border-radius:4px;font-size:0.8em;">operator</span>',
            community: '<span style="background:rgba(34,197,94,0.15);color:#86efac;padding:2px 7px;border-radius:4px;font-size:0.8em;">community</span>',
            user:      '<span style="background:rgba(234,179,8,0.15);color:#fde047;padding:2px 7px;border-radius:4px;font-size:0.8em;">user</span>',
            white:     '<span style="background:rgba(255,255,255,0.1);color:#e2e8f0;padding:2px 7px;border-radius:4px;font-size:0.8em;">white</span>',
        }[type] || `<span style="color:#888;font-size:0.85em;">${type}</span>`;

        const trustBar = `<div style="display:flex;align-items:center;gap:6px;">
            <div style="width:48px;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden;">
                <div style="width:${trust}%;height:100%;background:${trust>=70?'#4ade80':trust>=40?'#facc15':'#f87171'};border-radius:3px;"></div>
            </div>
            <span style="font-size:0.82em;color:#aaa;">${trust}</span>
        </div>`;

        const mlBadge = mlScore > 0
            ? `<span title="${mlScore < 0.3 ? 'Предупреждение: модель может быть недообучена (мало данных)' : 'Оценка нейросетевого отбора'}"
                style="display:inline-flex;align-items:center;gap:3px;font-size:0.78em;padding:2px 6px;border-radius:4px;
                background:${mlScore < 0.3 ? 'rgba(250,204,21,0.12)' : 'rgba(99,102,241,0.15)'};
                color:${mlScore < 0.3 ? '#fde047' : '#a5b4fc'};cursor:help;">
                ${mlScore < 0.3 ? '⚠' : '▲'} ${mlScore.toFixed(2)}
               </span>`
            : '<span style="color:#444;font-size:0.8em;">—</span>';

        const blacklistBtn = blacklisted
            ? `<button class="btn btn-secondary btn-sm bridge-label-btn" data-id="${id}" data-blacklisted="true" style="color:#facc15;">Разблок</button>`
            : `<button class="btn btn-secondary btn-sm bridge-label-btn" data-id="${id}" data-blacklisted="false">Блок</button>`;

        const rowStyle = blacklisted ? ' style="opacity:0.45;"' : '';

        return `<tr data-bridge-id="${id}"${rowStyle}>
            <td style="text-align:center;">${statusDot}</td>
            <td><code style="font-size:0.85em;" title="${id}">${shortID}</code></td>
            <td style="font-size:0.87em;">${address}</td>
            <td style="font-size:0.87em;">${region}</td>
            <td>${typeBadge}</td>
            <td>${latencyStr}</td>
            <td>${trustBar}</td>
            <td>${mlBadge}</td>
            <td style="font-size:0.82em;color:#888;">${lastCheckStr}</td>
            <td style="text-align:right;white-space:nowrap;">
                <button class="btn btn-secondary btn-sm bridge-check-btn" data-id="${id}">Проверить</button>
                <button class="btn btn-secondary btn-sm bridge-ping-btn" data-id="${id}">Пинг</button>
                ${blacklistBtn}
                <button class="btn btn-danger btn-sm bridge-delete-btn" data-id="${id}">Удалить</button>
            </td>
        </tr>`;
    },
    async _checkBridge(id, btn) {
        const icon = btn.querySelector('i');
        const orig = icon.className;
        icon.className = 'fas fa-spinner fa-spin';
        btn.disabled = true;
        try {
            const res = await api.checkBridge(id);
            const row = document.querySelector(`tr[data-bridge-id="${id}"]`);
            if (row) {
                const dot = row.cells[0];
                dot.innerHTML = res.is_alive
                    ? '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#4ade80;" title="Онлайн"></span>'
                    : '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#f87171;" title="Недоступен"></span>';
                const latencyColor = res.latency_ms < 100 ? '#4ade80' : res.latency_ms < 300 ? '#facc15' : '#f87171';
                row.cells[5].innerHTML = res.latency_ms > 0
                    ? `<span style="color:${latencyColor}">${res.latency_ms} мс</span>`
                    : '<span style="color:#555">—</span>';
                row.cells[8].textContent = 'только что';
            }
            await this._fetchBridgeStats();
        } catch (e) {
            this.showNotification('Ошибка проверки: ' + e.message, 'error');
        } finally {
            icon.className = orig;
            btn.disabled = false;
        }
    },
    async _deleteBridge(id) {
        if (!await this.showConfirm('Удалить мост ' + id + '?')) return;
        try {
            await api.deleteBridge(id);
            this.showNotification('Мост удалён', 'success');
            await Promise.all([this._fetchBridgeStats(), this._fetchBridgeList()]);
        } catch (e) {
            this.showNotification('Ошибка: ' + e.message, 'error');
        }
    },
    async _pingBridge(id, btn) {
        const icon = btn.querySelector('i');
        const orig = icon.className;
        icon.className = 'fas fa-spinner fa-spin';
        btn.disabled = true;
        try {
            const res = await api.pingBridge(id);
            const loss = res.loss_pct ?? 0;
            const avg = res.avg_latency ?? 0;
            this.showNotification(
                `Ping ${id.slice(0, 8)}: ${res.received}/${res.sent} пакетов, потери ${loss.toFixed(0)}%, задержка ${avg} мс`,
                loss === 0 ? 'success' : 'warning'
            );
            const row = document.querySelector(`tr[data-bridge-id="${id}"]`);
            if (row && avg > 0) {
                const latencyColor = avg < 100 ? '#4ade80' : avg < 300 ? '#facc15' : '#f87171';
                row.cells[5].innerHTML = `<span style="color:${latencyColor}">${avg} мс</span>`;
            }
        } catch (e) {
            this.showNotification('Ошибка ping: ' + e.message, 'error');
        } finally {
            icon.className = orig;
            btn.disabled = false;
        }
    },
    async _toggleBridgeLabel(id, currentlyBlacklisted) {
        const newState = !currentlyBlacklisted;
        const label = newState ? 'заблокировать' : 'снять блокировку с';
        if (!await this.showConfirm(`${label.charAt(0).toUpperCase() + label.slice(1)} мост ${id.slice(0, 8)}?`)) return;
        try {
            await api.setBridgeLabel(id, newState);
            this.showNotification(newState ? 'Мост заблокирован' : 'Блокировка снята', 'success');
            await this._fetchBridgeList();
        } catch (e) {
            this.showNotification('Ошибка: ' + e.message, 'error');
        }
    },
    async _fetchBridgeToken() {
        try {
            const data = await api.getBridgeToken();
            const el = document.getElementById('bridge-reg-token');
            if (el) el.textContent = data.token || '—';
            this._updateCurlCmd(data.token);
        } catch {}
    },
    _updateCurlCmd(token) {
        const el = document.getElementById('bridge-curl-cmd');
        if (!el) return;
        const base = window.location.origin;
        el.textContent =
            `curl -s -X POST ${base}/api/bridge-register \\\n` +
            `  -H "Content-Type: application/json" \\\n` +
            `  -d '{"token":"${token || 'TOKEN'}","address":"1.2.3.4:443","region":"ru","type":"community"}'`;
    },
    async loadBridgeMap() {
        this._bridgeMapData = [];
        try {
            const data = await api.getBridgeMap();
            const bridges = Array.isArray(data) ? data : [];
            this._bridgeMapData = bridges;

            const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
            set('map-total', bridges.length);
            set('map-alive', bridges.filter(b => b.is_alive).length);
            set('map-white', bridges.filter(b => b.type === 'white').length);
            const countries = new Set(bridges.map(b => b.country).filter(Boolean));
            set('map-countries', countries.size);

            this._renderBridgeMapCanvas(bridges);
            this._renderBridgeMapTable(bridges);
        } catch (e) {
            const tbody = document.getElementById('bridge-map-tbody');
            if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#f87171;padding:32px;">Ошибка: ${e.message}</td></tr>`;
        }

        const scanBtn = document.getElementById('bridge-map-scan-btn');
        if (scanBtn && !scanBtn._bound) {
            scanBtn._bound = true;
            scanBtn.addEventListener('click', async () => {
                scanBtn.disabled = true;
                scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Сканирование...';
                try {
                    await api.scanBridges();
                    await this.loadBridgeMap();
                    this.showNotification('Сканирование завершено', 'success');
                } catch (e) {
                    this.showNotification('Ошибка сканирования: ' + e.message, 'error');
                } finally {
                    scanBtn.disabled = false;
                    scanBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> Сканировать';
                }
            });
        }
        const refreshBtn = document.getElementById('bridge-map-refresh-btn');
        if (refreshBtn && !refreshBtn._bound) {
            refreshBtn._bound = true;
            refreshBtn.addEventListener('click', () => this.loadBridgeMap());
        }
    },
    _renderBridgeMapCanvas(bridges) {
        requestAnimationFrame(() => this._doRenderBridgeMap(bridges));
    },
    _doRenderBridgeMap(bridges) {
        const canvas = document.getElementById('bridge-map-canvas');
        if (!canvas) return;
        const container = canvas.parentElement;
        const w = container.offsetWidth || 800;
        const h = container.offsetHeight || 500;
        const dpr = window.devicePixelRatio || 1;
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        const ctx = canvas.getContext('2d');
        ctx.scale(dpr, dpr);

        ctx.fillStyle = '#0a0e1a';
        ctx.fillRect(0, 0, w, h);

        ctx.strokeStyle = 'rgba(0,229,255,0.06)';
        ctx.lineWidth = 0.5;
        for (let lat = -60; lat <= 80; lat += 20) {
            const y = this._latToY(lat, h);
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
        }
        for (let lon = -180; lon <= 180; lon += 30) {
            const x = this._lonToX(lon, w);
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
        }

        this._drawSimplifiedContinents(ctx, w, h);

        this._bridgeMapPoints = [];

        if (!bridges.some(b => b.lat || b.lon)) {
            ctx.fillStyle = 'rgba(255,255,255,0.15)';
            ctx.font = '16px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('Нет мостов с координатами', w / 2, h / 2);
            ctx.font = '12px sans-serif';
            ctx.fillStyle = 'rgba(255,255,255,0.08)';
            ctx.fillText('Добавьте lat/lon при регистрации моста', w / 2, h / 2 + 24);
            return;
        }

        for (const b of bridges) {
            if (!b.lat && !b.lon) continue;
            const x = this._lonToX(b.lon, w);
            const y = this._latToY(b.lat, h);

            const color = !b.is_alive ? '#f87171' : b.type === 'white' ? '#a5b4fc' : '#4ade80';
            const glow = ctx.createRadialGradient(x, y, 0, x, y, 18);
            glow.addColorStop(0, color + '40');
            glow.addColorStop(1, 'transparent');
            ctx.fillStyle = glow;
            ctx.fillRect(x - 18, y - 18, 36, 36);

            ctx.beginPath();
            ctx.arc(x, y, 5, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.strokeStyle = color + '80';
            ctx.lineWidth = 1.5;
            ctx.stroke();

            this._bridgeMapPoints.push({ x, y, bridge: b, radius: 12 });
        }

        if (!canvas._mousebound) {
            canvas._mousebound = true;
            const tooltip = document.getElementById('bridge-map-tooltip');
            canvas.addEventListener('mousemove', (e) => {
                const cr = canvas.getBoundingClientRect();
                const mx = e.clientX - cr.left;
                const my = e.clientY - cr.top;
                let found = null;
                for (const p of (this._bridgeMapPoints || [])) {
                    if (Math.hypot(mx - p.x, my - p.y) < p.radius) { found = p; break; }
                }
                if (found && tooltip) {
                    const b = found.bridge;
                    const typeBadge = b.type === 'white' ? '<span style="color:#a5b4fc;">WHITE</span>' : b.type;
                    tooltip.innerHTML = `
                        <div style="font-weight:600;margin-bottom:4px;">${b.country || '?'}, ${b.city || '?'}</div>
                        <div>Тип: ${typeBadge}</div>
                        <div>Задержка: <span style="color:${b.latency<100?'#4ade80':b.latency<300?'#facc15':'#f87171'}">${b.latency} мс</span></div>
                        <div>Нагрузка: ${Math.round((b.load||0)*100)}%</div>
                        <div>Пользователи: ${b.users || 0}</div>
                        <div style="margin-top:6px;font-size:0.8em;color:#888;">Нажмите для подключения</div>`;
                    tooltip.style.display = 'block';
                    tooltip.style.left = Math.min(found.x + 15, cr.width - 200) + 'px';
                    tooltip.style.top = Math.min(found.y + 15, cr.height - 120) + 'px';
                    canvas.style.cursor = 'pointer';
                } else {
                    if (tooltip) tooltip.style.display = 'none';
                    canvas.style.cursor = 'default';
                }
            });
            canvas.addEventListener('click', (e) => {
                const cr = canvas.getBoundingClientRect();
                const mx = e.clientX - cr.left;
                const my = e.clientY - cr.top;
                for (const p of (this._bridgeMapPoints || [])) {
                    if (Math.hypot(mx - p.x, my - p.y) < p.radius) {
                        this._showBridgeConnectDialog(p.bridge);
                        break;
                    }
                }
            });
            canvas.addEventListener('mouseleave', () => {
                if (tooltip) tooltip.style.display = 'none';
            });
        }
    },
    _lonToX(lon, w) { return ((lon + 180) / 360) * w; },
    _latToY(lat, h) { return ((90 - lat) / 180) * h; },
    _drawSimplifiedContinents(ctx, w, h) {
        const continents = [
            [[[-10,35],[30,35],[45,10],[50,-35],[20,-35],[-15,5]]],
            [[[-130,50],[-60,50],[-35,0],[-60,-55],[-80,-55],[-110,15],[-130,50]]],
            [[[60,60],[150,60],[150,10],[100,0],[60,10]]],
            [[[110,-10],[155,-10],[155,-40],[115,-40]]],
            [[[-25,65],[35,70],[60,60],[35,37],[-10,37],[-25,50]]],
        ];
        ctx.fillStyle = 'rgba(0,229,255,0.04)';
        ctx.strokeStyle = 'rgba(0,229,255,0.12)';
        ctx.lineWidth = 0.8;
        for (const shapes of continents) {
            for (const pts of shapes) {
                ctx.beginPath();
                for (let i = 0; i < pts.length; i++) {
                    const x = this._lonToX(pts[i][0], w);
                    const y = this._latToY(pts[i][1], h);
                    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
                }
                ctx.closePath();
                ctx.fill();
                ctx.stroke();
            }
        }
    },
    _renderBridgeMapTable(bridges) {
        const tbody = document.getElementById('bridge-map-tbody');
        if (!tbody) return;
        const alive = bridges.filter(b => b.is_alive);
        if (!alive.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#555;padding:32px;">Нет доступных мостов</td></tr>';
            return;
        }
        tbody.innerHTML = alive.map(b => {
            const typeBadge = b.type === 'white'
                ? '<span style="background:rgba(99,102,241,0.2);color:#a5b4fc;padding:2px 7px;border-radius:4px;font-size:0.8em;">white</span>'
                : `<span style="color:#888;font-size:0.85em;">${b.type || '—'}</span>`;
            const latColor = b.latency < 100 ? '#4ade80' : b.latency < 300 ? '#facc15' : '#f87171';
            const loadPct = Math.round((b.load || 0) * 100);
            const loadColor = loadPct < 50 ? '#4ade80' : loadPct < 80 ? '#facc15' : '#f87171';
            return `<tr>
                <td style="text-align:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#4ade80;"></span></td>
                <td>${escapeHtml(b.country || '?')}, ${escapeHtml(b.city || '?')}</td>
                <td>${typeBadge}</td>
                <td><span style="color:${latColor}">${b.latency} мс</span></td>
                <td>
                    <div style="display:flex;align-items:center;gap:6px;">
                        <div style="width:48px;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden;">
                            <div style="width:${loadPct}%;height:100%;background:${loadColor};border-radius:3px;"></div>
                        </div>
                        <span style="font-size:0.82em;color:#aaa;">${loadPct}%</span>
                    </div>
                </td>
                <td style="font-size:0.85em;color:#aaa;">${b.users || 0}</td>
                <td style="text-align:right;">
                    <button class="btn btn-primary btn-sm bridge-map-connect-btn" data-id="${b.id}" ${b.requires_key ? 'title="Требуется ключ доступа"' : ''}>
                        <i class="fas fa-plug"></i> ${b.requires_key ? 'Ключ' : 'Подключиться'}
                    </button>
                </td>
            </tr>`;
        }).join('');

        tbody.querySelectorAll('.bridge-map-connect-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const b = alive.find(x => x.id === btn.dataset.id);
                if (b) this._showBridgeConnectDialog(b);
            });
        });
    },
    async _showBridgeConnectDialog(bridge) {
        const isWhite = bridge.type === 'white' || bridge.requires_key;
        const title = `${bridge.country || '?'}, ${bridge.city || '?'}`;
        const body = `
            <div style="margin-bottom:16px;">
                <div style="font-size:1.1em;font-weight:600;margin-bottom:8px;">${title}</div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:0.88em;color:#aaa;">
                    <div>Тип: <span style="color:${isWhite ? '#a5b4fc' : '#4ade80'}">${bridge.type}</span></div>
                    <div>Задержка: <span style="color:#4ade80">${bridge.latency} мс</span></div>
                    <div>Нагрузка: ${Math.round((bridge.load||0)*100)}%</div>
                    <div>Пользователи: ${bridge.users || 0}</div>
                </div>
            </div>
            ${isWhite ? '<p style="color:#facc15;font-size:0.85em;margin-bottom:12px;"><i class="fas fa-key"></i> White мост — требуется ключ доступа</p>' : ''}
            <p style="font-size:0.85em;color:#888;">Подключиться к этому мосту?</p>`;

        if (!await this.showConfirm(body)) return;

        try {
            const res = await api.connectToBridge(bridge.id);
            if (res.success && res.connection) {
                const conn = res.connection;
                const configStr = JSON.stringify({
                    address: conn.address,
                    public_key: conn.public_key,
                    type: conn.type,
                }, null, 2);
                this.showNotification(`Подключение к мосту ${title} — конфигурация получена`, 'success');

                const configModal = document.createElement('div');
                configModal.className = 'modal-backdrop active';
                configModal.innerHTML = `
                    <div class="modal" style="max-width:500px;">
                        <div class="modal-header"><h3>Конфигурация подключения</h3><button class="modal-close modal-close-icon" onclick="this.closest('.modal-backdrop').remove()"><i class="fas fa-times"></i></button></div>
                        <div class="modal-body">
                            <pre style="background:rgba(0,0,0,0.3);padding:12px;border-radius:8px;font-size:0.82em;overflow-x:auto;color:#7ef7c8;">${configStr}</pre>
                            <p style="font-size:0.82em;color:#888;margin-top:8px;">Используйте эти данные в клиенте Whisp для подключения.</p>
                        </div>
                        <div class="modal-footer">
                            <button class="btn btn-secondary" onclick="this.closest('.modal-backdrop').remove()">Закрыть</button>
                            <button class="btn btn-primary" data-act="copy" data-copy="${escapeHtml(configStr)}">Копировать</button>
                        </div>
                    </div>`;
                document.body.appendChild(configModal);
            }
        } catch (e) {
            this.showNotification('Ошибка подключения: ' + e.message, 'error');
        }
    }
};
