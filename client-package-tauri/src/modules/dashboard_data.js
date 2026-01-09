// Fetches real IP info and system data

import { invoke } from '@tauri-apps/api/core';

// Site configurations
const SITES = [
    { id: 'google', name: 'Google', url: 'https://www.google.com/favicon.ico' },
    { id: 'youtube', name: 'Youtube', url: 'https://www.youtube.com/favicon.ico' },
    { id: 'github', name: 'Github', url: 'https://github.com/favicon.ico' },
    { id: 'chatgpt', name: 'ChatGpt', url: 'https://chat.openai.com/favicon.ico' },
    { id: 'netflix', name: 'Netflix', url: 'https://www.netflix.com/favicon.ico' },
    { id: 'instagram', name: 'Instagram', url: 'https://www.instagram.com/favicon.ico' }
];

// IP Info from external API
export async function fetchIPInfo() {
    try {
        // Use ip-api.com for free IP geolocation
        const response = await fetch('http://ip-api.com/json/?fields=status,message,country,city,isp,org,as,query,timezone');

        if (!response.ok) {
            throw new Error('Failed to fetch IP info');
        }

        const data = await response.json();

        if (data.status === 'success') {
            updateIPDisplay({
                ip: data.query,
                city: data.city,
                country: data.country,
                provider: data.isp || data.org,
                asn: data.as ? data.as.split(' ')[0] : '--',
                timezone: data.timezone
            });
        }

        return data;
    } catch (error) {
        console.error('[Dashboard] Failed to fetch IP info:', error);
        // Fallback to another API
        try {
            const fallbackResponse = await fetch('https://ipapi.co/json/');
            const fallbackData = await fallbackResponse.json();

            updateIPDisplay({
                ip: fallbackData.ip,
                city: fallbackData.city,
                country: fallbackData.country_name,
                provider: fallbackData.org,
                asn: fallbackData.asn,
                timezone: fallbackData.timezone
            });

            return fallbackData;
        } catch (fallbackError) {
            console.error('[Dashboard] Fallback IP fetch failed:', fallbackError);
            return null;
        }
    }
}

function updateIPDisplay(info) {
    const setTextContent = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value || '--';
    };

    setTextContent('real-ip', info.ip);
    setTextContent('ip-city', info.city);
    setTextContent('ip-country', info.country);
    setTextContent('ip-provider', info.provider);
    setTextContent('ip-asn', info.asn);
    setTextContent('ip-timezone', info.timezone);
}

// System Info from Tauri backend
export async function fetchSystemInfo() {
    try {
        // Try to get info from Tauri
        const isAdmin = await invoke('check_admin').catch(() => false);
        const autostartEnabled = await invoke('is_autostart_enabled').catch(() => false);

        updateSystemDisplay({
            os: getOSName(),
            uptime: formatUptime(performance.now()),
            autostart: autostartEnabled ? 'ВКЛ' : 'ВЫКЛ',
            admin: isAdmin ? 'ВКЛ' : 'ВЫКЛ',
            port: '51820',
            version: 'v1.2.0'
        });

        // Update uptime every second
        setInterval(() => {
            const uptimeEl = document.getElementById('sys-uptime');
            if (uptimeEl) {
                uptimeEl.textContent = formatUptime(performance.now());
            }
        }, 1000);

    } catch (error) {
        console.error('[Dashboard] Failed to fetch system info:', error);
    }
}

function updateSystemDisplay(info) {
    const setTextContent = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value || '--';
    };

    setTextContent('sys-os', info.os);
    setTextContent('sys-uptime', info.uptime);
    setTextContent('sys-autostart', info.autostart);
    setTextContent('sys-admin', info.admin);
    setTextContent('sys-port', info.port);
    setTextContent('sys-version', info.version);
}

function getOSName() {
    const userAgent = navigator.userAgent;
    if (userAgent.includes('Win')) return 'Windows x64';
    if (userAgent.includes('Mac')) return 'macOS';
    if (userAgent.includes('Linux')) return 'Linux';
    return 'Unknown OS';
}

function formatUptime(ms) {
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}

// Site ping testing - Test all sites
export async function testSitePings() {
    for (const site of SITES) {
        await testSinglePing(site.id, site.url);
    }
}

// Test a single site ping
async function testSinglePing(siteId, url) {
    const pingEl = document.getElementById(`ping-${siteId}`);
    const itemEl = document.querySelector(`.site-item[data-site="${siteId}"]`) ||
        document.querySelector(`.site-item[data-url*="${siteId}"]`);

    if (!pingEl) return;

    // Show loading state
    pingEl.textContent = '...';
    pingEl.classList.add('pinging');
    if (itemEl) itemEl.classList.add('pinging');

    try {
        // Perform multiple pings and take the average for accuracy
        const pings = [];

        for (let i = 0; i < 3; i++) {
            const startTime = performance.now();

            await fetch(url, {
                method: 'HEAD',
                mode: 'no-cors',
                cache: 'no-cache'
            });

            const endTime = performance.now();
            pings.push(endTime - startTime);
        }

        // Use the minimum ping (most accurate)
        const ping = Math.round(Math.min(...pings));

        pingEl.textContent = ping;
        pingEl.classList.remove('pinging');
        if (itemEl) itemEl.classList.remove('pinging');

        // Color based on latency
        if (ping < 150) {
            pingEl.classList.add('ping-good');
            pingEl.classList.remove('ping-medium', 'ping-bad');
        } else if (ping < 400) {
            pingEl.classList.add('ping-medium');
            pingEl.classList.remove('ping-good', 'ping-bad');
        } else {
            pingEl.classList.add('ping-bad');
            pingEl.classList.remove('ping-good', 'ping-medium');
        }

        return ping;

    } catch (error) {
        pingEl.textContent = 'ERR';
        pingEl.classList.remove('pinging');
        pingEl.classList.add('ping-bad');
        if (itemEl) itemEl.classList.remove('pinging');
        return null;
    }
}

// Render site items dynamically
function renderSiteItems() {
    const grid = document.querySelector('.sites-grid');
    if (!grid) return;

    grid.innerHTML = SITES.map(site => `
        <div class="site-item" data-site="${site.id}" data-url="${site.url}" style="background:var(--bg-surface);padding:12px;border-radius:8px;text-align:center;cursor:pointer;">
            <div style="font-size:20px;margin-bottom:5px;">
                ${getSiteIcon(site.id)}
            </div>
            <div style="font-weight:500;">${site.name}</div>
            <div id="ping-${site.id}" class="ping-value" style="color:var(--text-secondary);font-size:12px;">--</div>
        </div>
    `).join('');

    console.log(`[Dashboard] Rendered ${SITES.length} site items`);
}

function getSiteIcon(id) {
    const icons = {
        'google': '🔍',
        'youtube': '▶️',
        'github': '💻',
        'chatgpt': '🤖',
        'netflix': '🎬',
        'instagram': '📸'
    };
    return icons[id] || '🌐';
}

// Setup click handlers for individual site pings
function setupSitePingHandlers() {
    const siteItems = document.querySelectorAll('.site-item');

    siteItems.forEach(item => {
        item.style.cursor = 'pointer';

        item.addEventListener('click', async (e) => {
            e.preventDefault();

            // Find site config by URL or data attribute
            const siteId = item.dataset.site;
            const site = SITES.find(s => s.id === siteId);

            if (site) {
                console.log(`[Ping] Testing ${site.name}...`);
                await testSinglePing(site.id, site.url);
            }
        });
    });

    console.log(`[Dashboard] Setup click handlers for ${siteItems.length} site items`);
}

// Refresh all sites button handler
function setupRefreshAllHandler() {
    const refreshBtn = document.getElementById('site-refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            console.log('[Dashboard] Refreshing all site pings...');
            refreshBtn.style.transform = 'rotate(360deg)';
            refreshBtn.style.transition = 'transform 0.5s';
            await testSitePings();
            setTimeout(() => { refreshBtn.style.transform = ''; }, 500);
        });
    }

    const addBtn = document.getElementById('site-add-btn');
    if (addBtn) {
        addBtn.addEventListener('click', () => {
            const url = prompt('Введите адрес сайта для проверки:');
            if (url) alert(`Сайт ${url} добавлен (Демонстрация вызова)`);
        });
    }

    const linkBtn = document.getElementById('site-link-btn');
    if (linkBtn) {
        linkBtn.addEventListener('click', () => {
            alert('Действие с ссылкой выполнено');
        });
    }
}

// Initialize dashboard data
export function initDashboardData() {
    console.log('[Dashboard] Initializing real data...');

    fetchIPInfo();
    fetchSystemInfo();
    renderSiteItems(); // Render sites first
    testSitePings();

    // Setup click handlers
    setupSitePingHandlers();
    setupRefreshAllHandler();

    // Refresh IP button handler
    const refreshBtn = document.getElementById('refresh-ip');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            fetchIPInfo();
        });
    }

    // Refresh site pings every 60 seconds
    setInterval(testSitePings, 60000);
}

// Auto-initialize when module loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDashboardData);
} else {
    initDashboardData();
}
