export const translations = {
    ru: {
        "nav.home": "Главная",
        "nav.settings": "Настройки",
        "nav.proxies": "Прокси",
        "nav.connections": "Соединения",
        "mode.rule": "Правило",
        "mode.global": "Глобальный",
        "toggle.proxy": "Прокси",
        "toggle.tun": "Tun",
        "stat.rule": "Правило",
        "stat.connections": "Соединения",
        "stat.logs": "Журнал",
        "footer.exit": "Выход",
        "footer.lang": "Язык",
        "footer.update": "Обновить",
        "header.search": "Поиск прокси",
        "notify.title": "Уведомления",
        "notify.clear": "Очистить",
        "notify.empty": "Нет уведомлений",
        "traffic.download": "Загрузка",
        "traffic.upload": "Отправка",
        "traffic.memory": "Память",
        "card.profile_title": "Whispera VPN",
        "card.updated": "Обновлено",
        "btn.connect": "Подключиться",
        "btn.disconnect": "Отключиться",
        "card.site_testing": "Тестирование сайта",
        "card.ip_info": "IP [FYI]",
        "info.real_ip": "Реальный IP",
        "info.city": "Город",
        "info.country": "Страна",
        "info.provider": "Провайдер",
        "info.timezone": "Часовой пояс",
        "card.system": "Система",
        "info.os": "ОС",
        "info.uptime": "Время работы",
        "info.autostart": "Автозапуск",
        "page.settings": "Настройки",
        "page.profiles": "Профили",
        "page.connections": "Соединения",
        "page.stats": "Статистика",
        "key.title": "Ключ подключения",
        "key.placeholder": "Вставьте ключ whispera://...",
        "key.connect": "Подключиться",
        "key.server": "Сервер",
        "key.transport": "Транспорт",
        "key.obfs": "Обфускация",
        "page.logs": "Журнал"
    },
    en: {
        "nav.home": "Home",
        "nav.settings": "Settings",
        "nav.proxies": "Proxies",
        "nav.connections": "Connections",
        "mode.rule": "Rule",
        "mode.global": "Global",
        "toggle.proxy": "Proxy",
        "toggle.tun": "Tun",
        "stat.rule": "Rule",
        "stat.connections": "Connections",
        "stat.logs": "Logs",
        "footer.exit": "Exit",
        "footer.lang": "Language",
        "footer.update": "Update",
        "header.search": "Search proxies",
        "notify.title": "Notifications",
        "notify.clear": "Clear",
        "notify.empty": "No notifications",
        "traffic.download": "Download",
        "traffic.upload": "Upload",
        "traffic.memory": "Memory",
        "card.profile_title": "Whispera VPN",
        "card.updated": "Updated",
        "btn.connect": "Connect",
        "btn.disconnect": "Disconnect",
        "card.site_testing": "Site Testing",
        "card.ip_info": "IP [FYI]",
        "info.real_ip": "Real IP",
        "info.city": "City",
        "info.country": "Country",
        "info.provider": "Provider",
        "info.timezone": "Timezone",
        "card.system": "System",
        "info.os": "OS",
        "info.uptime": "Uptime",
        "info.autostart": "Autostart",
        "page.settings": "Settings",
        "page.profiles": "Profiles",
        "page.connections": "Connections",
        "page.stats": "Stats",
        "page.logs": "Logs",
        "key.title": "Connection Key",
        "key.placeholder": "Paste key whispera://...",
        "key.connect": "Connect",
        "key.server": "Server",
        "key.transport": "Transport",
        "key.obfs": "Obfuscation"
    }
};

let currentLang = 'ru';

export function initI18n() {
    const saved = localStorage.getItem('whispera_lang');
    if (saved && (saved === 'ru' || saved === 'en')) {
        currentLang = saved;
    }
    applyLanguage(currentLang);

    const langBtn = document.getElementById('lang-btn');
    if (langBtn) {
        langBtn.addEventListener('click', toggleLanguage);
    }
}

export function toggleLanguage() {
    currentLang = currentLang === 'ru' ? 'en' : 'ru';
    localStorage.setItem('whispera_lang', currentLang);
    applyLanguage(currentLang);
}

function applyLanguage(lang) {
    const t = translations[lang];

    // Update elements with data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (t[key]) el.textContent = t[key];
    });

    // Update elements with data-i18n-title
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.dataset.i18nTitle;
        if (t[key]) el.title = t[key];
    });

    // Update elements with data-i18n-placeholder
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.dataset.i18nPlaceholder;
        if (t[key]) el.placeholder = t[key];
    });

    console.log(`[I18N] Language switched to ${lang}`);
}
