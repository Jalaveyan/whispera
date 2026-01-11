// Whispera Configuration Manager - Упрощенное управление конфигурацией

class ConfigManager {
    constructor() {
        this.config = null;
        this.loadConfig();
    }

    async loadConfig() {
        try {
            // Загружаем конфигурацию из localStorage
            const saved = localStorage.getItem('whispera_config');
            if (saved) {
                this.config = JSON.parse(saved);
            }

            // Всегда обновляем данные с сервера (порты, IP, ключи)
            await this.loadFromServer();

        } catch (error) {
            console.error('Ошибка загрузки конфигурации:', error);
            if (!this.config) {
                this.config = this.getDefaultConfig();
            }
        }
    }

    async loadFromServer() {
        try {
            const info = await api.getSystemInfo();
            const serverSettings = {
                ip: info.server_ip || this.detectServerIP(),
                port: info.server_port || 51820,
                tcpPort: info.tcp_port || 4443,
                wsPort: info.ws_port || 8080,
                ws2Port: info.ws2_port || 8443,
                publicKey: info.server_pub || info.serverPublicKey
            };

            if (this.config) {
                // Обновляем только серверную часть, сохраняя пользовательские настройки
                this.config.server = { ...this.config.server, ...serverSettings };
            } else {
                // Создаем новую конфигурацию
                this.config = {
                    server: serverSettings,
                    obfuscation: {
                        defaultProfile: 'http2',
                        defaultMarionette: 'browser',
                        autoProfile: true
                    },
                    features: {
                        aiEvasion: true,
                        hardwareEvasion: true,
                        behavioralMimicry: true,
                        russianMimicry: true
                    }
                };
            }
            this.saveConfig();
        } catch (error) {
            console.error('Ошибка загрузки конфигурации с сервера:', error);
            if (!this.config) {
                this.config = this.getDefaultConfig();
            }
        }
    }

    getDefaultConfig() {
        return {
            server: {
                ip: this.detectServerIP(),
                port: 51820,
                tcpPort: 4443,
                wsPort: 8080,
                ws2Port: 8443,
                publicKey: ''
            },
            obfuscation: {
                defaultProfile: 'http2',
                defaultMarionette: 'browser',
                autoProfile: true
            },
            features: {
                aiEvasion: true,
                hardwareEvasion: true,
                behavioralMimicry: true,
                russianMimicry: true
            }
        };
    }

    detectServerIP() {
        const hostname = window.location.hostname;
        if (hostname && hostname !== 'localhost' && hostname !== '127.0.0.1' &&
            !hostname.startsWith('192.168.') && !hostname.startsWith('10.') &&
            !hostname.startsWith('172.16.')) {
            return hostname;
        }
        return '';
    }

    saveConfig() {
        try {
            localStorage.setItem('whispera_config', JSON.stringify(this.config));
        } catch (error) {
            console.error('Ошибка сохранения конфигурации:', error);
        }
    }

    get(key) {
        const keys = key.split('.');
        let value = this.config;
        for (const k of keys) {
            if (value && typeof value === 'object') {
                value = value[k];
            } else {
                return null;
            }
        }
        return value;
    }

    set(key, value) {
        const keys = key.split('.');
        let obj = this.config;
        for (let i = 0; i < keys.length - 1; i++) {
            if (!obj[keys[i]]) {
                obj[keys[i]] = {};
            }
            obj = obj[keys[i]];
        }
        obj[keys[keys.length - 1]] = value;
        this.saveConfig();
    }

    // Валидация и нормализация x25519 ключа (64 hex символа = 32 байта)
    normalizeKey(key, maxLength = 64) {
        if (!key || key === 'YOUR_SERVER_PUBLIC_KEY' || key === 'CLIENT_PRIVATE_KEY') {
            return key;
        }
        // Удаляем пробелы и переносы строк
        let cleaned = key.replace(/\s+/g, '').replace(/-/g, '');
        // Если ключ короче нужной длины - оставляем как есть (не обрезаем)
        // Если длиннее - обрезаем только если это явно лишнее
        if (cleaned.length > maxLength) {
            cleaned = cleaned.substring(0, maxLength);
        }
        return cleaned;
    }

    // Генерация оптимизированной конфигурации клиента
    generateClientConfig(user, customSettings = {}) {
        const serverIP = customSettings.serverIP || this.config.server.ip || this.detectServerIP();
        let serverPub = customSettings.serverPub || this.config.server.publicKey || 'YOUR_SERVER_PUBLIC_KEY';
        serverPub = this.normalizeKey(serverPub, 64);

        let clientPrivateKey = user.privateKey || 'CLIENT_PRIVATE_KEY';
        clientPrivateKey = this.normalizeKey(clientPrivateKey, 64);

        // Автоматическая оптимизация на основе профиля пользователя
        const obfsProfile = user.obfsProfile || this.config.obfuscation.defaultProfile || 'http2';
        const marionetteProfile = user.marionetteProfile || this.config.obfuscation.defaultMarionette || 'browser';

        // Определение портов на основе профиля
        let port = this.config.server.port || 51820;
        let tcpPort = this.config.server.tcpPort || 4443;
        let wsPort = this.config.server.wsPort || 8080;
        let ws2Port = this.config.server.ws2Port || 8443;

        // Рекомендации по профилям
        const profileRecommendations = {
            quic: {
                port: port,
                comment: '# QUIC профиль - быстрый и эффективный'
            },
            http2: {
                port: port,
                comment: '# HTTP/2 профиль - стабильный и надежный'
            },
            websocket: {
                port: ws2Port,
                comment: '# WebSocket профиль - универсальный'
            }
        };

        const recommendation = profileRecommendations[obfsProfile] || profileRecommendations.http2;

        return `# Whispera Client Configuration
# Generated automatically for user: ${user.username || 'user'}
# Profile: ${obfsProfile} / ${marionetteProfile}
${recommendation.comment}

client:
  server: "${serverIP}:${port}"
  server_tcp: "${serverIP}:${tcpPort}"
  server_ws: "ws://${serverIP}:${wsPort}/ws"
  server_ws2: "wss://${serverIP}:${ws2Port}/ws"
  server_pub: "${serverPub}"
  static_key: "${clientPrivateKey}"
  auto_profile: ${user.autoProfile !== false ? 'true' : 'false'}
  monitoring: true
  russian_service: "${user.russianService || 'vk'}"
  app_profile: "${user.appProfile || 'browser'}"
  obfs_preset: "${obfsProfile}"
  handshake_timeout: "5s"
  udp_upgrade_sec: 10

tun:
  interface: "whispera0"
  ip: "10.0.0.2/24"

obfuscation:
  fte_profile: "${obfsProfile}"
  marionette_profile: "${marionetteProfile}"
  ai_evasion: ${this.config.features.aiEvasion ? 'true' : 'false'}
  hardware_evasion: ${this.config.features.hardwareEvasion ? 'true' : 'false'}
  behavioral_mimicry: ${this.config.features.behavioralMimicry ? 'true' : 'false'}
  integrated_evasion: true
  russian_mimicry: ${this.config.features.russianMimicry ? 'true' : 'false'}

monitoring:
  enabled: true
  metrics_port: 9102

# Рекомендации:
# - Используйте автоматический профиль для лучшей производительности
# - Настройка оптимизирована для обхода блокировок
# - Все параметры были автоматически настроены системой`;
    }

    // Валидация конфигурации
    validateConfig(config) {
        const errors = [];

        if (!config.server || !config.server.ip) {
            errors.push('IP адрес сервера не указан');
        }

        if (!config.server || !config.server.publicKey) {
            errors.push('Публичный ключ сервера не указан');
        }

        if (config.server && config.server.port) {
            const port = parseInt(config.server.port);
            if (port < 443 || port > 65535) {
                errors.push('Порт должен быть в диапазоне 443-65535');
            }
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    // Автоматическая оптимизация настроек
    optimizeSettings(userContext = {}) {
        const optimized = { ...this.config };

        // Автоматический выбор профиля на основе контекста
        if (userContext.region === 'ru') {
            optimized.obfuscation.defaultMarionette = 'vk';
            optimized.features.russianMimicry = true;
        }

        // Оптимизация для мобильных устройств
        if (userContext.device === 'mobile') {
            optimized.obfuscation.defaultProfile = 'quic';
        }

        return optimized;
    }
}

// Глобальный экземпляр
const configManager = new ConfigManager();

