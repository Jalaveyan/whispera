// Whispera Web Panel Main Application

class WhisperaApp {
    constructor() {
        this.currentPage = 'dashboard';
        this.users = [];
        this.sessions = [];
        this.stats = {};
        this.currentConfigUser = null; // Сохраняем текущего пользователя для обновления конфига
        this.currentConfigFormat = 'yaml'; // Текущий формат конфигурации (yaml/json)
        this.init();
    }

    init() {
        // Проверяем авторизацию
        if (api.token) {
            this.showMainPanel();
            this.loadDashboard();
            // Setup wizard disabled
            // this.checkSetupWizard();
        } else {
            this.showLogin();
        }

        // Обработчики событий
        this.setupEventListeners();

        // Автоматическое обновление данных
        this.startAutoRefresh();

        // Автоматическое обновление статистики каждые 30 секунд
        if (this.currentPage === 'stats') {
            setInterval(() => this.loadTrafficStats(), 30000);
        } else if (this.currentPage === 'adblock') {
            setInterval(() => this.loadAdblockStats(), 30000);
        }

        // Принудительная инициализация поля username при показе логина
        this.ensureUsernameFieldWorks();

        // Update connection status indicator
        this.updateConnectionStatus();
        setInterval(() => this.updateConnectionStatus(), 10000);
    }

    updateConnectionStatus() {
        const statusDiv = document.getElementById('serverStatus');
        if (!statusDiv) return;

        const icon = statusDiv.querySelector('i');
        const text = statusDiv.querySelector('span');

        // Always show connected status (no demo mode)
        icon.className = 'fas fa-circle status-online';
        icon.style.color = '';
        text.textContent = 'Сервер работает';
        statusDiv.title = 'Подключено к ' + api.baseURL;
    }

    ensureUsernameFieldWorks() {
        // Убеждаемся, что поле username работает
        const usernameField = document.getElementById('username');
        if (usernameField) {
            // Убираем любые блокировки
            usernameField.disabled = false;
            usernameField.readOnly = false;
            usernameField.style.pointerEvents = 'auto';
            usernameField.style.opacity = '1';

            // Устанавливаем фокус через небольшую задержку (на случай если autofocus не сработал)
            setTimeout(() => {
                if (document.getElementById('loginScreen')?.style.display !== 'none') {
                    usernameField.focus();
                }
            }, 100);

            // Обработчик для проверки работоспособности
            usernameField.addEventListener('input', () => {
                console.log('Username field is working, value:', usernameField.value);
            });
        }
    }

    async checkSetupWizard() {

        try {
            // Проверяем, нужна ли первоначальная настройка
            const users = await api.getUsers();
            const info = await api.getSystemInfo();

            // Если нет пользователей или нет публичного ключа сервера
            if (users.length === 0 || !info.server_pub) {
                // Инициализируем мастер настройки
                if (typeof ConfigWizard !== 'undefined') {
                    wizard = new ConfigWizard();
                    await wizard.init();
                }
            }
        } catch (error) {
            console.error('Ошибка проверки мастера настройки:', error);
        }
    }

    setupEventListeners() {
        // Логин форма
        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        // Навигация
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.dataset.page;
                this.navigateTo(page);
            });
        });

        // Выход
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.handleLogout();
        });

        // Добавление пользователя
        document.getElementById('addUserBtn').addEventListener('click', () => {
            this.showAddUserModal();
        });

        // Форма добавления пользователя
        document.getElementById('addUserForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddUser();
        });

        // Закрытие модальных окон
        document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
            btn.addEventListener('click', () => {
                this.closeModal();
            });
        });

        // Обновление сессий
        document.getElementById('refreshSessionsBtn')?.addEventListener('click', () => {
            this.loadSessions();
        });

        // Делегирование событий для таблицы пользователей (Actions Delegation)
        const usersTable = document.getElementById('usersTableBody');
        // DISABLED: Using direct onclick instead
        if (false && usersTable) {
            usersTable.addEventListener('click', (e) => {
                const btn = e.target.closest('button');
                if (!btn) return;

                // Use getAttribute for safer access
                const userId = btn.getAttribute('data-userid');
                console.log('Button clicked:', btn.className, 'UserID:', userId);

                if (!userId) {
                    console.error('No UserID found on button');
                    return;
                }

                // Определяем действие по классу кнопки
                if (btn.classList.contains('action-quick-connect')) {
                    this.showQuickConnectModal(userId);
                } else if (btn.classList.contains('action-copy-key')) {
                    this.copyUserKey(userId);
                } else if (btn.classList.contains('action-generate-key')) {
                    this.generateUserKey(userId);
                } else if (btn.classList.contains('action-download')) {
                    this.showClientConfig(userId);
                } else if (btn.classList.contains('action-edit')) {
                    this.editUser(userId);
                } else if (btn.classList.contains('action-delete')) {
                    this.deleteUser(userId);
                }
            });
        }

        // Автоматическое обновление YAML при изменении IP адреса (как в 3x-ui)
        // Используем делегирование событий, так как элемент может не существовать при инициализации
        document.addEventListener('input', (e) => {
            if (e.target && e.target.id === 'serverIP') {
                this.updateConfigYAML();
            }
        });

        // Сохранение настроек
        document.getElementById('saveSettingsBtn')?.addEventListener('click', () => {
            this.saveSettings();
        });
    }

    async loadSettings() {
        try {
            // Загружаем настройки с сервера
            const info = await api.getSystemInfo();

            // Заполняем форму настроек
            const serverIPInput = document.getElementById('settingsServerIP');
            const serverPubInput = document.getElementById('settingsServerPub');

            if (serverIPInput) {
                const hostname = window.location.hostname;
                if (hostname && hostname !== 'localhost' && hostname !== '127.0.0.1') {
                    serverIPInput.value = hostname;
                    // Автоматически заполняем домен для Let's Encrypt
                    const leDomainInput = document.getElementById('letsencryptDomain');
                    if (leDomainInput && !leDomainInput.value) {
                        leDomainInput.value = hostname;
                    }
                } else {
                    serverIPInput.value = info.server_ip || '';
                }
            }

            // Загружаем порты
            const udpPortInput = document.getElementById('settingsUdpPort');
            const tcpPortInput = document.getElementById('settingsTcpPort');
            const wsPortInput = document.getElementById('settingsWsPort');
            const ws2PortInput = document.getElementById('settingsWs2Port');

            if (udpPortInput) udpPortInput.value = info.server_port || 51820;
            if (tcpPortInput) tcpPortInput.value = info.tcp_port || 4443;
            if (wsPortInput) wsPortInput.value = info.ws_port || 8080;
            if (ws2PortInput) ws2PortInput.value = info.ws2_port || 8443;
            if (serverPubInput) serverPubInput.value = info.server_pub || info.serverPublicKey || '';

            // Загружаем статус сертификата
            await this.checkCertificateStatus();

            // Загружаем настройки из ConfigManager
            if (typeof configManager !== 'undefined') {
                const obfsProfile = configManager.get('obfuscation.defaultProfile') || 'http2';
                const marionetteProfile = configManager.get('obfuscation.defaultMarionette') || 'browser';
                const autoProfile = configManager.get('obfuscation.autoProfile') !== false;

                const obfsSelect = document.getElementById('settingsObfsProfile');
                const marionetteSelect = document.getElementById('settingsMarionetteProfile');
                const autoProfileCheck = document.getElementById('settingsAutoProfile');

                if (obfsSelect) obfsSelect.value = obfsProfile;
                if (marionetteSelect) marionetteSelect.value = marionetteProfile;
                if (autoProfileCheck) autoProfileCheck.checked = autoProfile;

                // Загружаем дополнительные функции
                const aiEvasion = configManager.get('features.aiEvasion') !== false;
                const hardwareEvasion = configManager.get('features.hardwareEvasion') !== false;
                const behavioralMimicry = configManager.get('features.behavioralMimicry') !== false;
                const russianMimicry = configManager.get('features.russianMimicry') !== false;

                const aiEvasionCheck = document.getElementById('settingsAiEvasion');
                const hardwareEvasionCheck = document.getElementById('settingsHardwareEvasion');
                const behavioralMimicryCheck = document.getElementById('settingsBehavioralMimicry');
                const russianMimicryCheck = document.getElementById('settingsRussianMimicry');

                if (aiEvasionCheck) aiEvasionCheck.checked = aiEvasion;
                if (hardwareEvasionCheck) hardwareEvasionCheck.checked = hardwareEvasion;
                if (behavioralMimicryCheck) behavioralMimicryCheck.checked = behavioralMimicry;
                if (russianMimicryCheck) russianMimicryCheck.checked = russianMimicry;
            }
        } catch (error) {
            console.error('Ошибка загрузки настроек:', error);
        }
    }

    async saveSettings() {
        try {
            // Валидация портов
            const udpPort = parseInt(document.getElementById('settingsUdpPort')?.value);
            const tcpPort = parseInt(document.getElementById('settingsTcpPort')?.value);
            const wsPort = parseInt(document.getElementById('settingsWsPort')?.value);
            const ws2Port = parseInt(document.getElementById('settingsWs2Port')?.value);

            const ports = [
                { name: 'UDP', value: udpPort, protocol: 'udp' },
                { name: 'TCP', value: tcpPort, protocol: 'tcp' },
                { name: 'WebSocket', value: wsPort, protocol: 'tcp' },
                { name: 'WebSocket Secure', value: ws2Port, protocol: 'tcp' }
            ];

            // Базовая валидация диапазона
            for (const port of ports) {
                if (port.value && (port.value < 443 || port.value > 65535)) {
                    alert(`${port.name} порт должен быть в диапазоне 443-65535`);
                    return;
                }
            }

            // Проверка на дубликаты (раздельно по протоколам)
            const udpPorts = ports.filter(p => p.protocol === 'udp').map(p => p.value).filter(v => v);
            const tcpPorts = ports.filter(p => p.protocol === 'tcp').map(p => p.value).filter(v => v);

            const udpDuplicates = udpPorts.filter((v, i) => udpPorts.indexOf(v) !== i);
            const tcpDuplicates = tcpPorts.filter((v, i) => tcpPorts.indexOf(v) !== i);

            if (udpDuplicates.length > 0) {
                alert(`UDP порты не могут дублироваться! Найдены дубликаты: ${udpDuplicates.join(', ')}`);
                return;
            }
            if (tcpDuplicates.length > 0) {
                alert(`TCP порты не могут дублироваться! Найдены дубликаты: ${tcpDuplicates.join(', ')}`);
                return;
            }

            // Проверка занятости портов
            const portCheckResults = await this.checkPortsAvailability(ports);
            if (!portCheckResults.allAvailable) {
                const occupiedPorts = portCheckResults.occupied.map(p => `${p.name} (${p.value})`).join(', ');
                if (!confirm(`Следующие порты уже заняты: ${occupiedPorts}\n\nПродолжить сохранение? Это может привести к ошибкам подключения.`)) {
                    return;
                }
            }

            // Сохраняем в ConfigManager
            if (typeof configManager !== 'undefined') {
                const serverIP = document.getElementById('settingsServerIP')?.value || '';
                const obfsProfile = document.getElementById('settingsObfsProfile')?.value || 'http2';
                const marionetteProfile = document.getElementById('settingsMarionetteProfile')?.value || 'browser';
                const autoProfile = document.getElementById('settingsAutoProfile')?.checked || false;
                const aiEvasion = document.getElementById('settingsAiEvasion')?.checked || false;
                const hardwareEvasion = document.getElementById('settingsHardwareEvasion')?.checked || false;
                const behavioralMimicry = document.getElementById('settingsBehavioralMimicry')?.checked || false;
                const russianMimicry = document.getElementById('settingsRussianMimicry')?.checked || false;

                const autoFirewall = document.getElementById('settingsAutoFirewall')?.checked || false;

                configManager.set('server.ip', serverIP);
                configManager.set('server.port', udpPort || 51820);
                configManager.set('server.tcpPort', tcpPort || 4443);
                configManager.set('server.wsPort', wsPort || 8080);
                configManager.set('server.ws2Port', ws2Port || 8443);
                configManager.set('server.autoFirewall', autoFirewall);
                configManager.set('obfuscation.defaultProfile', obfsProfile);
                configManager.set('obfuscation.defaultMarionette', marionetteProfile);
                configManager.set('obfuscation.autoProfile', autoProfile);
                configManager.set('features.aiEvasion', aiEvasion);
                configManager.set('features.hardwareEvasion', hardwareEvasion);
                configManager.set('features.behavioralMimicry', behavioralMimicry);
                configManager.set('features.russianMimicry', russianMimicry);

                configManager.saveConfig();

                // Автоматически настраиваем firewall если включено
                if (autoFirewall) {
                    try {
                        const firewallPorts = [
                            { port: udpPort || 51820, protocol: 'udp', name: 'UDP основной' },
                            { port: tcpPort || 4443, protocol: 'tcp', name: 'TCP fallback' },
                            { port: wsPort || 8080, protocol: 'tcp', name: 'WebSocket' },
                            { port: ws2Port || 8443, protocol: 'tcp', name: 'WebSocket Secure' }
                        ];
                        await api.configureFirewall(firewallPorts);
                    } catch (firewallError) {
                        console.warn('Не удалось настроить firewall автоматически:', firewallError);
                        // Не показываем ошибку, так как это опциональная функция
                    }
                }
            }

            // Сохранение на сервер через API
            if (typeof configManager !== 'undefined' && configManager.config) {
                await api.updateConfig(configManager.config);
            }

            this.showSuccessMessage('Настройки сохранены успешно!');
        } catch (error) {
            alert('Ошибка сохранения настроек: ' + error.message);
        }
    }

    showErrorMessage(message) {
        // Показываем ошибку пользователю
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #f44336; color: white; padding: 1rem; border-radius: 4px; z-index: 10000; max-width: 400px;';
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);

        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }

    showSuccessMessage(message) {
        const toast = document.createElement('div');
        toast.className = 'toast toast-success';
        toast.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    async handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorDiv = document.getElementById('loginError');

        try {
            errorDiv.style.display = 'none';
            await api.login(username, password);
            this.showMainPanel();
            this.loadDashboard();
        } catch (error) {
            errorDiv.textContent = error.message || 'Ошибка авторизации';
            errorDiv.style.display = 'block';
        }
    }

    handleLogout() {
        api.logout();
        this.showLogin();
    }

    showLogin() {
        document.getElementById('loginScreen').style.display = 'flex';
        document.getElementById('mainPanel').style.display = 'none';
        // Убеждаемся, что поле username работает при показе логина
        setTimeout(() => this.ensureUsernameFieldWorks(), 50);
    }

    showMainPanel() {
        document.getElementById('loginScreen').style.display = 'none';
        document.getElementById('mainPanel').style.display = 'flex';
    }

    navigateTo(page) {
        // Обновляем активную страницу в меню
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-page="${page}"]`)?.classList.add('active');

        // Показываем нужную страницу
        document.querySelectorAll('.page').forEach(p => {
            p.classList.remove('active');
        });
        document.getElementById(`page-${page}`).classList.add('active');

        // Обновляем заголовок
        const titles = {
            dashboard: 'Главная',
            users: 'Пользователи',
            sessions: 'Подключения',
            stats: 'Статистика',
            settings: 'Настройки',
            adblock: 'Блокировщик рекламы',
            logs: 'Логи',
            routing: 'Маршрутизация',
            subscriptions: 'Подписки',
            outbounds: 'Серверы',
            geo: 'Geo базы'
        };
        document.getElementById('pageTitle').textContent = titles[page] || page;

        this.currentPage = page;

        // Загружаем данные для страницы
        this.loadPageData(page);
    }

    async loadPageData(page) {
        switch (page) {
            case 'dashboard':
                await this.loadDashboard();
                break;
            case 'users':
                await this.loadUsers();
                break;
            case 'sessions':
                await this.loadSessions();
                break;
            case 'stats':
                await this.loadStats();
                break;
            case 'settings':
                await this.loadSettings();
                break;
            case 'logs':
                await this.loadLogs();
                break;
            case 'adblock':
                await this.loadAdblockStats();
                break;
            case 'routing':
                await this.loadRoutingRules();
                break;
            case 'subscriptions':
                await this.loadSubscriptions();
                break;
            case 'outbounds':
                await this.loadOutbounds();
                break;
            case 'inbounds':
                await this.loadInbounds();
                break;
            case 'geo':
                await this.loadGeoStatus();
                break;
        }
    }

    // Inbounds Methods
    async loadInbounds() {
        try {
            const data = await api.request('GET', '/api/inbounds');
            if (data.success) {
                this.renderInboundsTable(data.inbounds);
            }
        } catch (error) {
            console.error('Error loading inbounds:', error);
            this.showErrorMessage('Не удалось загрузить список входящих подключений');
        }
    }

    renderInboundsTable(inbounds) {
        const tbody = document.getElementById('inboundsTableBody');
        if (!tbody) return;

        if (!inbounds || inbounds.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">Нет настроенных подключений</td></tr>';
            return;
        }

        tbody.innerHTML = inbounds.map(inbound => {
            const net = inbound.stream_settings?.network || 'tcp';
            const security = inbound.stream_settings?.security || 'none';
            // Extract private key if exists for quick copy
            const pk = inbound.stream_settings?.phantom?.private_key ||
                inbound.stream_settings?.reality?.private_key ||
                inbound.stream_settings?.tls?.key_file || '';
            const pkDisplay = pk ? `<code title="${pk}">${pk.substring(0, 8)}...</code>` : '-';

            return `
            <tr>
                <td><strong>${inbound.tag}</strong></td>
                <td>${inbound.protocol}</td>
                <td>${inbound.listen}:${inbound.port}</td>
                <td><span class="badge badge-info">${net}</span></td>
                <td><span class="badge ${security === 'none' ? '' : 'badge-success'}">${security}</span></td>
                <td>${pkDisplay}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="app.deleteInbound('${inbound.tag}')">
                        <i class="fas fa-trash"></i>
                    </button>
                    <!-- Add Edit button later -->
                </td>
            </tr>
            `;
        }).join('');
    }

    showAddInboundModal() {
        const modal = document.getElementById('inboundModal');
        if (modal) {
            modal.classList.add('active');
            modal.style.display = 'flex';
        }
        // Reset form
        document.getElementById('inboundForm').reset();
    }

    async saveInbound() {
        const form = document.getElementById('inboundForm');
        const formData = new FormData(form);

        const inbound = {
            tag: formData.get('tag'),
            port: parseInt(formData.get('port')),
            listen: formData.get('listen'),
            protocol: 'whispera', // Fixed for now
            stream_settings: {
                network: 'tcp',
                security: 'phantom',
                phantom: {
                    private_key: formData.get('private_key'),
                    dest: formData.get('dest'),
                    server_names: formData.get('server_names') ? formData.get('server_names').split(',').map(s => s.trim()) : []
                }
            }
        };

        try {
            const res = await api.request('/api/inbounds/add', {
                method: 'POST',
                body: JSON.stringify(inbound)
            });
            if (res.success) {
                this.showSuccessMessage('Входящее подключение добавлено');
                this.closeModal();
                this.loadInbounds();
                // Show reminder to restart
                alert('Для применения изменений необходимо перезагрузить сервис!');
            }
        } catch (error) {
            console.error('Error saving inbound:', error);
            this.showErrorMessage(error.message || 'Ошибка сохранения');
        }
    }

    async deleteInbound(tag) {
        if (!confirm(`Удалить входящее подключение "${tag}"?`)) return;

        try {
            await api.request('/api/inbounds/delete', {
                method: 'POST',
                body: JSON.stringify({ tag })
            });
            this.showSuccessMessage('Подключение удалено');
            this.loadInbounds();
            alert('Для применения изменений необходимо перезагрузить сервис!');
        } catch (error) {
            this.showErrorMessage('Ошибка удаления: ' + error.message);
        }
    }

    async generateKeyForInbound() {
        try {
            const keys = await api.generateKeys();
            if (keys && keys.privateKey) {
                document.getElementsByName('private_key')[0].value = keys.privateKey;
            }
        } catch (error) {
            console.error('Key gen error:', error);
            this.showErrorMessage('Ошибка генерации ключа');
        }
    }

    async restartService() {
        if (!confirm('Вы уверены, что хотите перезагрузить конфигурацию сервиса? Это может разорвать активные соединения.')) return;

        try {
            await api.request('/api/v1/config/reload', {
                method: 'POST'
            });
            this.showSuccessMessage('Конфигурация перезагружена. Если порты не открылись, перезапустите сервис полностью (systemctl restart).');
        } catch (e) {
            this.showErrorMessage('Ошибка перезагрузки: ' + e.message);
        }
    }

    // Заполнить dropdown портов в Quick Connect Modal
    // Заполнить input+datalist портов
    async populatePortSelector() {
        const dataList = document.getElementById('existingPortsList');
        const portInput = document.getElementById('quickConnectPort');
        if (!dataList || !portInput) return;

        try {
            // Загружаем список inbounds
            const response = await api.request('/api/inbounds');
            const inbounds = response.inbounds || [];

            // Сохраняем кэш для проверки существования порта
            this.cachedInbounds = inbounds;

            // Очищаем datalist
            dataList.innerHTML = '';

            if (inbounds && inbounds.length > 0) {
                // Добавляем существующие порты в подсказки
                inbounds.forEach(inbound => {
                    const option = document.createElement('option');
                    option.value = inbound.port;
                    option.label = `${inbound.tag || 'Inbound'}`;
                    dataList.appendChild(option);
                });

                // Если поле пустое, ставим первый порт
                if (!portInput.value) {
                    portInput.value = inbounds[0].port;
                    this.updateQuickConnectForPort();
                }
            }
        } catch (error) {
            console.error('Error loading inbounds for port selector:', error);
        }
    }

    // Обработка изменения порта (ввод вручную или выбор)
    async handleQuickConnectPortChange() {
        const portInput = document.getElementById('quickConnectPort');
        const statusEl = document.getElementById('portCreationStatus');

        if (!portInput) return;

        const port = parseInt(portInput.value);
        if (!port || port < 1 || port > 65535) {
            this.showErrorMessage("Некорректный порт");
            return;
        }

        // Проверяем, существует ли порт
        const exists = this.cachedInbounds?.some(i => i.port === port);

        if (exists) {
            // Порт существует - просто обновляем данные
            await this.updateQuickConnectForPort();
        } else {
            // Порт НОВЫЙ - создаем автоматически!
            if (confirm(`Порт ${port} не найден. Создать новое входящее подключение на порту ${port} автоматически?`)) {
                try {
                    if (statusEl) statusEl.style.display = 'block'; // Показываем спиннер

                    const newInbound = {
                        tag: `auto-${port}`,
                        port: port,
                        protocol: 'whispera',
                        listen: '0.0.0.0',
                        stream_settings: {
                            network: 'tcp',
                            security: 'phantom',
                            phantom: {
                                private_key: '' // Auto-generate
                            }
                        }
                    };

                    console.log(`Creating auto-inbound for port ${port}...`);
                    await api.request('/api/inbounds/add', {
                        method: 'POST',
                        body: JSON.stringify(newInbound)
                    });

                    this.showSuccessMessage(`Порт ${port} успешно создан и открыт!`);

                    // Перезагружаем списки
                    await this.populatePortSelector();

                    // Устанавливаем значение обратно (т.к. populate может сбросить)
                    portInput.value = port;

                    // Обновляем ключи
                    await this.updateQuickConnectForPort();

                } catch (error) {
                    console.error('Auto-create inbound failed:', error);
                    this.showErrorMessage(`Ошибка создания порта: ${error.message}`);
                } finally {
                    if (statusEl) statusEl.style.display = 'none';
                }
            } else {
                // Пользователь отказался
                portInput.value = ""; // Очистить
            }
        }
    }

    // Обновить Quick Connect данные при выборе порта
    async updateQuickConnectForPort() {
        const portSelect = document.getElementById('quickConnectPort');
        const selectedPort = portSelect?.value;

        if (!selectedPort) {
            console.warn('No port selected');
            return;
        }

        try {
            // Получаем информацию о сервере
            const info = await api.getSystemInfo();
            const serverIP = window.location.hostname || info.server_ip || 'YOUR_SERVER_IP';

            // Получаем публичный ключ для выбранного порта
            // Если у inbound есть свой ключ, сервер должен вернуть его через API
            const publicKeyResponse = await api.request(`/api/inbounds/pubkey?port=${selectedPort}`);
            const serverPubKey = publicKeyResponse.public_key || info.public_key;

            // Получаем текущий приватный ключ пользователя
            const privateKeyInput = document.getElementById('quickConnectPrivateKey');
            const privateKey = privateKeyInput?.value || '';

            // Обновляем поля
            const serverUrlInput = document.getElementById('quickConnectServerUrl');
            if (serverUrlInput) {
                serverUrlInput.value = `${serverIP}:${selectedPort}`;
            }

            // Генерируем полный URL с новым портом
            const fullUrl = this.generateQuickConnectUrl(serverIP, selectedPort, serverPubKey, privateKey);
            const fullUrlInput = document.getElementById('quickConnectFullUrl');
            if (fullUrlInput) {
                fullUrlInput.value = fullUrl;
            }

            console.log(`[QuickConnect] Updated for port ${selectedPort}, pubkey: ${serverPubKey?.substring(0, 16)}...`);
        } catch (error) {
            console.error('Error updating Quick Connect for port:', error);
            this.showErrorMessage('Не удалось получить данные для порта: ' + error.message);
        }
    }

    // Показать модальное окно Quick Connect для пользователя
    async showQuickConnectModal(userId) {
        const user = this.users.find(u => u.id == userId);
        if (!user || !user.privateKey) {
            alert('У пользователя нет ключа подключения');
            return;
        }

        try {
            // Получаем информацию о сервере
            const info = await api.getSystemInfo();
            const serverIP = window.location.hostname || info.server_ip || 'YOUR_SERVER_IP';

            // Заполняем порты
            await this.populatePortSelector();

            // Получаем порт по умолчанию (первый inbound)
            const portSelect = document.getElementById('quickConnectPort');
            const defaultPort = portSelect?.value || info.port || 443;
            const serverPubKey = info.public_key || '';

            // Заполняем поля
            const privateKeyInput = document.getElementById('quickConnectPrivateKey');
            if (privateKeyInput) {
                privateKeyInput.value = user.privateKey;
            }

            const serverUrlInput = document.getElementById('quickConnectServerUrl');
            if (serverUrlInput) {
                serverUrlInput.value = `${serverIP}:${defaultPort}`;
            }

            // Генерируем полный URL
            const fullUrl = this.generateQuickConnectUrl(serverIP, defaultPort, serverPubKey, user.privateKey);
            const fullUrlInput = document.getElementById('quickConnectFullUrl');
            if (fullUrlInput) {
                fullUrlInput.value = fullUrl;
            }

            // Показываем модальное окно
            const modal = document.getElementById('quickConnectModal');
            if (modal) {
                modal.classList.add('active');
                modal.style.display = 'flex';
            }

            console.log(`[QuickConnect] Opened for user ${user.username}, initial port: ${defaultPort}`);
        } catch (error) {
            console.error('Error showing Quick Connect modal:', error);
            this.showErrorMessage('Не удалось открыть Quick Connect: ' + error.message);
        }
    }

    async loadDashboard() {
        try {
            // Загружаем статистику
            const stats = await api.getStats();
            this.updateDashboardStats(stats);

            // Загружаем пользователей
            const users = await api.getUsers();
            document.getElementById('totalUsers').textContent = users.length || 0;

            // Загружаем сессии
            const sessions = await api.getSessions();
            const activeSessions = sessions.filter(s => s.status === 'active');
            document.getElementById('activeSessions').textContent = activeSessions.length || 0;

            // Загружаем информацию о сервере
            const serverInfo = await api.getSystemInfo();
            this.updateServerInfo(serverInfo);
        } catch (error) {
            console.error('Error loading dashboard:', error);
        }
    }

    updateDashboardStats(stats) {
        if (stats.traffic) {
            document.getElementById('totalUpload').textContent = this.formatBytes(stats.traffic.upload || 0);
            document.getElementById('totalDownload').textContent = this.formatBytes(stats.traffic.download || 0);
        }
    }

    updateServerInfo(info) {
        const infoDiv = document.getElementById('serverInfo');
        if (infoDiv && info) {
            infoDiv.innerHTML = `
                <div class="info-item">
                    <strong>Версия:</strong> ${info.version || 'Unknown'}
                </div>
                <div class="info-item">
                    <strong>Uptime:</strong> ${this.formatUptime(info.uptime || 0)}
                </div>
                <div class="info-item">
                    <strong>Память:</strong> ${this.formatBytes(info.memory || 0)}
                </div>
            `;
        }
    }

    async loadUsers() {
        try {
            this.users = await api.getUsers();
            this.renderUsersTable();
        } catch (error) {
            console.error('Error loading users:', error);
            this.showErrorMessage('Не удалось загрузить пользователей: ' + (error.message || 'Неизвестная ошибка'));
        }
    }

    renderUsersTable() {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        if (this.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 2rem;">Нет пользователей</td></tr>';
            return;
        }

        tbody.innerHTML = this.users.map(user => {
            const privateKey = user.privateKey || user.key || '';
            const hasKey = privateKey.length >= 10; // Relaxed check for demo keys
            const keyPreview = hasKey ? `${privateKey.substring(0, 12)}...${privateKey.substring(privateKey.length - 8)}` : 'Нет ключа';
            // Safe ID for functions
            const uid = user.id;

            return `
            <tr>
                <td>${user.id || '-'}</td>
                <td><strong>${user.username || '-'}</strong></td>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                        <code style="font-size: 0.85rem; background: ${hasKey ? 'rgba(99, 102, 241, 0.2)' : 'rgba(239, 68, 68, 0.2)'}; color: ${hasKey ? 'var(--secondary-color)' : '#fca5a5'}; padding: 0.4rem 0.75rem; border-radius: 6px; font-weight: 500; border: 1px solid ${hasKey ? 'rgba(99, 102, 241, 0.4)' : 'var(--danger-color)'};">
                            ${keyPreview}
                        </code>
                        ${hasKey ? `
                            <button class="btn btn-sm btn-primary action-quick-connect" onclick="app.showQuickConnectModal('${uid}')" title="Ключ для Quick Connect">
                                <i class="fas fa-bolt"></i> Quick Connect
                            </button>
                            <button class="btn btn-sm btn-secondary action-copy-key" onclick="app.copyUserKey('${uid}')" title="Копировать ключ">
                                <i class="fas fa-copy"></i>
                            </button>
                        ` : `
                            <button class="btn btn-sm btn-warning action-generate-key" onclick="app.generateUserKey('${uid}')" title="Сгенерировать ключ">
                                <i class="fas fa-key"></i> Создать ключ
                            </button>
                        `}
                    </div>
                </td>
                <td>
                    <div style="font-size: 0.9rem;">
                        <span style="color: #10b981;">↑ ${this.formatBytes(user.upload || 0)}</span>
                        <span style="margin: 0 0.5rem; color: #6b7280;">/</span>
                        <span style="color: #3b82f6;">↓ ${this.formatBytes(user.download || 0)}</span>
                    </div>
                </td>
                <td>${user.trafficLimit ? this.formatBytes(user.trafficLimit) : '<span style="color: #10b981;">Безлимит</span>'}</td>
                <td>${user.expiryDate ? new Date(user.expiryDate).toLocaleDateString() : '<span style="color: #10b981;">Не ограничен</span>'}</td>
                <td>
                    <span class="badge ${user.status === 'active' ? 'badge-success' : 'badge-danger'}">
                        ${user.status === 'active' ? 'Активен' : 'Неактивен'}
                    </span>
                </td>
                <td>
                    <div style="display: flex; gap: 0.25rem; flex-wrap: wrap;">
                        <button class="btn btn-sm btn-primary action-download" onclick="app.showClientConfig('${uid}')" title="Конфигурация клиента">
                            <i class="fas fa-download"></i>
                        </button>
                        <button class="btn btn-sm btn-secondary action-edit" onclick="app.editUser('${uid}')" title="Редактировать">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-sm btn-danger action-delete" onclick="app.deleteUser('${uid}')" title="Удалить">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');
    }

    async showClientConfig(userId) {
        const user = this.users.find(u => u.id == userId);
        if (!user) {
            alert('Пользователь не найден');
            return;
        }

        // КРИТИЧНО: Если у пользователя нет приватного ключа, генерируем и сохраняем его
        if (!user.privateKey || user.privateKey === '' || user.privateKey === 'NOT_GENERATED') {
            try {
                // Генерируем ключи
                let keys = null;
                try {
                    keys = await api.generateKeys();
                } catch (apiError) {
                    keys = await this.generateKeysClientSide();
                }

                if (keys && keys.privateKey) {
                    // Обновляем пользователя на сервере с новым ключом
                    const updatedUser = {
                        ...user,
                        privateKey: keys.privateKey.trim(),
                        publicKey: keys.publicKey ? keys.publicKey.trim() : null
                    };

                    await api.updateUser(user.id, updatedUser);

                    // Обновляем локальный объект пользователя
                    user.privateKey = updatedUser.privateKey;
                    user.publicKey = updatedUser.publicKey;

                    // Перезагружаем список пользователей
                    await this.loadUsers();

                    this.showSuccessMessage('Приватный ключ автоматически сгенерирован и сохранен!');
                }
            } catch (error) {
                console.error('Ошибка генерации ключа:', error);
                alert('Не удалось сгенерировать ключ. Попробуйте вручную через кнопку "Генерировать"');
            }
        }

        // Сохраняем пользователя для обновления конфига
        this.currentConfigUser = user;

        try {
            // Получаем информацию о сервере через API
            const serverInfo = await api.getSystemInfo();
            const serverPub = serverInfo.server_pub || serverInfo.serverPublicKey || 'YOUR_SERVER_PUBLIC_KEY';

            // Автоматическое определение IP адреса (как в 3x-ui)
            let serverIP = serverInfo.server_ip || serverInfo.serverIP;

            // Если IP не получен из API, используем hostname из URL
            if (!serverIP || serverIP === '' || serverIP === 'YOUR_SERVER_IP') {
                const hostname = window.location.hostname;
                // Пропускаем localhost и внутренние IP
                if (hostname !== 'localhost' && hostname !== '127.0.0.1' &&
                    !hostname.startsWith('192.168.') && !hostname.startsWith('10.')) {
                    serverIP = hostname;
                } else {
                    // Если это localhost, оставляем placeholder для ручного ввода
                    serverIP = 'YOUR_SERVER_IP';
                }
            }

            // Заполняем модальное окно
            document.getElementById('configUsername').value = user.username || '';
            document.getElementById('clientPrivateKey').value = user.privateKey || 'NOT_GENERATED';
            document.getElementById('serverPublicKey').value = serverPub;
            document.getElementById('serverIP').value = serverIP;

            // Генерируем конфигурацию в текущем формате
            const configContent = this.generateWhisperaConfig(user, serverPub, serverIP, this.currentConfigFormat);
            document.getElementById('clientConfigYAML').value = configContent;

            // Обновляем UI в зависимости от формата
            this.updateConfigFormatUI();

            // Показываем модальное окно
            document.getElementById('clientConfigModal').classList.add('active');
        } catch (error) {
            console.error('Ошибка при загрузке информации о сервере:', error);
            // В случае ошибки используем значения по умолчанию
            const serverIP = window.location.hostname !== 'localhost' &&
                window.location.hostname !== '127.0.0.1'
                ? window.location.hostname : 'YOUR_SERVER_IP';

            document.getElementById('configUsername').value = user.username || '';
            document.getElementById('clientPrivateKey').value = user.privateKey || 'NOT_GENERATED';
            document.getElementById('serverPublicKey').value = 'YOUR_SERVER_PUBLIC_KEY';
            document.getElementById('serverIP').value = serverIP;

            const configContent = this.generateWhisperaConfig(user, 'YOUR_SERVER_PUBLIC_KEY', serverIP, this.currentConfigFormat);
            document.getElementById('clientConfigYAML').value = configContent;

            // Обновляем UI в зависимости от формата
            this.updateConfigFormatUI();

            document.getElementById('clientConfigModal').classList.add('active');
        }
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

    generateWhisperaConfig(user, serverPub, serverIP, format = 'yaml') {
        const port = 51820;

        // Нормализуем ключи (обрезаем до 64 символов для x25519)
        const normalizedServerPub = this.normalizeKey(serverPub, 64);
        const normalizedStaticKey = this.normalizeKey(user.privateKey || 'CLIENT_PRIVATE_KEY', 64);
        const tcpPort = 4443;
        const wsPort = 8080;
        const ws2Port = 8443;

        const obfsProfile = user.obfsProfile || (typeof configManager !== 'undefined' ? configManager.get('obfuscation.defaultProfile') : 'http2') || 'http2';
        const marionetteProfile = user.marionetteProfile || (typeof configManager !== 'undefined' ? configManager.get('obfuscation.defaultMarionette') : 'browser') || 'browser';

        // Если нужен JSON формат для C# клиента
        if (format === 'json') {
            return this.generateAppSettingsJson(user, serverPub, serverIP, port, obfsProfile, marionetteProfile);
        }

        // Используем ConfigManager для генерации оптимизированной YAML конфигурации
        if (typeof configManager !== 'undefined') {
            return configManager.generateClientConfig(user, {
                serverIP: serverIP,
                serverPub: serverPub
            });
        }

        // Fallback на старую YAML генерацию
        return `# Whispera Client Configuration
# Generated for user: ${user.username || 'user'}

client:
  server: "${serverIP}:${port}"
  server_tcp: "${serverIP}:${tcpPort}"
  server_ws: "ws://${serverIP}:${wsPort}/ws"
  server_ws2: "wss://${serverIP}:${ws2Port}/ws"
  server_pub: "${normalizedServerPub}"
  static_key: "${normalizedStaticKey}"
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
  ai_evasion: true
  hardware_evasion: true
  behavioral_mimicry: true
  integrated_evasion: true
  russian_mimicry: true

monitoring:
  enabled: true
  metrics_port: 9102`;
    }

    generateAppSettingsJson(user, serverPub, serverIP, port, obfsProfile, marionetteProfile) {
        const config = {
            "Logging": {
                "LogLevel": {
                    "Default": "Information",
                    "Microsoft": "Warning",
                    "Microsoft.Hosting.Lifetime": "Information"
                }
            },
            "WhisperaClient": {
                "ServerIp": serverIP,
                "ServerPort": port,
                "ClientPrivateKey": user.privateKey || "",
                "ServerPublicKey": serverPub,
                "FteProfile": obfsProfile,
                "MarionetteProfile": marionetteProfile,
                "RussianService": user.russianService || "vk",
                "AiEvasion": user.aiEvasion !== false,
                "HardwareEvasion": user.hardwareEvasion !== false,
                "BehavioralMimicry": user.behavioralMimicry !== false,
                "RussianMimicry": user.russianMimicry !== false,
                "AutoProfile": user.autoProfile !== false,
                "Monitoring": user.monitoring !== false,
                "AppProfile": user.appProfile || "browser"
            }
        };

        // Используем значения из ConfigManager если доступны
        if (typeof configManager !== 'undefined') {
            const defaultObfs = configManager.get('obfuscation.defaultProfile');
            const defaultMarionette = configManager.get('obfuscation.defaultMarionette');
            const aiEvasion = configManager.get('features.aiEvasion');
            const hardwareEvasion = configManager.get('features.hardwareEvasion');
            const behavioralMimicry = configManager.get('features.behavioralMimicry');
            const russianMimicry = configManager.get('features.russianMimicry');

            if (defaultObfs) config.WhisperaClient.FteProfile = defaultObfs;
            if (defaultMarionette) config.WhisperaClient.MarionetteProfile = defaultMarionette;
            if (aiEvasion !== null) config.WhisperaClient.AiEvasion = aiEvasion;
            if (hardwareEvasion !== null) config.WhisperaClient.HardwareEvasion = hardwareEvasion;
            if (behavioralMimicry !== null) config.WhisperaClient.BehavioralMimicry = behavioralMimicry;
            if (russianMimicry !== null) config.WhisperaClient.RussianMimicry = russianMimicry;
        }

        return JSON.stringify(config, null, 2);
    }

    // Обновление конфигурации при изменении IP или формата
    updateConfigYAML() {
        if (!this.currentConfigUser) return;

        const serverIP = document.getElementById('serverIP').value || 'YOUR_SERVER_IP';
        const serverPub = document.getElementById('serverPublicKey').value || 'YOUR_SERVER_PUBLIC_KEY';
        const user = this.currentConfigUser;

        // Перегенерируем конфигурацию с новыми параметрами
        const configContent = this.generateWhisperaConfig(user, serverPub, serverIP, this.currentConfigFormat);
        document.getElementById('clientConfigYAML').value = configContent;
    }

    // Переключение формата конфигурации
    switchConfigFormat(format) {
        this.currentConfigFormat = format;

        // Обновляем кнопки выбора формата
        document.querySelectorAll('.format-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.format === format) {
                btn.classList.add('active');
            }
        });

        // Перегенерируем конфигурацию в новом формате
        this.updateConfigYAML();
        this.updateConfigFormatUI();
    }

    // Обновление UI в зависимости от формата
    updateConfigFormatUI() {
        const formatLabel = document.getElementById('configFormatLabel');
        const downloadBtnText = document.getElementById('downloadBtnText');
        const clientInfoText = document.getElementById('clientInfoText');

        if (this.currentConfigFormat === 'json') {
            if (formatLabel) formatLabel.textContent = 'JSON конфигурация (appsettings.json)';
            if (downloadBtnText) downloadBtnText.textContent = 'Скачать appsettings.json';
            if (clientInfoText) {
                clientInfoText.innerHTML = `
                    <strong>C# клиент:</strong> Используйте JSON конфигурацию. 
                    Скопируйте файл <code>appsettings.json</code> в папку <code>dist/</code> клиентского приложения.
                    <br><br>
                    <strong>Инструкция:</strong>
                    <ol style="margin: 0.5rem 0 0 1.5rem; padding: 0;">
                        <li>Скачайте файл appsettings.json</li>
                        <li>Скопируйте его в папку с WhisperaClient.exe</li>
                        <li>Запустите WhisperaClient.exe</li>
                    </ol>
                `;
            }
        } else {
            if (formatLabel) formatLabel.textContent = 'YAML конфигурация';
            if (downloadBtnText) downloadBtnText.textContent = 'Скачать YAML';
            if (clientInfoText) {
                clientInfoText.innerHTML = `
                    <strong>Go клиент:</strong> Используйте YAML конфигурацию. 
                    Скопируйте содержимое в файл <code>client_config.yaml</code>
                    <br><br>
                    <strong>Инструкция:</strong>
                    <ol style="margin: 0.5rem 0 0 1.5rem; padding: 0;">
                        <li>Скачайте YAML файл</li>
                        <li>Скопируйте его рядом с whispera-client</li>
                        <li>Запустите клиент: <code>whispera-client -config client_config.yaml</code></li>
                    </ol>
                `;
            }
        }
    }


    async deleteUser(userId) {
        alert('DEBUG: deleteUser function entry. userId=' + userId + ', app is ' + (typeof app));
        if (!confirm('Вы уверены, что хотите удалить этого пользователя?')) {
            return;
        }
        try {
            const user = this.users.find(u => String(u.id) === String(userId));
            if (!user) {
                alert('Пользователь не найден');
                return;
            }
            await api.deleteUser(userId);
            this.showSuccessMessage(`Пользователь "${user.username}" удален.`);
            await this.loadUsers();
        } catch (error) {
            console.error('Ошибка удаления пользователя:', error);
            alert('Ошибка удаления пользователя: ' + error.message);
        }
    }

    editUser(userId) {
        const user = this.users.find(u => String(u.id) === String(userId));
        if (!user) {
            alert('Пользователь не найден');
            return;
        }
        alert('Функция редактирования восстанавливается для пользователя: ' + user.username);
    }

    async loadSessions() {
        try {
            this.sessions = await api.getSessions();
            this.renderSessionsTable();
        } catch (error) {
            console.error('Error loading sessions:', error);
        }
    }

    renderSessionsTable() {
        const tbody = document.getElementById('sessionsTableBody');
        if (!tbody) return;

        if (this.sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;">Нет активных подключений</td></tr>';
            return;
        }

        tbody.innerHTML = this.sessions.map(session => `
            <tr>
                <td>${session.id || '-'}</td>
                <td>${session.username || '-'}</td>
                <td>${session.ip || '-'}</td>
                <td>${session.connectedAt ? new Date(session.connectedAt).toLocaleString() : '-'}</td>
                <td>
                    ${this.formatBytes(session.upload || 0)} / ${this.formatBytes(session.download || 0)}
                </td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="app.killSession('${session.id}')">
                        <i class="fas fa-times"></i> Отключить
                    </button>
                </td>
            </tr>
        `).join('');
    }

    async loadStats() {
        await this.loadTrafficStats();
    }

    async loadTrafficStats() {
        try {
            const period = document.getElementById('statsPeriod')?.value || '24h';

            // Загружаем общую статистику
            const stats = await api.getStats();
            const trafficStats = await api.getTrafficStats();

            // Обновляем общую статистику
            const totalUpload = stats.traffic?.upload || 0;
            const totalDownload = stats.traffic?.download || 0;
            const totalTraffic = totalUpload + totalDownload;

            document.getElementById('totalUploadStats').textContent = this.formatBytes(totalUpload);
            document.getElementById('totalDownloadStats').textContent = this.formatBytes(totalDownload);
            document.getElementById('totalTrafficStats').textContent = this.formatBytes(totalTraffic);

            // Загружаем активных пользователей
            const users = await api.getUsers();
            const activeUsers = users.filter(u => u.status === 'active').length;
            document.getElementById('activeUsersStats').textContent = activeUsers;

            // Загружаем историю трафика
            const history = await api.getTrafficHistory(period);
            this.renderTrafficChart(history);

            // Загружаем трафик по пользователям
            await this.loadUserTrafficStats(users);

        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async loadUserTrafficStats(users) {
        const tbody = document.getElementById('userTrafficTableBody');
        if (!tbody) return;

        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;">Нет пользователей</td></tr>';
            return;
        }

        // Загружаем трафик для каждого пользователя
        const userTrafficPromises = users.map(async (user) => {
            try {
                const userStats = await api.getUserTraffic(user.id);
                return {
                    user: user,
                    stats: userStats || { upload: 0, download: 0 }
                };
            } catch {
                return {
                    user: user,
                    stats: { upload: user.upload || 0, download: user.download || 0 }
                };
            }
        });

        const userTrafficData = await Promise.all(userTrafficPromises);

        tbody.innerHTML = userTrafficData.map(({ user, stats }) => {
            const upload = stats.upload || user.upload || 0;
            const download = stats.download || user.download || 0;
            const total = upload + download;
            const limit = user.trafficLimit || 0;
            const usedPercent = limit > 0 ? ((total / limit) * 100).toFixed(1) : 0;

            return `
                <tr>
                    <td><strong>${user.username || '-'}</strong></td>
                    <td>${this.formatBytes(upload)}</td>
                    <td>${this.formatBytes(download)}</td>
                    <td><strong>${this.formatBytes(total)}</strong></td>
                    <td>${limit > 0 ? this.formatBytes(limit) : 'Безлимит'}</td>
                    <td>
                        ${limit > 0 ? `
                            <div class="progress-bar-container">
                                <div class="progress-bar" style="width: ${Math.min(usedPercent, 100)}%; background: ${usedPercent > 90 ? 'var(--danger-color)' : usedPercent > 70 ? 'var(--warning-color)' : 'var(--success-color)'}"></div>
                                <span class="progress-text">${usedPercent}%</span>
                            </div>
                        ` : '<span class="badge badge-success">Безлимит</span>'}
                    </td>
                </tr>
            `;
        }).join('');
    }

    renderTrafficChart(history) {
        const canvas = document.getElementById('trafficChartCanvas');
        if (!canvas || !history || !history.data) {
            console.log('Chart data not available');
            return;
        }

        const ctx = canvas.getContext('2d');
        const data = history.data;

        // Устанавливаем размер canvas
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = 300;

        // Простая отрисовка графика (можно заменить на Chart.js)
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        if (data.length === 0) {
            ctx.fillStyle = '#6b7280';
            ctx.font = '16px Arial';
            ctx.textAlign = 'center';
            ctx.fillText('Нет данных для отображения', canvas.width / 2, canvas.height / 2);
            return;
        }

        // Рисуем график
        const maxValue = Math.max(...data.map(d => (d.upload || 0) + (d.download || 0)));
        const padding = 40;
        const chartWidth = canvas.width - padding * 2;
        const chartHeight = canvas.height - padding * 2;
        const stepX = chartWidth / (data.length - 1 || 1);

        // Оси
        ctx.strokeStyle = '#e5e7eb';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(padding, padding);
        ctx.lineTo(padding, canvas.height - padding);
        ctx.lineTo(canvas.width - padding, canvas.height - padding);
        ctx.stroke();

        // График трафика
        ctx.strokeStyle = '#4a90e2';
        ctx.lineWidth = 2;
        ctx.beginPath();

        data.forEach((point, index) => {
            const x = padding + index * stepX;
            const value = (point.upload || 0) + (point.download || 0);
            const y = canvas.height - padding - (value / maxValue) * chartHeight;

            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        ctx.stroke();
    }

    async checkPortsAvailability(ports) {
        const results = {
            allAvailable: true,
            occupied: [],
            checked: []
        };

        // Получаем список занятых портов с сервера (если доступно)
        let usedPorts = [];
        try {
            usedPorts = await api.getUsedPorts();
        } catch (error) {
            console.log('Не удалось получить список занятых портов с сервера');
        }

        // Проверяем каждый порт
        for (const portInfo of ports) {
            if (!portInfo.value) continue;

            // Проверяем через API
            let isAvailable = true;
            let occupiedBy = null;

            try {
                const checkResult = await api.checkPortAvailability(portInfo.value, portInfo.protocol);
                isAvailable = checkResult.available !== false;
                occupiedBy = checkResult.occupiedBy || null;
            } catch (error) {
                // Если API недоступен, проверяем локально
                // Проверяем в списке занятых портов
                const found = usedPorts.find(p =>
                    p.port === portInfo.value &&
                    (p.protocol === portInfo.protocol || p.protocol === 'tcp+udp')
                );

                if (found) {
                    isAvailable = false;
                    occupiedBy = found.service || found.name || 'Неизвестная служба';
                }
            }

            results.checked.push({
                ...portInfo,
                available: isAvailable,
                occupiedBy: occupiedBy
            });

            if (!isAvailable) {
                results.allAvailable = false;
                results.occupied.push({
                    ...portInfo,
                    occupiedBy: occupiedBy
                });
            }
        }

        return results;
    }

    // Проверка доступности одного порта
    async checkPortAvailability(inputId, protocol) {
        const input = document.getElementById(inputId);
        const statusId = inputId.replace('settings', '').toLowerCase() + 'PortStatus';
        const helpId = inputId.replace('settings', '').toLowerCase() + 'PortHelp';
        const statusEl = document.getElementById(statusId);
        const helpEl = document.getElementById(helpId);

        if (!input || !input.value) {
            if (statusEl) statusEl.textContent = '';
            return;
        }

        const port = parseInt(input.value);
        if (port < 443 || port > 65535) {
            if (statusEl) {
                statusEl.className = 'port-status port-error';
                statusEl.innerHTML = '<i class="fas fa-times-circle"></i>';
            }
            if (helpEl) {
                helpEl.innerHTML = '<span style="color: var(--danger-color);">Порт должен быть в диапазоне 443-65535</span>';
            }
            input.classList.add('input-error');
            return;
        }

        // Показываем индикатор загрузки
        if (statusEl) {
            statusEl.className = 'port-status port-checking';
            statusEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        }

        try {
            const result = await api.checkPortAvailability(port, protocol);
            const isAvailable = result.available !== false;
            const occupiedBy = result.occupiedBy || null;

            if (statusEl) {
                if (isAvailable) {
                    statusEl.className = 'port-status port-available';
                    statusEl.innerHTML = '<i class="fas fa-check-circle"></i>';
                    input.classList.remove('input-error');
                    input.classList.add('input-success');
                } else {
                    statusEl.className = 'port-status port-error';
                    statusEl.innerHTML = '<i class="fas fa-times-circle"></i>';
                    input.classList.remove('input-success');
                    input.classList.add('input-error');
                }
            }

            if (helpEl) {
                if (isAvailable) {
                    helpEl.innerHTML = `<i class="fas fa-check-circle" style="color: var(--success-color);"></i> Порт ${port} свободен`;
                } else {
                    const service = occupiedBy ? ` (занят ${occupiedBy})` : '';
                    helpEl.innerHTML = `<i class="fas fa-exclamation-triangle" style="color: var(--danger-color);"></i> <strong>Порт ${port} уже занят${service}!</strong> Укажите другой порт.`;
                }
            }
        } catch (error) {
            console.error('Ошибка проверки порта:', error);
            if (statusEl) {
                statusEl.className = 'port-status port-warning';
                statusEl.innerHTML = '<i class="fas fa-question-circle"></i>';
            }
            if (helpEl) {
                helpEl.innerHTML = '<span style="color: var(--warning-color);">Не удалось проверить доступность порта</span>';
            }
        }
    }

    // Проверка всех портов
    async checkAllPorts() {
        const ports = [
            { id: 'settingsUdpPort', protocol: 'udp', name: 'UDP' },
            { id: 'settingsTcpPort', protocol: 'tcp', name: 'TCP' },
            { id: 'settingsWsPort', protocol: 'tcp', name: 'WebSocket' },
            { id: 'settingsWs2Port', protocol: 'tcp', name: 'WebSocket Secure' }
        ];

        // Показываем уведомление о начале проверки
        this.showSuccessMessage('Проверка портов...');

        // Проверяем все порты
        for (const portInfo of ports) {
            await this.checkPortAvailability(portInfo.id, portInfo.protocol);
            // Небольшая задержка между проверками
            await new Promise(resolve => setTimeout(resolve, 200));
        }

        // Подсчитываем результаты
        const errorInputs = document.querySelectorAll('.input-error');
        if (errorInputs.length > 0) {
            this.showErrorMessage(`Найдено ${errorInputs.length} занятых портов! Пожалуйста, укажите другие порты.`);
        } else {
            this.showSuccessMessage('Все порты свободны!');
        }
    }

    showErrorMessage(message) {
        const toast = document.createElement('div');
        toast.className = 'toast toast-error';
        toast.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    async configureFirewallNow() {
        if (!confirm('Настроить firewall для всех указанных портов? Это может потребовать прав администратора.')) {
            return;
        }

        try {
            const udpPort = parseInt(document.getElementById('settingsUdpPort')?.value) || 443;
            const tcpPort = parseInt(document.getElementById('settingsTcpPort')?.value) || 4443;
            const wsPort = parseInt(document.getElementById('settingsWsPort')?.value) || 8080;
            const ws2Port = parseInt(document.getElementById('settingsWs2Port')?.value) || 8443;

            const ports = [
                { port: udpPort, protocol: 'udp', name: 'UDP основной' },
                { port: tcpPort, protocol: 'tcp', name: 'TCP fallback' },
                { port: wsPort, protocol: 'tcp', name: 'WebSocket' },
                { port: ws2Port, protocol: 'tcp', name: 'WebSocket Secure' }
            ];

            // Проверяем доступность портов перед настройкой firewall
            const checkResults = await this.checkPortsAvailability([
                { name: 'UDP', value: udpPort, protocol: 'udp' },
                { name: 'TCP', value: tcpPort, protocol: 'tcp' },
                { name: 'WebSocket', value: wsPort, protocol: 'tcp' },
                { name: 'WebSocket Secure', value: ws2Port, protocol: 'tcp' }
            ]);

            if (!checkResults.allAvailable) {
                const occupiedPorts = checkResults.occupied.map(p =>
                    `${p.name} (${p.value})${p.occupiedBy ? ' - занят ' + p.occupiedBy : ''}`
                ).join('\n');

                if (!confirm(`ВНИМАНИЕ! Следующие порты уже заняты:\n\n${occupiedPorts}\n\nПродолжить настройку firewall?`)) {
                    return;
                }
            }

            await api.configureFirewall(ports);
            this.showSuccessMessage('Firewall успешно настроен!');
        } catch (error) {
            alert('Ошибка настройки firewall: ' + error.message);
        }
    }

    async loadLogs() {
        try {
            const logs = await api.getLogs(500);
            const logsContent = document.getElementById('logsContent');
            if (logsContent) {
                logsContent.textContent = logs.logs ? logs.logs.join('\n') : 'Нет логов';
            }
        } catch (error) {
            console.error('Error loading logs:', error);
        }
    }

    showAddUserModal() {
        // Сбрасываем превью ключей при открытии
        this.hideKeyPreview();
        document.getElementById('addUserModal').classList.add('active');
    }

    closeModal() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.remove('active');
            modal.style.display = 'none';
        });
        // Сбрасываем превью ключей при закрытии
        this.hideKeyPreview();
    }

    async handleAddUser() {
        const form = document.getElementById('addUserForm');
        const formData = new FormData(form);

        // Валидация имени пользователя
        const username = formData.get('username').trim();
        if (!username || !/^[a-zA-Z0-9_]+$/.test(username)) {
            alert('Имя пользователя может содержать только латинские буквы, цифры и подчеркивание');
            return;
        }

        // Генерируем ключи перед созданием пользователя
        let keys = null;
        try {
            // Показываем индикатор генерации ключей
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalHTML = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Генерация ключей...';

            // Генерируем ключи
            try {
                keys = await api.generateKeys();
            } catch (apiError) {
                // Если API недоступен, генерируем на клиенте
                console.log('API недоступен, генерируем ключи на клиенте');
                keys = await this.generateKeysClientSide();
            }

            if (!keys || !keys.privateKey) {
                throw new Error('Не удалось сгенерировать ключи');
            }

            // Показываем превью ключей
            this.showKeyPreview(keys);

            // Подготавливаем данные пользователя
            const userData = {
                username: username,
                email: formData.get('email') || null,
                trafficLimit: parseFloat(formData.get('trafficLimit')) || 0,
                expiryDate: formData.get('expiryDate') || null,
                // Whispera-specific settings
                obfsProfile: formData.get('obfsProfile') || 'http2',
                marionetteProfile: formData.get('marionetteProfile') || 'browser',
                autoProfile: formData.get('autoProfile') === 'on',
                russianService: 'vk', // Default for Whispera
                appProfile: 'browser',
                // Ключи - сохраняем полностью, без обрезания
                privateKey: keys.privateKey ? keys.privateKey.trim() : '',
                publicKey: keys.publicKey ? keys.publicKey.trim() : null
            };

            // Обновляем UI
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Создание пользователя...';

            // Создаем пользователя
            const result = await api.addUser(userData);

            this.showSuccessMessage(`Пользователь "${username}" успешно создан!`);
            this.closeModal();
            form.reset();
            this.hideKeyPreview();
            await this.loadUsers();

            // Восстанавливаем кнопку
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalHTML;
        } catch (error) {
            console.error('Ошибка создания пользователя:', error);
            alert('Ошибка создания пользователя: ' + error.message);

            // Восстанавливаем кнопку
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fas fa-plus"></i> Создать пользователя';
            }
        }
    }

    showKeyPreview(keys) {
        const previewSection = document.getElementById('keyPreviewSection');
        const privateKeyPreview = document.getElementById('previewPrivateKey');
        const publicKeyPreview = document.getElementById('previewPublicKey');

        if (previewSection && privateKeyPreview) {
            previewSection.style.display = 'block';
            privateKeyPreview.textContent = keys.privateKey || 'Не сгенерирован';

            if (publicKeyPreview) {
                publicKeyPreview.textContent = keys.publicKey || 'Будет вычислен на сервере';
            }

            // Прокручиваем к превью
            previewSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    hideKeyPreview() {
        const previewSection = document.getElementById('keyPreviewSection');
        if (previewSection) {
            previewSection.style.display = 'none';
        }
    }

    downloadConfig() {
        const content = document.getElementById('clientConfigYAML').value;
        const username = document.getElementById('configUsername').value;

        // Определяем расширение файла и MIME тип в зависимости от формата
        const extension = this.currentConfigFormat === 'json' ? 'json' : 'yaml';
        const mimeType = this.currentConfigFormat === 'json' ? 'application/json' : 'text/yaml';
        const filename = this.currentConfigFormat === 'json'
            ? 'appsettings.json'
            : `whispera-client-${username || 'config'}.yaml`;

        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);

        // Показываем уведомление
        this.showSuccessMessage(`Конфигурация ${filename} скачана успешно!`);
    }

    copyConfigToClipboard() {
        const content = document.getElementById('clientConfigYAML').value;
        navigator.clipboard.writeText(content).then(() => {
            this.showSuccessMessage('Конфигурация скопирована в буфер обмена!');
        }).catch(err => {
            console.error('Ошибка копирования:', err);
            alert('Не удалось скопировать конфигурацию. Попробуйте выделить текст вручную.');
        });
    }

    // Генерация ключей клиента
    async generateClientKeys() {
        try {
            // Показываем индикатор загрузки
            const generateBtn = event.target.closest('button');
            const originalHTML = generateBtn.innerHTML;
            generateBtn.disabled = true;
            generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Генерация...';

            // Генерируем ключи через API
            let keys;
            try {
                keys = await api.generateKeys();
            } catch (apiError) {
                // Если API недоступен, генерируем ключи на клиенте
                console.log('API недоступен, генерируем ключи на клиенте');
                keys = await this.generateKeysClientSide();
            }

            if (keys && keys.privateKey) {
                // Обновляем поля в форме
                // Сохраняем полный ключ (64 символа)
                const fullKey = keys.privateKey ? keys.privateKey.trim() : '';
                document.getElementById('clientPrivateKey').value = fullKey;
                console.log('Generated private key length:', fullKey.length);

                // Если есть публичный ключ, показываем его
                if (keys.publicKey) {
                    const publicKeyGroup = document.getElementById('clientPublicKeyGroup');
                    const publicKeyInput = document.getElementById('clientPublicKey');
                    if (publicKeyGroup && publicKeyInput) {
                        publicKeyGroup.style.display = 'block';
                        publicKeyInput.value = keys.publicKey;
                    }
                }

                // Обновляем текущего пользователя с новым ключом
                if (this.currentConfigUser) {
                    this.currentConfigUser.privateKey = keys.privateKey;
                    if (keys.publicKey) {
                        this.currentConfigUser.publicKey = keys.publicKey;
                    }
                }

                // Перегенерируем конфигурацию с новым ключом
                this.updateConfigYAML();

                this.showSuccessMessage('Ключи успешно сгенерированы!');
            } else {
                throw new Error('Не удалось получить ключи');
            }

            // Восстанавливаем кнопку
            generateBtn.disabled = false;
            generateBtn.innerHTML = originalHTML;
        } catch (error) {
            console.error('Ошибка генерации ключей:', error);
            alert('Ошибка генерации ключей: ' + error.message);

            // Восстанавливаем кнопку
            const generateBtn = event.target.closest('button');
            if (generateBtn) {
                generateBtn.disabled = false;
                generateBtn.innerHTML = '<i class="fas fa-key"></i> Генерировать';
            }
        }
    }

    // Генерация ключей на клиенте (fallback если API недоступен)
    async generateKeysClientSide() {
        // Используем Web Crypto API для генерации ключей
        try {
            // Генерируем приватный ключ (32 байта)
            const privateKeyBytes = new Uint8Array(32);
            crypto.getRandomValues(privateKeyBytes);

            // Конвертируем в hex
            const privateKeyHex = Array.from(privateKeyBytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');

            // Пытаемся вычислить публичный ключ через API сервера
            let publicKeyHex = null;
            try {
                const derived = await api.derivePublicKey(privateKeyHex);
                if (derived && derived.publicKey) {
                    publicKeyHex = derived.publicKey;
                }
            } catch (deriveError) {
                console.log('Не удалось получить публичный ключ через API, используем только приватный');
            }

            return {
                privateKey: privateKeyHex,
                publicKey: publicKeyHex
            };
        } catch (error) {
            throw new Error('Не удалось сгенерировать ключи: ' + error.message);
        }
    }

    async generateServerKeys() {
        try {
            // Показываем индикатор загрузки
            const generateBtn = event.target.closest('button');
            const originalHTML = generateBtn.innerHTML;
            generateBtn.disabled = true;
            generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Генерация...';

            // Генерируем ключи через API
            let keys;
            try {
                keys = await api.generateServerKeys();
            } catch (apiError) {
                // Если API недоступен, генерируем ключи на клиенте
                console.log('API недоступен, генерируем ключи на клиенте');
                keys = await this.generateKeysClientSide();
            }

            if (keys && keys.publicKey) {
                // Обновляем поле публичного ключа сервера
                document.getElementById('serverPublicKey').value = keys.publicKey;

                // Перегенерируем конфигурацию с новым ключом
                if (this.currentConfigUser) {
                    this.updateConfigYAML();
                }

                this.showSuccessMessage('Ключи сервера успешно сгенерированы!');
            } else {
                throw new Error('Не удалось получить ключи');
            }

            // Восстанавливаем кнопку
            generateBtn.disabled = false;
            generateBtn.innerHTML = originalHTML;
        } catch (error) {
            console.error('Ошибка генерации ключей сервера:', error);
            alert('Ошибка генерации ключей сервера: ' + error.message);

            // Восстанавливаем кнопку
            const generateBtn = event.target.closest('button');
            if (generateBtn) {
                generateBtn.disabled = false;
                generateBtn.innerHTML = '<i class="fas fa-key"></i> Генерировать';
            }
        }
    }

    async generateKeysClientSide() {
        // Fallback for demo mode/client side generation
        // Uses global api helper if available, or simple random logic
        if (api && api.generateMockBase64Key) {
            return {
                privateKey: api.generateMockBase64Key(),
                publicKey: api.generateMockBase64Key()
            };
        }

        // Basic fallback
        const randomBytes = new Uint8Array(32);
        window.crypto.getRandomValues(randomBytes);
        const key = btoa(String.fromCharCode(...randomBytes));
        return {
            privateKey: key,
            publicKey: btoa(String.fromCharCode(...new Uint8Array(32).map(() => Math.floor(Math.random() * 256))))
        };
    }

    async generateUserKey(userId) {
        if (!confirm('Сгенерировать новый ключ для пользователя? Старый ключ перестанет работать.')) {
            return;
        }

        const btn = event.target.closest('button');
        const originalHTML = btn ? btn.innerHTML : '';
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        }

        try {
            // Generate new keys
            let keys;
            try {
                keys = await api.generateKeys();
            } catch (e) {
                keys = await this.generateKeysClientSide();
            }

            if (keys && keys.privateKey) {
                // Update user on server
                const user = this.users.find(u => u.id == userId);
                if (user) {
                    // Update user object with new keys
                    // Note: In a real app we might only send the public key to server if it's wireguard,
                    // but here we simulate updating the "key" (token/private key)
                    await api.updateUser(userId, {
                        ...user,
                        key: keys.privateKey,
                        privateKey: keys.privateKey,
                        publicKey: keys.publicKey
                    });

                    this.showSuccessMessage('Ключ успешно обновлен');
                    await this.loadUsers();
                }
            }
        } catch (error) {
            console.error('Error generating key:', error);
            alert('Ошибка генерации ключа: ' + error.message);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }
    }

    async editUser(id) {
        const user = this.users.find(u => u.id == id);
        if (!user) {
            alert('Пользователь не найден');
            return;
        }

        // Используем модальное окно редактирования
        this.showEditUserModal(id);
    }

    async deleteUser(id) {
        console.log('App: deleteUser called with ID:', id);
        if (!confirm('Вы уверены, что хотите удалить этого пользователя?')) {
            return;
        }

        try {
            await api.deleteUser(id);
            await this.loadUsers();
        } catch (error) {
            alert('Ошибка удаления пользователя: ' + error.message);
        }
    }

    async killSession(id) {
        try {
            await api.killSession(id);
            await this.loadSessions();
        } catch (error) {
            alert('Ошибка отключения сессии: ' + error.message);
        }
    }

    startAutoRefresh() {
        // Обновляем данные каждые 30 секунд
        setInterval(() => {
            if (this.currentPage === 'dashboard') {
                this.loadDashboard();
            } else if (this.currentPage === 'sessions') {
                this.loadSessions();
            } else if (this.currentPage === 'stats') {
                this.loadTrafficStats();
            } else if (this.currentPage === 'adblock') {
                this.loadAdblockStats();
            }
        }, 30000);
    }

    // AdBlocker methods
    async loadAdblockStats() {
        try {
            const stats = await api.getAdblockStats();

            // Обновляем статистику
            document.getElementById('adblockTotalBlocked').textContent = stats.total_blocked || 0;
            document.getElementById('adblockDNSBlocked').textContent = stats.dns_blocked || 0;
            document.getElementById('adblockHTTPSBlocked').textContent = stats.https_blocked || 0;
            document.getElementById('adblockMLBlocked').textContent = stats.ml_blocked || 0;

            // Загружаем правила
            const rules = await api.getAdblockRules();
            this.renderAdblockRules(rules);

            // Обновляем статистику по доменам
            if (stats.blocked_domains) {
                this.renderAdblockDomains(stats.blocked_domains);
            }
        } catch (error) {
            console.error('Error loading adblock stats:', error);
            // Показываем фиктивные данные для демонстрации
            document.getElementById('adblockTotalBlocked').textContent = '0';
            document.getElementById('adblockDNSBlocked').textContent = '0';
            document.getElementById('adblockHTTPSBlocked').textContent = '0';
            document.getElementById('adblockMLBlocked').textContent = '0';
        }
    }

    renderAdblockRules(rules) {
        const tbody = document.getElementById('adblockRulesTableBody');
        if (!tbody) return;

        if (!rules || rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem;">Нет правил</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(rule => `
            <tr>
                <td><strong>${rule.domain || rule.url || rule.pattern || '-'}</strong></td>
                <td><span class="badge badge-${rule.type === 'dns' ? 'blue' : rule.type === 'https' ? 'purple' : 'orange'}">${rule.type || 'both'}</span></td>
                <td>
                    <span class="badge ${rule.enabled ? 'badge-success' : 'badge-secondary'}">
                        ${rule.enabled ? 'Включено' : 'Выключено'}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="app.removeAdblockRule('${rule.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    renderAdblockDomains(domains) {
        const tbody = document.getElementById('adblockDomainsTableBody');
        if (!tbody) return;

        if (!domains || Object.keys(domains).length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; padding: 2rem;">Нет данных</td></tr>';
            return;
        }

        const sortedDomains = Object.entries(domains)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20); // Топ 20

        tbody.innerHTML = sortedDomains.map(([domain, count]) => `
            <tr>
                <td><strong>${domain}</strong></td>
                <td>${count}</td>
            </tr>
        `).join('');
    }

    async saveAdblockSettings() {
        try {
            const settings = {
                enabled: document.getElementById('adblockEnabled')?.checked || false,
                dnsEnabled: document.getElementById('adblockDNSEnabled')?.checked || false,
                httpsEnabled: document.getElementById('adblockHTTPSEnabled')?.checked || false,
                mlEnabled: document.getElementById('adblockMLEnabled')?.checked || false
            };

            await api.updateAdblockSettings(settings);
            this.showSuccessMessage('Настройки блокировщика рекламы сохранены!');
        } catch (error) {
            alert('Ошибка сохранения настроек: ' + error.message);
        }
    }

    showAddRuleModal() {
        const domain = prompt('Введите домен или URL для блокировки:');
        if (!domain) return;

        const type = prompt('Выберите тип блокировки (dns, https, both):', 'both');
        if (!type) return;

        this.addAdblockRule({
            domain: domain,
            type: type,
            enabled: true
        });
    }

    async addAdblockRule(rule) {
        try {
            await api.addAdblockRule(rule);
            this.showSuccessMessage('Правило добавлено!');
            await this.loadAdblockStats();
        } catch (error) {
            alert('Ошибка добавления правила: ' + error.message);
        }
    }

    async removeAdblockRule(ruleId) {
        if (!confirm('Удалить это правило?')) return;

        try {
            await api.removeAdblockRule(ruleId);
            this.showSuccessMessage('Правило удалено!');
            await this.loadAdblockStats();
        } catch (error) {
            alert('Ошибка удаления правила: ' + error.message);
        }
    }

    // Quick Connect методы
    copyQuickConnectKey() {
        const privateKeyInput = document.getElementById('clientPrivateKey');
        const privateKey = privateKeyInput?.value?.trim() || '';
        if (!privateKey || privateKey === 'NOT_GENERATED') {
            alert('Сначала сгенерируйте ключ клиента!');
            return;
        }

        // Проверяем длину ключа
        if (privateKey.length < 32) {
            alert(`Внимание: ключ слишком короткий (${privateKey.length} символов). Должно быть 64 символа для x25519.`);
        }

        // Получаем URL сервера
        const serverUrl = window.location.origin;
        const serverIP = document.getElementById('serverIP')?.value || 'YOUR_SERVER_IP';

        // Копируем полный ключ в буфер обмена
        if (navigator.clipboard) {
            navigator.clipboard.writeText(privateKey).then(() => {
                this.showSuccessMessage('Ключ скопирован в буфер обмена!');

                // Показываем информацию о Quick Connect
                const infoDiv = document.getElementById('quickConnectInfo');
                const urlSpan = document.getElementById('quickConnectServerUrl');
                if (infoDiv && urlSpan) {
                    urlSpan.textContent = serverUrl;
                    infoDiv.style.display = 'block';
                }
            }).catch(err => {
                console.error('Failed to copy:', err);
                alert('Не удалось скопировать ключ. Скопируйте вручную из поля выше.');
            });
        } else {
            // Fallback для старых браузеров
            const textArea = document.createElement('textarea');
            textArea.value = privateKey;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                this.showSuccessMessage('Ключ скопирован в буфер обмена!');
            } catch (err) {
                alert('Не удалось скопировать ключ. Скопируйте вручную из поля выше.');
            }
            document.body.removeChild(textArea);
        }
    }

    showQuickConnectInstructions() {
        const instructions = `
Инструкция по быстрому подключению (Quick Connect):

1. Откройте Whispera Client (Tauri)
2. Перейдите на главную страницу
3. Найдите поле "Быстрое подключение"
4. Вставьте скопированный ключ в формате:
   whispera://server:port?pub=...&key=...
5. Нажмите "Подключиться по ключу"

Все настройки будут загружены автоматически через API!

Формат ключа:
whispera://IP_СЕРВЕРА:ПОРТ?pub=ПУБЛИЧНЫЙ_КЛЮЧ&key=ПРИВАТНЫЙ_КЛЮЧ

Ключ можно скопировать из модального окна Quick Connect.
        `;

        alert(instructions);
    }

    // Показать модальное окно Quick Connect для пользователя
    async showQuickConnectModal(userId) {
        const user = this.users.find(u => u.id == userId);
        if (!user || !user.privateKey) {
            alert('У пользователя нет ключа подключения');
            return;
        }

        const modal = document.getElementById('quickConnectModal');
        if (!modal) {
            alert('Модальное окно не найдено');
            return;
        }

        const privateKey = user.privateKey.trim();

        // Получаем информацию о сервере из API
        let serverIP = 'YOUR_SERVER_IP';
        let serverPort = 8443;
        let serverPubKey = '';

        try {
            const systemInfo = await api.getSystemInfo();
            serverIP = systemInfo.server_ip || systemInfo.serverIP || 'YOUR_SERVER_IP';
            serverPort = systemInfo.server_port || systemInfo.serverPort || 51820;
            serverPubKey = systemInfo.server_pub || systemInfo.serverPublicKey || '';

            // Если IP не найден, пытаемся извлечь из hostname
            if (serverIP === 'YOUR_SERVER_IP' || !serverIP) {
                const hostname = window.location.hostname;
                if (hostname && hostname !== 'localhost' && hostname !== '127.0.0.1' &&
                    !hostname.startsWith('192.168.') && !hostname.startsWith('10.')) {
                    serverIP = hostname;
                }
            }
        } catch (error) {
            console.error('Ошибка получения информации о сервере:', error);
            // Используем значения по умолчанию
            const hostname = window.location.hostname;
            if (hostname && hostname !== 'localhost' && hostname !== '127.0.0.1') {
                serverIP = hostname;
            }
        }

        // Формируем URL в формате whispera://server:port?pub=...&key=...
        const quickConnectUrl = this.generateQuickConnectUrl(serverIP, serverPort, serverPubKey, privateKey);
        const serverUrl = `${serverIP}:${serverPort}`;

        document.getElementById('quickConnectPrivateKey').value = privateKey;
        document.getElementById('quickConnectServerUrl').value = serverUrl;
        document.getElementById('quickConnectFullUrl').value = quickConnectUrl;

        // Показываем модальное окно
        modal.style.display = 'block';

        // Закрытие по клику вне модального окна
        window.onclick = (event) => {
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        };

        // Закрытие по кнопке
        const closeButtons = modal.querySelectorAll('.modal-close, .modal-cancel');
        closeButtons.forEach(btn => {
            btn.onclick = () => {
                modal.style.display = 'none';
            };
        });
    }

    // Генерация URL для Quick Connect в формате whispera://server:port?pub=...&key=...
    generateQuickConnectUrl(serverIP, serverPort, serverPubKey, privateKey) {
        // Кодируем параметры для URL
        const params = new URLSearchParams();
        if (serverPubKey) {
            params.set('pub', serverPubKey);
        }
        if (privateKey) {
            params.set('key', privateKey);
        }

        // Add default parameters for better connectivity and evasion
        params.set('transport', 'tcp');
        params.set('phantom', '1');
        params.set('sni', 'random_ru');
        params.set('asn', '1');
        params.set('tls', 'chrome');

        // Формируем URL в формате whispera://server:port?pub=...&key=...
        const url = `whispera://${serverIP}:${serverPort}?${params.toString()}`;
        return url;
    }

    // Копировать приватный ключ из модального окна
    copyQuickConnectKeyFromModal() {
        const keyInput = document.getElementById('quickConnectPrivateKey');
        if (!keyInput || !keyInput.value) {
            alert('Ключ не найден');
            return;
        }

        this.copyToClipboard(keyInput.value, 'Приватный ключ скопирован!');
    }

    // Копировать URL сервера
    copyServerUrl() {
        const urlInput = document.getElementById('quickConnectServerUrl');
        if (!urlInput || !urlInput.value) {
            alert('URL сервера не найден');
            return;
        }

        this.copyToClipboard(urlInput.value, 'URL сервера скопирован!');
    }

    // Копировать полную строку Quick Connect
    copyQuickConnectFullUrl() {
        const fullUrlInput = document.getElementById('quickConnectFullUrl');
        if (!fullUrlInput || !fullUrlInput.value) {
            alert('Строка подключения не найдена');
            return;
        }

        this.copyToClipboard(fullUrlInput.value, 'Строка Quick Connect скопирована! Вставьте её в клиент.');
    }

    // Копировать ключ пользователя
    copyUserKey(userId) {
        const user = this.users.find(u => u.id == userId);
        if (!user || !user.privateKey) {
            alert('У пользователя нет ключа подключения');
            return;
        }

        this.copyToClipboard(user.privateKey, 'Ключ скопирован в буфер обмена!');
    }

    // Сгенерировать ключ для пользователя
    async generateUserKey(userId) {
        if (!confirm('Сгенерировать новый ключ для этого пользователя? Старый ключ будет заменён.')) {
            return;
        }

        try {
            const keys = await api.generateKeys();
            if (!keys || !keys.privateKey) {
                throw new Error('Не удалось сгенерировать ключи');
            }

            const user = this.users.find(u => u.id == userId);
            if (!user) {
                throw new Error('Пользователь не найден');
            }

            // Обновляем пользователя с новым ключом
            const updatedUser = {
                ...user,
                privateKey: keys.privateKey.trim(),
                publicKey: keys.publicKey ? keys.publicKey.trim() : null
            };

            await api.updateUser(userId, updatedUser);
            this.showSuccessMessage('Ключ успешно сгенерирован и сохранён!');

            // Перезагружаем список пользователей
            await this.loadUsers();
        } catch (error) {
            this.showErrorMessage('Ошибка при генерации ключа: ' + error.message);
        }
    }

    // Утилита для копирования в буфер обмена
    copyToClipboard(text, successMessage = 'Скопировано!') {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                this.showSuccessMessage(successMessage);
            }).catch(err => {
                console.error('Failed to copy:', err);
                this.fallbackCopyToClipboard(text, successMessage);
            });
        } else {
            this.fallbackCopyToClipboard(text, successMessage);
        }
    }

    // Fallback для старых браузеров
    fallbackCopyToClipboard(text, successMessage) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            this.showSuccessMessage(successMessage);
        } catch (err) {
            alert('Не удалось скопировать. Скопируйте вручную:\n\n' + text);
        }
        document.body.removeChild(textArea);
    }

    // Утилиты
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);

        if (days > 0) return `${days}д ${hours}ч`;
        if (hours > 0) return `${hours}ч ${minutes}м`;
        return `${minutes}м`;
    }

    // Let's Encrypt certificate management
    async checkCertificateStatus() {
        try {
            const statusDiv = document.getElementById('certificateStatus');
            if (!statusDiv) return;

            statusDiv.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Загрузка статуса...';

            const status = await api.getCertificateStatus();

            let statusHTML = '';
            if (status.letsencrypt_available) {
                statusHTML = `
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fas fa-check-circle" style="color: #10b981;"></i>
                        <strong>Let's Encrypt сертификат активен</strong>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem; color: #6b7280;">
                        Тип: ${status.certificate_type || 'letsencrypt'}<br>
                        ${status.domains && status.domains.length > 0 ? `Домены: ${status.domains.join(', ')}<br>` : ''}
                        Путь: ${status.certificate_path || 'N/A'}
                    </div>
                `;
            } else if (status.certificate_exists) {
                statusHTML = `
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fas fa-info-circle" style="color: #3b82f6;"></i>
                        <strong>Самоподписанный сертификат</strong>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem; color: #6b7280;">
                        Используется самоподписанный сертификат. Для доверенного сертификата получите Let's Encrypt.
                    </div>
                `;
            } else {
                statusHTML = `
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fas fa-exclamation-triangle" style="color: #f59e0b;"></i>
                        <strong>Сертификат не найден</strong>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem; color: #6b7280;">
                        Получите Let's Encrypt сертификат для безопасного HTTPS соединения.
                    </div>
                `;
            }

            statusDiv.innerHTML = statusHTML;
            statusDiv.className = 'info-box ' + (status.letsencrypt_available ? 'info-success' : status.certificate_exists ? 'info-info' : 'info-warning');
        } catch (error) {
            const statusDiv = document.getElementById('certificateStatus');
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fas fa-times-circle" style="color: #ef4444;"></i>
                        <strong>Ошибка загрузки статуса</strong>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem; color: #6b7280;">
                        ${error.message || 'Не удалось загрузить статус сертификата'}
                    </div>
                `;
                statusDiv.className = 'info-box info-error';
            }
            console.error('Ошибка проверки статуса сертификата:', error);
        }
    }

    async obtainLetsEncryptCert() {
        const domain = document.getElementById('letsencryptDomain')?.value.trim();
        const email = document.getElementById('letsencryptEmail')?.value.trim();

        if (!domain) {
            this.showErrorMessage('Введите домен для Let\'s Encrypt');
            return;
        }

        // Проверка: домен не должен быть IP адресом
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipRegex.test(domain)) {
            this.showErrorMessage('Ошибка: Введите доменное имя (например, example.com), а не IP адрес. Let\'s Encrypt требует доменное имя.');
            return;
        }

        if (!confirm(`Получить Let's Encrypt сертификат для домена ${domain}?\n\nУбедитесь, что:\n- DNS A запись указывает на этот сервер\n- Порты 80 и 443 открыты\n- Certbot установлен`)) {
            return;
        }

        try {
            this.showSuccessMessage('Запрос на получение сертификата отправлен. Это может занять 1-2 минуты...');

            const result = await api.obtainCertificate(domain, email || `admin@${domain}`);

            if (result.success) {
                this.showSuccessMessage('Получение сертификата запущено. Сервер будет временно остановлен на время генерации. Проверьте статус через 1-2 минуты.');
                // Обновляем статус через 10 секунд
                setTimeout(() => this.checkCertificateStatus(), 10000);
            } else {
                this.showErrorMessage(result.message || result.error || 'Не удалось запустить получение сертификата');
            }
        } catch (error) {
            let errorMessage = 'Ошибка при получении сертификата: ';

            // Парсим сообщение об ошибке
            if (error.message) {
                const msg = error.message.toLowerCase();
                if (msg.includes('ip address') || msg.includes('domain name')) {
                    errorMessage = 'Ошибка: Введите доменное имя (например, example.com), а не IP адрес.';
                } else if (msg.includes('dns') || msg.includes('localhost')) {
                    errorMessage = 'Ошибка DNS: Убедитесь, что DNS A запись для домена указывает на IP этого сервера, а не на localhost.';
                } else if (msg.includes('certbot') || msg.includes('not installed')) {
                    errorMessage = 'Ошибка: Certbot не установлен. Установите его командой: apt-get install certbot';
                } else if (msg.includes('port') || msg.includes('80')) {
                    errorMessage = 'Ошибка: Порт 80 занят или недоступен. Убедитесь, что порт 80 свободен для certbot.';
                } else {
                    errorMessage += error.message;
                }
            } else {
                errorMessage += String(error);
            }

            this.showErrorMessage(errorMessage);
            console.error('Ошибка получения сертификата:', error);
        }
    }

    async renewLetsEncryptCert() {
        if (!confirm('Обновить Let\'s Encrypt сертификат?\n\nЭто может занять несколько минут.')) {
            return;
        }

        try {
            this.showSuccessMessage('Запрос на обновление сертификата отправлен...');

            const result = await api.renewCertificate();

            if (result.success) {
                this.showSuccessMessage('Обновление сертификата запущено. Проверьте статус через несколько минут.');
                // Обновляем статус через 5 секунд
                setTimeout(() => this.checkCertificateStatus(), 5000);
            } else {
                this.showErrorMessage(result.message || 'Не удалось запустить обновление сертификата');
            }
        } catch (error) {
            this.showErrorMessage('Ошибка при обновлении сертификата: ' + (error.message || error));
            console.error('Ошибка обновления сертификата:', error);
        }
    }

    // =============================================
    // ROUTING PAGE METHODS
    // =============================================

    async loadRoutingRules() {
        try {
            const response = await api.getRoutingRules();
            const rules = response.rules || [];
            this.renderRoutingRulesTable(rules);
        } catch (error) {
            console.error('Error loading routing rules:', error);
            this.showErrorMessage('Не удалось загрузить правила маршрутизации');
        }
    }

    renderRoutingRulesTable(rules) {
        const tbody = document.getElementById('routingRulesTableBody');
        if (!tbody) return;

        if (!rules || rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;">Нет правил маршрутизации</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(rule => `
            <tr>
                <td><span class="badge badge-${rule.type === 'domain' ? 'blue' : 'purple'}">${rule.type || 'domain'}</span></td>
                <td><code>${rule.condition || '-'}</code></td>
                <td><strong>${rule.outbound || 'direct'}</strong></td>
                <td>${rule.priority || 0}</td>
                <td>
                    <span class="badge ${rule.enabled ? 'badge-success' : 'badge-secondary'}">
                        ${rule.enabled ? 'Включено' : 'Выключено'}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="app.deleteRoutingRule('${rule.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    showAddRoutingRuleModal() {
        const type = prompt('Выберите тип правила (domain, ip, port, protocol):', 'domain');
        if (!type) return;

        const condition = prompt('Введите условие (например: geosite:ru, geoip:cn, 80, tcp):', '');
        if (!condition) return;

        const outbound = prompt('Выберите outbound (direct, proxy, block):', 'direct');
        if (!outbound) return;

        const priority = parseInt(prompt('Приоритет (0-100, меньше = выше):', '10')) || 10;

        this.addRoutingRule({
            type: type,
            condition: condition,
            outbound: outbound,
            priority: priority,
            enabled: true
        });
    }

    async addRoutingRule(rule) {
        try {
            await api.addRoutingRule(rule);
            this.showSuccessMessage('Правило маршрутизации добавлено!');
            await this.loadRoutingRules();
        } catch (error) {
            this.showErrorMessage('Ошибка добавления правила: ' + error.message);
        }
    }

    async deleteRoutingRule(ruleId) {
        if (!confirm('Удалить это правило маршрутизации?')) return;

        try {
            await api.deleteRoutingRule(ruleId);
            this.showSuccessMessage('Правило удалено!');
            await this.loadRoutingRules();
        } catch (error) {
            this.showErrorMessage('Ошибка удаления правила: ' + error.message);
        }
    }

    // =============================================
    // SUBSCRIPTIONS PAGE METHODS
    // =============================================

    async loadSubscriptions() {
        try {
            const response = await api.getSubscriptions();
            const subscriptions = response.subscriptions || [];
            this.renderSubscriptionsTable(subscriptions);
        } catch (error) {
            console.error('Error loading subscriptions:', error);
            this.showErrorMessage('Не удалось загрузить подписки');
        }
    }

    renderSubscriptionsTable(subscriptions) {
        const tbody = document.getElementById('subscriptionsTableBody');
        if (!tbody) return;

        if (!subscriptions || subscriptions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 2rem;">Нет подписок</td></tr>';
            return;
        }

        tbody.innerHTML = subscriptions.map(sub => `
            <tr>
                <td><strong>${sub.name || '-'}</strong></td>
                <td><code style="font-size: 0.85rem;">${this.truncateUrl(sub.url) || '-'}</code></td>
                <td>${sub.interval || '-'}</td>
                <td>${sub.lastUpdate ? new Date(sub.lastUpdate).toLocaleString() : 'Никогда'}</td>
                <td>${sub.serverCount || 0}</td>
                <td>
                    <span class="badge ${sub.enabled ? 'badge-success' : 'badge-secondary'}">
                        ${sub.enabled ? 'Активна' : 'Отключена'}
                    </span>
                </td>
                <td>
                    <div style="display: flex; gap: 0.25rem;">
                        <button class="btn btn-sm btn-secondary" onclick="app.refreshSubscription('${sub.id}')" title="Обновить">
                            <i class="fas fa-sync"></i>
                        </button>
                        <button class="btn btn-sm btn-${sub.enabled ? 'warning' : 'success'}" onclick="app.toggleSubscription('${sub.id}', ${!sub.enabled})" title="${sub.enabled ? 'Отключить' : 'Включить'}">
                            <i class="fas fa-${sub.enabled ? 'pause' : 'play'}"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="app.deleteSubscription('${sub.id}')" title="Удалить">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    truncateUrl(url, maxLength = 40) {
        if (!url) return '';
        if (url.length <= maxLength) return url;
        return url.substring(0, maxLength) + '...';
    }

    showAddSubscriptionModal() {
        const name = prompt('Название подписки:', '');
        if (!name) return;

        const url = prompt('URL подписки:', '');
        if (!url) return;

        const interval = prompt('Интервал обновления (6h, 12h, 24h, 7d):', '24h');

        this.addSubscription({
            name: name,
            url: url,
            interval: interval || '24h',
            enabled: true
        });
    }

    async addSubscription(subscription) {
        try {
            await api.addSubscription(subscription);
            this.showSuccessMessage('Подписка добавлена!');
            await this.loadSubscriptions();
        } catch (error) {
            this.showErrorMessage('Ошибка добавления подписки: ' + error.message);
        }
    }

    async refreshSubscription(subId) {
        try {
            await api.updateSubscription(subId, {});
            this.showSuccessMessage('Подписка обновлена!');
            await this.loadSubscriptions();
        } catch (error) {
            this.showErrorMessage('Ошибка обновления подписки: ' + error.message);
        }
    }

    async toggleSubscription(subId, enabled) {
        try {
            await api.enableSubscription(subId, enabled);
            this.showSuccessMessage(enabled ? 'Подписка включена!' : 'Подписка отключена!');
            await this.loadSubscriptions();
        } catch (error) {
            this.showErrorMessage('Ошибка изменения статуса: ' + error.message);
        }
    }

    async deleteSubscription(subId) {
        if (!confirm('Удалить эту подписку?')) return;

        try {
            await api.deleteSubscription(subId);
            this.showSuccessMessage('Подписка удалена!');
            await this.loadSubscriptions();
        } catch (error) {
            this.showErrorMessage('Ошибка удаления подписки: ' + error.message);
        }
    }

    async updateAllSubscriptions() {
        try {
            await api.updateAllSubscriptions();
            this.showSuccessMessage('Все подписки обновлены!');
            await this.loadSubscriptions();
        } catch (error) {
            this.showErrorMessage('Ошибка обновления подписок: ' + error.message);
        }
    }

    // =============================================
    // OUTBOUNDS PAGE METHODS
    // =============================================

    async loadOutbounds() {
        try {
            const response = await api.getOutbounds();
            const outbounds = response.outbounds || [];
            this.renderOutboundsTable(outbounds);
        } catch (error) {
            console.error('Error loading outbounds:', error);
            this.showErrorMessage('Не удалось загрузить серверы');
        }
    }

    renderOutboundsTable(outbounds) {
        const tbody = document.getElementById('outboundsTableBody');
        if (!tbody) return;

        if (!outbounds || outbounds.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 2rem;">Нет серверов</td></tr>';
            return;
        }

        tbody.innerHTML = outbounds.map(out => {
            const latencyClass = out.latency < 50 ? 'success' : out.latency < 100 ? 'warning' : 'danger';
            const availClass = out.availability > 99 ? 'success' : out.availability > 95 ? 'warning' : 'danger';

            return `
                <tr>
                    <td><strong>${out.tag || '-'}</strong></td>
                    <td><code>${out.address || '-'}</code></td>
                    <td><span class="badge badge-blue">${out.protocol || out.type || '-'}</span></td>
                    <td><span class="badge badge-${latencyClass}">${out.latency || 0} ms</span></td>
                    <td><span class="badge badge-${availClass}">${out.availability || 0}%</span></td>
                    <td>
                        <span class="badge ${out.enabled ? 'badge-success' : 'badge-secondary'}">
                            ${out.enabled ? 'Активен' : 'Отключен'}
                        </span>
                    </td>
                    <td>
                        <div style="display: flex; gap: 0.25rem;">
                            ${out.type !== 'direct' && out.type !== 'blackhole' ? `
                                <button class="btn btn-sm btn-secondary" onclick="app.editOutbound('${out.tag}')" title="Редактировать">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-danger" onclick="app.deleteOutbound('${out.tag}')" title="Удалить">
                                    <i class="fas fa-trash"></i>
                                </button>
                            ` : '<span style="color: #9ca3af; font-size: 0.85rem;">Системный</span>'}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    showAddOutboundModal() {
        const tag = prompt('Тег сервера (уникальный идентификатор):', 'proxy-new');
        if (!tag) return;

        const address = prompt('Адрес сервера (host:port):', '');
        if (!address) return;

        const protocol = prompt('Протокол (whispera, vmess, vless, shadowsocks):', 'whispera');

        this.addOutbound({
            tag: tag,
            type: protocol || 'whispera',
            address: address,
            protocol: protocol || 'whispera',
            enabled: true
        });
    }

    async addOutbound(outbound) {
        try {
            await api.addOutbound(outbound);
            this.showSuccessMessage('Сервер добавлен!');
            await this.loadOutbounds();
        } catch (error) {
            this.showErrorMessage('Ошибка добавления сервера: ' + error.message);
        }
    }

    async editOutbound(tag) {
        const address = prompt('Новый адрес сервера:', '');
        if (!address) return;

        try {
            await api.updateOutbound(tag, { address: address });
            this.showSuccessMessage('Сервер обновлен!');
            await this.loadOutbounds();
        } catch (error) {
            this.showErrorMessage('Ошибка обновления сервера: ' + error.message);
        }
    }

    async deleteOutbound(tag) {
        if (!confirm(`Удалить сервер "${tag}"?`)) return;

        try {
            await api.deleteOutbound(tag);
            this.showSuccessMessage('Сервер удален!');
            await this.loadOutbounds();
        } catch (error) {
            this.showErrorMessage('Ошибка удаления сервера: ' + error.message);
        }
    }

    // =============================================
    // GEO PAGE METHODS
    // =============================================

    async loadGeoStatus() {
        try {
            const status = await api.getGeoStatus();

            // Update status cards
            const geoIPStatus = document.getElementById('geoIPStatus');
            const geoSiteStatus = document.getElementById('geoSiteStatus');
            const geoLastUpdate = document.getElementById('geoLastUpdate');

            if (geoIPStatus) {
                geoIPStatus.textContent = status.geoip?.loaded ?
                    `${(status.geoip.entries || 0).toLocaleString()} записей` : 'Не загружена';
            }
            if (geoSiteStatus) {
                geoSiteStatus.textContent = status.geosite?.loaded ?
                    `${(status.geosite.entries || 0).toLocaleString()} записей` : 'Не загружена';
            }
            if (geoLastUpdate) {
                geoLastUpdate.textContent = status.lastUpdate ?
                    new Date(status.lastUpdate).toLocaleDateString() : 'Неизвестно';
            }

            // Update paths and sizes
            const geoIPPath = document.getElementById('geoIPPath');
            const geoSitePath = document.getElementById('geoSitePath');
            const geoIPSize = document.getElementById('geoIPSize');
            const geoSiteSize = document.getElementById('geoSiteSize');
            const autoUpdateCheckbox = document.getElementById('geoAutoUpdateEnabled');

            if (geoIPPath) geoIPPath.value = status.geoip?.path || '/etc/whispera/geoip.dat';
            if (geoSitePath) geoSitePath.value = status.geosite?.path || '/etc/whispera/geosite.dat';
            if (geoIPSize) geoIPSize.value = status.geoip?.size || '-';
            if (geoSiteSize) geoSiteSize.value = status.geosite?.size || '-';
            if (autoUpdateCheckbox) autoUpdateCheckbox.checked = status.autoUpdate !== false;

        } catch (error) {
            console.error('Error loading geo status:', error);
            this.showErrorMessage('Не удалось загрузить статус Geo баз');
        }
    }

    async updateGeoDatabases() {
        if (!confirm('Загрузить обновленные Geo базы данных с сервера? Это может занять несколько минут.')) return;

        try {
            await api.updateGeoDatabases();
            this.showSuccessMessage('Geo базы данных обновлены!');
            await this.loadGeoStatus();
        } catch (error) {
            this.showErrorMessage('Ошибка обновления Geo баз: ' + error.message);
        }
    }

    async reloadGeoDatabases() {
        try {
            await api.reloadGeoDatabases();
            this.showSuccessMessage('Geo базы данных перезагружены!');
            await this.loadGeoStatus();
        } catch (error) {
            this.showErrorMessage('Ошибка перезагрузки Geo баз: ' + error.message);
        }
    }

    async updateGeoSettings() {
        try {
            const autoUpdate = document.getElementById('geoAutoUpdateEnabled')?.checked || false;

            await api.updateGeoSettings({
                autoUpdate: autoUpdate
            });

            this.showSuccessMessage('Настройки Geo сохранены!');
        } catch (error) {
            this.showErrorMessage('Ошибка сохранения настроек: ' + error.message);
        }
    }

    // =============================================
    // EDIT USER MODAL
    // =============================================

    showEditUserModal(userId) {
        const user = this.users.find(u => u.id == userId);
        if (!user) {
            this.showErrorMessage('Пользователь не найден');
            return;
        }

        // Create modal content dynamically or show existing modal
        const username = prompt('Имя пользователя:', user.username || '');
        if (username === null) return; // Cancelled

        const trafficLimit = prompt('Лимит трафика (GB, 0 = безлимит):',
            user.trafficLimit ? (user.trafficLimit / 1073741824).toFixed(2) : '0');
        if (trafficLimit === null) return;

        const expiryDate = prompt('Срок действия (YYYY-MM-DD, пусто = бессрочно):',
            user.expiryDate ? user.expiryDate.split('T')[0] : '');

        this.updateUserData(userId, {
            username: username || user.username,
            trafficLimit: trafficLimit ? parseFloat(trafficLimit) * 1073741824 : 0,
            expiryDate: expiryDate || null
        });
    }

    async updateUserData(userId, userData) {
        try {
            const user = this.users.find(u => u.id == userId);
            if (!user) throw new Error('Пользователь не найден');

            await api.updateUser(userId, { ...user, ...userData });
            this.showSuccessMessage('Пользователь обновлен!');
            await this.loadUsers();
        } catch (error) {
            this.showErrorMessage('Ошибка обновления пользователя: ' + error.message);
        }
    }
}

// Вспомогательная функция для копирования в буфер обмена
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');

    // Визуальная обратная связь
    const btn = event.target.closest('button');
    const originalHTML = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i>';
    btn.classList.add('btn-success');
    setTimeout(() => {
        btn.innerHTML = originalHTML;
        btn.classList.remove('btn-success');
    }, 2000);
}


// Инициализация приложения
// Инициализация приложения
// Делаем app глобальным для доступа из onclick обработчиков в HTML
window.onerror = function (msg, url, line, col, error) {
    alert("GLOBAL ERROR: " + msg + "\nAt: " + url + ":" + line);
};

window.app = null;
document.addEventListener('DOMContentLoaded', async () => {
    console.log('DOMContentLoaded fired');
    try {
        window.app = new WhisperaApp();
        console.log('App instantiated');
    } catch (e) {
        alert('CRITICAL: App instantiation failed: ' + e.message);
    }
});

