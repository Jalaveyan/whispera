
class ThreeCity {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;

        const EffectComposer = THREE.EffectComposer || window.EffectComposer;
        const RenderPass = THREE.RenderPass || window.RenderPass;
        const UnrealBloomPass = THREE.UnrealBloomPass || window.UnrealBloomPass;

        if (!EffectComposer || !RenderPass) {
            console.error("❌ Three.js Post-processing classes MISSING!");
        }

        this.renderer = new THREE.WebGLRenderer({
            canvas: this.canvas,
            antialias: true,
            canvas: this.canvas,
            antialias: true,
            alpha: true
        });

        this.scene = new THREE.Scene();
        this.scene.background = null;
        this.camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 10000);
        this.camera.position.set(0, 300, 1000);

        this.composer = null;
        this.clock = new THREE.Clock();
        this.buildings = [];
        this.mouse = { x: 0, y: 0 };
        this.cameraTarget = new THREE.Vector3(0, 300, -3000);
        this.currentPage = 'dashboard';

        this.init(EffectComposer, RenderPass, UnrealBloomPass);
        console.log("🏙️ Whispera ThreeCity Engine: Started");
        if (this.scene) console.log("🏙️ Scene objects:", this.scene.children.length);
    }

    init(EffectComposer, RenderPass, UnrealBloomPass) {
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
        this.renderer.toneMappingExposure = 1.2;

        try {
            const renderScene = new RenderPass(this.scene, this.camera);
            this.bloomPass = new UnrealBloomPass(
                new THREE.Vector2(window.innerWidth, window.innerHeight),
                1.5, 0.4, 0.85
            );
            this.bloomPass.threshold = 0.1;
            this.bloomPass.strength = 1.5;
            this.bloomPass.radius = 0.8;

            this.composer = new EffectComposer(this.renderer);
            this.composer.addPass(renderScene);
            this.composer.addPass(this.bloomPass);
            console.log("✅ EffectComposer initialized (Tuned)");
        } catch (e) {
            console.error("❌ EffectComposer failed:", e);
            this.composer = null;
        }

        this.scene.add(new THREE.AmbientLight(0xffffff, 0.1));

        const mainLight = new THREE.DirectionalLight(0x00f2ff, 1.0);
        mainLight.position.set(100, 500, 200);
        this.scene.add(mainLight);

        const pinkLight = new THREE.DirectionalLight(0xff00c1, 1.5);
        pinkLight.position.set(-100, 200, -500);
        this.scene.add(pinkLight);

        this.createVoxelFloor();
        this.createVoxelCity();
        this.createHoloTable();
        this.createDataRain();
        this.animate();

        window.addEventListener('resize', () => this.onResize());
        window.addEventListener('mousemove', (e) => {
            this.mouse.x = (e.clientX / window.innerWidth - 0.5) * 2;
            this.mouse.y = (e.clientY / window.innerHeight - 0.5) * 2;
        });
    }

    createVoxelFloor() {
        const count = 80000;
        const geometry = new THREE.BufferGeometry();
        const positions = [];
        const colors = [];
        const randoms = [];

        const range = 12000;
        const baseColor = new THREE.Color(0x000d33);
        const tipColor = new THREE.Color(0x00f2ff);

        for (let i = 0; i < count; i++) {
            const x = (Math.random() - 0.5) * range;
            const z = (Math.random() - 0.5) * range;
            const yBase = -200;
            const height = 20 + Math.random() * 40;

            positions.push(x, yBase, z);
            positions.push(x, yBase + height, z);

            colors.push(baseColor.r, baseColor.g, baseColor.b);
            colors.push(tipColor.r, tipColor.g, tipColor.b);

            const r = Math.random();
            randoms.push(r, r);
        }

        geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
        geometry.setAttribute('aRandom', new THREE.Float32BufferAttribute(randoms, 1));

        const vertexShader = `
            attribute float aRandom;
            varying vec3 vColor;
            uniform float time;

            void main() {
                vColor = color;
                vec3 pos = position;
                
                // NO SWAY - Static ticks
                
                gl_Position = projectionMatrix * modelViewMatrix * vec4(pos, 1.0);
            }
        `;

        const fragmentShader = `
            varying vec3 vColor;
            uniform float time;
            
            void main() {
                // Energetic Pulse
                float pulse = sin(time * 5.0) * 0.3 + 0.9;
                gl_FragColor = vec4(vColor * pulse, 1.0);
            }
        `;

        const material = new THREE.ShaderMaterial({
            uniforms: {
                time: { value: 0 }
            },
            vertexShader: vertexShader,
            fragmentShader: fragmentShader,
            vertexColors: true,
            transparent: true,
            opacity: 0.8,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });

        this.floor = new THREE.LineSegments(geometry, material);
        this.scene.add(this.floor);
        this.floorMaterial = material;
    }

    createTextTexture(text, color = 'white') {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = 2048;
        canvas.height = 512;

        ctx.font = 'bold 100px "Segoe UI", Arial, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        ctx.shadowColor = color;
        ctx.shadowBlur = 0;

        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;

        ctx.lineWidth = 15;
        ctx.strokeStyle = 'black';
        ctx.strokeText(text, centerX, centerY);

        ctx.fillStyle = color;
        ctx.fillText(text, centerX, centerY);

        const texture = new THREE.CanvasTexture(canvas);
        texture.needsUpdate = true;
        return texture;
    }


    createHoloTable() {
        const tableGroup = new THREE.Group();
        tableGroup.position.set(0, -150, -6000);
        this.scene.add(tableGroup);
        this.holoTable = tableGroup;

        const baseGeo = new THREE.CylinderGeometry(200, 250, 40, 32);
        const baseMat = new THREE.MeshBasicMaterial({
            color: 0x002233,
            wireframe: true,
            transparent: true,
            opacity: 0.5
        });
        const base = new THREE.Mesh(baseGeo, baseMat);
        tableGroup.add(base);

        const coneGeo = new THREE.ConeGeometry(180, 600, 32, 1, true);
        const coneMat = new THREE.ShaderMaterial({
            uniforms: { time: { value: 0 } },
            vertexShader: `
                varying vec2 vUv;
                void main() {
                    vUv = uv;
                    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
                }
            `,
            fragmentShader: `
                varying vec2 vUv;
                uniform float time;
                void main() {
                    // Fade out at top
                    float alpha = (1.0 - vUv.y) * 0.3;
                    // Scanline
                    float scan = sin(vUv.y * 50.0 - time * 5.0) * 0.1;
                    gl_FragColor = vec4(0.0, 1.0, 1.0, alpha + scan);
                }
            `,
            transparent: true,
            side: THREE.DoubleSide,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });
        const cone = new THREE.Mesh(coneGeo, coneMat);
        cone.position.y = 300;
        cone.rotation.x = Math.PI;
        tableGroup.add(cone);
        this.holoConemat = coneMat;

        const screenGeo = new THREE.PlaneGeometry(300, 180);
        const screenMat = new THREE.ShaderMaterial({
            uniforms: { time: { value: 0 } },
            vertexShader: `
                varying vec2 vUv;
                void main() {
                    vUv = uv;
                    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
                }
            `,
            fragmentShader: `
                varying vec2 vUv;
                uniform float time;
                
                float random(vec2 st) {
                    return fract(sin(dot(st.xy, vec2(12.9898,78.233))) * 43758.5453123);
                }

                void main() {
                    // Scrolling Data Lines
                    float scroll = vUv.y + time * 0.2;
                    float lines = step(0.8, random(vec2(0.0, floor(scroll * 20.0))));
                    
                    // Border
                    float border = step(0.95, vUv.x) + step(0.95, 1.0 - vUv.x) + step(0.95, vUv.y) + step(0.95, 1.0 - vUv.y);
                    
                    vec3 color = vec3(0.0, 0.8, 1.0);
                    float alpha = (lines * 0.5 + border) * 0.8;
                    
                    // Flicker
                    alpha *= (0.9 + random(vec2(time, 0.0)) * 0.2);

                    gl_FragColor = vec4(color, alpha);
                }
            `,
            transparent: true,
            side: THREE.DoubleSide,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });

        this.holoScreens = [];
        for (let i = 0; i < 3; i++) {
            const screen = new THREE.Mesh(screenGeo, screenMat);
            const angle = (i / 3) * Math.PI * 2;
            const radius = 250;
            screen.position.set(Math.cos(angle) * radius, 300, Math.sin(angle) * radius);
            screen.lookAt(0, 300, -6000);
            tableGroup.add(screen);
            this.holoScreens.push(screen);
        }
        this.holoScreenMat = screenMat;

        const rknTexture = this.createTextTexture("Сможешь ли ты победить РКН ?", "#ffcc00");
        const rknMat = new THREE.SpriteMaterial({
            map: rknTexture,
            transparent: true,
            opacity: 0,
            blending: THREE.NormalBlending,
            depthTest: true
        });

        this.rknPivot = new THREE.Group();
        this.rknPivot.position.set(0, 300, 0);
        tableGroup.add(this.rknPivot);

        const rknSprite = new THREE.Sprite(rknMat);
        rknSprite.position.set(0, 0, 600);
        rknSprite.scale.set(1200, 300, 1);

        this.rknPivot.add(rknSprite);
        this.rknText = rknSprite;
    }

    createVoxelCity() {
        const buildingCount = 200;
        const particlesPerBuilding = 1500;
        const totalParticles = buildingCount * particlesPerBuilding;

        const positions = [];
        const randoms = [];

        for (let i = 0; i < buildingCount; i++) {
            let bx = (Math.random() - 0.5) * 6000;
            if (Math.abs(bx) < 600) bx += (bx > 0 ? 600 : -600);

            const bz = (Math.random() - 0.5) * 8000;
            const bw = 100 + Math.random() * 200;
            const bh = 400 + Math.random() * 1000;
            const bd = 100 + Math.random() * 200;

            for (let p = 0; p < particlesPerBuilding; p++) {
                const x = bx + (Math.random() - 0.5) * bw;
                const y = -200 + Math.random() * bh;
                const z = bz + (Math.random() - 0.5) * bd;

                positions.push(x, y, z);
                randoms.push(Math.random());
            }
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        geometry.setAttribute('aRandom', new THREE.Float32BufferAttribute(randoms, 1));

        const vertexShader = `
            attribute float aRandom;
            varying float vRand;
            varying vec3 vPos;
            
            void main() {
                vRand = aRandom;
                vPos = position;
                vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
                gl_Position = projectionMatrix * mvPosition;
                gl_PointSize = (5.0 * vRand + 2.0) * (1000.0 / -mvPosition.z);
            }
        `;

        const fragmentShader = `
            uniform float time;
            varying float vRand;
            varying vec3 vPos;
            
            void main() {
                // Height gradient
                float hFn = smoothstep(-200.0, 1000.0, vPos.y);
                
                // Digital "Glitch" flicker
                float flicker = sin(time * 10.0 + vRand * 100.0) * 0.5 + 0.5;
                
                // Scanline Vertical
                float scanY = mod(vPos.y - time * 200.0, 500.0);
                float beam = 1.0 - step(20.0, scanY);
                
                // Color mapping: Dark Blue base, Red highlights
                vec3 baseColor = mix(vec3(0.0, 0.05, 0.2), vec3(0.0, 0.2, 0.4), hFn);
                vec3 glowColor = vec3(1.0, 0.0, 0.2); // Red/Orange
                
                // Mix in red flicker randomly
                if (vRand > 0.9) {
                     baseColor = mix(baseColor, vec3(1.0, 0.0, 0.0), flicker);
                }
                
                vec3 finalColor = mix(baseColor, glowColor, beam);
                float alpha = (0.4 + 0.6 * flicker * beam) * (1.0 - smoothstep(1000.0, 7000.0, length(vPos.xz))); // Fog fade
                
                gl_FragColor = vec4(finalColor, alpha);
            }
        `;

        const material = new THREE.ShaderMaterial({
            uniforms: {
                time: { value: 0 }
            },
            vertexShader: vertexShader,
            fragmentShader: fragmentShader,
            transparent: true,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });

        this.cityPoints = new THREE.Points(geometry, material);
        this.scene.add(this.cityPoints);
        this.cityMaterial = material;

        const reflectionMaterial = material.clone();
        reflectionMaterial.uniforms = { time: { value: 0 } };

        const fragmentShaderReflection = fragmentShader.replace(
            'gl_FragColor = vec4(finalColor, alpha);',
            'gl_FragColor = vec4(finalColor * 0.3, alpha * 0.2);'
        );

        const refMaterial = new THREE.ShaderMaterial({
            uniforms: {
                time: { value: 0 }
            },
            vertexShader: vertexShader,
            fragmentShader: fragmentShaderReflection,
            transparent: true,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });

        this.cityReflection = new THREE.Points(geometry, refMaterial);
        this.cityReflection.position.y = -400;
        this.cityReflection.scale.y = -1;
        this.scene.add(this.cityReflection);
        this.cityRefMaterial = refMaterial;
    }



    createDataRain() {
        const count = 5000;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(count * 3);
        const speeds = new Float32Array(count);
        const colors = new Float32Array(count * 3);

        for (let i = 0; i < count; i++) {
            positions[i * 3] = (Math.random() - 0.5) * 10000;
            positions[i * 3 + 1] = Math.random() * 4000;
            positions[i * 3 + 2] = (Math.random() - 0.5) * 10000;
            speeds[i] = Math.random() * 25 + 10;

            if (Math.random() > 0.8) {
                colors[i * 3] = 1.0;
                colors[i * 3 + 1] = 0.0;
                colors[i * 3 + 2] = 0.2;
            } else {
                colors[i * 3] = 0.0;
                colors[i * 3 + 1] = 0.5 + Math.random() * 0.5;
                colors[i * 3 + 2] = 1.0;
            }
        }

        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            vertexColors: true,
            size: 3,
            transparent: true,
            opacity: 0.6,
            blending: THREE.AdditiveBlending,
            depthWrite: false
        });

        this.rainSystem = new THREE.Points(geometry, material);
        this.rainSpeeds = speeds;
        this.scene.add(this.rainSystem);

        const refMaterial = material.clone();
        refMaterial.opacity = 0.15;
        refMaterial.size = 2;

        this.rainReflection = new THREE.Points(geometry, refMaterial);
        this.rainReflection.position.y = -400;
        this.rainReflection.scale.y = -1;
        this.scene.add(this.rainReflection);
    }

    triggerLightning() {
        const light = new THREE.PointLight(0xffffff, 1000, 10000);
        light.position.set(Math.random() * 4000 - 2000, 2000, -1000);
        this.scene.add(light);

        gsap.to(light, {
            intensity: 0,
            duration: 0.4,
            ease: "power4.out",
            onComplete: () => this.scene.remove(light)
        });
    }

    onResize() {
        this.camera.aspect = window.innerWidth / window.innerHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.composer.setSize(window.innerWidth, window.innerHeight);
    }

    onNavigate(page) {
        this.currentPage = page;


        const zDepths = {
            'dashboard': -5000,
            'users': -4500,
            'sessions': -4000,
            'inbounds': -3500,
            'outbounds': -3000,
            'routing': -2500,
            'subscriptions': -2000,
            'adblock': -1500,
            'settings': -1000,
            'logs': -500
        };

        const targetZ = zDepths[page] !== undefined ? zDepths[page] : 0;

        const targetX = (Math.random() - 0.5) * 200;
        const targetY = 300;

        gsap.to(this.camera.position, {
            x: targetX,
            y: targetY,
            z: targetZ,
            duration: 1.5,
            ease: "power2.inOut"
        });

        gsap.to(this.cameraTarget, {
            x: 0,
            y: 0,
            z: targetZ - 4000,
            duration: 1.5,
            ease: "power2.inOut"
        });
    }

    animate() {
        requestAnimationFrame(() => this.animate());
        const time = this.clock.getElapsedTime();

        this.camera.lookAt(this.cameraTarget);

        if (this.floorMaterial) this.floorMaterial.uniforms.time.value = time;
        if (this.cityMaterial) this.cityMaterial.uniforms.time.value = time;
        if (this.cityRefMaterial) this.cityRefMaterial.uniforms.time.value = time;

        if (this.holoTable) {
            this.holoTable.rotation.y += 0.002;
            if (this.holoConemat) this.holoConemat.uniforms.time.value = time;
            if (this.holoScreenMat) this.holoScreenMat.uniforms.time.value = time;

            if (this.holoScreens) {
                this.holoScreens.forEach((screen, i) => {
                    screen.position.y = 300 + Math.sin(time * 2.0 + i) * 20.0;
                });
            }
        }

        if (this.rknPivot) {
            this.rknPivot.rotation.y -= 0.01;
        }

        const targetOpacity = (this.currentPage === 'users') ? 1.0 : 0.0;
        this.rknText.material.opacity += (targetOpacity - this.rknText.material.opacity) * 0.05;

        if (this.rainSystem) {
            const positions = this.rainSystem.geometry.attributes.position.array;
            for (let i = 0; i < 3000; i++) {
                positions[i * 3 + 1] -= this.rainSpeeds[i];
                if (positions[i * 3 + 1] < -500) {
                    positions[i * 3 + 1] = 4000;
                }
            }
            this.rainSystem.geometry.attributes.position.needsUpdate = true;
        }

        if (this.composer) {
            this.composer.render();
        } else {
            this.renderer.render(this.scene, this.camera);
        }
    }
}

class WhisperaApp {
    constructor() {
        this.threeCity = new ThreeCity('city-canvas');





        this.currentPage = 'dashboard';
        this.translations = {
            ru: {
                "nav.dashboard": "Дашборд",
                "nav.users": "Пользователи",
                "nav.sessions": "Сессии",
                "nav.inbounds": "Входящие",
                "nav.outbounds": "Исходящие",
                "nav.routing": "Маршрутизация",
                "nav.subscriptions": "Подписки",
                "nav.adblock": "Блокировщик",
                "nav.settings": "Настройки",
                "nav.logs": "Логи",
                "nav.logout": "Выход",

                "page.dashboard.title": "Дашборд",
                "dashboard.stats.users": "Пользователи",
                "dashboard.stats.sessions": "Активные сессии",
                "dashboard.stats.upload": "Отправлено",
                "dashboard.stats.download": "Получено",
                "dashboard.traffic.title": "Трафик (МБ/с)",
                "dashboard.server.title": "Информация о сервере",
                "dashboard.server.uptime": "Количество времени в работе",

                "common.save": "Сохранить",
                "common.cancel": "Отмена",
                "common.add": "Добавить",
                "common.create": "Создать",
                "common.delete": "Удалить",
                "common.edit": "Изменить",
                "common.login_desc": "Панель управления",
                "common.login_username": "Логин",
                "common.login_password": "Пароль",
                "common.login_btn": "Войти",
                "common.admin": "Админ",
                "common.role_admin": "Администратор",
                "modal.user.title": "Добавить пользователя",
                "common.add_rule": "Добавить правило",

                "modal.common.tag": "Тег",
                "modal.common.protocol": "Протокол",
                "modal.common.port": "Порт",
                "modal.common.address": "Адрес",
                "modal.common.name": "Название",
                "modal.common.url": "URL",

                "modal.inbound.title": "Добавить входящее подключение",
                "modal.outbound.title": "Добавить сервер",
                "modal.routing.title": "Добавить правило маршрутизации",
                "modal.subscription.title": "Добавить подписку",
                "modal.adblock.title": "Добавить правило блокировки",

                "modal.routing.type": "Тип",
                "modal.routing.value": "Значение (домен или IP)",
                "modal.routing.outbound_tag": "Исходящий тег",
                "modal.routing.option.domain": "Домен",
                "modal.adblock.option.domain": "Домен",
                "modal.adblock.option.keyword": "Ключевое слово",
                "modal.routing.option.ip": "IP",

                "modal.adblock.domain": "Домен",
                "modal.adblock.type": "Тип",

                "settings.title": "Настройки системы",
                "settings.config.title": "Основные настройки",
                "settings.config.port": "Порт подключения пользователей",
                "settings.config.domain": "Основной домен (SNI)",
                "settings.config.email": "Email администратора",
                "settings.config.public_url": "Public URL подписки",
                "settings.config.public_url_hint": "Если задан — IP сервера скрыт в ссылках подписки",
                "settings.config.reload": "Перезагрузить ядро",

                "settings.security.title": "Безопасность и SSL",
                "settings.security.cert": "Сертификат",
                "settings.security.expiry": "Истекает",
                "settings.security.renew": "Обновить сертификат вручную",
                "settings.security.firewall": "Управление Firewall",

                "settings.appearance.title": "Внешний вид",
                "settings.appearance.language": "Язык интерфейса",
                "settings.appearance.theme": "Тема",

                "settings.backup.title": "Резервное копирование",
                "settings.backup.desc": "Скачать полный дамп базы данных и конфигурации.",
                "settings.backup.download": "Скачать Backup",
                "settings.backup.restore": "Восстановить...",

                "settings.admin.title": "Учетная запись администратора",
                "settings.admin.email": "Email (Логин)",
                "settings.admin.password": "Новый пароль",

                "modal.user.obfs": "Профиль обфускации",
                "modal.user.marionette": "Профиль Marionette",
                "modal.user.russian": "Российский сервис",
                "modal.user.traffic.placeholder": "0 = безлимит",
                "modal.user.password.placeholder": "Минимум 8 символов",

                "option.obfs.http2": "HTTP/2 (По умолчанию)",
                "option.obfs.random": "Случайный",
                "option.marionette.browser": "Браузер (По умолчанию)",
                "option.marionette.crawler": "Кроулер",
                "option.russian.vk": "ВКонтакте (По умолчанию)",
                "option.russian.yandex": "Яндекс",
                "option.russian.mailru": "Mail.ru",

                "modal.user.email": "Email",
                "modal.user.password": "Пароль",
                "modal.user.traffic": "Лимит трафика (GB)",
                "modal.user.expiry": "Срок действия",

                "page.users.title": "Пользователи",
                "table.header.email": "Email / Имя",
                "table.header.plan": "Тариф",
                "table.header.traffic": "Трафик",
                "table.header.status": "Статус",
                "table.header.key": "Ключ",
                "table.header.actions": "Действия",
                "table.empty.users": "Нет пользователей",

                "page.sessions.title": "Активные сессии",
                "table.header.sessions.user": "Пользователь",
                "table.header.sessions.ip": "IP клиента",
                "table.header.sessions.connected": "Подключен",
                "table.header.sessions.traffic": "Трафик",
                "table.empty.sessions": "Нет активных сессий",

                "page.inbounds.title": "Входящие подключения",
                "table.header.tag": "Тег",
                "table.header.protocol": "Протокол",
                "table.header.port": "Порт",
                "table.header.transport": "Транспорт",
                "table.empty.inbounds": "Нет входящих подключений",

                "page.outbounds.title": "Исходящие серверы",
                "table.header.type": "Тип",
                "table.header.address": "Адрес",
                "table.header.latency": "Латентность",
                "table.empty.outbounds": "Нет исходящих серверов",

                "page.routing.title": "Маршрутизация",
                "table.header.condition": "Условие",
                "table.header.outbound": "Исходящий",
                "table.header.priority": "Приоритет",
                "table.empty.routing": "Нет правил маршрутизации",

                "page.subscriptions.title": "Подписки",
                "page.subscriptions.update_all": "Обновить все",
                "table.header.name": "Название",
                "table.header.url": "URL",
                "table.header.interval": "Интервал",
                "table.header.count": "Серверов",
                "table.empty.subscriptions": "Нет активных подписок",

                "page.bridges.title": "Мониторинг мостов",
                "page.adblock.title": "Блокировщик рекламы",
                "page.adblock.total": "Всего заблокировано",
                "page.adblock.dns": "DNS",
                "page.adblock.https": "HTTPS",
                "page.adblock.rules": "Правила блокировки",
                "table.header.domain": "Домен/URL",
                "table.header.enabled": "Включено",
                "table.empty.adblock": "Нет правил блокировки",

                "page.logs.title": "Системные логи",
                "page.logs.loading": "Загрузка логов...",

                "common.refresh": "Обновить",
                "common.loading": "Загрузка...",
                "nav.bridges": "Мосты",
                "nav.bridge_map": "Карта мостов",
                "dashboard.stats.memory": "Память",
                "bridges.btn.add": "Добавить мост",
                "bridges.stat.total": "Всего мостов",
                "bridges.stat.alive": "Активных",
                "bridges.stat.dead": "Недоступных",
                "bridges.stat.latency": "Средняя задержка",
                "bridges.table.region": "Регион",
                "bridges.table.latency": "Задержка",
                "bridges.table.trust": "Доверие",
                "bridges.table.last_check": "Последняя проверка",
                "bridges.token.title": "Токен регистрации мостов",
                "bridges.token.desc": "Передайте этот токен при установке нового моста через install-bridge.sh. Мост автоматически зарегистрируется и появится в таблице выше.",
                "bridges.token.new": "Новый токен",
                "bridges.token.curl_hint": "Или зарегистрируйте мост вручную через curl:",
                "settings.stealth.title": "Режим обхода блокировок",
                "settings.stealth.strategy": "Стратегия транспорта",
                "settings.stealth.auto": "Авто (оптимальный)",
                "settings.stealth.russia": "Россия — ВК / Яндекс приоритет",
                "settings.stealth.save": "Сохранить режим",
                "settings.probe.title": "Защита от активного зондирования",
                "settings.probe.blocked": "Заблокировано IP",
                "settings.probe.watching": "Под наблюдением",
                "settings.probe.block_placeholder": "IP для блокировки",
                "settings.probe.block_btn": "Блок",
                "settings.probe.unblock_placeholder": "IP для разблокировки",
                "settings.probe.unblock_btn": "Разблок",
                "settings.appearance.bg": "Фон панели",
                "settings.appearance.upload": "Загрузить",
                "settings.appearance.reset": "Сброс",
                "settings.admin.password.placeholder": "Оставьте пустым, чтобы не менять",
                "modal.bridge.title": "Добавить мост",
                "modal.bridge.address": "Адрес",
                "modal.bridge.region": "Регион",
                "modal.bridge.provider": "Провайдер",
                "modal.bridge.type": "Тип",
                "modal.bridge.pubkey": "Публичный ключ",
                "modal.inbound.transport": "Транспорт",
                "modal.inbound.group.server": "Серверные (работают)",
                "modal.inbound.group.http_quic": "HTTP/QUIC транспорты",
                "modal.inbound.group.public_infra": "Публичная инфраструктура",
                "modal.inbound.group.public_tunnel": "Публичные туннели",
                "modal.inbound.group.social": "VK / OK / Яндекс / Боты",
                "modal.inbound.sni": "SNI (через запятую, пусто = принимать любой)",
                "modal.inbound.sni.hint": "Только для TCP/WS/HTTP. Пустое поле = allowlist отключён.",
                "modal.outbound.multihop": "Multi-hop цепочка",
                "modal.outbound.chain_placeholder": "тег или bridge:id, через запятую",
                "modal.outbound.multihop.desc": "Трафик пройдёт через указанные узлы. Нажмите на мост чтобы добавить в цепочку.",
                "modal.subscription.transports": "Транспорты (через запятую, пусто = все)",
                "modal.user.transport": "Транспорт для ключа",
                "modal.user.transport.hint": "(несколько — гонка)",
                "modal.user.transport.server": "Серверные",
                "modal.user.transport.external": "Внешний сервис",
                "modal.user.transport.bypass": "Обходы",
                "modal.user.port": "Порт (опционально)",
                "modal.user.port.placeholder": "Авто (из inbound)",
                "modal.user.port.hint": "Авто-определяется из inbound по транспорту. Можно изменить — будет открыт в firewall автоматически",
                "modal.user.sni": "SNI (для Phantom/TLS)",
                "modal.user.sni.placeholder": "Авто (из настроек inbound)",
                "modal.user.transport_params": "Параметры транспорта",
                "option.russian.auto": "Авто (не указывать)",
                "option.marionette.group.android": "Мессенджеры (Android)",
                "option.marionette.group.ios": "Мессенджеры (iOS)",
            },
            en: {
                "common.login_desc": "Management panel",
                "common.login_username": "Username",
                "common.login_password": "Password",
                "common.login_btn": "Login",
                "common.admin": "Admin",
                "common.role_admin": "Administrator",
                "nav.dashboard": "Dashboard",
                "nav.users": "Users",
                "nav.sessions": "Sessions",
                "nav.inbounds": "Inbounds",
                "nav.outbounds": "Outbounds",

                "page.dashboard.title": "Dashboard",
                "dashboard.stats.users": "Users",
                "dashboard.stats.sessions": "Active Sessions",
                "dashboard.stats.upload": "Upload",
                "dashboard.stats.download": "Download",
                "dashboard.traffic.title": "Traffic (MB/s)",
                "dashboard.server.title": "Server Information",
                "dashboard.server.uptime": "Uptime",
                "nav.routing": "Routing",
                "nav.subscriptions": "Subscriptions",
                "nav.adblock": "AdBlock",
                "nav.settings": "Settings",
                "nav.logs": "Logs",
                "nav.logout": "Logout",

                "common.save": "Save",
                "common.cancel": "Cancel",
                "common.add": "Add",
                "common.create": "Create",
                "common.delete": "Delete",
                "common.edit": "Edit",

                "modal.user.title": "Add User",
                "common.add_rule": "Add Rule",

                "modal.common.tag": "Tag",
                "modal.common.protocol": "Protocol",
                "modal.common.port": "Port",
                "modal.common.address": "Address",
                "modal.common.name": "Name",
                "modal.common.url": "URL",

                "modal.inbound.title": "Add Inbound",
                "modal.outbound.title": "Add Server",
                "modal.routing.title": "Add Routing Rule",
                "modal.subscription.title": "Add Subscription",
                "modal.adblock.title": "Add Block Rule",

                "modal.routing.type": "Type",
                "modal.routing.value": "Value (domain or IP)",
                "modal.routing.outbound_tag": "Outbound Tag",
                "modal.routing.option.domain": "Domain",
                "modal.adblock.option.domain": "Domain",
                "modal.adblock.option.keyword": "Keyword",
                "modal.routing.option.ip": "IP",

                "modal.adblock.domain": "Domain",
                "modal.adblock.type": "Type",

                "settings.title": "System Settings",
                "settings.config.title": "Server Configuration",
                "settings.config.port": "User Connection Port",
                "settings.config.domain": "Main Domain (SNI)",
                "settings.config.email": "Admin Email",
                "settings.config.public_url": "Subscription Public URL",
                "settings.config.public_url_hint": "If set — server IP is hidden in subscription links",
                "settings.config.reload": "Reload Core",

                "settings.security.title": "Security & SSL",
                "settings.security.cert": "Certificate",
                "settings.security.expiry": "Expires",
                "settings.security.renew": "Renew Certificate Manually",
                "settings.security.firewall": "Manage Firewall",

                "settings.appearance.title": "Appearance",
                "settings.appearance.language": "Interface Language",
                "settings.appearance.theme": "Theme",

                "settings.backup.title": "Backup & Restore",
                "settings.backup.desc": "Download full database and configuration dump.",
                "settings.backup.download": "Download Backup",
                "settings.backup.restore": "Restore...",

                "settings.admin.title": "Administrator Account",
                "settings.admin.email": "Email (Login)",
                "settings.admin.password": "New Password",

                "modal.user.obfs": "Obfuscation Profile",
                "modal.user.marionette": "Marionette Profile",
                "modal.user.russian": "Russian Service",
                "modal.user.traffic.placeholder": "0 = unlimited",
                "modal.user.password.placeholder": "Minimum 8 characters",

                "option.obfs.http2": "HTTP/2 (Default)",
                "option.obfs.random": "Random",
                "option.marionette.browser": "Browser (Default)",
                "option.marionette.crawler": "Crawler",
                "option.russian.vk": "VK (Default)",
                "option.russian.yandex": "Yandex",
                "option.russian.mailru": "Mail.ru",

                "modal.user.email": "Email",
                "modal.user.password": "Password",
                "modal.user.traffic": "Traffic Limit (GB)",
                "modal.user.expiry": "Expiry Date",

                "page.users.title": "Users",
                "table.header.email": "Email / Name",
                "table.header.plan": "Plan",
                "table.header.traffic": "Traffic",
                "table.header.status": "Status",
                "table.header.key": "Key",
                "table.header.actions": "Actions",
                "table.empty.users": "No users found",

                "page.sessions.title": "Active Sessions",
                "table.header.sessions.user": "User",
                "table.header.sessions.ip": "Client IP",
                "table.header.sessions.connected": "Connected",
                "table.header.sessions.traffic": "Traffic",
                "table.empty.sessions": "No active sessions",

                "page.inbounds.title": "Inbounds",
                "table.header.tag": "Tag",
                "table.header.protocol": "Protocol",
                "table.header.port": "Port",
                "table.header.transport": "Transport",
                "table.empty.inbounds": "No inbounds found",

                "page.outbounds.title": "Outbound Servers",
                "table.header.type": "Type",
                "table.header.address": "Address",
                "table.header.latency": "Latency",
                "table.empty.outbounds": "No outbound servers",

                "page.routing.title": "Routing",
                "table.header.condition": "Condition",
                "table.header.outbound": "Outbound",
                "table.header.priority": "Priority",
                "table.empty.routing": "No routing rules",

                "page.subscriptions.title": "Subscriptions",
                "page.subscriptions.update_all": "Update All",
                "table.header.name": "Name",
                "table.header.url": "URL",
                "table.header.interval": "Interval",
                "table.header.count": "Servers",
                "table.empty.subscriptions": "No active subscriptions",

                "page.bridges.title": "Bridge Monitor",
                "page.adblock.title": "AdBlock",
                "page.adblock.total": "Total Blocked",
                "page.adblock.dns": "DNS",
                "page.adblock.https": "HTTPS",
                "page.adblock.rules": "Blocking Rules",
                "table.header.domain": "Domain/URL",
                "table.header.enabled": "Enabled",
                "table.empty.adblock": "No blocking rules",

                "page.logs.title": "System Logs",
                "page.logs.loading": "Loading logs...",

                "common.refresh": "Refresh",
                "common.loading": "Loading...",
                "nav.bridges": "Bridges",
                "nav.bridge_map": "Bridge Map",
                "dashboard.stats.memory": "Memory",
                "bridges.btn.add": "Add Bridge",
                "bridges.stat.total": "Total Bridges",
                "bridges.stat.alive": "Active",
                "bridges.stat.dead": "Unavailable",
                "bridges.stat.latency": "Avg Latency",
                "bridges.table.region": "Region",
                "bridges.table.latency": "Latency",
                "bridges.table.trust": "Trust",
                "bridges.table.last_check": "Last Check",
                "bridges.token.title": "Bridge Registration Token",
                "bridges.token.desc": "Pass this token when installing a new bridge via install-bridge.sh. The bridge will automatically register and appear in the table above.",
                "bridges.token.new": "New Token",
                "bridges.token.curl_hint": "Or register the bridge manually via curl:",
                "settings.stealth.title": "Censorship Bypass Mode",
                "settings.stealth.strategy": "Transport Strategy",
                "settings.stealth.auto": "Auto (optimal)",
                "settings.stealth.russia": "Russia — VK / Yandex priority",
                "settings.stealth.save": "Save Mode",
                "settings.probe.title": "Active Probing Protection",
                "settings.probe.blocked": "Blocked IPs",
                "settings.probe.watching": "Watching",
                "settings.probe.block_placeholder": "IP to block",
                "settings.probe.block_btn": "Block",
                "settings.probe.unblock_placeholder": "IP to unblock",
                "settings.probe.unblock_btn": "Unblock",
                "settings.appearance.bg": "Panel Background",
                "settings.appearance.upload": "Upload",
                "settings.appearance.reset": "Reset",
                "settings.admin.password.placeholder": "Leave blank to keep unchanged",
                "modal.bridge.title": "Add Bridge",
                "modal.bridge.address": "Address",
                "modal.bridge.region": "Region",
                "modal.bridge.provider": "Provider",
                "modal.bridge.type": "Type",
                "modal.bridge.pubkey": "Public Key",
                "modal.inbound.transport": "Transport",
                "modal.inbound.group.server": "Server (working)",
                "modal.inbound.group.http_quic": "HTTP/QUIC Transports",
                "modal.inbound.group.public_infra": "Public Infrastructure",
                "modal.inbound.group.public_tunnel": "Public Tunnels",
                "modal.inbound.group.social": "VK / OK / Yandex / Bots",
                "modal.inbound.sni": "SNI (comma-separated, empty = accept any)",
                "modal.inbound.sni.hint": "TCP/WS/HTTP only. Empty field = allowlist disabled.",
                "modal.outbound.multihop": "Multi-hop Chain",
                "modal.outbound.chain_placeholder": "tag or bridge:id, comma-separated",
                "modal.outbound.multihop.desc": "Traffic will pass through specified nodes. Click a bridge to add to the chain.",
                "modal.subscription.transports": "Transports (comma-separated, empty = all)",
                "modal.user.transport": "Transport for Key",
                "modal.user.transport.hint": "(multiple — race)",
                "modal.user.transport.server": "Server",
                "modal.user.transport.external": "External Service",
                "modal.user.transport.bypass": "Bypass",
                "modal.user.port": "Port (optional)",
                "modal.user.port.placeholder": "Auto (from inbound)",
                "modal.user.port.hint": "Auto-detected from inbound by transport. Can be changed — will be opened in firewall automatically.",
                "modal.user.sni": "SNI (for Phantom/TLS)",
                "modal.user.sni.placeholder": "Auto (from inbound settings)",
                "modal.user.transport_params": "Transport Parameters",
                "option.russian.auto": "Auto (not specified)",
                "option.marionette.group.android": "Messengers (Android)",
                "option.marionette.group.ios": "Messengers (iOS)",
            },
            zh: {
                "common.login_desc":"管理面板","common.login_username":"用户名","common.login_password":"密码","common.login_btn":"登录","common.admin":"管理员","common.role_admin":"管理员",
                "nav.dashboard":"仪表盘","nav.users":"用户","nav.sessions":"会话","nav.inbounds":"入站","nav.outbounds":"出站","nav.routing":"路由","nav.subscriptions":"订阅","nav.adblock":"广告拦截","nav.settings":"设置","nav.logs":"日志","nav.logout":"退出","nav.bridges":"网桥",
                "page.dashboard.title":"仪表盘","dashboard.stats.users":"用户","dashboard.stats.sessions":"活跃会话","dashboard.stats.upload":"上传","dashboard.stats.download":"下载","dashboard.stats.memory":"内存","dashboard.traffic.title":"流量 (MB/s)","dashboard.server.title":"服务器信息","dashboard.server.uptime":"运行时间",
                "common.save":"保存","common.cancel":"取消","common.add":"添加","common.create":"创建","common.delete":"删除","common.edit":"编辑","common.refresh":"刷新","common.loading":"加载中...","common.add_rule":"添加规则",
                "modal.user.title":"添加用户","modal.common.tag":"标签","modal.common.protocol":"协议","modal.common.port":"端口","modal.common.address":"地址","modal.common.name":"名称","modal.common.url":"URL",
                "modal.inbound.title":"添加入站","modal.outbound.title":"添加服务器","modal.routing.title":"添加路由规则","modal.subscription.title":"添加订阅","modal.adblock.title":"添加拦截规则",
                "modal.routing.type":"类型","modal.routing.value":"值（域名或IP）","modal.routing.outbound_tag":"出站标签","modal.routing.option.domain":"域名","modal.adblock.option.domain":"域名","modal.adblock.option.keyword":"关键词","modal.routing.option.ip":"IP","modal.adblock.domain":"域名","modal.adblock.type":"类型",
                "settings.title":"系统设置","settings.config.title":"服务器配置","settings.config.port":"用户连接端口","settings.config.domain":"主域名 (SNI)","settings.config.email":"管理员邮箱","settings.config.reload":"重载核心",
                "settings.security.title":"安全与SSL","settings.security.cert":"证书","settings.security.expiry":"到期时间","settings.security.renew":"手动更新证书","settings.security.firewall":"防火墙管理",
                "settings.appearance.title":"外观","settings.appearance.language":"界面语言","settings.appearance.theme":"主题","settings.appearance.bg":"面板背景","settings.appearance.upload":"上传","settings.appearance.reset":"重置",
                "settings.backup.title":"备份与恢复","settings.backup.desc":"下载完整数据库和配置转储。","settings.backup.download":"下载备份","settings.backup.restore":"恢复...",
                "settings.admin.title":"管理员账户","settings.admin.email":"邮箱（登录）","settings.admin.password":"新密码","settings.admin.password.placeholder":"留空则保持不变",
                "modal.user.obfs":"混淆配置","modal.user.marionette":"Marionette配置","modal.user.russian":"俄罗斯服务","modal.user.traffic.placeholder":"0 = 无限制","modal.user.password.placeholder":"最少8个字符",
                "option.obfs.http2":"HTTP/2（默认）","option.obfs.random":"随机","option.marionette.browser":"浏览器（默认）","option.marionette.crawler":"爬虫","option.russian.vk":"VK（默认）","option.russian.yandex":"Yandex","option.russian.mailru":"Mail.ru","option.russian.auto":"自动（不指定）",
                "option.marionette.group.android":"Android 通讯软件","option.marionette.group.ios":"iOS 通讯软件",
                "modal.user.email":"邮箱","modal.user.password":"密码","modal.user.traffic":"流量限制 (GB)","modal.user.expiry":"到期日期",
                "page.users.title":"用户","table.header.email":"邮箱 / 名称","table.header.plan":"套餐","table.header.traffic":"流量","table.header.status":"状态","table.header.key":"密钥","table.header.actions":"操作","table.empty.users":"暂无用户",
                "page.sessions.title":"活跃会话","table.header.sessions.user":"用户","table.header.sessions.ip":"客户端IP","table.header.sessions.connected":"已连接","table.header.sessions.traffic":"流量","table.empty.sessions":"暂无活跃会话",
                "page.inbounds.title":"入站连接","table.header.tag":"标签","table.header.protocol":"协议","table.header.port":"端口","table.header.transport":"传输","table.empty.inbounds":"暂无入站",
                "page.outbounds.title":"出站服务器","table.header.type":"类型","table.header.address":"地址","table.header.latency":"延迟","table.empty.outbounds":"暂无出站服务器",
                "page.routing.title":"路由","table.header.condition":"条件","table.header.outbound":"出站","table.header.priority":"优先级","table.empty.routing":"暂无路由规则",
                "page.subscriptions.title":"订阅","page.subscriptions.update_all":"全部更新","table.header.name":"名称","table.header.url":"URL","table.header.interval":"间隔","table.header.count":"服务器数","table.empty.subscriptions":"暂无活跃订阅",
                "page.bridges.title":"网桥监控","bridges.btn.add":"添加网桥","bridges.stat.total":"总网桥数","bridges.stat.alive":"在线","bridges.stat.dead":"离线","bridges.stat.latency":"平均延迟","bridges.table.region":"地区","bridges.table.latency":"延迟","bridges.table.trust":"信任度","bridges.table.last_check":"最后检查",
                "bridges.token.title":"网桥注册令牌","bridges.token.desc":"通过 install-bridge.sh 安装新网桥时传递此令牌。网桥将自动注册并出现在上方表格中。","bridges.token.new":"新令牌",
                "page.adblock.title":"广告拦截","page.adblock.total":"总计拦截","page.adblock.dns":"DNS","page.adblock.https":"HTTPS","page.adblock.rules":"拦截规则","table.header.domain":"域名/URL","table.header.enabled":"已启用","table.empty.adblock":"暂无拦截规则",
                "settings.stealth.title":"翻墙模式","settings.stealth.strategy":"传输策略","settings.stealth.auto":"自动（最优）","settings.stealth.russia":"俄罗斯 — VK / Yandex 优先","settings.stealth.save":"保存模式",
                "settings.probe.title":"主动探测防护","settings.probe.blocked":"已封锁IP","settings.probe.watching":"监控中","settings.probe.block_placeholder":"要封锁的IP","settings.probe.block_btn":"封锁","settings.probe.unblock_placeholder":"要解锁的IP","settings.probe.unblock_btn":"解锁",
                "modal.bridge.title":"添加网桥","modal.bridge.address":"地址","modal.bridge.region":"地区","modal.bridge.provider":"提供商","modal.bridge.type":"类型","modal.bridge.pubkey":"公钥",
                "modal.inbound.transport":"传输","modal.inbound.group.server":"服务端（可用）","modal.inbound.group.http_quic":"HTTP/QUIC 传输","modal.inbound.group.public_infra":"公共基础设施","modal.inbound.group.public_tunnel":"公共隧道","modal.inbound.group.social":"VK / OK / Yandex / 机器人",
                "modal.inbound.sni":"SNI（逗号分隔，空=接受任何）","modal.inbound.sni.hint":"仅适用于TCP/WS/HTTP。空字段=禁用白名单。",
                "modal.outbound.multihop":"多跳链","modal.outbound.chain_placeholder":"标签或bridge:id，逗号分隔","modal.outbound.multihop.desc":"流量将经过指定节点。点击网桥添加到链中。",
                "modal.subscription.transports":"传输（逗号分隔，空=全部）",
                "modal.user.transport":"密钥传输","modal.user.transport.hint":"（多个=竞速）","modal.user.transport.server":"服务端","modal.user.transport.external":"外部服务","modal.user.transport.bypass":"绕过",
                "modal.user.port":"端口（可选）","modal.user.port.placeholder":"自动（来自入站）","modal.user.port.hint":"根据传输从入站自动检测。可更改——将自动在防火墙中开放。",
                "modal.user.sni":"SNI（用于Phantom/TLS）","modal.user.sni.placeholder":"自动（来自入站设置）","modal.user.transport_params":"传输参数",
                "page.logs.title":"系统日志","page.logs.loading":"加载日志中...",
            },
            fa: {
                "common.login_desc":"پنل مدیریت","common.login_username":"نام کاربری","common.login_password":"رمز عبور","common.login_btn":"ورود","common.admin":"مدیر","common.role_admin":"مدیر سیستم",
                "nav.dashboard":"داشبورد","nav.users":"کاربران","nav.sessions":"جلسات","nav.inbounds":"ورودی‌ها","nav.outbounds":"خروجی‌ها","nav.routing":"مسیریابی","nav.subscriptions":"اشتراک‌ها","nav.adblock":"مسدودکننده","nav.settings":"تنظیمات","nav.logs":"لاگ‌ها","nav.logout":"خروج","nav.bridges":"پل‌ها",
                "page.dashboard.title":"داشبورد","dashboard.stats.users":"کاربران","dashboard.stats.sessions":"جلسات فعال","dashboard.stats.upload":"آپلود","dashboard.stats.download":"دانلود","dashboard.stats.memory":"حافظه","dashboard.traffic.title":"ترافیک (MB/s)","dashboard.server.title":"اطلاعات سرور","dashboard.server.uptime":"آپتایم",
                "common.save":"ذخیره","common.cancel":"لغو","common.add":"افزودن","common.create":"ایجاد","common.delete":"حذف","common.edit":"ویرایش","common.refresh":"بازنشانی","common.loading":"در حال بارگذاری...","common.add_rule":"افزودن قانون",
                "modal.user.title":"افزودن کاربر","modal.common.tag":"برچسب","modal.common.protocol":"پروتکل","modal.common.port":"پورت","modal.common.address":"آدرس","modal.common.name":"نام","modal.common.url":"URL",
                "modal.inbound.title":"افزودن ورودی","modal.outbound.title":"افزودن سرور","modal.routing.title":"افزودن قانون مسیریابی","modal.subscription.title":"افزودن اشتراک","modal.adblock.title":"افزودن قانون مسدودسازی",
                "modal.routing.type":"نوع","modal.routing.value":"مقدار (دامنه یا IP)","modal.routing.outbound_tag":"برچسب خروجی","modal.routing.option.domain":"دامنه","modal.adblock.option.domain":"دامنه","modal.adblock.option.keyword":"کلیدواژه","modal.routing.option.ip":"IP","modal.adblock.domain":"دامنه","modal.adblock.type":"نوع",
                "settings.title":"تنظیمات سیستم","settings.config.title":"پیکربندی سرور","settings.config.port":"پورت اتصال کاربر","settings.config.domain":"دامنه اصلی (SNI)","settings.config.email":"ایمیل مدیر","settings.config.reload":"بارگذاری مجدد هسته",
                "settings.security.title":"امنیت و SSL","settings.security.cert":"گواهی","settings.security.expiry":"انقضا","settings.security.renew":"تجدید گواهی دستی","settings.security.firewall":"مدیریت فایروال",
                "settings.appearance.title":"ظاهر","settings.appearance.language":"زبان رابط","settings.appearance.theme":"تم","settings.appearance.bg":"پس‌زمینه پنل","settings.appearance.upload":"آپلود","settings.appearance.reset":"بازنشانی",
                "settings.backup.title":"پشتیبان‌گیری و بازیابی","settings.backup.desc":"دانلود پشتیبان کامل پایگاه داده و پیکربندی.","settings.backup.download":"دانلود پشتیبان","settings.backup.restore":"بازیابی...",
                "settings.admin.title":"حساب مدیر","settings.admin.email":"ایمیل (ورود)","settings.admin.password":"رمز عبور جدید","settings.admin.password.placeholder":"برای حفظ رمز خالی بگذارید",
                "modal.user.obfs":"پروفایل مبهم‌سازی","modal.user.marionette":"پروفایل Marionette","modal.user.russian":"سرویس روسی","modal.user.traffic.placeholder":"0 = نامحدود","modal.user.password.placeholder":"حداقل ۸ کاراکتر",
                "option.obfs.http2":"HTTP/2 (پیش‌فرض)","option.obfs.random":"تصادفی","option.marionette.browser":"مرورگر (پیش‌فرض)","option.marionette.crawler":"خزنده","option.russian.vk":"VK (پیش‌فرض)","option.russian.yandex":"Yandex","option.russian.mailru":"Mail.ru","option.russian.auto":"خودکار (بدون تعیین)",
                "option.marionette.group.android":"پیام‌رسان‌های Android","option.marionette.group.ios":"پیام‌رسان‌های iOS",
                "modal.user.email":"ایمیل","modal.user.password":"رمز عبور","modal.user.traffic":"محدودیت ترافیک (GB)","modal.user.expiry":"تاریخ انقضا",
                "page.users.title":"کاربران","table.header.email":"ایمیل / نام","table.header.plan":"طرح","table.header.traffic":"ترافیک","table.header.status":"وضعیت","table.header.key":"کلید","table.header.actions":"عملیات","table.empty.users":"کاربری یافت نشد",
                "page.sessions.title":"جلسات فعال","table.header.sessions.user":"کاربر","table.header.sessions.ip":"IP کلاینت","table.header.sessions.connected":"متصل شده","table.header.sessions.traffic":"ترافیک","table.empty.sessions":"جلسه فعالی وجود ندارد",
                "page.inbounds.title":"اتصالات ورودی","table.header.tag":"برچسب","table.header.protocol":"پروتکل","table.header.port":"پورت","table.header.transport":"انتقال","table.empty.inbounds":"ورودی یافت نشد",
                "page.outbounds.title":"سرورهای خروجی","table.header.type":"نوع","table.header.address":"آدرس","table.header.latency":"تأخیر","table.empty.outbounds":"سرور خروجی یافت نشد",
                "page.routing.title":"مسیریابی","table.header.condition":"شرط","table.header.outbound":"خروجی","table.header.priority":"اولویت","table.empty.routing":"قانون مسیریابی یافت نشد",
                "page.subscriptions.title":"اشتراک‌ها","page.subscriptions.update_all":"به‌روزرسانی همه","table.header.name":"نام","table.header.url":"URL","table.header.interval":"بازه","table.header.count":"سرورها","table.empty.subscriptions":"اشتراک فعالی وجود ندارد",
                "page.bridges.title":"مانیتور پل","bridges.btn.add":"افزودن پل","bridges.stat.total":"کل پل‌ها","bridges.stat.alive":"فعال","bridges.stat.dead":"غیرفعال","bridges.stat.latency":"تأخیر میانگین","bridges.table.region":"منطقه","bridges.table.latency":"تأخیر","bridges.table.trust":"اعتماد","bridges.table.last_check":"آخرین بررسی",
                "bridges.token.title":"توکن ثبت پل","bridges.token.desc":"هنگام نصب پل جدید از طریق install-bridge.sh این توکن را ارائه دهید. پل به صورت خودکار ثبت و در جدول بالا نمایش داده می‌شود.","bridges.token.new":"توکن جدید",
                "page.adblock.title":"مسدودکننده تبلیغات","page.adblock.total":"کل مسدود شده","page.adblock.dns":"DNS","page.adblock.https":"HTTPS","page.adblock.rules":"قوانین مسدودسازی","table.header.domain":"دامنه/URL","table.header.enabled":"فعال","table.empty.adblock":"قانون مسدودسازی یافت نشد",
                "settings.stealth.title":"حالت دور زدن سانسور","settings.stealth.strategy":"استراتژی انتقال","settings.stealth.auto":"خودکار (بهینه)","settings.stealth.russia":"روسیه — VK / Yandex اولویت","settings.stealth.save":"ذخیره حالت",
                "settings.probe.title":"محافظت در برابر پروب فعال","settings.probe.blocked":"IP‌های مسدود شده","settings.probe.watching":"در حال نظارت","settings.probe.block_placeholder":"IP برای مسدود کردن","settings.probe.block_btn":"مسدود","settings.probe.unblock_placeholder":"IP برای رفع مسدودیت","settings.probe.unblock_btn":"رفع مسدودیت",
                "modal.bridge.title":"افزودن پل","modal.bridge.address":"آدرس","modal.bridge.region":"منطقه","modal.bridge.provider":"ارائه‌دهنده","modal.bridge.type":"نوع","modal.bridge.pubkey":"کلید عمومی",
                "modal.inbound.transport":"انتقال","modal.inbound.group.server":"سرور (کار می‌کند)","modal.inbound.group.http_quic":"انتقال HTTP/QUIC","modal.inbound.group.public_infra":"زیرساخت عمومی","modal.inbound.group.public_tunnel":"تونل‌های عمومی","modal.inbound.group.social":"VK / OK / Yandex / بات‌ها",
                "modal.inbound.sni":"SNI (با کاما جدا شود، خالی = هر SNI)","modal.inbound.sni.hint":"فقط TCP/WS/HTTP. خالی = لیست سفید غیرفعال.",
                "modal.outbound.multihop":"زنجیر چندپرش","modal.outbound.chain_placeholder":"برچسب یا bridge:id، با کاما","modal.outbound.multihop.desc":"ترافیک از گره‌های مشخص شده عبور می‌کند. روی پل کلیک کنید تا به زنجیر اضافه شود.",
                "modal.subscription.transports":"انتقال‌ها (با کاما، خالی = همه)",
                "modal.user.transport":"انتقال برای کلید","modal.user.transport.hint":"(چندگانه — مسابقه)","modal.user.transport.server":"سرور","modal.user.transport.external":"سرویس خارجی","modal.user.transport.bypass":"دور زدن",
                "modal.user.port":"پورت (اختیاری)","modal.user.port.placeholder":"خودکار (از ورودی)","modal.user.port.hint":"از ورودی بر اساس انتقال تشخیص داده می‌شود. می‌توان تغییر داد — در فایروال باز می‌شود.",
                "modal.user.sni":"SNI (برای Phantom/TLS)","modal.user.sni.placeholder":"خودکار (از تنظیمات ورودی)","modal.user.transport_params":"پارامترهای انتقال",
                "page.logs.title":"لاگ‌های سیستم","page.logs.loading":"در حال بارگذاری لاگ‌ها...",
            }
        };
        this.init();
    }

    init() {
        if (api.token) {
            this.showMainApp();
            this.loadDashboard();
        } else {
            this.showLogin();
        }

        this.bindEvents();
        this.initBackgroundEffects();
        this.animateLoginEntrance();
        this.initUIAnimations();
        this.initCustomSelects();

        const savedLang = localStorage.getItem('whispera_lang') || 'ru';
        this.applyLanguage(savedLang);

        const savedTheme = localStorage.getItem('whispera_theme') || 'dark';
        this.handleThemeChange(savedTheme);

        if (api.token) {
            const savedPage = localStorage.getItem('whispera_page') || 'dashboard';
            if (savedPage !== 'dashboard') {
                this.navigateTo(savedPage);
            }
        }
    }

    initBackgroundEffects() {
        const mesh = document.querySelector('.bg-mesh');
        if (!mesh) return;

        gsap.to('.blob-1', {
            duration: 20,
            x: 'random(-200, 300)',
            y: 'random(-100, 400)',
            scale: 'random(0.9, 1.2)',
            repeat: -1,
            yoyo: true,
            ease: "sine.inOut"
        });

        gsap.to('.blob-2', {
            duration: 25,
            x: 'random(-400, 100)',
            y: 'random(-400, 100)',
            scale: 'random(0.8, 1.1)',
            repeat: -1,
            yoyo: true,
            ease: "sine.inOut"
        });

        gsap.to('.blob-3', {
            duration: 15,
            x: 'random(-100, 100)',
            y: 'random(-100, 100)',
            opacity: 'random(0.1, 0.3)',
            repeat: -1,
            yoyo: true,
            ease: "none"
        });

        window.addEventListener('mousemove', (e) => {
            const { clientX, clientY } = e;
            const xPos = (clientX / window.innerWidth - 0.5) * 60;
            const yPos = (clientY / window.innerHeight - 0.5) * 60;

            gsap.to('.bg-mesh', {
                duration: 2.5,
                x: xPos,
                y: yPos,
                ease: "power2.out"
            });

            gsap.to('.bg-grid-animated', {
                duration: 4,
                x: xPos * 0.4,
                y: yPos * 0.4,
                ease: "power2.out"
            });
        });

        this.createDataParticles();
        this.initRainSystem();
        this.initCircuitFlow();
        this.initUIGlitches();

        setTimeout(() => {
            try {
                this.threeCity = new ThreeCity('city-canvas');

                setInterval(() => {
                    if (this.threeCity && Math.random() > 0.7) {
                        this.threeCity.triggerLightning();
                    }
                }, 10000);
            } catch (e) { console.warn("ThreeCity error:", e); }
        }, 500);
    }

    initDataBurst() {
        setInterval(() => {
            if (Math.random() > 0.7) {
                const burst = document.createElement('div');
                burst.className = 'bg-data-burst';
                document.querySelector('.bg-effects').appendChild(burst);

                gsap.to(burst, {
                    opacity: 0.3,
                    duration: 0.05,
                    repeat: 5,
                    yoyo: true,
                    onComplete: () => burst.remove()
                });
            }
        }, 15000);
    }



    initUIGlitches() {
        setInterval(() => {
            const targets = document.querySelectorAll('.cyber-card, .btn-cyber, .cyber-logo-text');
            const target = targets[Math.floor(Math.random() * targets.length)];

            if (target && !target.classList.contains('ui-glitch-active')) {
                if (!target.hasAttribute('data-text')) {
                    target.setAttribute('data-text', target.innerText || 'SYSTEM');
                }

                target.classList.add('ui-glitch-active');
                setTimeout(() => {
                    target.classList.remove('ui-glitch-active');
                }, gsap.utils.random(200, 800));
            }
        }, 8000);

        document.querySelectorAll('.btn-cyber, .nav-item').forEach(el => {
            el.addEventListener('mouseenter', () => {
                if (Math.random() > 0.5) {
                    el.classList.add('flicker-fast');
                    setTimeout(() => el.classList.remove('flicker-fast'), 200);
                }
            });
        });
    }

    initCircuitFlow() {
        const paths = document.querySelectorAll('.circuit-path');
        paths.forEach((path, i) => {
            const length = path.getTotalLength();
            gsap.set(path, { strokeDasharray: length, strokeDashoffset: length });

            const pulse = () => {
                const tl = gsap.timeline({
                    onComplete: () => {
                        path.classList.remove('active');
                        setTimeout(pulse, gsap.utils.random(2000, 8000));
                    }
                });

                tl.to(path, {
                    onStart: () => path.classList.add('active'),
                    strokeDashoffset: 0,
                    duration: gsap.utils.random(1.5, 4),
                    ease: "sine.inOut"
                }).to(path, {
                    opacity: 0.15,
                    duration: 1
                }, "-=1");
            };
            setTimeout(pulse, i * 800);
        });
    }

    initNeonSigns() {
        const signs = document.querySelectorAll('.neon-sign');
        signs.forEach(sign => {
            gsap.to(sign, {
                opacity: "random(0.05, 0.2)",
                duration: 0.1,
                repeat: -1,
                yoyo: true,
                ease: "none"
            });

            const glitch = () => {
                gsap.to(sign, {
                    opacity: 0,
                    duration: 0.05,
                    repeat: 3,
                    yoyo: true,
                    onComplete: () => {
                        setTimeout(glitch, gsap.utils.random(5000, 15000));
                    }
                });
            };
            glitch();
        });
    }

    animateCityLights() {
        gsap.to('.city-glow', {
            duration: 'random(10, 20)',
            x: 'random(-100, 100)',
            y: 'random(-100, 100)',
            scale: 'random(0.8, 1.2)',
            opacity: 'random(0.2, 0.5)',
            repeat: -1,
            yoyo: true,
            stagger: 2,
            ease: "sine.inOut"
        });

        setInterval(() => {
            const glow = document.querySelectorAll('.city-glow')[Math.floor(Math.random() * 3)];
            if (glow) {
                gsap.to(glow, { duration: 0.1, opacity: 0.1, repeat: 3, yoyo: true });
            }
        }, 5000);
    }

    initRainSystem() {
        const rainContainer = document.querySelector('.bg-rain');
        if (!rainContainer) return;

        for (let i = 0; i < 60; i++) {
            this.createRainDrop(rainContainer, true);
        }
    }

    createRainDrop(container, initial = false) {
        const drop = document.createElement('div');
        drop.className = 'rain-drop';
        container.appendChild(drop);

        const x = Math.random() * window.innerWidth;
        const delay = initial ? Math.random() * -5 : 0;
        const duration = 0.5 + Math.random() * 0.5;

        gsap.set(drop, { x, y: initial ? Math.random() * window.innerHeight : -100, opacity: 0.2 + Math.random() * 0.5 });

        gsap.to(drop, {
            y: window.innerHeight + 100,
            duration: duration,
            delay: delay,
            ease: "none",
            onComplete: () => {
                drop.remove();
                this.createRainDrop(container);
            }
        });
    }

    createDataParticles() {
        const effects = document.querySelector('.bg-effects');
        if (!effects) return;

        for (let i = 0; i < 30; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            effects.appendChild(particle);

            this.animateParticle(particle);
        }
    }

    animateParticle(p) {
        gsap.set(p, {
            x: Math.random() * window.innerWidth,
            y: Math.random() * window.innerHeight,
            opacity: Math.random() * 0.5,
            scale: Math.random() * 2
        });

        gsap.to(p, {
            duration: 'random(10, 30)',
            x: `+= ${Math.random() * 400 - 200} `,
            y: `+= ${Math.random() * 400 - 200} `,
            opacity: 0,
            repeat: -1,
            yoyo: true,
            ease: "sine.inOut"
        });
    }

    animateLoginEntrance() {
        const loginContainer = document.querySelector('.login-container');
        if (!loginContainer) return;

        gsap.from(loginContainer, {
            duration: 1.2,
            y: 50,
            opacity: 0,
            ease: "expo.out"
        });

        gsap.from('.login-header .cyber-logo-text', {
            duration: 1.5,
            scale: 0.8,
            delay: 0.2,
            opacity: 0,
            ease: "elastic.out(1, 0.5)"
        });

        gsap.from('.form-group', {
            duration: 1,
            x: -20,
            opacity: 0,
            stagger: 0.1,
            delay: 0.5,
            ease: "power3.out"
        });
    }

    initUIAnimations() {
        document.querySelectorAll('.card, .stat-card, .cyber-card').forEach(card => {
            card.addEventListener('mouseenter', () => {
                gsap.to(card, {
                    duration: 0.3,
                    y: -5,
                    boxShadow: '0 15px 45px rgba(0, 229, 255, 0.2)',
                    borderColor: 'rgba(0, 229, 255, 0.6)',
                    ease: "back.out(1.7)"
                });

                const flash = document.createElement('div');
                flash.style.cssText = "position:absolute; inset:0; background:rgba(0,229,255,0.1); pointer-events:none; z-index:10;";
                card.appendChild(flash);
                gsap.to(flash, { opacity: 0, duration: 0.5, onComplete: () => flash.remove() });
            });
            card.addEventListener('mouseleave', () => {
                gsap.to(card, {
                    duration: 0.3,
                    y: 0,
                    boxShadow: 'var(--md-sys-elevation-1)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    ease: "power2.out"
                });
            });
        });

        const logo = document.querySelector('.cyber-logo-text');
        if (logo) {
            logo.addEventListener('mouseenter', () => {
                const tl = gsap.timeline();
                tl.to(logo, { duration: 0.05, x: 2, skewX: 5, color: '#ff00c1' })
                    .to(logo, { duration: 0.05, x: -2, skewX: -5, color: '#00f2ff' })
                    .to(logo, { duration: 0.05, x: 1, skewX: 2, color: '#ffffff' })
                    .to(logo, { duration: 0.05, x: 0, skewX: 0 });
            });
        }

        document.querySelectorAll('.btn-primary, .btn-cyber').forEach(btn => {
            btn.addEventListener('mousemove', (e) => {
                const rect = btn.getBoundingClientRect();
                const x = (e.clientX - rect.left - rect.width / 2) * 0.4;
                const y = (e.clientY - rect.top - rect.height / 2) * 0.4;

                gsap.to(btn, {
                    duration: 0.2,
                    x: x,
                    y: y,
                    rotateX: -y * 0.1,
                    rotateY: x * 0.1,
                    ease: "power1.out"
                });
            });

            btn.addEventListener('mouseleave', () => {
                gsap.to(btn, {
                    duration: 0.6,
                    x: 0,
                    y: 0,
                    rotateX: 0,
                    rotateY: 0,
                    ease: "elastic.out(1, 0.3)"
                });
            });
        });
    }

    initCustomSelects() {
        document.querySelectorAll('select:not(.custom-select-hidden)').forEach(select => {
            if (select.offsetParent !== null) {
                new CustomSelect(select);
            }
        });
    }

    applyLanguage(lang) {
        if (!this.translations[lang]) lang = 'ru';

        localStorage.setItem('whispera_lang', lang);

        const dictionary = this.translations[lang];
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            if (dictionary[key]) {
                if ((element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') && element.hasAttribute('placeholder')) {
                    element.placeholder = dictionary[key];
                } else {
                    element.textContent = dictionary[key];
                }
            }
        });

        document.querySelectorAll('[data-i18n-label]').forEach(element => {
            const key = element.getAttribute('data-i18n-label');
            if (dictionary[key]) element.label = dictionary[key];
        });

        const rtlLangs = new Set(['fa']);
        document.documentElement.dir = rtlLangs.has(lang) ? 'rtl' : 'ltr';
        document.documentElement.lang = lang;

        if (document.getElementById('panel-language')) {
            document.getElementById('panel-language').value = lang;
        }
    }

    initBackgroundEffects() {
        const savedBg = JSON.parse(localStorage.getItem('whispera_bg') || 'null');
        if (savedBg) {
            this.applyBackground(savedBg.url, savedBg.type);
            document.getElementById('bg-reset-btn').style.display = 'block';
        } else {
            this.applyBackground(null, null);
        }

        const bg = document.querySelector('.bg-gradient');
        if (!bg) return;

        document.addEventListener('mousemove', (e) => {
            const x = (e.clientX / window.innerWidth) * 100;
            const y = (e.clientY / window.innerHeight) * 100;

            bg.style.setProperty('--x', `${x}%`);
            bg.style.setProperty('--y', `${y}%`);
        });
    }

    async handleBackgroundUpload(file) {
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        const status = document.getElementById('bg-upload-status');
        const btn = document.getElementById('bg-upload-btn');
        const originalText = btn.innerHTML;

        try {
            status.textContent = 'Загрузка...';
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData,
                headers: {
                    'Authorization': `Bearer ${api.token}`
                }
            });

            if (!response.ok) throw new Error('Upload failed');

            const data = await response.json();

            const bgData = { url: data.url, type: data.type };
            localStorage.setItem('whispera_bg', JSON.stringify(bgData));
            this.applyBackground(data.url, data.type);

            document.getElementById('bg-reset-btn').style.display = 'block';
            status.textContent = 'Успешно!';
            status.style.color = '#4ade80';

            setTimeout(() => status.textContent = '', 3000);

        } catch (error) {
            console.error(error);
            status.textContent = 'Ошибка: ' + error.message;
            status.style.color = '#f87171';
            this.showNotification('Upload Error: ' + error.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
            document.getElementById('bg-upload-input').value = '';
        }
    }

    resetBackground() {
        localStorage.removeItem('whispera_bg');
        this.applyBackground(null, null);
        document.getElementById('bg-reset-btn').style.display = 'none';
        this.showNotification('Фон сброшен', 'success');
    }

    applyBackground(url, type) {
        const bgVideo = document.getElementById('bg-video');
        if (bgVideo) bgVideo.remove();

        const canvas = document.getElementById('city-canvas');
        const bgEffects = document.querySelector('.bg-effects');
        const bgRain = document.querySelector('.bg-rain');

        if (!url) {
            document.body.style.backgroundImage = '';
            document.body.classList.remove('custom-bg-active');

            if (canvas) canvas.style.opacity = '1';
            if (bgEffects) bgEffects.style.display = 'block';
            if (bgRain) bgRain.style.display = 'block';
            return;
        }

        document.body.classList.add('custom-bg-active');

        if (canvas) canvas.style.opacity = '0';
        if (bgEffects) bgEffects.style.display = 'none';
        if (bgRain) bgRain.style.display = 'none';

        if (type === 'video') {
            document.body.style.backgroundImage = '';
            const video = document.createElement('video');
            video.id = 'bg-video';
            video.src = url;
            video.autoplay = true;
            video.loop = true;
            video.muted = true;
            video.playsInline = true;
            video.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; object-fit: cover; z-index: -9999;';
            document.body.appendChild(video);
        } else {
            document.body.style.backgroundImage = `url('${url}')`;
            document.body.style.backgroundSize = 'cover';
            document.body.style.backgroundPosition = 'center';
            document.body.style.backgroundRepeat = 'no-repeat';
            document.body.style.backgroundAttachment = 'fixed';
        }
    }

    async handleLogin() {

        const loginForm = document.getElementById('login-form');
        const username = loginForm.username.value;
        const password = loginForm.password.value;
        const btn = loginForm.querySelector('button');
        const originalText = btn.innerHTML;

        try {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';

            const response = await api.login(username, password);

            if (response.token) {
                api.setToken(response.token);
                this.showMainApp();
                localStorage.setItem('whispera_page', 'dashboard');
                this.navigateTo('dashboard');
                this.showNotification('Welcome back, Commander.', 'success');
            } else {
                throw new Error('Invalid credentials');
            }
        } catch (error) {
            this.showNotification('Access Denied: ' + error.message, 'error');
            const card = document.querySelector('.cyber-card');
            if (card) {
                card.classList.add('shake');
                setTimeout(() => card.classList.remove('shake'), 500);
            }
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }


    bindEvents() {
        document.getElementById('login-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                this.navigateTo(page);
                if (window.innerWidth <= 768) this.closeSidebar();
            });
        });

        document.getElementById('menu-toggle')?.addEventListener('click', () => this.toggleSidebar());
        document.getElementById('sidebar-overlay')?.addEventListener('click', () => this.closeSidebar());

        document.getElementById('logout-btn')?.addEventListener('click', () => {
            this.handleLogout();
        });

        document.getElementById('add-user-btn')?.addEventListener('click', async () => {
            this.showModal('add-user-modal');
            const portField = document.getElementById('new-user-port');
            if (portField) {
                portField.value = '';
                portField.dataset.autoSet = '1';
                portField.addEventListener('input', () => { delete portField.dataset.autoSet; }, { once: true });
            }
            try {
                const data = await api.getInbounds();
                this._cachedInbounds = (data.inbounds || data) || [];
                this._updateUserPort();
            } catch { this._cachedInbounds = []; }
        });

        document.getElementById('add-user-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddUser();
        });

        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => this.closeModals());
        });

        document.getElementById('reload-config-btn')?.addEventListener('click', async () => {
            try {
                await api.reloadConfig();
                this.showNotification('Конфигурация перезагружена', 'success');
            } catch (error) {
                this.showNotification('Ошибка: ' + error.message, 'error');
            }
        });

        document.getElementById('bridges-refresh-btn')?.addEventListener('click', () => {
            this._fetchBridgeStats();
            this._fetchBridgeList();
        });
        document.getElementById('bridges-add-btn')?.addEventListener('click', () => this.showModal('add-bridge-modal'));
        document.getElementById('add-bridge-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fd = new FormData(e.target);
            const submitBtn = e.target.querySelector('button[type="submit"]');
            const origHtml = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Проверка...';
            submitBtn.disabled = true;
            try {
                const res = await api.addBridge({
                    address:    fd.get('address'),
                    region:     fd.get('region'),
                    provider:   fd.get('provider'),
                    type:       fd.get('type'),
                    public_key: fd.get('public_key'),
                });
                this.closeModals();
                e.target.reset();
                if (res && res.is_alive) {
                    this.showNotification(`Мост добавлен ✓ доступен (${res.latency_ms} мс)`, 'success');
                } else if (res && res.id) {
                    this.showNotification('Мост добавлен, но недоступен — проверьте адрес', 'warning');
                } else {
                    this.showNotification('Мост добавлен', 'success');
                }
                await Promise.all([this._fetchBridgeStats(), this._fetchBridgeList()]);
            } catch (err) {
                this.showNotification('Ошибка: ' + err.message, 'error');
            } finally {
                submitBtn.innerHTML = origHtml;
                submitBtn.disabled = false;
            }
        });
        document.getElementById('bridge-copy-token-btn')?.addEventListener('click', () => {
            const token = document.getElementById('bridge-reg-token')?.textContent;
            if (token) navigator.clipboard.writeText(token).then(() => this.showNotification('Токен скопирован', 'success'));
        });
        document.getElementById('bridge-regen-token-btn')?.addEventListener('click', async () => {
            if (!await this.showConfirm('Перегенерировать токен? Все мосты потеряют связь до обновления.')) return;
            try {
                const data = await api.regenerateBridgeToken();
                const el = document.getElementById('bridge-reg-token');
                if (el) el.textContent = data.token || '—';
                this._updateCurlCmd(data.token);
                this.showNotification('Токен обновлён', 'success');
            } catch (e) {
                this.showNotification('Ошибка: ' + e.message, 'error');
            }
        });

        document.getElementById('add-inbound-btn')?.addEventListener('click', () => this.showModal('add-inbound-modal'));
        document.getElementById('add-inbound-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddInbound();
        });
        document.querySelector('[name="transport"]')?.addEventListener('change', (e) => {
            this.onInboundTransportChange(e.target.value);
        });
        document.getElementById('transport-checkboxes')?.addEventListener('change', () => {
            const selected = Array.from(document.querySelectorAll('input[name="transport-cb"]:checked')).map(i => i.value);
            this.onKeyTransportChange(selected.length === 1 ? selected[0] : selected);
            this._updateUserPort();
        });

        document.getElementById('add-outbound-btn')?.addEventListener('click', () => {
            this.showModal('add-outbound-modal');
            this._loadBridgesForChainPicker();
        });
        document.getElementById('add-outbound-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddOutbound();
        });

        document.getElementById('add-routing-btn')?.addEventListener('click', () => this.showModal('add-routing-modal'));
        document.getElementById('add-routing-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddRoutingRule();
        });

        document.getElementById('add-subscription-btn')?.addEventListener('click', () => this.showModal('add-subscription-modal'));
        document.getElementById('add-subscription-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddSubscription();
        });
        document.getElementById('update-subscriptions-btn')?.addEventListener('click', async () => {
            try {
                await api.updateAllSubscriptions();
                this.showNotification('Все подписки обновлены', 'success');
                this.loadSubscriptions();
            } catch (error) {
                this.showNotification('Ошибка: ' + error.message, 'error');
            }
        });

        document.getElementById('add-adblock-rule-btn')?.addEventListener('click', () => this.showModal('add-adblock-modal'));
        document.getElementById('add-adblock-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddAdblockRule();
        });
        document.getElementById('save-adblock-btn')?.addEventListener('click', async () => {
            try {
                this.showNotification('Настройки блокировщика сохранены', 'success');
            } catch (e) {
                this.showNotification('Ошибка сохранения: ' + e.message, 'error');
            }
        });


        document.getElementById('server-settings-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSaveServerSettings();
        });

        const stealthSelect = document.getElementById('stealth-mode-select');
        if (stealthSelect) {
            stealthSelect.addEventListener('change', () => this._updateStealthHint(stealthSelect.value));
            this._updateStealthHint(stealthSelect.value);
        }
        document.getElementById('save-stealth-mode-btn')?.addEventListener('click', async () => {
            const mode = document.getElementById('stealth-mode-select')?.value || '';
            try {
                await api.updateStealthMode(mode);
                this.showNotification(mode === 'russia' ? 'Режим «Россия» активирован' : 'Режим транспорта сброшен в Авто', 'success');
            } catch (e) {
                this.showNotification('Ошибка сохранения: ' + e.message, 'error');
            }
        });

        document.getElementById('force-reload-btn')?.addEventListener('click', async () => {
            if (await this.showConfirm('Вы уверены? Это приведет к перезапуску ядра сервера.')) {
                try {
                    await api.reloadConfig();
                    this.showNotification('Ядро успешно перезагружено', 'success');
                } catch (error) {
                    this.showNotification('Ошибка перезагрузки: ' + error.message, 'error');
                }
            }
        });

        document.getElementById('renew-cert-btn')?.addEventListener('click', async () => {
            const btn = document.getElementById('renew-cert-btn');
            const originalContent = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Обновление...';
            btn.disabled = true;
            try {
                await api.renewCertificate();
                this.showNotification('Сертификат успешно обновлен', 'success');
                document.getElementById('ssl-status').textContent = 'Активен (Обновлено)';
                document.getElementById('ssl-expiry').textContent = '2027-01-01';
            } catch (error) {
                this.showNotification('Ошибка: ' + error.message, 'error');
            } finally {
                btn.innerHTML = originalContent;
                btn.disabled = false;
            }
        });

        document.getElementById('firewall-manage-btn')?.addEventListener('click', () => {
            this.showFirewallModal();
        });

        document.getElementById('probe-refresh-btn')?.addEventListener('click', () => this._loadProbeStats());
        document.getElementById('probe-block-btn')?.addEventListener('click', async () => {
            const ip = document.getElementById('probe-block-ip')?.value.trim();
            if (!ip) return;
            try {
                await api.probeBlockIP(ip, 'manual');
                this.showNotification(`IP ${ip} заблокирован`, 'success');
                document.getElementById('probe-block-ip').value = '';
                this._loadProbeStats();
            } catch (e) { this.showNotification('Ошибка: ' + e.message, 'error'); }
        });
        document.getElementById('probe-unblock-btn')?.addEventListener('click', async () => {
            const ip = document.getElementById('probe-unblock-ip')?.value.trim();
            if (!ip) return;
            try {
                await api.probeUnblockIP(ip);
                this.showNotification(`IP ${ip} разблокирован`, 'success');
                document.getElementById('probe-unblock-ip').value = '';
                this._loadProbeStats();
            } catch (e) { this.showNotification('Ошибка: ' + e.message, 'error'); }
        });

        document.getElementById('panel-theme')?.addEventListener('change', (e) => {
            this.handleThemeChange(e.target.value);
        });

        const bgInput = document.getElementById('bg-upload-input');
        if (bgInput) {
            bgInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) this.handleBackgroundUpload(file);
            });
        }

        document.getElementById('bg-reset-btn')?.addEventListener('click', () => {
            this.resetBackground();
        });

        document.getElementById('panel-language')?.addEventListener('change', (e) => {
            this.applyLanguage(e.target.value);
            this.showNotification(e.target.value === 'ru' ? 'Язык изменен' : 'Language changed', 'success');
        });

        document.getElementById('backup-download-btn')?.addEventListener('click', () => this.handleDownloadBackup());

        document.getElementById('backup-upload')?.addEventListener('change', (e) => this.handleRestoreBackup(e));

        document.getElementById('admin-profile-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleUpdateAdminProfile();
        });

        document.getElementById('btn-notifications')?.addEventListener('click', () => {
            const lang = localStorage.getItem('whispera_lang') || 'ru';
            const msg = lang === 'ru' ? 'Нет новых уведомлений' : 'No new notifications';
            this.showNotification(msg, 'info');
        });

        const profileBtn = document.getElementById('btn-profile');
        const profileDropdown = document.getElementById('profile-dropdown');

        if (profileBtn && profileDropdown) {
            profileBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                profileDropdown.classList.toggle('active');
            });

            document.addEventListener('click', (e) => {
                if (!profileBtn.contains(e.target) && !profileDropdown.contains(e.target)) {
                    profileDropdown.classList.remove('active');
                }
            });

            document.getElementById('logout-btn-dropdown')?.addEventListener('click', () => {
                this.handleLogout();
            });

            document.getElementById('settings-btn-dropdown')?.addEventListener('click', () => {
                this.navigateTo('settings');
                profileDropdown?.classList.remove('active');
            });
        }
    }

    async handleUpdateAdminProfile() {
        const email = document.getElementById('admin-profile-email').value;
        const password = document.getElementById('admin-profile-password').value;

        if (!email) {
            this.showNotification('Email обязателен', 'error');
            return;
        }

        try {
            await api.updateAdminProfile(email, password);
            this.showNotification('Профиль администратора обновлен', 'success');
            localStorage.setItem('whispera_email', email);
            document.getElementById('admin-profile-password').value = '';
        } catch (error) {
            this.showNotification('Ошибка обновления профиля: ' + error.message, 'error');
        }
    }

    async handleAddUser() {
        const email = document.getElementById('new-user-email').value;
        const password = document.getElementById('new-user-password').value;
        const trafficLimit = parseInt(document.getElementById('new-user-traffic').value) || 0;
        const expiryDate = document.getElementById('new-user-expiry').value || null;

        const obfsProfile = document.getElementById('new-user-obfs').value;
        const marionetteProfile = document.getElementById('new-user-marionette').value;
        const russianService = document.getElementById('new-user-russian').value;
        const transport = Array.from(document.querySelectorAll('input[name="transport-cb"]:checked')).map(i => i.value).join(',') || 'tcp';
        const sni = document.getElementById('new-user-sni')?.value || '';
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

            if (portVal > 0) {
                const serverTransports = new Set(['tcp', 'udp', 'ws', 'httpupgrade', 'h2c', 'grpc', 'shadowtls', 'shadowsocks']);
                const existingInbounds = this._cachedInbounds || [];
                const transportSecurity = {
                    tcp: 'phantom', udp: 'phantom', ws: 'phantom',
                    httpupgrade: 'phantom', h2c: 'phantom', grpc: 'phantom',
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
                        const usesPhantom = security === 'phantom';
                        const tag = transports.length > 1 ? `inbound-${portVal}-${tr}` : `inbound-${portVal}`;
                        try {
                            await api.addInbound({
                                tag,
                                protocol: 'whispera',
                                port: portVal,
                                stream_settings: {
                                    network: tr,
                                    security,
                                    phantom: usesPhantom ? { server_names: sni ? [sni] : [] } : undefined,
                                }
                            });
                        } catch (e) {
                            console.warn(`Auto-create inbound ${tag} failed:`, e.message);
                        }
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
                        sni: sni || undefined,
                        russianService,
                    };
                    if (portVal > 0) keyOpts.port = portVal;
                    const tc = this.collectTransportConfig();
                    if (tc) keyOpts.transportConfig = tc;
                    const keyRes = await api.generateConnectionKey(keyOpts);
                    const userId = res.user?.id;
                    if (userId && keyRes.key) {
                        api.updateUser(userId, { connectionURI: keyRes.key }).catch(() => {});
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
    }

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

        const phantomTransports = new Set(['tcp', 'udp', 'ws', 'httpupgrade', 'grpc', 'h2c']);
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
        };
        const sniGroup = document.getElementById('inbound-sni-group');
        const paramsGroup = document.getElementById('inbound-params-group');
        const paramsLabel = document.getElementById('inbound-params-label');
        const paramsHint = document.getElementById('inbound-params-hint');
        const paramsTA = document.querySelector('[name="params_json"]');
        if (phantomTransports.has(transport)) {
            sniGroup.style.display = '';
            paramsGroup.style.display = 'none';
        } else {
            sniGroup.style.display = 'none';
            paramsGroup.style.display = '';
            const info = paramsTransports[transport] || { label: 'Параметры (JSON)', hint: '', placeholder: '{}' };
            paramsLabel.textContent = info.label;
            paramsHint.textContent = info.hint;
            if (paramsTA) paramsTA.placeholder = info.placeholder;
        }
    }

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
    }

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
    }

    collectTransportConfig() {
        const result = {};
        document.querySelectorAll('.tcfg-field').forEach(el => {
            const v = el.value.trim();
            if (v) result[el.dataset.key] = isNaN(v) ? v : (v.includes('.') ? parseFloat(v) : parseInt(v));
        });
        return Object.keys(result).length > 0 ? result : null;
    }

    async handleAddInbound() {
        const form = document.getElementById('add-inbound-form');
        const raw = Object.fromEntries(new FormData(form));
        const transport = raw.transport || 'tcp';
        const phantomTransports = new Set(['tcp', 'udp', 'ws', 'httpupgrade', 'grpc', 'h2c']);
        const usesPhantom = phantomTransports.has(transport);
        const serverNames = raw.server_names
            ? raw.server_names.split(',').map(s => s.trim()).filter(Boolean)
            : [];
        let params = {};
        if (!usesPhantom && raw.params_json) {
            try { params = JSON.parse(raw.params_json); } catch { params = {}; }
        }
        const data = {
            tag: raw.tag,
            protocol: raw.protocol,
            port: parseInt(raw.port),
            stream_settings: {
                network: transport,
                security: usesPhantom ? 'phantom' : 'none',
                phantom: usesPhantom ? { server_names: serverNames } : undefined,
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
    }

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
    }

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
    }

    async handleAddRoutingRule() {
        const form = document.getElementById('add-routing-form');
        const data = Object.fromEntries(new FormData(form));

        const rule = {
            type: data.type,
            condition: data.value,
            outbound: data.outboundTag,
            priority: 0
        };

        try {
            await api.addRoutingRule(rule);
            this.closeModals();
            this.loadRouting();
            this.showNotification('Правило добавлено', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }

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
    }

    async handleAddAdblockRule() {
        const form = document.getElementById('add-adblock-form');
        const data = Object.fromEntries(new FormData(form));

        try {
            await api.addAdblockRule(data);
            this.closeModals();
            this.loadAdblock();
            this.showNotification('Правило блокировки добавлено', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }


    async _loadProbeStats() {
        try {
            const s = await api.getProbeStats();
            const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
            set('probe-stat-blocked', s.blocked_ips ?? '—');
            set('probe-stat-tracked', s.tracked_ips ?? '—');
            set('probe-stat-dns',     s.require_dns   ? `вкл (лог: ${s.dns_log_size ?? 0})` : 'выкл');
            set('probe-stat-sni',     s.check_sni_own ? `вкл (${(s.own_ips ?? []).join(', ')})` : 'выкл');
        } catch (e) {
        }
    }

    _updateStealthHint(mode) {
        const hint = document.getElementById('stealth-mode-hint');
        if (!hint) return;
        if (mode === 'russia') {
            hint.innerHTML = '<b>🇷🇺 Россия:</b> VK WebRTC → Яндекс.Телемост → ОК WebRTC → VK Bot → CDN Worker → остальные.<br>Приоритет — транспорты через российскую инфраструктуру, блокировка которых невозможна без масштабных коллатеральных потерь.';
            hint.style.borderColor = 'rgba(239,68,68,0.4)';
            hint.style.background = 'rgba(239,68,68,0.06)';
        } else {
            hint.innerHTML = '<b>Авто:</b> Все доступные транспорты конкурируют в параллельном режиме. Побеждает первый успешно установивший соединение.';
            hint.style.borderColor = 'rgba(99,102,241,0.2)';
            hint.style.background = 'rgba(99,102,241,0.08)';
        }
    }

    async handleSaveServerSettings() {
        const port = document.getElementById('server-port').value;
        const domain = document.getElementById('server-domain').value;
        const email = document.getElementById('admin-contact').value;
        const publicURL = (document.getElementById('public-url')?.value || '').trim();

        localStorage.setItem('whispera_domain', domain);
        localStorage.setItem('whispera_admin_email', email);

        try {
            await api.request('/api/v1/config/update', {
                method: 'POST',
                body: JSON.stringify({
                    server: { port: parseInt(port) || 0, public_url: publicURL }
                })
            });
            this.showNotification('Настройки успешно сохранены', 'success');
        } catch (error) {
            this.showNotification('Ошибка сохранения: ' + error.message, 'error');
        }
    }

    handleThemeChange(theme) {
        localStorage.setItem('whispera_theme', theme);
        const root = document.documentElement;

        if (theme === 'midnight') {
            root.style.setProperty('--md-sys-color-background', '#0f172a');
            root.style.setProperty('--md-sys-color-surface', 'rgba(30, 41, 59, 0.7)');
            root.style.setProperty('--md-sys-color-surface-container-low', 'rgba(30, 41, 59, 0.6)');
            root.style.setProperty('--md-sys-color-surface-container', 'rgba(51, 65, 85, 0.6)');
            root.style.setProperty('--md-sys-color-primary', '#38bdf8');
            root.style.setProperty('--md-sys-color-secondary-container', 'rgba(56, 189, 248, 0.15)');
        } else if (theme === 'amoled') {
            root.style.setProperty('--md-sys-color-background', '#000000');
            root.style.setProperty('--md-sys-color-surface', '#000000');
            root.style.setProperty('--md-sys-color-surface-container-low', '#0a0a0a');
            root.style.setProperty('--md-sys-color-surface-container', '#121212');
            root.style.setProperty('--md-sys-color-primary', '#ffffff');
            root.style.setProperty('--md-sys-color-secondary-container', '#333333');
            root.style.setProperty('--glass-blur-lg', 'none');
            root.style.setProperty('--glass-blur-md', 'none');
        } else {
            root.style.removeProperty('--md-sys-color-background');
            root.style.removeProperty('--md-sys-color-surface');
            root.style.removeProperty('--md-sys-color-surface-container-low');
            root.style.removeProperty('--md-sys-color-surface-container');
            root.style.removeProperty('--md-sys-color-primary');
            root.style.removeProperty('--md-sys-color-secondary-container');
            root.style.removeProperty('--glass-blur-lg');
            root.style.removeProperty('--glass-blur-md');
        }
        this.showNotification('Тема обновлена', 'success');
    }

    async handleDownloadBackup() {
        try {
            const data = await api.getBackup();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `whispera - backup - ${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            this.showNotification('Скачивание началось', 'success');
        } catch (error) {
            this.showNotification('Ошибка создания бэкапа: ' + error.message, 'error');
        }
    }

    async handleRestoreBackup(event) {
        const file = event.target.files[0];
        if (!file) return;

        if (await this.showConfirm('Восстановление перезапишет текущие настройки. Продолжить?')) {
            try {
                await api.restoreBackup(file);
                this.showNotification('Настройки восстановлены! Перезагрузка...', 'success');
                setTimeout(() => window.location.reload(), 2000);
            } catch (error) {
                this.showNotification('Ошибка восстановления: ' + error.message, 'error');
            }
        }
        event.target.value = '';
    }

    handleLogout() {
        api.logout();
        document.getElementById('login-form')?.reset();
        this.showLogin();
    }

    showLogin() {
        document.getElementById('login-screen').classList.add('active');
        document.getElementById('main-app').classList.remove('active');
    }

    showMainApp() {
        document.getElementById('login-screen').classList.remove('active');
        document.getElementById('main-app').classList.add('active');
    }

    navigateTo(page) {
        localStorage.setItem('whispera_page', page);
        if (this.threeCity) {
            try { this.threeCity.onNavigate(page); } catch (e) {}
        }

        if (page !== 'bridges') this._stopBridgeAutoRefresh();

        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
        const navItem = document.querySelector(`.nav-item[data-page="${page}"]`);
        if (navItem) navItem.classList.add('active');

        document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
        const pageEl = document.getElementById(`page-${page}`);
        if (pageEl) {
            pageEl.classList.add('active');

            const titleMap = {
                'dashboard': 'page.dashboard.title',
                'users': 'page.users.title',
                'sessions': 'page.sessions.title',
                'inbounds': 'page.inbounds.title',
                'outbounds': 'page.outbounds.title',
                'routing': 'page.routing.title',
                'subscriptions': 'page.subscriptions.title',
                'adblock': 'page.adblock.title',
                'bridges': 'page.bridges.title',
                'bridge-map': 'nav.bridge_map',
                'logs': 'page.logs.title',
                'settings': 'settings.title'
            };
            const key = titleMap[page] || 'page.dashboard.title';
            const lang = localStorage.getItem('whispera_lang') || 'ru';
            const dict = this.translations[lang] || this.translations['ru'];
            document.getElementById('page-title').textContent = dict[key] || key;
            document.getElementById('page-title').dataset.i18n = key;
        }

        switch (page) {
            case 'dashboard': this.loadDashboard(); break;
            case 'users': this.loadUsers(); break;
            case 'sessions': this.loadSessions(); break;
            case 'inbounds': this.loadInbounds(); break;
            case 'outbounds': this.loadOutbounds(); break;
            case 'bridges': this.loadBridges(); break;
            case 'bridge-map': this.loadBridgeMap(); break;
            case 'routing': this.loadRouting(); break;
            case 'subscriptions': this.loadSubscriptions(); break;
            case 'adblock': this.loadAdblock(); break;
            case 'settings': this.loadSettings(); break;
            case 'logs': this.loadLogs(); break;
        }
    }

    async loadDashboard() {
        try {
            const [stats, info] = await Promise.all([
                api.getStats().catch(() => ({})),
                api.getSystemInfo().catch(() => ({})),
            ]);

            document.getElementById('stat-users').textContent = stats.total_users || 0;
            document.getElementById('stat-sessions').textContent = stats.active_sessions || 0;
            document.getElementById('stat-upload').textContent = this.formatBytes(stats.total_upload || 0);
            document.getElementById('stat-download').textContent = this.formatBytes(stats.total_download || 0);

            document.getElementById('stat-memory').textContent = info.memory_usage || '-';
            document.getElementById('stat-cpu').textContent = info.cpu_load != null ? info.cpu_load.toFixed(1) + '%' : '-';

            document.getElementById('server-version').textContent = info.version || '-';
            document.getElementById('server-ip').textContent = info.server_ip || '-';
            document.getElementById('server-uptime').textContent = this.formatUptime(info.uptime || 0);
            document.getElementById('server-os').textContent = info.os || '-';
            document.getElementById('server-arch').textContent = info.arch || '-';

            this.updateTrafficChart(stats.total_download || 0, stats.total_upload || 0);

        } catch (error) {
            console.error('Dashboard load error:', error);
        }
    }

    async loadSettings() {
        const domain = localStorage.getItem('whispera_domain') || '';
        const email = localStorage.getItem('whispera_admin_email') || '';
        const theme = localStorage.getItem('whispera_theme') || 'dark';
        const lang = localStorage.getItem('whispera_lang') || 'ru';

        if (document.getElementById('server-domain')) document.getElementById('server-domain').value = domain;
        if (document.getElementById('admin-contact')) document.getElementById('admin-contact').value = email;
        if (document.getElementById('panel-theme')) document.getElementById('panel-theme').value = theme;
        if (document.getElementById('panel-language')) document.getElementById('panel-language').value = lang;

        this.initCustomSelects();

        const loginEmail = localStorage.getItem('whispera_email') || '';
        if (document.getElementById('admin-profile-email')) document.getElementById('admin-profile-email').value = loginEmail;

        try {
            const info = await api.getSystemInfo();
            if (info.server_port && document.getElementById('server-port')) {
                document.getElementById('server-port').value = info.server_port;
            }
            if (info.ssl_expiry) {
                const sslExpiry = document.getElementById('ssl-expiry');
                if (sslExpiry) sslExpiry.textContent = info.ssl_expiry;
            }
            if (info.ssl_status) {
                const sslStatus = document.getElementById('ssl-status');
                if (sslStatus) sslStatus.textContent = info.ssl_status === 'active' ? 'Активен' : 'Нет сертификата';
            }
        } catch (e) {
            console.log('Failed to load system info for settings');
        }

        try {
            const cfg = await api.request('/api/v1/config');
            const sel = document.getElementById('stealth-mode-select');
            if (sel) {
                sel.value = cfg.stealth_mode || '';
                this._updateStealthHint(sel.value);
            }
            const puInput = document.getElementById('public-url');
            if (puInput) puInput.value = cfg.public_url || '';
        } catch (e) {
            console.log('Failed to load stealth mode / config');
        }

        this._loadProbeStats();
    }

    initTrafficChart() {
        const ctx = document.getElementById('traffic-chart').getContext('2d');
        this.trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(10).fill(''),
                datasets: [{
                    label: 'Download',
                    data: Array(10).fill(0),
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Upload',
                    data: Array(10).fill(0),
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8' }
                    }
                },
                scales: {
                    y: {
                        grid: { color: '#334155' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { display: false }
                    }
                },
                animation: { duration: 800, easing: 'easeOutQuart' }
            }
        });
    }

    updateTrafficChart(download, upload) {
        if (!this.trafficChart) this.initTrafficChart();

        const data = this.trafficChart.data;

        data.datasets[0].data.shift();
        data.datasets[1].data.shift();

        data.datasets[0].data.push(download);
        data.datasets[1].data.push(upload);

        this.trafficChart.update();
    }

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
                    <td>${i.tag}</td>
                    <td>${i.protocol}</td>
                    <td>${allPorts}</td>
                    <td>${network}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="app.deleteInbound('${i.tag}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    }


    async loadBridges() {
        this._stopBridgeAutoRefresh();
        await Promise.all([this._fetchBridgeStats(), this._fetchBridgeList(), this._fetchBridgeToken()]);
        this._startBridgeAutoRefresh();
    }

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
    }

    _stopBridgeAutoRefresh() {
        if (this._bridgeRefreshTimer) {
            clearInterval(this._bridgeRefreshTimer);
            this._bridgeRefreshTimer = null;
        }
    }

    async _fetchBridgeStats() {
        try {
            const s = await api.getBridgeStats();
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
            set('bstat-total',   s.total   ?? '—');
            set('bstat-alive',   s.alive   ?? '—');
            set('bstat-dead',    s.dead    ?? '—');
            set('bstat-latency', s.avg_latency ? s.avg_latency + ' мс' : '—');
        } catch {}
    }

    async _fetchBridgeList() {
        const tbody = document.getElementById('bridges-tbody');
        if (!tbody) return;
        try {
            const data = await api.getBridgesAdmin();
            const bridges = Array.isArray(data) ? data : (data.bridges || []);
            if (!bridges.length) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:#555;padding:32px;">Мостов нет. Добавьте первый мост.</td></tr>';
                return;
            }
            tbody.innerHTML = bridges.map(b => this._renderBridgeRow(b)).join('');
            tbody.querySelectorAll('.bridge-check-btn').forEach(btn => {
                btn.addEventListener('click', () => this._checkBridge(btn.dataset.id, btn));
            });
            tbody.querySelectorAll('.bridge-delete-btn').forEach(btn => {
                btn.addEventListener('click', () => this._deleteBridge(btn.dataset.id));
            });
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:#f87171;padding:32px;">Ошибка загрузки: ${e.message}</td></tr>`;
        }
    }

    _renderBridgeRow(b) {
        const alive = b.is_alive ?? b.IsAlive ?? false;
        const latency = b.latency_ms ?? b.Latency ?? 0;
        const trust = b.trust_level ?? b.TrustLevel ?? 0;
        const region = b.region || b.Region || '—';
        const type = b.type || b.Type || '—';
        const address = b.address || b.Address || '—';
        const id = b.id || b.ID || '';
        const shortID = id.length > 8 ? id.slice(0, 8) + '…' : id;
        const lastCheck = b.last_check || b.LastCheck;
        const lastCheckStr = lastCheck ? this._relativeTime(new Date(lastCheck)) : '—';

        const statusDot = alive
            ? '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#4ade80;" title="Онлайн"></span>'
            : '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#f87171;" title="Недоступен"></span>';

        const latencyColor = latency === 0 ? '#555' : latency < 100 ? '#4ade80' : latency < 300 ? '#facc15' : '#f87171';
        const latencyStr = latency > 0 ? `<span style="color:${latencyColor}">${latency} мс</span>` : '<span style="color:#555">—</span>';

        const typeBadge = {
            operator:  '<span style="background:rgba(99,102,241,0.2);color:#a5b4fc;padding:2px 7px;border-radius:4px;font-size:0.8em;">operator</span>',
            community: '<span style="background:rgba(34,197,94,0.15);color:#86efac;padding:2px 7px;border-radius:4px;font-size:0.8em;">community</span>',
            user:      '<span style="background:rgba(234,179,8,0.15);color:#fde047;padding:2px 7px;border-radius:4px;font-size:0.8em;">user</span>',
        }[type] || `<span style="color:#888;font-size:0.85em;">${type}</span>`;

        const trustBar = `<div style="display:flex;align-items:center;gap:6px;">
            <div style="width:48px;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden;">
                <div style="width:${trust}%;height:100%;background:${trust>=70?'#4ade80':trust>=40?'#facc15':'#f87171'};border-radius:3px;"></div>
            </div>
            <span style="font-size:0.82em;color:#aaa;">${trust}</span>
        </div>`;

        return `<tr data-bridge-id="${id}">
            <td style="text-align:center;">${statusDot}</td>
            <td><code style="font-size:0.85em;" title="${id}">${shortID}</code></td>
            <td style="font-size:0.87em;">${address}</td>
            <td style="font-size:0.87em;">${region}</td>
            <td>${typeBadge}</td>
            <td>${latencyStr}</td>
            <td>${trustBar}</td>
            <td style="font-size:0.82em;color:#888;">${lastCheckStr}</td>
            <td style="text-align:right;">
                <button class="btn btn-icon btn-sm bridge-check-btn" data-id="${id}" title="Проверить сейчас">
                    <i class="fas fa-stethoscope"></i>
                </button>
                <button class="btn btn-icon btn-sm bridge-delete-btn" data-id="${id}" title="Удалить" style="color:#f87171;">
                    <i class="fas fa-trash-alt"></i>
                </button>
            </td>
        </tr>`;
    }

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
                row.cells[7].textContent = 'только что';
            }
            await this._fetchBridgeStats();
        } catch (e) {
            this.showNotification('Ошибка проверки: ' + e.message, 'error');
        } finally {
            icon.className = orig;
            btn.disabled = false;
        }
    }

    async _deleteBridge(id) {
        if (!await this.showConfirm('Удалить мост ' + id + '?')) return;
        try {
            await api.deleteBridge(id);
            this.showNotification('Мост удалён', 'success');
            await Promise.all([this._fetchBridgeStats(), this._fetchBridgeList()]);
        } catch (e) {
            this.showNotification('Ошибка: ' + e.message, 'error');
        }
    }

    async _fetchBridgeToken() {
        try {
            const data = await api.getBridgeToken();
            const el = document.getElementById('bridge-reg-token');
            if (el) el.textContent = data.token || '—';
            this._updateCurlCmd(data.token);
        } catch {}
    }

    _updateCurlCmd(token) {
        const el = document.getElementById('bridge-curl-cmd');
        if (!el) return;
        const base = window.location.origin;
        el.textContent =
            `curl -s -X POST ${base}/api/bridge-register \\\n` +
            `  -H "Content-Type: application/json" \\\n` +
            `  -d '{"token":"${token || 'TOKEN'}","address":"1.2.3.4:443","region":"ru","type":"community"}'`;
    }

    _relativeTime(date) {
        const diff = Math.floor((Date.now() - date.getTime()) / 1000);
        if (diff < 5)   return 'только что';
        if (diff < 60)  return diff + ' сек. назад';
        if (diff < 3600) return Math.floor(diff / 60) + ' мин. назад';
        if (diff < 86400) return Math.floor(diff / 3600) + ' ч. назад';
        return Math.floor(diff / 86400) + ' д. назад';
    }


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
    }

    _renderBridgeMapCanvas(bridges) {
        requestAnimationFrame(() => this._doRenderBridgeMap(bridges));
    }

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
    }

    _lonToX(lon, w) { return ((lon + 180) / 360) * w; }
    _latToY(lat, h) { return ((90 - lat) / 180) * h; }

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
    }

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
                <td>${b.country || '?'}, ${b.city || '?'}</td>
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
    }

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
                configModal.className = 'modal active';
                configModal.innerHTML = `
                    <div class="modal-content" style="max-width:500px;">
                        <div class="modal-header"><h3>Конфигурация подключения</h3></div>
                        <div class="modal-body">
                            <pre style="background:rgba(0,0,0,0.3);padding:12px;border-radius:8px;font-size:0.82em;overflow-x:auto;color:#7ef7c8;">${configStr}</pre>
                            <p style="font-size:0.82em;color:#888;margin-top:8px;">Используйте эти данные в клиенте Whisp для подключения.</p>
                        </div>
                        <div class="modal-footer">
                            <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Закрыть</button>
                            <button class="btn btn-primary" onclick="navigator.clipboard.writeText(\`${configStr.replace(/`/g, '\\`')}\`);this.textContent='Скопировано!';">Копировать</button>
                        </div>
                    </div>`;
                document.body.appendChild(configModal);
            }
        } catch (e) {
            this.showNotification('Ошибка подключения: ' + e.message, 'error');
        }
    }

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
                    ? o.chain.map(h => `<span style="background:rgba(0,229,255,0.1);color:#00e5ff;padding:1px 6px;border-radius:3px;font-size:11px;margin:1px;">${h}</span>`).join(' → ')
                    : '<span style="color:#555;">—</span>';
                return `<tr>
                    <td>${o.tag}</td>
                    <td>${o.protocol}</td>
                    <td>${o.address || '-'}</td>
                    <td>${chain}</td>
                    <td>${o.latency ? o.latency + 'ms' : '-'}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="app.deleteOutbound('${o.tag}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">Ошибка загрузки</td></tr>';
        }
    }

    async loadRouting() {
        const tbody = document.getElementById('routing-table-body');
        try {
            const data = await api.getRoutingRules();
            const rules = data.rules || data || [];

            if (rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет правил маршрутизации</td></tr>';
                return;
            }

            tbody.innerHTML = rules.map(r => `
    <tr>
                    <td>${r.type}</td>
                    <td>${r.domain || r.ip || '-'}</td>
                    <td>${r.outboundTag}</td>
                    <td>${r.priority || 0}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="app.deleteRoutingRule('${r.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    }

    async loadSubscriptions() {
        const tbody = document.getElementById('subscriptions-table-body');
        try {
            const data = await api.getSubscriptions();
            const subs = data.subscriptions || data || [];

            if (subs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет подписок</td></tr>';
                return;
            }

            tbody.innerHTML = subs.map(s => `
                <tr>
                    <td>${s.name}</td>
                    <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        <span title="${s.sub_url || ''}">${s.sub_url || '-'}</span>
                    </td>
                    <td>${(s.transports || []).join(', ') || 'все'}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${s.sub_url || ''}').then(()=>app.showNotification('URL скопирован','success'))" title="Копировать URL">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="app.deleteSubscription('${s.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    }

    async loadAdblock() {
        const tbody = document.getElementById('adblock-table-body');
        try {
            const [stats, rulesData] = await Promise.all([
                api.getAdblockStats().catch(() => ({})),
                api.getAdblockRules().catch(() => ({ rules: [] }))
            ]);

            document.getElementById('stat-adblock-total').textContent = stats.total_blocked || 0;
            document.getElementById('stat-adblock-dns').textContent = stats.dns_blocked || 0;
            document.getElementById('stat-adblock-https').textContent = stats.https_blocked || 0;

            const rules = rulesData.rules || [];
            if (rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center">Нет правил блокировки</td></tr>';
                return;
            }

            tbody.innerHTML = rules.map(r => `
    <tr>
                    <td>${r.domain}</td>
                    <td>${r.type}</td>
                    <td><span class="status ${r.enabled ? 'active' : 'inactive'}">${r.enabled ? 'Вкл' : 'Выкл'}</span></td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="app.deleteAdblockRule('${r.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">Ошибка загрузки</td></tr>';
        }
    }

    async loadUsers() {
        const tbody = document.getElementById('users-table-body');
        try {
            const data = await api.getUsers();
            const users = data.users || [];
            this._usersById = {};
            users.forEach(u => { this._usersById[u.id] = u; });

            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center">Нет пользователей</td></tr>';
                return;
            }

            tbody.innerHTML = users.map(user => `
    <tr>
          <td>${user.username || '-'}</td>
          <td>${user.trafficLimit ? (user.trafficLimit / 1073741824).toFixed(0) + ' GB' : 'Free'}</td>
          <td>${this.formatBytes(user.upload || 0)} / ${this.formatBytes(user.download || 0)}</td>
          <td><span class="status ${user.status === 'active' ? 'active' : 'inactive'}">${user.status === 'active' ? 'Active' : 'Inactive'}</span></td>
          <td>
            <div style="display: flex; align-items: center; gap: 5px;">
                <input type="text" value="${user.publicKey || '-'}" readonly style="width: 120px; font-size: 0.85em; border: 1px solid var(--md-sys-color-outline); background: var(--md-sys-color-surface-container-highest); color: var(--md-sys-color-on-surface); padding: 4px 8px; border-radius: 4px;">
                <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${user.publicKey || ''}').then(() => app.showNotification('Key copied', 'success'))" style="padding: 4px 8px;" title="Копировать публичный ключ">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
          </td>
          <td>
            <div style="display: flex; gap: 4px;">
                ${user.privateKey ? `<button class="btn btn-secondary btn-sm" onclick="app.generateKeyForUser(${user.id})" style="padding: 4px 8px;" title="Получить ключ подключения">
                    <i class="fas fa-key"></i>
                </button>` : ''}
                <button class="btn btn-secondary btn-sm" onclick="app.showEditUserModal(${user.id})" style="padding: 4px 8px;" title="Редактировать">
                    <i class="fas fa-pen"></i>
                </button>
                <button class="btn btn-danger btn-sm" onclick="app.deleteUser('${user.id}')" title="Удалить">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
          </td>
        </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">Ошибка загрузки</td></tr>';
        }
    }

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
    }

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
        modal.className = 'modal active';
        modal.style.zIndex = '10000';
        modal.innerHTML = `
        <div class="modal-content" style="max-width:460px;">
            <div class="modal-header">
                <h3>Редактировать пользователя</h3>
                <button class="modal-close modal-close-icon" onclick="this.closest('.modal').remove()"><i class="fas fa-times"></i></button>
            </div>
            <div class="modal-body" style="display:flex;flex-direction:column;gap:2px;">
                ${field('Email', `<input id="eu-username" class="form-control" type="text" value="${user.username || ''}">`)}
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
                ${field('Профиль обфускации', `
                    <select id="eu-obfs" class="form-control">
                        <option value=""    ${!user.obfsProfile                  ? 'selected' : ''}>По умолчанию</option>
                        <option value="vk"  ${user.obfsProfile === 'vk'          ? 'selected' : ''}>VK</option>
                        <option value="ok"  ${user.obfsProfile === 'ok'          ? 'selected' : ''}>OK</option>
                        <option value="yt"  ${user.obfsProfile === 'yt'          ? 'selected' : ''}>YouTube</option>
                    </select>`)}
                ${field('Российский сервис (ASN bypass)', `
                    <select id="eu-russian" class="form-control">
                        <option value=""           ${!user.russianService                    ? 'selected' : ''}>Авто</option>
                        <option value="vk"         ${user.russianService === 'vk'            ? 'selected' : ''}>VK</option>
                        <option value="ok"         ${user.russianService === 'ok'            ? 'selected' : ''}>Одноклассники</option>
                        <option value="yandex"     ${user.russianService === 'yandex'        ? 'selected' : ''}>Яндекс</option>
                        <option value="wildberries"${user.russianService === 'wildberries'   ? 'selected' : ''}>Wildberries</option>
                    </select>`)}
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Отмена</button>
                <button class="btn btn-primary" onclick="app.saveUserEdit(${userId}, this.closest('.modal'))">Сохранить</button>
            </div>
        </div>`;
        document.body.appendChild(modal);
    }

    async saveUserEdit(userId, modal) {
        const username = modal.querySelector('#eu-username').value.trim();
        const status   = modal.querySelector('#eu-status').value;
        const trafficGB = parseFloat(modal.querySelector('#eu-traffic').value) || 0;
        const expiryDate = modal.querySelector('#eu-expiry').value;
        const obfsProfile = modal.querySelector('#eu-obfs').value;
        const russianService = modal.querySelector('#eu-russian').value;

        if (!username) { this.showNotification('Email не может быть пустым', 'error'); return; }

        try {
            await api.updateUser(userId, {
                username,
                status,
                trafficLimit: Math.round(trafficGB * 1073741824),
                expiryDate: expiryDate || '',
                obfsProfile,
                russianService,
            });
            modal.remove();
            this.showNotification('Пользователь обновлён', 'success');
            this.loadUsers();
        } catch (err) {
            this.showNotification('Ошибка: ' + err.message, 'error');
        }
    }

    async loadSessions() {
        const tbody = document.getElementById('sessions-table-body');
        try {
            const data = await api.getSessions();
            const sessions = data.sessions || [];

            if (sessions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет активных сессий</td></tr>';
                return;
            }

            tbody.innerHTML = sessions.map(s => `
    <tr>
          <td>${s.user_id || '-'}</td>
          <td>${s.client_ip || '-'}</td>
          <td>${this.formatTime(s.connected_at)}</td>
          <td>${this.formatBytes(s.bytes_in || 0)} / ${this.formatBytes(s.bytes_out || 0)}</td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="app.killSession('${s.id}')">
              <i class="fas fa-times"></i>
            </button>
          </td>
        </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    }

    async loadLogs() {
        const container = document.getElementById('logs-container');
        container.textContent = 'Загрузка логов...';
        try {
            const data = await api.getLogs(200);
            const logs = data.logs || data || [];
            if (logs.length === 0) {
                container.textContent = 'Нет доступных логов.';
            } else {
                container.textContent = logs.join('\n');
            }
        } catch (error) {
            container.textContent = 'Ошибка загрузки логов: ' + error.message;
        }
    }

    async deleteUser(id) {
        if (!(await this.showConfirm('Удалить пользователя?'))) return;
        try {
            await api.deleteUser(id);
            this.loadUsers();
            this.showNotification('Пользователь удален', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }

    async killSession(id) {
        if (!(await this.showConfirm('Завершить сессию?'))) return;
        try {
            await api.killSession(id);
            this.loadSessions();
            this.showNotification('Сессия завершена', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }

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

    async deleteRoutingRule(id) {
        if (!(await this.showConfirm('Удалить правило?'))) return;
        try {
            await api.deleteRoutingRule(id);
            this.loadRouting();
            this.showNotification('Правило удалено', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }

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

    async deleteAdblockRule(id) {
        if (!(await this.showConfirm('Удалить правило блокировки?'))) return;
        try {
            await api.deleteAdblockRule(id);
            this.loadAdblock();
            this.showNotification('Правило удалено', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }

    showModal(id) {
        document.getElementById(id)?.classList.add('active');
        const modal = document.getElementById(id);
        if (modal) {
            this.initCustomSelects();
        }
    }

    closeModals() {
        document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
    }

    showNotification(message, type = 'info') {
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notification-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `toast ${type} `;

        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            info: 'info-circle',
            warning: 'exclamation-triangle'
        };
        const iconName = icons[type] || 'info-circle';

        toast.innerHTML = `
    <div class="toast-icon"><i class="fas fa-${iconName}"></i></div>
            <div class="toast-content">${message}</div>
            <button class="toast-close" onclick="this.parentElement.remove()"><i class="fas fa-times"></i></button>
`;

        const close = () => {
            if (toast.parentElement) {
                toast.classList.add('hiding');
                toast.addEventListener('animationend', () => {
                    if (toast.parentElement) toast.remove();
                });
            }
        };

        toast.querySelector('.toast-close').onclick = close;

        setTimeout(close, 5000);

        container.appendChild(toast);
    }

    async showFirewallModal() {
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.style.zIndex = '10000';
        modal.innerHTML = `
        <div class="modal-content" style="max-width:680px;">
            <div class="modal-header">
                <h3><i class="fas fa-fire-alt" style="margin-right:8px;color:#f59e0b;"></i>Управление Firewall (UFW)</h3>
                <button class="modal-close modal-close-icon" onclick="this.closest('.modal').remove()"><i class="fas fa-times"></i></button>
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
                <button class="btn btn-secondary btn-sm" onclick="this.closest('.modal').remove()">Закрыть</button>
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
                            <button onclick="app._firewallDeleteRule(${r.number})" class="btn btn-danger btn-sm" style="padding:0 10px;height:30px;font-size:12px;" title="Удалить правило">
                                <i class="fas fa-trash"></i>
                            </button>
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
    }

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

    showKeyModal(email, privKey, connectionURI) {
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.style.zIndex = '10000';

        const uri = connectionURI || privKey;
        const uriEsc = uri.replace(/'/g, "\\'").replace(/"/g, '&quot;');
        const pkEsc = privKey.replace(/'/g, "\\'").replace(/"/g, '&quot;');

        const copyBtn = (text, label) => `
            <div class="form-group">
                <label style="font-size:0.8em;text-transform:uppercase;opacity:0.7;letter-spacing:0.05em;">${label}</label>
                <div style="display:flex;gap:6px;align-items:center;">
                    <input type="text" value="${text}" readonly
                        style="flex:1;font-family:monospace;font-size:0.82em;padding:8px 10px;
                               background:var(--bg-secondary,#1a1a2e);border:1px solid var(--border,#333);
                               border-radius:6px;color:inherit;min-width:0;">
                    <button onclick="navigator.clipboard.writeText('${text}').then(()=>app.showNotification('Скопировано','success'))"
                        style="flex-shrink:0;padding:8px 12px;border-radius:6px;border:none;
                               background:var(--accent,#6366f1);color:#fff;cursor:pointer;font-size:13px;">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </div>`;

        modal.innerHTML = `
    <div class="modal-content" style="max-width:540px;">
        <div class="modal-header">
            <h3>Пользователь создан</h3>
            <button class="modal-close modal-close-icon" onclick="this.closest('.modal').remove()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body" style="display:flex;flex-direction:column;gap:4px;">
            <p style="margin:0 0 8px;">Пользователь: <strong>${email}</strong></p>
            ${connectionURI ? copyBtn(uriEsc, 'Ключ подключения (импортируйте в клиент)') : copyBtn(pkEsc, 'Приватный ключ')}
            ${connectionURI ? `<div id="key-modal-qr-wrap" style="display:flex;flex-direction:column;align-items:center;gap:6px;margin:8px 0;">
                <img id="key-modal-qr" style="border-radius:8px;background:#fff;padding:8px;width:220px;height:220px;" />
                <span style="font-size:0.78em;opacity:0.5;">Сканируйте QR-кодом в клиенте</span>
            </div>` : ''}
            ${connectionURI && privKey ? `
            <div style="margin-top:4px;padding:10px 12px;background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.25);border-radius:8px;">
                <div style="font-size:0.78em;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;opacity:0.7;margin-bottom:6px;">
                    <i class="fas fa-brain" style="margin-right:4px;color:#6366f1;"></i>ML Токен (для режима ML в клиенте)
                </div>
                <div style="display:flex;gap:6px;align-items:center;">
                    <input type="text" value="${pkEsc}" readonly
                        style="flex:1;font-family:monospace;font-size:0.78em;padding:6px 10px;
                               background:var(--bg-secondary,#1a1a2e);border:1px solid rgba(99,102,241,0.3);
                               border-radius:6px;color:inherit;min-width:0;">
                    <button onclick="navigator.clipboard.writeText('${pkEsc}').then(()=>app.showNotification('ML токен скопирован','success'))"
                        style="flex-shrink:0;padding:6px 10px;border-radius:6px;border:none;
                               background:rgba(99,102,241,0.3);color:#fff;cursor:pointer;font-size:12px;">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
                <div style="font-size:0.75em;opacity:0.5;margin-top:4px;">Вставьте в поле «ML Токен» в разделе Режим ML клиента whisp</div>
            </div>` : ''}
            <p style="margin-top:4px;font-size:0.82em;opacity:0.6;">
                <i class="fas fa-info-circle"></i> Ключ содержит все параметры подключения. Сохраните — он больше не будет показан.
            </p>
        </div>
        <div class="modal-footer">
            <button class="btn btn-primary" onclick="this.closest('.modal').remove()">Готово</button>
        </div>
    </div>`;
        document.body.appendChild(modal);

        if (connectionURI) {
            setTimeout(() => {
                const img = modal.querySelector('#key-modal-qr');
                const qrWrap = modal.querySelector('#key-modal-qr-wrap');
                if (img) {
                    fetch('/api/qr?data=' + encodeURIComponent(connectionURI))
                        .then(r => r.json())
                        .then(d => {
                            if (d.url) {
                                img.src = d.url;
                            } else if (qrWrap) {
                                qrWrap.innerHTML = '<span style="font-size:0.8em;opacity:0.5;text-align:center;">QR недоступен — скопируйте ключ вручную</span>';
                            }
                        })
                        .catch(() => {
                            if (qrWrap) qrWrap.innerHTML = '<span style="font-size:0.8em;opacity:0.5;text-align:center;">QR недоступен — скопируйте ключ вручную</span>';
                        });
                }
            }, 0);
        }
    }

    showConfirm(message) {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'modal active';
            modal.style.zIndex = '10000';

            const lang = localStorage.getItem('whispera_lang') || 'ru';
            const textYes = lang === 'ru' ? 'Да' : 'Yes';
            const textNo = lang === 'ru' ? 'Отмена' : 'Cancel';
            const title = lang === 'ru' ? 'Подтверждение' : 'Confirmation';

            modal.innerHTML = `
    <div class="modal-content" style="max-width: 400px;">
                    <div class="modal-header" style="border-bottom: none; padding-bottom: 8px;">
                        <h3 style="margin: 0; font-size: 20px;">${title}</h3>
                    </div>
                    <div class="modal-body" style="padding: 0 24px 24px; font-size: 16px; color: var(--md-sys-color-on-surface-variant); line-height: 1.5;">
                        ${message}
                    </div>
                    <div class="modal-footer" style="padding: 8px 24px 24px; display: flex; justify-content: flex-end; gap: 12px; border-top: none;">
                        <button class="btn btn-secondary" id="confirm-cancel">${textNo}</button>
                        <button class="btn btn-danger" id="confirm-ok">${textYes}</button>
                    </div>
                </div>
    `;

            document.body.appendChild(modal);

            const cleanup = () => {
                modal.classList.remove('active');
                setTimeout(() => modal.remove(), 250);
            };

            modal.querySelector('#confirm-cancel').onclick = () => {
                cleanup();
                resolve(false);
            };

            modal.querySelector('#confirm-ok').onclick = () => {
                cleanup();
                resolve(true);
            };

            modal.onclick = (e) => {
                if (e.target === modal) {
                    cleanup();
                    resolve(false);
                }
            };
        });
    }

    toggleSidebar() {
        const sidebar = document.querySelector('.sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    }

    closeSidebar() {
        const sidebar = document.querySelector('.sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    formatUptime(seconds) {
        if (!seconds) return '-';
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        if (days > 0) return `${days}д ${hours} ч`;
        if (hours > 0) return `${hours}ч ${mins} м`;
        return `${mins} м`;
    }

    formatTime(isoString) {
        if (!isoString) return '-';
        return new Date(isoString).toLocaleString('ru-RU');
    }
}

class CustomSelect {
    constructor(selectElement) {
        this.select = selectElement;
        this.select.classList.add('custom-select-hidden');
        this.select.style.display = 'none';

        this.wrapper = document.createElement('div');
        this.wrapper.className = 'custom-select-wrapper';
        this.select.parentNode.insertBefore(this.wrapper, this.select);
        this.wrapper.appendChild(this.select);

        this.customSelect = document.createElement('div');
        this.customSelect.className = 'custom-select';
        this.wrapper.appendChild(this.customSelect);

        this.trigger = document.createElement('div');
        this.trigger.className = 'custom-select-trigger';
        this.trigger.innerHTML = `<span>${this.select.options[this.select.selectedIndex]?.text || ''}</span>`;
        this.customSelect.appendChild(this.trigger);

        this.options = document.createElement('div');
        this.options.className = 'custom-options';
        document.body.appendChild(this.options);

        this.setupOptions();
        this.bindEvents();
    }

    setupOptions() {
        this.options.innerHTML = '';
        for (const option of this.select.options) {
            const customOption = document.createElement('span');
            customOption.className = `custom-option ${option.selected ? 'selected' : ''}`;
            customOption.dataset.value = option.value;
            customOption.textContent = option.text;
            customOption.addEventListener('click', () => {
                this.select.value = option.value;
                this.select.dispatchEvent(new Event('change'));
                this.trigger.querySelector('span').textContent = option.text;
                this.close();
                this.options.querySelectorAll('.custom-option').forEach(opt => opt.classList.remove('selected'));
                customOption.classList.add('selected');
            });
            this.options.appendChild(customOption);
        }
    }

    updatePosition() {
        const rect = this.trigger.getBoundingClientRect();
        const spaceBelow = window.innerHeight - rect.bottom;
        const spaceAbove = rect.top;
        const dropdownHeight = Math.min(this.options.scrollHeight, 300);

        this.options.style.width = `${rect.width}px`;
        this.options.style.left = `${rect.left}px`;

        if (spaceBelow < dropdownHeight && spaceAbove > spaceBelow) {
            this.options.style.top = `${rect.top - dropdownHeight - 8}px`;
            this.options.style.transformOrigin = 'bottom left';
        } else {
            this.options.style.top = `${rect.bottom + 8}px`;
            this.options.style.transformOrigin = 'top left';
        }
    }

    open() {
        document.querySelectorAll('.custom-select').forEach(s => s.classList.remove('open'));
        document.querySelectorAll('.custom-options').forEach(o => {
            if (o !== this.options) {
                o.style.opacity = '0';
                o.style.visibility = 'hidden';
                o.style.pointerEvents = 'none';
            }
        });

        this.customSelect.classList.add('open');
        this.updatePosition();
        this.options.style.opacity = '1';
        this.options.style.visibility = 'visible';
        this.options.style.pointerEvents = 'all';

        this.resizeListener = () => {
            if (this.customSelect.classList.contains('open')) this.updatePosition();
        };
        window.addEventListener('resize', this.resizeListener);
        window.addEventListener('scroll', this.resizeListener, true);
    }

    close() {
        this.customSelect.classList.remove('open');
        this.options.style.opacity = '0';
        this.options.style.visibility = 'hidden';
        this.options.style.pointerEvents = 'none';
        if (this.resizeListener) {
            window.removeEventListener('resize', this.resizeListener);
            window.removeEventListener('scroll', this.resizeListener, true);
        }
    }

    bindEvents() {
        this.trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            if (this.customSelect.classList.contains('open')) {
                this.close();
            } else {
                this.open();
            }
        });

        document.addEventListener('click', (e) => {
            if (!this.wrapper.contains(e.target) && !this.options.contains(e.target)) {
                this.close();
            }
        });
    }
}

window.app = new WhisperaApp();
