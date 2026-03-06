
class ThreeCity {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;

        const EffectComposer = THREE.EffectComposer || window.EffectComposer;
        const RenderPass = THREE.RenderPass || window.RenderPass;
        const UnrealBloomPass = THREE.UnrealBloomPass || window.UnrealBloomPass;

        if (!EffectComposer || !RenderPass) {
            console.error("❌ Three.js Post-processing classes MISSING!");
            document.title = "ERR: Three.js Modules";
        } else {
            document.title = "Whispera: 3D City Active";
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

        this.bindEvents();





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
                if (element.tagName === 'INPUT' && element.getAttribute('placeholder')) {
                    element.placeholder = dictionary[key];
                } else {
                    element.textContent = dictionary[key];
                }
            }
        });

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
                document.getElementById('login-screen').classList.remove('active');
                this.loadDashboard();
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
            });
        });

        document.getElementById('logout-btn')?.addEventListener('click', () => {
            api.logout();
            this.showLogin();
        });

        document.getElementById('add-user-btn')?.addEventListener('click', () => {
            this.showModal('add-user-modal');
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

        document.getElementById('add-inbound-btn')?.addEventListener('click', () => this.showModal('add-inbound-modal'));
        document.getElementById('add-inbound-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddInbound();
        });
        document.querySelector('[name="transport"]')?.addEventListener('change', (e) => {
            this.onInboundTransportChange(e.target.value);
        });

        document.getElementById('add-outbound-btn')?.addEventListener('click', () => this.showModal('add-outbound-modal'));
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
            this.showNotification('Управление Firewall будет доступно в версии 1.1', 'info');
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
        const id = localStorage.getItem('whispera_user_id');
        if (!id) {
            this.showNotification('Ошибка: ID пользователя не найден. Попробуйте перезайти.', 'error');
            return;
        }

        const email = document.getElementById('admin-profile-email').value;
        const password = document.getElementById('admin-profile-password').value;

        if (!email) {
            this.showNotification('Email обязателен', 'error');
            return;
        }

        try {
            await api.updateUser(id, { email, password });
            this.showNotification('Профиль администратора обновлен', 'success');

            localStorage.setItem('whispera_email', email);

            document.getElementById('admin-profile-password').value = '';
        } catch (error) {
            this.showNotification('Ошибка обновления профиля: ' + error.message, 'error');
        }
    }

    async handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            await api.login(username, password);
            this.showMainApp();
            this.loadDashboard();
        } catch (error) {
            this.showNotification('Неверный логин или пароль', 'error');
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

        try {
            const res = await api.createUser(email, password, trafficLimit, expiryDate, {
                obfsProfile,
                marionetteProfile,
                russianService
            });
            this.closeModals();
            this.loadUsers();

            if (res.user && res.user.private_key) {
                this.showKeyModal(res.user.email, res.user.private_key);
            } else {
                this.showNotification('Пользователь создан', 'success');
            }
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }

    onInboundTransportChange(transport) {
        const phantomTransports = new Set(['tcp', 'udp', 'ws', 'splithttp', 'httpupgrade', 'grpc', 'h2c']);
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

    async handleAddInbound() {
        const form = document.getElementById('add-inbound-form');
        const raw = Object.fromEntries(new FormData(form));
        const transport = raw.transport || 'tcp';
        const phantomTransports = new Set(['tcp', 'udp', 'ws', 'splithttp', 'httpupgrade', 'grpc', 'h2c']);
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

        try {
            await api.addOutbound(data);
            this.closeModals();
            this.loadOutbounds();
            this.showNotification('Сервер добавлен', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
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


    async handleSaveServerSettings() {
        const port = document.getElementById('server-port').value;
        const domain = document.getElementById('server-domain').value;
        const email = document.getElementById('admin-contact').value;

        localStorage.setItem('whispera_domain', domain);
        localStorage.setItem('whispera_admin_email', email);

        try {
            await api.updateServerSettings({ port, domain, email });
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

    showLogin() {
        document.getElementById('login-screen').classList.add('active');
        document.getElementById('main-app').classList.remove('active');
    }

    showMainApp() {
        document.getElementById('login-screen').classList.remove('active');
        document.getElementById('main-app').classList.add('active');
    }

    navigateTo(page) {
        if (this.threeCity) {
            this.threeCity.onNavigate(page);
        }

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
                'logs': 'page.logs.title',
                'settings': 'settings.title'
            };
            const key = titleMap[page] || 'page.dashboard.title';
            document.getElementById('page-title').textContent = this.t(key);
            document.getElementById('page-title').dataset.i18n = key;
        }

        switch (page) {
            case 'dashboard': this.loadDashboard(); break;
            case 'users': this.loadUsers(); break;
            case 'sessions': this.loadSessions(); break;
            case 'inbounds': this.loadInbounds(); break;
            case 'outbounds': this.loadOutbounds(); break;
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

            document.getElementById('stat-memory').textContent = info.memory_usage || '0 MiB';
            document.getElementById('stat-cpu').textContent = (info.cpu_load || 0) + '%';

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

        const loginEmail = localStorage.getItem('whispera_email') || '';
        if (document.getElementById('admin-profile-email')) document.getElementById('admin-profile-email').value = loginEmail;

        try {
            const info = await api.getSystemInfo();
            if (info.port && document.getElementById('server-port')) {
                document.getElementById('server-port').value = info.port;
            }
        } catch (e) {
            console.log('Failed to load system info for settings');
        }
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

            tbody.innerHTML = inbounds.map(i => `
    <tr>
                    <td>${i.tag}</td>
                    <td>${i.protocol}</td>
                    <td>${i.port}</td>
                    <td>${i.streamSettings?.network || 'tcp'}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="app.deleteInbound('${i.tag}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    }

    async loadOutbounds() {
        const tbody = document.getElementById('outbounds-table-body');
        try {
            const data = await api.getOutbounds();
            const outbounds = data.outbounds || data || [];

            if (outbounds.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет исходящих серверов</td></tr>';
                return;
            }

            tbody.innerHTML = outbounds.map(o => `
    <tr>
                    <td>${o.tag}</td>
                    <td>${o.protocol}</td>
                    <td>${o.address || '-'}</td>
                    <td>${o.latency ? o.latency + 'ms' : '-'}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="app.deleteOutbound('${o.tag}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
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

            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет пользователей</td></tr>';
                return;
            }

            tbody.innerHTML = users.map(user => `
    <tr>
          <td>${user.email || user.name || '-'}</td>
          <td>${user.plan_name || 'Free'}</td>
          <td>${this.formatBytes(user.bytes_in || 0)} / ${this.formatBytes(user.bytes_out || 0)}</td>
          <td><span class="status ${user.is_active ? 'active' : 'inactive'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
          <td>
            <div style="display: flex; align-items: center; gap: 5px;">
                <input type="text" value="${user.private_key || '-'}" readonly style="width: 120px; font-size: 0.85em; border: 1px solid var(--md-sys-color-outline); background: var(--md-sys-color-surface-container-highest); color: var(--md-sys-color-on-surface); padding: 4px 8px; border-radius: 4px;">
                <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${user.private_key || ''}').then(() => app.showNotification('Key copied', 'success'))" style="padding: 4px 8px;">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
          </td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="app.deleteUser('${user.id}')">
              <i class="fas fa-trash"></i>
            </button>
          </td>
        </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
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

    async loadSettings() {
    }

    async loadLogs() {
        const container = document.getElementById('logs-container');
        container.textContent = 'Загрузка логов...';
        try {
            const data = await api.getLogs();
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

    showKeyModal(email, key) {
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.style.zIndex = '10000';

        const lang = localStorage.getItem('whispera_lang') || 'ru';
        const title = lang === 'ru' ? 'Пользователь создан' : 'User Created';
        const label = lang === 'ru' ? 'Приватный ключ (Сохраните его!):' : 'Private Key (Save this!):';
        const note = lang === 'ru' ? 'Этот ключ требуется для настройки клиента.' : 'This key is required to configure the client.';
        const done = lang === 'ru' ? 'Готово' : 'Done';

        modal.innerHTML = `
    <div class="modal-content" style="max-width: 500px;">
                <div class="modal-header">
                    <h3>${title}</h3>
                    <button class="modal-close modal-close-icon" onclick="this.closest('.modal').remove()"><i class="fas fa-times"></i></button>
                </div>
                <div class="modal-body">
                    <p style="margin-bottom: 10px;">User: <strong>${email}</strong></p>
                    <div class="form-group">
                        <label>${label}</label>
                        <div class="input-group">
                            <input type="text" value="${key}" readonly class="form-control" style="font-family: monospace; font-size: 1.1em;">
                            <button class="btn btn-primary" onclick="navigator.clipboard.writeText('${key}').then(() => app.showNotification('Key copied', 'success'))">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    </div>
                    <div style="margin-top: 15px; font-size: 0.9em; opacity: 0.8;">
                        <p><i class="fas fa-info-circle"></i> ${note}</p>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="this.closest('.modal').remove()">${done}</button>
                </div>
            </div>
    `;
        document.body.appendChild(modal);
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
