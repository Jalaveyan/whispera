
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::Manager;

mod go_client;
mod mihomo;
mod ml_server;

use go_client::{GoClientConfig, GoClientManager};
use mihomo::MihomoManager;
use ml_server::MlServerManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutingRule {
    id: String,
    kind: String,
    value: String,
    action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppSettings {
    conn_key: String,
    auto_connect: bool,
    theme: String,
    mihomo_port: u16,
    socks_addr: String,
    kill_switch: bool,
    #[serde(default)]
    dns_redirect: bool,
    #[serde(default = "default_true")]
    ipv6: bool,
    #[serde(default = "default_tun")]
    tun_stack: String,
    #[serde(default = "default_true")]
    hwid: bool,
    #[serde(default = "default_true")]
    auth_tip: bool,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    routing_rules: Vec<RoutingRule>,
    #[serde(default)]
    ml_transport: String,
    #[serde(default)]
    ml_server: String,
    #[serde(default)]
    ml_token: String,
}

fn default_true() -> bool {
    true
}
fn default_tun() -> String {
    "Mixed".to_string()
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            conn_key: String::new(),
            auto_connect: false,
            theme: "dark".to_string(),
            mihomo_port: 9887,
            socks_addr: "127.0.0.1:1080".to_string(),
            kill_switch: false,
            dns_redirect: false,
            ipv6: true,
            tun_stack: "Mixed".to_string(),
            hwid: true,
            auth_tip: true,
            secret: String::new(),
            routing_rules: Vec::new(),
            ml_transport: String::new(),
            ml_server: String::new(),
            ml_token: String::new(),
        }
    }
}

struct AppState {
    mihomo: Mutex<MihomoManager>,
    go_client: Mutex<GoClientManager>,
    ml_server: Mutex<MlServerManager>,
}

fn settings_path(app: &tauri::AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_config_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    fs::create_dir_all(&dir).ok();
    dir.join("settings.json")
}

fn mihomo_config_path(app: &tauri::AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_config_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    fs::create_dir_all(&dir).ok();
    dir.join("mihomo_config.yaml")
}

#[tauri::command]
fn get_app_settings(app: tauri::AppHandle) -> Result<AppSettings, String> {
    let path = settings_path(&app);
    if path.exists() {
        let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let settings: AppSettings = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        Ok(settings)
    } else {
        Ok(AppSettings::default())
    }
}

#[tauri::command]
fn save_app_setting(app: tauri::AppHandle, mut settings: AppSettings) -> Result<(), String> {
    let path = settings_path(&app);
    if path.exists() {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(existing) = serde_json::from_str::<AppSettings>(&raw) {
                settings.routing_rules = existing.routing_rules;
                settings.ml_transport = existing.ml_transport;
                settings.ml_server = existing.ml_server;
                settings.ml_token = existing.ml_token;
            }
        }
    }
    let data = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(&path, data).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn connect(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut settings = get_app_settings(app.clone())?;

    if settings.conn_key.is_empty() {
        return Err("Connection key is required (whispera://...)".to_string());
    }

    let socks_addr = if settings.socks_addr.contains(':') {
        settings.socks_addr.clone()
    } else {
        format!("{}:1080", settings.socks_addr)
    };

    let ml_transport = {
        let host = settings.conn_key
            .trim_start_matches("whispera://")
            .split('?').next().unwrap_or("")
            .split(':').next().unwrap_or("")
            .to_string();

        if !host.is_empty() {
            let ml_c = ml_client();
            match ml_request(&ml_c, reqwest::Method::POST, &ml_url("/recommend/transport"))
                .timeout(Duration::from_secs(3))
                .json(&serde_json::json!({ "server_host": host, "server_port": 8443 }))
                .send()
                .await
            {
                Ok(resp) => resp.json::<serde_json::Value>().await
                    .ok()
                    .and_then(|j| j["transport"].as_str().map(|s| s.to_string()))
                    .unwrap_or_default(),
                Err(_) => String::new(),
            }
        } else {
            String::new()
        }
    };

    if !ml_transport.is_empty() {
        settings.ml_transport = ml_transport.clone();
        let path = settings_path(&app);
        if let Ok(data) = serde_json::to_string_pretty(&settings) {
            fs::write(&path, data).ok();
        }
    }

    let transport_to_use = if !ml_transport.is_empty() { &ml_transport } else { "" };

    let mut gc = state.go_client.lock().map_err(|e| e.to_string())?;
    gc.start(&GoClientConfig {
        conn_key: &settings.conn_key,
        server_addr: "",
        ml_token: "",
        socks_addr: &socks_addr,
        kill_switch: settings.kill_switch,
        transport: transport_to_use,
    })?;

    let config_path = mihomo_config_path(&app);
    let routing_rules: Vec<mihomo::MihomoRoutingRule> = settings
        .routing_rules
        .iter()
        .map(|r| mihomo::MihomoRoutingRule {
            kind: r.kind.clone(),
            value: r.value.clone(),
            action: r.action.clone(),
        })
        .collect();

    let mihomo_config = mihomo::generate_config(&mihomo::MihomoConfig {
        socks_addr: &socks_addr,
        mixed_port: settings.mihomo_port,
        tun_stack: &settings.tun_stack,
        dns_redirect: settings.dns_redirect,
        ipv6: settings.ipv6,
        routing_rules: &routing_rules,
    });
    fs::write(&config_path, &mihomo_config).map_err(|e| e.to_string())?;

    let mut mgr = state.mihomo.lock().map_err(|e| e.to_string())?;
    mgr.start(&config_path)?;

    Ok(format!(
        "Connected via key (socks5: {}) | mihomo port {}",
        settings.socks_addr, settings.mihomo_port
    ))
}

#[tauri::command]
async fn connect_ml(
    app: tauri::AppHandle,
    server: String,
    token: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    if server.is_empty() {
        return Err("Server address required (host:port)".to_string());
    }

    let settings = get_app_settings(app.clone())?;
    let socks_addr = if settings.socks_addr.contains(':') {
        settings.socks_addr.clone()
    } else {
        format!("{}:1080", settings.socks_addr)
    };

    let host = server.split(':').next().unwrap_or(&server).to_string();
    let port: u16 = server.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(8443);
    let ml_c2 = ml_client();
    let ml_transport = match ml_request(&ml_c2, reqwest::Method::POST, &ml_url("/recommend/transport"))
        .timeout(Duration::from_secs(3))
        .json(&serde_json::json!({ "server_host": host, "server_port": port }))
        .send()
        .await
    {
        Ok(resp) => resp.json::<serde_json::Value>().await
            .ok()
            .and_then(|j| j["transport"].as_str().map(|s| s.to_string()))
            .unwrap_or_default(),
        Err(_) => String::new(),
    };

    let path = settings_path(&app);
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(mut s) = serde_json::from_str::<AppSettings>(&raw) {
            s.ml_server = server.clone();
            s.ml_token = token.clone();
            s.ml_transport = ml_transport.clone();
            if let Ok(data) = serde_json::to_string_pretty(&s) { fs::write(&path, data).ok(); }
        }
    }

    let transport_ref: &str = &ml_transport;

    let mut gc = state.go_client.lock().map_err(|e| e.to_string())?;
    gc.start(&GoClientConfig {
        conn_key: "",
        server_addr: &server,
        ml_token: &token,
        socks_addr: &socks_addr,
        kill_switch: settings.kill_switch,
        transport: transport_ref,
    })?;

    Ok(format!("ML connected to {} via {}", server, if ml_transport.is_empty() { "tcp" } else { &ml_transport }))
}

#[tauri::command]
fn disconnect(state: tauri::State<AppState>) -> Result<String, String> {
    let mut mihomo = state.mihomo.lock().map_err(|e| e.to_string())?;
    mihomo.stop()?;

    let mut gc = state.go_client.lock().map_err(|e| e.to_string())?;
    gc.stop()?;

    Ok("Disconnected".to_string())
}

#[tauri::command]
fn get_status(state: tauri::State<AppState>) -> Result<bool, String> {
    let mut mihomo = state.mihomo.lock().map_err(|e| e.to_string())?;
    let mut gc = state.go_client.lock().map_err(|e| e.to_string())?;
    Ok(mihomo.is_running() && gc.is_running())
}

#[derive(Serialize)]
struct SiteCheckResult {
    status: u16,
    ping_ms: u64,
}

#[tauri::command]
async fn check_site(url: String) -> Result<SiteCheckResult, String> {
    let host = url
        .replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    if host.is_empty() {
        return Err("Invalid URL".to_string());
    }

    let addr = format!("{}:443", host);
    let start = std::time::Instant::now();

    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_stream)) => {
            let ping = start.elapsed().as_millis() as u64;
            Ok(SiteCheckResult {
                status: 200,
                ping_ms: ping,
            })
        }
        Ok(Err(e)) => Err(format!("Connect failed: {}", e)),
        Err(_) => Err("Timeout".to_string()),
    }
}

#[derive(Serialize)]
struct IpInfoResponse {
    ip: String,
    city: String,
    region: String,
    country: String,
    org: String,
    loc: String,
}

#[tauri::command]
async fn get_ip_info() -> Result<IpInfoResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get("https://ipinfo.io/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

    Ok(IpInfoResponse {
        ip: json["ip"].as_str().unwrap_or("—").to_string(),
        city: json["city"].as_str().unwrap_or("—").to_string(),
        region: json["region"].as_str().unwrap_or("—").to_string(),
        country: json["country"].as_str().unwrap_or("—").to_string(),
        org: json["org"].as_str().unwrap_or("—").to_string(),
        loc: json["loc"].as_str().unwrap_or("").to_string(),
    })
}

#[derive(Serialize)]
struct SystemInfoResponse {
    os: String,
    uptime: String,
    version: String,
    admin: bool,
}

#[tauri::command]
fn get_system_info() -> Result<SystemInfoResponse, String> {
    let os_info = format!("Windows ({})", std::env::consts::ARCH);

    let uptime_ms = winapi_uptime();
    let uptime_secs = uptime_ms / 1000;
    let hours = uptime_secs / 3600;
    let minutes = (uptime_secs % 3600) / 60;
    let uptime = format!("{}h {}m", hours, minutes);

    let admin = is_elevated();

    Ok(SystemInfoResponse {
        os: os_info,
        uptime,
        version: "v0.1.3".to_string(),
        admin,
    })
}

fn winapi_uptime() -> u64 {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetTickCount64() -> u64;
        }
        unsafe { GetTickCount64() }
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("net")
            .arg("session")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[tauri::command]
fn open_config_dir(app: tauri::AppHandle) -> Result<(), String> {
    let dir = app
        .path()
        .app_config_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    fs::create_dir_all(&dir).ok();
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(dir.to_string_lossy().to_string())
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", &url])
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn get_ml_transport(app: tauri::AppHandle) -> Result<String, String> {
    Ok(get_app_settings(app)?.ml_transport)
}

#[tauri::command]
fn get_routing_rules(app: tauri::AppHandle) -> Result<Vec<RoutingRule>, String> {
    let settings = get_app_settings(app)?;
    Ok(settings.routing_rules)
}

#[tauri::command]
async fn save_routing_rules(app: tauri::AppHandle, rules: Vec<RoutingRule>) -> Result<(), String> {
    let path = settings_path(&app);
    let mut settings = get_app_settings(app.clone())?;
    settings.routing_rules = rules;
    let data = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(&path, &data).map_err(|e| e.to_string())?;

    let config_path = mihomo_config_path(&app);
    let socks_addr = if settings.socks_addr.contains(':') {
        settings.socks_addr.clone()
    } else {
        format!("{}:1080", settings.socks_addr)
    };
    let routing_rules: Vec<mihomo::MihomoRoutingRule> = settings
        .routing_rules
        .iter()
        .map(|r| mihomo::MihomoRoutingRule {
            kind: r.kind.clone(),
            value: r.value.clone(),
            action: r.action.clone(),
        })
        .collect();
    let mihomo_config = mihomo::generate_config(&mihomo::MihomoConfig {
        socks_addr: &socks_addr,
        mixed_port: settings.mihomo_port,
        tun_stack: &settings.tun_stack,
        dns_redirect: settings.dns_redirect,
        ipv6: settings.ipv6,
        routing_rules: &routing_rules,
    });
    fs::write(&config_path, &mihomo_config).map_err(|e| e.to_string())?;

    let config_str = config_path.to_string_lossy().replace('\\', "/");
    let _ = reqwest::Client::new()
        .put("http://127.0.0.1:9090/configs?force=true")
        .json(&serde_json::json!({ "path": config_str }))
        .timeout(Duration::from_secs(3))
        .send()
        .await;

    Ok(())
}

#[tauri::command]
fn install_services(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
) -> Result<String, String> {
    let settings = get_app_settings(app.clone())?;
    let config_path = mihomo_config_path(&app);

    if !config_path.exists() {
        let stub = mihomo::generate_config(&mihomo::MihomoConfig {
            socks_addr: &settings.socks_addr,
            mixed_port: settings.mihomo_port,
            tun_stack: &settings.tun_stack,
            dns_redirect: settings.dns_redirect,
            ipv6: settings.ipv6,
            routing_rules: &[],
        });
        fs::write(&config_path, &stub).ok();
    }

    let socks_addr = if settings.socks_addr.contains(':') {
        settings.socks_addr.clone()
    } else {
        format!("{}:1080", settings.socks_addr)
    };

    {
        let mihomo_mgr = state.mihomo.lock().map_err(|e| e.to_string())?;
        mihomo_mgr.install_service(&config_path)?;
    }
    {
        let gc_mgr = state.go_client.lock().map_err(|e| e.to_string())?;
        gc_mgr.install_service(&go_client::GoClientConfig {
            conn_key: &settings.conn_key,
            server_addr: "",
            ml_token: "",
            socks_addr: &socks_addr,
            kill_switch: settings.kill_switch,
            transport: &settings.ml_transport,
        })?;
    }

    Ok("Services installed: WhisperaNH, WhisperaGW".to_string())
}


fn read_ml_api_token() -> String {
    let path = if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(|a| format!(r"{}\Whispera\api_token", a))
            .unwrap_or_default()
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .map(|h| format!("{}/Library/Application Support/Whispera/api_token", h))
            .unwrap_or_default()
    } else {
        std::env::var("XDG_CONFIG_HOME")
            .map(|x| format!("{}/whispera/api_token", x))
            .unwrap_or_else(|_| {
                std::env::var("HOME")
                    .map(|h| format!("{}/.config/whispera/api_token", h))
                    .unwrap_or_default()
            })
    };
    if path.is_empty() { return String::new(); }
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn ml_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn ml_url(path: &str) -> String {
    format!("https://127.0.0.1:8000{}", path)
}

fn ml_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
) -> reqwest::RequestBuilder {
    let token = read_ml_api_token();
    let req = client.request(method, url);
    if token.is_empty() {
        req
    } else {
        req.header("Authorization", format!("Bearer {}", token))
    }
}

#[tauri::command]
async fn get_ml_status(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    // First check managed subprocess
    {
        let mut ml = state.ml_server.lock().map_err(|e| e.to_string())?;
        if ml.is_running() {
            return Ok(true);
        }
    }
    // Fallback: health check (covers externally started server)
    let ok = ml_client()
        .get(ml_url("/health"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    Ok(ok)
}

#[tauri::command]
fn start_ml_server(state: tauri::State<AppState>) -> Result<String, String> {
    let mut ml = state.ml_server.lock().map_err(|e| e.to_string())?;
    ml.start()?;
    Ok("ML server started".to_string())
}

#[tauri::command]
fn stop_ml_server(state: tauri::State<AppState>) -> Result<String, String> {
    let mut ml = state.ml_server.lock().map_err(|e| e.to_string())?;
    ml.stop()?;
    Ok("ML server stopped".to_string())
}

#[tauri::command]
fn get_ml_logs(state: tauri::State<AppState>) -> Result<String, String> {
    let ml = state.ml_server.lock().map_err(|e| e.to_string())?;
    Ok(ml.get_log_tail(150))
}

#[tauri::command]
fn ml_binary_exists(state: tauri::State<AppState>) -> Result<bool, String> {
    let ml = state.ml_server.lock().map_err(|e| e.to_string())?;
    Ok(ml.binary_exists())
}

#[tauri::command]
async fn ml_rank_bridges(bridges_json: String) -> Result<String, String> {
    let client = ml_client();

    let resp = ml_request(&client, reqwest::Method::POST, &ml_url("/rank/bridges"))
        .timeout(Duration::from_secs(5))
        .header("Content-Type", "application/json")
        .body(bridges_json)
        .send()
        .await
        .map_err(|e| format!("ML server unavailable: {}", e))?;

    resp.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn ml_analyze_network(host: String, port: u16) -> Result<String, String> {
    let client = ml_client();

    let body = serde_json::json!({ "host": host, "port": port });

    let resp = ml_request(&client, reqwest::Method::POST, &ml_url("/network/analyze"))
        .timeout(Duration::from_secs(15))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("ML server unavailable: {}", e))?;

    resp.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn ml_recommend_transport(server_host: String, server_port: u16) -> Result<String, String> {
    let client = ml_client();

    let body = serde_json::json!({ "server_host": server_host, "server_port": server_port });

    let resp = ml_request(&client, reqwest::Method::POST, &ml_url("/recommend/transport"))
        .timeout(Duration::from_secs(15))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("ML server unavailable: {}", e))?;

    resp.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
fn uninstall_services(state: tauri::State<AppState>) -> Result<String, String> {
    {
        let mut mihomo_mgr = state.mihomo.lock().map_err(|e| e.to_string())?;
        mihomo_mgr.uninstall_service()?;
    }
    {
        let mut gc_mgr = state.go_client.lock().map_err(|e| e.to_string())?;
        gc_mgr.uninstall_service()?;
    }
    Ok("Services removed".to_string())
}

fn main() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let mihomo_path = exe_dir.join("mihomo.exe");
    let go_client_path = exe_dir.join("whispera-go-client.exe");

    #[cfg(dev)]
    let ml_server_path = PathBuf::from("__dev_mode__/whispera-ml-server.exe");

    #[cfg(not(dev))]
    let ml_server_path = {
        let candidate = exe_dir.join("whispera-ml-server.exe");
        if candidate.exists() {
            candidate
        } else {
            exe_dir.join("_up_").join("whispera-ml-server.exe")
        }
    };
    let ml_log_path = exe_dir.join("ml-server.log");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState {
            mihomo: Mutex::new(MihomoManager::new(mihomo_path)),
            go_client: Mutex::new(GoClientManager::new(go_client_path)),
            ml_server: Mutex::new(MlServerManager::new(ml_server_path, ml_log_path)),
        })
        .setup(|app| {
            #[cfg(not(dev))]
            {
                let state: tauri::State<AppState> = app.state();
                if let Ok(mut ml) = state.ml_server.lock() {
                    ml.start().ok();
                };
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let app = window.app_handle();
                let state: tauri::State<AppState> = app.state();
                state.mihomo.lock().ok().map(|mut m| m.stop().ok());
                state.go_client.lock().ok().map(|mut gc| gc.stop().ok());
                state.ml_server.lock().ok().map(|mut ml| ml.stop().ok());
                window.close().ok();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_app_settings,
            save_app_setting,
            connect,
            disconnect,
            get_status,
            check_site,
            get_ip_info,
            get_system_info,
            open_config_dir,
            open_url,
            install_services,
            uninstall_services,
            get_routing_rules,
            save_routing_rules,
            get_ml_transport,
            connect_ml,
            get_ml_status,
            start_ml_server,
            stop_ml_server,
            get_ml_logs,
            ml_binary_exists,
            ml_rank_bridges,
            ml_analyze_network,
            ml_recommend_transport,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
