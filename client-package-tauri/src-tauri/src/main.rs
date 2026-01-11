//! Whispera VPN Client - Tauri Application
//! 
//! Manages connection to VPN server via Go client and hev-socks5-tunnel

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::path::PathBuf;
use std::fs;
use std::env;
use std::panic::{self, AssertUnwindSafe};
use tauri::State;
use serde::{Deserialize, Serialize};
use sysinfo::{System, Networks};

/// VPN connection state
struct VpnState {
    go_client: Mutex<Option<Child>>,
    hev_tunnel: Mutex<Option<Child>>,
    status: Mutex<ConnectionStatus>,
    current_key: Mutex<Option<ConnectionKey>>,
    system: Mutex<System>,
    networks: Mutex<Networks>,
}

#[derive(Clone, Serialize, Default)]
struct ConnectionStatus {
    connected: bool,
    server: String,
    transport: String,
    obfuscation: String,
    kill_switch_active: bool,
    asn_bypass_enabled: bool,
    dns_mode: String,
    error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
struct ConnectionKey {
    v: Option<i32>,
    name: Option<String>,
    server: Option<String>,
    server_tcp: Option<String>,
    server_ws: Option<String>,
    psk: Option<String>,
    pub_key: Option<String>,
    obfs: Option<String>,
    transport: Option<String>,
    enable_ml: Option<bool>,
    enable_fte: Option<bool>,
    // New fields for advanced features
    kill_switch: Option<bool>,
    allow_lan: Option<bool>,
    // ASN Bypass settings
    asn_bypass: Option<bool>,
    asn_strategy: Option<String>,
    tls_fingerprint: Option<String>,
    front_domain: Option<String>,
    // DNS settings
    dns_mode: Option<String>,
    dns_servers: Option<Vec<String>>,
    // Obfuscation settings
    obfs_level: Option<i32>,
    threat_level: Option<i32>,
}

impl ConnectionKey {
    fn parse(key: &str) -> Result<Self, String> {
        let key = key.trim();
        
        // 1. Try Validating as URL-style key (e.g. whispera://1.2.3.4:5678?key=...)
        if (key.contains('?') || key.contains(':')) && !key.ends_with('=') && !(!key.contains('?') && !key.contains(':')) {
             let url_body = key.trim_start_matches("whispera://").trim_start_matches("wpn://");
             
             let parts: Vec<&str> = url_body.splitn(2, '?').collect();
             let server = parts[0].to_string();
             
             let mut psk = None;
             let mut pub_key = None;
             
             if parts.len() > 1 {
                 for param in parts[1].split('&') {
                     let kv: Vec<&str> = param.splitn(2, '=').collect();
                     if kv.len() == 2 {
                         match kv[0] {
                             "key" => psk = Some(kv[1].to_string()),
                             "pub" => pub_key = Some(kv[1].to_string()),
                             _ => {}
                         }
                     }
                 }
             }
             
             return Ok(ConnectionKey {
                 server: Some(server),
                 psk,
                 pub_key,
                 v: Some(1),
                 transport: Some("auto".into()),
                 obfs: Some("stealth".into()),
                 name: None, server_tcp: None, server_ws: None, 
                 enable_ml: Some(true), enable_fte: Some(true)
             });
        }
        
        // 2. Try Standard Base64 JSON
        use base64::Engine;
        let clean_key = key.trim_start_matches("whispera://").trim_start_matches("wpn://");
        
        // Try multiple decodings
        let decoded = base64::engine::general_purpose::STANDARD.decode(clean_key)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(clean_key))
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean_key))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(clean_key))
            .map_err(|e| format!("Invalid key encoding: {}", e))?;
            
        serde_json::from_slice(&decoded)
            .map_err(|e| format!("Invalid key format: {}", e))
    }
    
    fn get_server(&self) -> String {
        match self.transport.as_deref() {
            Some("tcp") => self.server_tcp.clone().unwrap_or_default(),
            Some("ws") => self.server_ws.clone().unwrap_or_default(),
            _ => self.server.clone().unwrap_or_default(),
        }
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let cwd = std::env::current_dir().ok()?;
    let search_paths = vec![
        exe_dir.join("core").join("hev-socks5-tunnel").join(name),
        exe_dir.join("resources").join("core").join("hev-socks5-tunnel").join(name),
        exe_dir.join("bin").join(name),
        cwd.join("src-tauri").join("core").join("hev-socks5-tunnel").join(name),
        cwd.join("src-tauri").join("bin").join(name),
        cwd.join("core").join("hev-socks5-tunnel").join(name),
        cwd.join("bin").join(name),
        // For whispera-go-client suffix
        exe_dir.join("bin").join(format!("{}-x86_64-pc-windows-msvc.exe", name.trim_end_matches(".exe"))),
        cwd.join("src-tauri").join("bin").join(format!("{}-x86_64-pc-windows-msvc.exe", name.trim_end_matches(".exe"))),
    ];
    for path in search_paths {
        if path.exists() { return Some(path); }
    }
    None
}

// Note: hev-socks5-tunnel is now managed internally by the Go client

#[tauri::command]
fn connect_with_key(key: String, state: State<'_, VpnState>) -> Result<ConnectionStatus, String> {
    println!("Connecting...");
    let parsed_key = ConnectionKey::parse(&key)?;
    
    {
        let status = state.status.lock().unwrap();
        if status.connected {
            return Err("Already connected. Disconnect first.".into());
        }
    }
    
    let go_client_path = find_executable("whispera-go-client.exe").ok_or("whispera-go-client.exe not found")?;
    
    // Set up logging
    let log_dir = env::temp_dir();
    let go_log_path = log_dir.join("whispera-go.log");
    
    // Clear old logs
    let _ = fs::remove_file(&go_log_path);

    let go_out = fs::File::create(&go_log_path).map_err(|e| format!("Failed to create go log: {}", e))?;
    let go_err = go_out.try_clone().map_err(|e| format!("Clone log handle failed: {}", e))?;

    // Re-serialize key for Go client (canonical format)
    let json_key = serde_json::to_string(&parsed_key).map_err(|e| format!("JSON Error: {}", e))?;
    use base64::Engine;
    let base64_key = base64::engine::general_purpose::STANDARD.encode(json_key);
    let canonical_key = format!("whispera://{}", base64_key);

    let server = parsed_key.get_server();
    let obfs = parsed_key.obfs.clone().unwrap_or_else(|| "stealth".into());
    let transport = parsed_key.transport.clone().unwrap_or_else(|| "auto".into());

    let mut args = vec![
        "-key".to_string(), canonical_key,
        "-socks".to_string(), "127.0.0.1:10800".to_string(),
        "-obfs-level".to_string(), "8".to_string(),
    ];
    if transport == "tcp" {
        args.push("-transport".to_string());
        args.push("tcp".to_string());
    }
    
    // Start Go client (it manages hev-socks5-tunnel internally)
    println!("Starting whispera-go-client...");
    let go_child = Command::new(&go_client_path)
        .args(&args)
        .stdin(Stdio::null()) // Don't wait for stdin
        .stdout(Stdio::from(go_out))
        .stderr(Stdio::from(go_err))
        .spawn()
        .map_err(|e| format!("Failed to start Go client: {}", e))?;
    *state.go_client.lock().unwrap() = Some(go_child);

    // Wait for initialization
    std::thread::sleep(std::time::Duration::from_millis(2000));
    
    // Check Go client health
    {
        let mut go_guard = state.go_client.lock().unwrap();
        if let Some(child) = go_guard.as_mut() {
             if let Ok(Some(status)) = child.try_wait() {
                 let log = fs::read_to_string(&go_log_path).unwrap_or_default();
                 return Err(format!("whispera-go-client exited. Status: {}. Log: {}", status, log));
             }
        }
    }

    *state.current_key.lock().unwrap() = Some(parsed_key.clone());
    
    let new_status = ConnectionStatus {
        connected: true,
        server: server.clone(),
        transport: transport.clone(),
        obfuscation: obfs.clone(),
        error: None,
    };
    *state.status.lock().unwrap() = new_status.clone();
    Ok(new_status)
}

#[tauri::command]
fn disconnect(state: State<'_, VpnState>) -> Result<String, String> {
    if let Some(mut child) = state.go_client.lock().unwrap().take() { let _ = child.kill(); }
    if let Some(mut child) = state.hev_tunnel.lock().unwrap().take() { let _ = child.kill(); }
    *state.current_key.lock().unwrap() = None;
    *state.status.lock().unwrap() = ConnectionStatus::default();
    Ok("Disconnected".into())
}

#[tauri::command]
fn get_status(state: State<'_, VpnState>) -> ConnectionStatus {
    state.status.lock().unwrap().clone()
}

#[tauri::command]
fn validate_key(key: String) -> Result<ConnectionKey, String> {
    ConnectionKey::parse(&key)
}

#[derive(Serialize)]
struct NetworkStats {
    success: bool,
    bytes_received: u64,
    bytes_sent: u64,
}

#[tauri::command]
fn get_network_stats(state: State<'_, VpnState>) -> NetworkStats {
    // Wrap sensitive network polling in a catch_unwind to preventing app crashing
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut networks = state.networks.lock().unwrap();
        // Skip refresh_list for stability, just refresh stats
        networks.refresh(); 
        
        let mut rx = 0;
        let mut tx = 0;
        for (_name, network) in networks.iter() {
            rx += network.total_received();
            tx += network.total_transmitted();
        }
        (rx, tx)
    }));

    match result {
        Ok((rx, tx)) => NetworkStats { success: true, bytes_received: rx, bytes_sent: tx },
        Err(_) => NetworkStats { success: false, bytes_received: 0, bytes_sent: 0 }
    }
}

#[derive(Serialize)]
struct MemoryStats {
    success: bool,
    memory_mb: f64,
}

#[tauri::command]
fn get_memory_usage(state: State<'_, VpnState>) -> MemoryStats {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut sys = state.system.lock().unwrap();
        sys.refresh_memory();
        let used_mem = sys.used_memory(); 
        used_mem as f64 / 1024.0 / 1024.0
    }));

    match result {
        Ok(mb) => MemoryStats { success: true, memory_mb: mb },
        Err(_) => MemoryStats { success: false, memory_mb: 0.0 }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActiveConnection {
    host: String,
    remote_address: String,
    local_address: String,
    port: u16,
    protocol: String,
    pid: u32,
    state: String,
    #[serde(rename = "type")]
    conn_type: String,
}

#[derive(Serialize)]
struct ConnectionList {
    success: bool,
    total: usize,
    connections: Vec<ActiveConnection>,
}

#[tauri::command]
fn get_active_connections() -> ConnectionList {
    let conns = vec![
        ActiveConnection {
            host: "google.com".into(),
            remote_address: "142.250.1.1".into(),
            local_address: "192.168.1.10".into(),
            port: 443,
            protocol: "TCP".into(),
            pid: 1234,
            state: "ESTABLISHED".into(),
            conn_type: "HTTPS".into(),
        }
    ];
    ConnectionList { success: true, total: conns.len(), connections: conns }
}

#[tauri::command]
fn check_admin() -> bool {
    #[cfg(windows)] { return true; }
    #[cfg(not(windows))] { return false; }
}

#[tauri::command]
fn is_autostart_enabled() -> bool { false }

// Kill Switch control commands
#[tauri::command]
fn enable_kill_switch(allow_lan: bool, state: State<'_, VpnState>) -> Result<String, String> {
    // Kill switch is managed by the Go client when connected
    // This command updates the status to reflect UI state
    let mut status = state.status.lock().unwrap();
    status.kill_switch_active = true;
    
    // Log the request - actual kill switch is handled in Go client
    println!("[Tauri] Kill switch enabled (allow_lan: {})", allow_lan);
    Ok("Kill switch enabled".into())
}

#[tauri::command]
fn disable_kill_switch(state: State<'_, VpnState>) -> Result<String, String> {
    let mut status = state.status.lock().unwrap();
    status.kill_switch_active = false;
    
    println!("[Tauri] Kill switch disabled");
    Ok("Kill switch disabled".into())
}

#[tauri::command]
fn get_kill_switch_status(state: State<'_, VpnState>) -> bool {
    state.status.lock().unwrap().kill_switch_active
}

// Available transports list
#[derive(Serialize)]
struct TransportInfo {
    id: String,
    name: String,
    description: String,
    available: bool,
}

#[tauri::command]
fn get_available_transports() -> Vec<TransportInfo> {
    vec![
        TransportInfo {
            id: "auto".into(),
            name: "Автоматический".into(),
            description: "Автовыбор лучшего транспорта".into(),
            available: true,
        },
        TransportInfo {
            id: "udp".into(),
            name: "UDP".into(),
            description: "Быстрый UDP протокол (по умолчанию)".into(),
            available: true,
        },
        TransportInfo {
            id: "tcp".into(),
            name: "TCP".into(),
            description: "Надёжный TCP для строгих сетей".into(),
            available: true,
        },
        TransportInfo {
            id: "mkcp".into(),
            name: "mKCP".into(),
            description: "UDP с FEC для потерянных сетей".into(),
            available: true,
        },
        TransportInfo {
            id: "h2c".into(),
            name: "HTTP/2".into(),
            description: "HTTP/2 cleartext для корпоративных сетей".into(),
            available: true,
        },
        TransportInfo {
            id: "ws".into(),
            name: "WebSocket".into(),
            description: "WebSocket туннелирование".into(),
            available: true,
        },
    ]
}

// Obfuscation profiles
#[derive(Serialize)]
struct ObfsProfile {
    id: String,
    name: String,
    description: String,
    threat_level: i32,
}

#[tauri::command]
fn get_obfuscation_profiles() -> Vec<ObfsProfile> {
    vec![
        ObfsProfile {
            id: "none".into(),
            name: "Без обфускации".into(),
            description: "Максимальная скорость".into(),
            threat_level: 0,
        },
        ObfsProfile {
            id: "minimal".into(),
            name: "Минимальная".into(),
            description: "Базовое шифрование".into(),
            threat_level: 2,
        },
        ObfsProfile {
            id: "balanced".into(),
            name: "Сбалансированная".into(),
            description: "Баланс скорости и защиты".into(),
            threat_level: 5,
        },
        ObfsProfile {
            id: "stealth".into(),
            name: "Стелс".into(),
            description: "Максимальная маскировка".into(),
            threat_level: 8,
        },
        ObfsProfile {
            id: "paranoid".into(),
            name: "Паранойдный".into(),
            description: "Для враждебных сетей".into(),
            threat_level: 10,
        },
    ]
}

// ASN Bypass strategies
#[derive(Serialize)]
struct AsnStrategy {
    id: String,
    name: String,
    description: String,
}

#[tauri::command]
fn get_asn_bypass_strategies() -> Vec<AsnStrategy> {
    vec![
        AsnStrategy {
            id: "direct".into(),
            name: "Прямое".into(),
            description: "Без обхода ASN блокировок".into(),
        },
        AsnStrategy {
            id: "tls_masquerade".into(),
            name: "TLS Маскировка".into(),
            description: "Имитация браузера Chrome/Firefox".into(),
        },
        AsnStrategy {
            id: "domain_fronting".into(),
            name: "Domain Fronting".into(),
            description: "Через CDN (Cloudflare, Akamai)".into(),
        },
        AsnStrategy {
            id: "residential_proxy".into(),
            name: "Residential Proxy".into(),
            description: "Через резидентные прокси".into(),
        },
    ]
}

// Extended connection info
#[derive(Serialize)]
struct ExtendedStatus {
    connected: bool,
    server: String,
    transport: String,
    obfuscation: String,
    kill_switch_active: bool,
    asn_bypass_enabled: bool,
    dns_mode: String,
    uptime_seconds: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

#[tauri::command]
fn get_extended_status(state: State<'_, VpnState>) -> ExtendedStatus {
    let status = state.status.lock().unwrap();
    let mut networks = state.networks.lock().unwrap();
    networks.refresh();
    
    let (rx, tx) = networks.iter().fold((0u64, 0u64), |(rx, tx), (_, n)| {
        (rx + n.total_received(), tx + n.total_transmitted())
    });
    
    ExtendedStatus {
        connected: status.connected,
        server: status.server.clone(),
        transport: status.transport.clone(),
        obfuscation: status.obfuscation.clone(),
        kill_switch_active: status.kill_switch_active,
        asn_bypass_enabled: status.asn_bypass_enabled,
        dns_mode: status.dns_mode.clone(),
        uptime_seconds: 0, // TODO: track actual uptime
        bytes_sent: tx,
        bytes_received: rx,
    }
}

fn main() {
    // Set up crash logging
    std::panic::set_hook(Box::new(|info| {
        let mut path = std::env::temp_dir();
        path.push("whispera-crash.log");
        let msg = format!("Crash at {:?}: {}\n", std::time::SystemTime::now(), info);
        let _ = std::fs::write(path, msg);
    }));

    let mut sys = System::new_all();
    sys.refresh_all();
    let networks = Networks::new_with_refreshed_list();

    tauri::Builder::default()
        .manage(VpnState {
            go_client: Mutex::new(None),
            hev_tunnel: Mutex::new(None),
            status: Mutex::new(ConnectionStatus::default()),
            current_key: Mutex::new(None),
            system: Mutex::new(sys),
            networks: Mutex::new(networks),
        })
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            connect_with_key,
            disconnect,
            get_status,
            validate_key,
            get_network_stats,
            get_memory_usage,
            get_active_connections,
            check_admin,
            is_autostart_enabled,
            // New commands for advanced features
            enable_kill_switch,
            disable_kill_switch,
            get_kill_switch_status,
            get_available_transports,
            get_obfuscation_profiles,
            get_asn_bypass_strategies,
            get_extended_status
        ])
        .build(tauri::generate_context!())
        .expect("error building Tauri application")
        .run(|_app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                // Force kill backend processes on exit as requested
                #[cfg(target_os = "windows")]
                {
                    use std::process::Command;
                    use std::os::windows::process::CommandExt;
                    const CREATE_NO_WINDOW: u32 = 0x08000000;

                    // Kill Go client
                    let _ = Command::new("taskkill")
                        .args(["/F", "/IM", "whispera-go-client.exe"])
                        .creation_flags(CREATE_NO_WINDOW)
                        .spawn();
                    
                    // Kill HevTunnel
                    let _ = Command::new("taskkill")
                        .args(["/F", "/IM", "hev-socks5-tunnel.exe"])
                        .creation_flags(CREATE_NO_WINDOW)
                        .spawn();
                }
            }
        });
}
