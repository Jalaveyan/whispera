// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Command, Child, Stdio};
use std::sync::Mutex;
use std::fs;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use base64::Engine;

#[allow(dead_code)]
struct VpnState {
    go_client: Option<Child>,
    socks_tunnel: Option<Child>,
    server_ip: Option<String>,
    gateway_ip: Option<String>,
    tun_gateway: String,
}

static VPN_STATE: Mutex<Option<VpnState>> = Mutex::new(None);

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ConnectionKey {
    server: Option<String>,
    #[serde(rename = "server_tcp")]
    server_tcp: Option<String>,
    psk: Option<String>,
    #[serde(rename = "pub")]
    server_pub: Option<String>,
    #[serde(rename = "obfs_profile")]
    obfs_profile: Option<String>,
    transport: Option<String>,
    phantom: Option<bool>,
    #[serde(rename = "phantom_sni")]
    phantom_sni: Option<String>,
    #[serde(rename = "asn_bypass")]
    asn_bypass: Option<bool>,
    tls_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConnectResult {
    success: bool,
    message: String,
    server: Option<String>,
    profile: Option<String>,
    socks_port: u16,
}

/// Parse whispera:// connection key
fn parse_connection_key(key: &str) -> Result<ConnectionKey, String> {
    let key = key.trim();
    
    // URL format: whispera://server:port?key=...&pub=...
    if key.starts_with("whispera://") && key.contains('?') {
        let url = url::Url::parse(key).map_err(|e| format!("Invalid URL: {}", e))?;
        
        let host = url.host_str().unwrap_or("").to_string();
        let port = url.port().unwrap_or(51820);
        let server = format!("{}:{}", host, port);
        
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        
        return Ok(ConnectionKey {
            server: Some(server),
            server_tcp: None,
            psk: params.get("key").map(|s| s.to_string()),
            server_pub: params.get("pub").map(|s| s.to_string()),
            obfs_profile: params.get("profile").map(|s| s.to_string()).or(Some("vk".to_string())),
            transport: params.get("transport").map(|s| s.to_string()),
            phantom: params.get("phantom").map(|s| s == "1" || s == "true"),
            phantom_sni: params.get("sni").map(|s| s.to_string()),
            asn_bypass: params.get("asn").map(|s| s == "1" || s == "true"),
            tls_fingerprint: params.get("tls").map(|s| s.to_string()),
        });
    }
    
    // Base64 JSON format
    let key = key.trim_start_matches("whispera://").trim_start_matches("wpn://");
    
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let json_str = String::from_utf8(decoded).map_err(|e| format!("UTF-8 error: {}", e))?;
    
    serde_json::from_str(&json_str).map_err(|e| format!("JSON parse error: {}", e))
}

/// Extract IP from server address
fn extract_server_ip(server: &str) -> Option<String> {
    let host = server.split(':').next()?;
    
    // Check if it's already an IP
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    
    // Try to resolve hostname
    use std::net::ToSocketAddrs;
    let addr = format!("{}:0", host);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Some(addr.ip().to_string());
        }
    }
    
    None
}

/// Get default gateway IP
fn get_default_gateway() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("cmd")
            .args(&["/C", "route", "print", "0.0.0.0"])
            .output()
            .ok()?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse route output to find default gateway
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                return Some(parts[2].to_string());
            }
        }
        
        // Fallback: try ipconfig
        let output = Command::new("cmd")
            .args(&["/C", "ipconfig"])
            .output()
            .ok()?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("Default Gateway") || line.contains("Основной шлюз") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let gw = parts[1].trim();
                    if !gw.is_empty() && gw.parse::<IpAddr>().is_ok() {
                        return Some(gw.to_string());
                    }
                }
            }
        }
    }
    
    None
}

/// Add routes for VPN
fn add_routes(server_ip: &str, gateway: &str, tun_gateway: &str) -> Result<(), String> {
    println!("Whispera: Adding routes...");
    println!("  Server IP: {}", server_ip);
    println!("  Gateway: {}", gateway);
    println!("  TUN Gateway: {}", tun_gateway);
    
    #[cfg(target_os = "windows")]
    {
        // Route to VPN server through real gateway
        let _ = Command::new("route")
            .args(&["add", server_ip, "mask", "255.255.255.255", gateway, "metric", "1"])
            .output();
        
        // Route all traffic through TUN
        let _ = Command::new("route")
            .args(&["add", "0.0.0.0", "mask", "128.0.0.0", tun_gateway, "metric", "1"])
            .output();
        
        let _ = Command::new("route")
            .args(&["add", "128.0.0.0", "mask", "128.0.0.0", tun_gateway, "metric", "1"])
            .output();
        
        println!("Whispera: Routes added successfully");
    }
    
    Ok(())
}

/// Remove routes
fn remove_routes(server_ip: &str, tun_gateway: &str) {
    println!("Whispera: Removing routes...");
    
    #[cfg(target_os = "windows")]
    {
        // Remove TUN routes
        let _ = Command::new("route")
            .args(&["delete", "0.0.0.0", "mask", "128.0.0.0", tun_gateway])
            .output();
        
        let _ = Command::new("route")
            .args(&["delete", "128.0.0.0", "mask", "128.0.0.0", tun_gateway])
            .output();
        
        // Remove server route
        let _ = Command::new("route")
            .args(&["delete", server_ip])
            .output();
        
        println!("Whispera: Routes removed");
    }
}

/// Kill all Whispera processes
fn kill_all_processes() {
    println!("Whispera: Killing processes...");
    
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("taskkill")
            .args(&["/F", "/IM", "whispera-go-client.exe"])
            .output();
        
        let _ = Command::new("taskkill")
            .args(&["/F", "/IM", "whispera-go-client-x86_64-pc-windows-msvc.exe"])
            .output();
        
        let _ = Command::new("taskkill")
            .args(&["/F", "/IM", "hev-socks5-tunnel.exe"])
            .output();
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("pkill")
            .args(&["-f", "whispera-go-client"])
            .output();
        
        let _ = Command::new("pkill")
            .args(&["-f", "hev-socks5-tunnel"])
            .output();
    }
    
    println!("Whispera: Processes killed");
}

/// Generate hev-socks5-tunnel config
fn generate_hev_config(socks_port: u16) -> String {
    format!(r#"misc:
  log-level: info
  log-file: whispera-client.log

socks5:
  address: 127.0.0.1
  port: {}
  udp: true

tunnel:
  mtu: 1500
"#, socks_port)
}

/// Generate Go client config
fn generate_client_config(ck: &ConnectionKey, socks_port: u16) -> String {
    let server = ck.server.clone().unwrap_or_else(|| "127.0.0.1:51820".to_string());
    let psk = ck.psk.clone().unwrap_or_default();
    let server_pub = ck.server_pub.clone().unwrap_or_default();
    let profile = ck.obfs_profile.clone().unwrap_or_else(|| "vk".to_string());
    let phantom_enabled = ck.phantom.unwrap_or(false);
    let phantom_sni = ck.phantom_sni.clone().unwrap_or_else(|| "cloudflare.com".to_string());
    let asn_bypass = ck.asn_bypass.unwrap_or(false);
    let tls_fp = ck.tls_fingerprint.clone().unwrap_or_else(|| "chrome".to_string());

    format!(r#"# Whispera Client Configuration (auto-generated)
server: "{}"
psk: "{}"
server_pub: "{}"

# SOCKS5 proxy
socks:
  enabled: true
  address: "127.0.0.1"
  port: {}

# Obfuscation
obfuscation:
  enabled: true
  profile: "{}"

# Phantom protocol
phantom:
  enabled: {}
  sni: "{}"

# ASN Bypass
asn_bypass:
  enabled: {}
  tls_fingerprint: "{}"

# Connection
connection:
  timeout: 30s
  keep_alive: 25s
"#, server, psk, server_pub, socks_port, profile, phantom_enabled, phantom_sni, asn_bypass, tls_fp)
}

#[tauri::command]
fn connect(key: String) -> Result<ConnectResult, String> {
    println!("Whispera: Connecting with key...");
    
    // First, kill any existing processes
    kill_all_processes();
    
    // Parse the connection key
    let ck = parse_connection_key(&key)?;
    
    let server = ck.server.clone().unwrap_or_else(|| "unknown".to_string());
    let profile = ck.obfs_profile.clone().unwrap_or_else(|| "vk".to_string());
    
    println!("Whispera: Parsed key - Server: {}, Profile: {}", server, profile);
    
    // Extract server IP
    let server_ip = extract_server_ip(&server)
        .ok_or_else(|| "Failed to resolve server IP".to_string())?;
    
    // Get default gateway
    let gateway = get_default_gateway()
        .ok_or_else(|| "Failed to get default gateway".to_string())?;
    
    println!("Whispera: Server IP: {}, Gateway: {}", server_ip, gateway);
    
    // Get paths
    let exe_dir = std::env::current_exe()
        .map(|p| p.parent().unwrap().to_path_buf())
        .map_err(|e| format!("Failed to get exe path: {}", e))?;
    
    let bin_dir = exe_dir.join("bin");
    
    // Try both naming conventions
    let go_client_path = if bin_dir.join("whispera-go-client-x86_64-pc-windows-msvc.exe").exists() {
        bin_dir.join("whispera-go-client-x86_64-pc-windows-msvc.exe")
    } else {
        bin_dir.join("whispera-go-client.exe")
    };
    
    let hev_tunnel_path = bin_dir.join("hev-socks5-tunnel.exe");
    let config_path = bin_dir.join("client_config.yaml");
    let hev_config_path = bin_dir.join("hev-config.yml");
    
    // Check if binaries exist
    if !go_client_path.exists() {
        return Err(format!("Go client not found: {:?}", go_client_path));
    }
    
    // Use SOCKS5 port
    let socks_port: u16 = 1080;
    let tun_gateway = "10.0.85.1".to_string();
    
    // Generate configs
    let client_config = generate_client_config(&ck, socks_port);
    let hev_config = generate_hev_config(socks_port);
    
    fs::write(&config_path, &client_config)
        .map_err(|e| format!("Failed to write config: {}", e))?;
    fs::write(&hev_config_path, &hev_config)
        .map_err(|e| format!("Failed to write hev config: {}", e))?;
    
    println!("Whispera: Starting Go client...");
    
    // Start Go client
    let go_client = Command::new(&go_client_path)
        .args(&["-config", config_path.to_str().unwrap(), "-key", &key])
        .current_dir(&bin_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start Go client: {}", e))?;
    
    println!("Whispera: Go client started with PID: {}", go_client.id());
    
    // Wait a bit for client to initialize
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Start hev-socks5-tunnel if it exists (for TUN mode)
    let socks_tunnel = if hev_tunnel_path.exists() {
        println!("Whispera: Starting hev-socks5-tunnel...");
        
        let tunnel = Command::new(&hev_tunnel_path)
            .args(&[hev_config_path.to_str().unwrap()])
            .current_dir(&bin_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start tunnel: {}", e))?;
        
        println!("Whispera: hev-socks5-tunnel started with PID: {}", tunnel.id());
        
        // Wait for TUN to initialize
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Add routes
        add_routes(&server_ip, &gateway, &tun_gateway)?;
        
        Some(tunnel)
    } else {
        println!("Whispera: hev-socks5-tunnel not found, using SOCKS5 proxy mode only");
        None
    };
    
    // Store state
    let mut state = VPN_STATE.lock().unwrap();
    *state = Some(VpnState {
        go_client: Some(go_client),
        socks_tunnel,
        server_ip: Some(server_ip),
        gateway_ip: Some(gateway),
        tun_gateway,
    });
    
    Ok(ConnectResult {
        success: true,
        message: format!("Connected to {} with {} profile", server, profile),
        server: Some(server),
        profile: Some(profile),
        socks_port,
    })
}

#[tauri::command]
fn disconnect() -> Result<String, String> {
    println!("Whispera: Disconnecting...");
    
    let mut state = VPN_STATE.lock().unwrap();
    
    if let Some(ref mut vpn) = *state {
        // Remove routes first
        if let Some(ref server_ip) = vpn.server_ip {
            remove_routes(server_ip, &vpn.tun_gateway);
        }
        
        // Kill Go client
        if let Some(ref mut child) = vpn.go_client {
            let _ = child.kill();
            println!("Whispera: Go client stopped");
        }
        
        // Kill hev-socks5-tunnel
        if let Some(ref mut child) = vpn.socks_tunnel {
            let _ = child.kill();
            println!("Whispera: hev-socks5-tunnel stopped");
        }
        
        *state = None;
    }
    
    // Also kill any orphaned processes
    kill_all_processes();
    
    Ok("Disconnected".to_string())
}

#[tauri::command]
fn get_status() -> Result<String, String> {
    let state = VPN_STATE.lock().unwrap();
    
    if state.is_some() {
        Ok("connected".to_string())
    } else {
        Ok("disconnected".to_string())
    }
}

fn main() {
    // Set up panic handler to cleanup on crash
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Cleanup on panic
        let _ = disconnect_cleanup();
        default_panic(info);
    }));
    
    tauri::Builder::default()
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event.event() {
                println!("Whispera: Window closing, cleaning up...");
                let _ = disconnect_cleanup();
            }
        })
        .invoke_handler(tauri::generate_handler![connect, disconnect, get_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn disconnect_cleanup() -> Result<(), ()> {
    println!("Whispera: Cleanup on exit...");
    
    let mut state = VPN_STATE.lock().map_err(|_| ())?;
    
    if let Some(ref mut vpn) = *state {
        // Remove routes
        if let Some(ref server_ip) = vpn.server_ip {
            remove_routes(server_ip, &vpn.tun_gateway);
        }
        
        // Kill processes
        if let Some(ref mut child) = vpn.go_client {
            let _ = child.kill();
        }
        if let Some(ref mut child) = vpn.socks_tunnel {
            let _ = child.kill();
        }
    }
    
    *state = None;
    
    // Kill all orphaned processes
    kill_all_processes();
    
    Ok(())
}
