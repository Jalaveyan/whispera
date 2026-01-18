// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Command, Child, Stdio};
use std::sync::Mutex;
use std::fs;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use base64::Engine;
use std::io::{BufRead, BufReader};
use std::thread;

#[allow(dead_code)]
struct VpnState {
    go_client: Option<Child>,
    mihomo: Option<Child>,
    server_ip: Option<String>,
    gateway_ip: Option<String>,
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
            .args(&["/F", "/IM", "mihomo.exe"])
            .output();
        
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("pkill")
            .args(&["-f", "whispera-go-client"])
            .output();
        
        let _ = Command::new("pkill")
            .args(&["-f", "mihomo"])
            .output();
    }
    
    println!("Whispera: Processes killed");
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

# SOCKS5 proxy - Mihomo connects here
socks:
  enabled: true
  address: "127.0.0.1"
  port: {}

# Obfuscation
obfuscation:
  enabled: true
  profile: "{}"

# Phantom protocol (REALITY-like)
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

# Disable internal TUN - Mihomo handles this
tun:
  enabled: false
"#, server, psk, server_pub, socks_port, profile, phantom_enabled, phantom_sni, asn_bypass, tls_fp)
}

/// Generate Mihomo config with server IP exclusion
fn generate_mihomo_config(server_ip: &str, socks_port: u16) -> String {
    format!(r#"# Whispera Mihomo Configuration (auto-generated)

mixed-port: 7890
allow-lan: false
bind-address: '127.0.0.1'
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

# GeoIP
geodata-mode: true
geo-auto-update: true
geo-update-interval: 24

# DNS with Fake-IP
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - 'localhost.ptlogin2.qq.com'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - 'lens.l.google.com'
    - 'time.windows.com'
    - 'time.nist.gov'
    - 'time.apple.com'
    - '*.ntp.org.cn'
    - '+.pool.ntp.org'
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
  nameserver:
    - 'tls://8.8.8.8#PROXY'
    - 'tls://1.1.1.1#PROXY'
  fallback:
    - 'https://1.1.1.1/dns-query#PROXY'
    - 'https://8.8.8.8/dns-query#PROXY'
  fallback-filter:
    geoip: true
    geoip-code: RU
    ipcidr:
      - 240.0.0.0/4

# TUN Mode
tun:
  enable: true
  stack: gvisor
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53
  device: Whispera
  mtu: 1500
  strict-route: false
  # CRITICAL: Exclude VPN server from TUN to prevent routing loop
  inet4-route-exclude-address:
    - {}/32

# Sniffer
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]

# Profile
profile:
  store-selected: true
  store-fake-ip: true

# Performance
unified-delay: true
tcp-concurrent: true
global-client-fingerprint: chrome

# Proxy Groups
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Whispera

# Whispera SOCKS5 proxy (Go client)
proxies:
  - name: Whispera
    type: socks5
    server: 127.0.0.1
    port: {}
    udp: true

# Rules
rules:
  # CRITICAL: VPN server must go direct to prevent loop
  - IP-CIDR,{}/32,DIRECT,no-resolve
  
  # Private networks
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve
  - IP-CIDR,fe80::/10,DIRECT,no-resolve
  - IP-CIDR,::1/128,DIRECT,no-resolve
  
  # Local domains
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT
  - DOMAIN-KEYWORD,localhost,DIRECT
  
  # Everything else through Whispera
  - MATCH,PROXY
"#, server_ip, socks_port, server_ip)
}

/// Find binary directory
fn find_bin_dir() -> Result<std::path::PathBuf, String> {
    let exe_dir = std::env::current_exe()
        .map(|p| p.parent().unwrap().to_path_buf())
        .map_err(|e| format!("Failed to get exe path: {}", e))?;
    
    let possible_bin_dirs = vec![
        exe_dir.join("bin"),
        exe_dir.join("resources").join("bin"), // Standard Tauri bundle path
        exe_dir.join("..").join("..").join("bin"),
        exe_dir.join("..").join("..").join("..").join("src-tauri").join("bin"),
        std::path::PathBuf::from("C:\\Whispera-main\\client-package-tauri\\src-tauri\\bin"),
    ];
    
    for dir in &possible_bin_dirs {
        let client = dir.join("whispera-go-client-x86_64-pc-windows-msvc.exe");
        let mihomo = dir.join("mihomo-x86_64-pc-windows-msvc.exe");
        
        if client.exists() && mihomo.exists() {
            return Ok(dir.clone());
        } else if client.exists() {
            return Ok(dir.clone());
        }
    }
    
    // Fallback to first existing
    for dir in &possible_bin_dirs {
        if dir.exists() {
            return Ok(dir.clone());
        }
    }
    
    Err("Binary directory not found".to_string())
}

#[tauri::command]
fn connect(key: String) -> Result<ConnectResult, String> {
    println!("Whispera: Connecting with Mihomo TUN mode...");
    
    // Kill any existing processes
    kill_all_processes();
    
    // Small delay to ensure processes are killed
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    // Parse the connection key
    let ck = parse_connection_key(&key)?;
    
    let server = ck.server.clone().unwrap_or_else(|| "unknown".to_string());
    let profile = ck.obfs_profile.clone().unwrap_or_else(|| "vk".to_string());
    
    println!("Whispera: Server: {}, Profile: {}", server, profile);
    
    // Extract server IP - critical for routing
    let server_ip = extract_server_ip(&server)
        .ok_or_else(|| "Failed to resolve server IP".to_string())?;
    
    // Get default gateway
    let gateway = get_default_gateway()
        .ok_or_else(|| "Failed to get default gateway".to_string())?;
    
    println!("Whispera: Server IP: {}, Gateway: {}", server_ip, gateway);
    
    // Find bin directory
    let bin_dir = find_bin_dir()?;
    println!("Whispera: Binary dir: {:?}", bin_dir);
    
    // Find Go client
    let go_client_path = if bin_dir.join("whispera-go-client-x86_64-pc-windows-msvc.exe").exists() {
        bin_dir.join("whispera-go-client-x86_64-pc-windows-msvc.exe")
    } else {
        bin_dir.join("whispera-go-client.exe")
    };
    
    let mihomo_path = if bin_dir.join("mihomo-x86_64-pc-windows-msvc.exe").exists() {
        bin_dir.join("mihomo-x86_64-pc-windows-msvc.exe")
    } else {
        bin_dir.join("mihomo.exe")
    };

    let config_path = bin_dir.join("client_config.yaml");
    let mihomo_config_path = bin_dir.join("mihomo-config-runtime.yaml");
    
    // Check binaries exist
    if !go_client_path.exists() {
        return Err(format!("Go client not found: {:?}", go_client_path));
    }
    if !mihomo_path.exists() {
        return Err(format!("Mihomo not found: {:?}. Download from: https://github.com/MetaCubeX/mihomo/releases", mihomo_path));
    }
    
    // SOCKS5 port for Go client
    let socks_port: u16 = 10800;
    
    // Generate configs
    let client_config = generate_client_config(&ck, socks_port);
    let mihomo_config = generate_mihomo_config(&server_ip, socks_port);
    
    fs::write(&config_path, &client_config)
        .map_err(|e| format!("Failed to write client config: {}", e))?;
    fs::write(&mihomo_config_path, &mihomo_config)
        .map_err(|e| format!("Failed to write Mihomo config: {}", e))?;
    
    println!("Whispera: Configs generated");
    
    // STEP 1: Start Go client first (SOCKS5 server)
    println!("Whispera: Starting Go client (SOCKS5 server)...");
    
    let go_client = Command::new(&go_client_path)
        .args(&["-config", config_path.to_str().unwrap(), "-key", &key, "--no-tun"])
        .current_dir(&bin_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to start Go client: {}", e))?;
    
    println!("Whispera: Go client started with PID: {}", go_client.id());
    
    // Wait for Go client to initialize SOCKS5 server AND establish VPN connection
    // This is critical: VPN connection must be established before Mihomo TUN starts
    // Otherwise TUN will capture the VPN traffic causing a routing loop
    println!("Whispera: Waiting for VPN tunnel to establish (10s)...");
    std::thread::sleep(std::time::Duration::from_secs(10));
    
    // STEP 2: Start Mihomo (TUN + routing)
    println!("Whispera: Starting Mihomo TUN...");
    
    let mihomo = Command::new(&mihomo_path)
        .args(&["-d", bin_dir.to_str().unwrap(), "-f", mihomo_config_path.to_str().unwrap()])
        .current_dir(&bin_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to start Mihomo: {}", e))?;
    
    println!("Whispera: Mihomo started with PID: {}", mihomo.id());
    
    // Wait for Mihomo to initialize TUN
    println!("Whispera: Waiting for TUN interface...");
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Store state
    let mut state = VPN_STATE.lock().unwrap();
    *state = Some(VpnState {
        go_client: Some(go_client),
        mihomo: Some(mihomo),
        server_ip: Some(server_ip),
        gateway_ip: Some(gateway),
    });
    
    println!("Whispera: Connection established!");
    
    Ok(ConnectResult {
        success: true,
        message: format!("Connected to {} via Mihomo TUN", server),
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
        // Kill Mihomo first (to release TUN)
        if let Some(ref mut child) = vpn.mihomo {
            let _ = child.kill();
            println!("Whispera: Mihomo stopped");
        }
        
        // Then kill Go client
        if let Some(ref mut child) = vpn.go_client {
            let _ = child.kill();
            println!("Whispera: Go client stopped");
        }
        
        *state = None;
    }
    
    // Kill any orphaned processes
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

fn disconnect_cleanup() -> Result<(), ()> {
    println!("Whispera: Cleanup on exit...");
    
    let mut state = VPN_STATE.lock().map_err(|_| ())?;
    
    if let Some(ref mut vpn) = *state {
        if let Some(ref mut child) = vpn.mihomo {
            let _ = child.kill();
        }
        if let Some(ref mut child) = vpn.go_client {
            let _ = child.kill();
        }
    }
    
    *state = None;
    kill_all_processes();
    
    Ok(())
}

fn main() {
    // Panic handler for cleanup
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
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
