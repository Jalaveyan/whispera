use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
#[cfg(windows)]
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x00004000;

const SERVICE_NAME: &str = "WhisperaNH";
const SERVICE_DISPLAY: &str = "Whispera Network Helper";

pub struct MihomoManager {
    binary_path: PathBuf,
    process: Option<Child>,
    elevated: bool,
    use_service: bool,
}

impl MihomoManager {
    pub fn new(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            process: None,
            elevated: false,
            use_service: false,
        }
    }

    /// Install mihomo as a Windows Service.
    /// The config_path must be the final config location (e.g. AppData).
    /// Requires admin rights.
    pub fn install_service(&self, config_path: &Path) -> Result<(), String> {
        let bin = self.binary_path.to_string_lossy().to_string();
        let cfg = config_path.to_string_lossy().to_string();
        let home_dir = config_path
            .parent()
            .unwrap_or(config_path)
            .to_string_lossy()
            .to_string();

        let bin_path = format!(
            "\"{}\" -d \"{}\" -f \"{}\"",
            bin.replace('"', "\\\""),
            home_dir.replace('"', "\\\""),
            cfg.replace('"', "\\\""),
        );

        // Remove existing service first
        let _ = Command::new("sc")
            .args(["stop", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = Command::new("sc")
            .args(["delete", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output();

        let status = Command::new("sc")
            .args([
                "create",
                SERVICE_NAME,
                &format!("binPath= {}", bin_path),
                "type=",
                "own",
                "start=",
                "demand",
                &format!("DisplayName= {}", SERVICE_DISPLAY),
                "error=",
                "ignore",
            ])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("sc create failed: {}", e))?;

        if !status.status.success() {
            let stdout = String::from_utf8_lossy(&status.stdout).to_string();
            let stderr = String::from_utf8_lossy(&status.stderr).to_string();
            // Error 1073 means service already exists — that's OK
            if !stdout.contains("1073") && !stderr.contains("1073") {
                return Err(format!("Service install failed: {} {}", stdout, stderr));
            }
        }

        // Set description
        let _ = Command::new("sc")
            .args([
                "description",
                SERVICE_NAME,
                "Whispera VPN network proxy and TUN routing",
            ])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output();

        // Run as LocalSystem (has rights to create TUN adapter)
        let _ = Command::new("sc")
            .args(["config", SERVICE_NAME, "obj=", "LocalSystem"])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output();

        Ok(())
    }

    pub fn uninstall_service(&mut self) -> Result<(), String> {
        let _ = Command::new("sc")
            .args(["stop", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        Command::new("sc")
            .args(["delete", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn start_service(&mut self) -> Result<(), String> {
        let out = Command::new("sc")
            .args(["start", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| e.to_string())?;

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();

        // 1056 = already running
        if out.status.success()
            || stdout.contains("RUNNING")
            || stderr.contains("1056")
            || stdout.contains("1056")
        {
            self.use_service = true;
            // Give mihomo time to initialize TUN
            std::thread::sleep(std::time::Duration::from_millis(2000));
            return Ok(());
        }

        Err(format!("sc start failed: {} {}", stdout, stderr))
    }

    fn stop_service(&mut self) -> Result<(), String> {
        Command::new("sc")
            .args(["stop", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .ok();
        std::thread::sleep(std::time::Duration::from_millis(1500));
        // Force-kill any remaining mihomo process
        Command::new("taskkill")
            .args(["/F", "/IM", "mihomo.exe"])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .ok();
        self.use_service = false;
        Ok(())
    }

    pub fn start(&mut self, config_path: &Path) -> Result<(), String> {
        if self.is_running() {
            self.stop()?;
        }

        // Try service mode if registered
        if service_exists(SERVICE_NAME) {
            // Update config path by reinstalling service
            if self.install_service(config_path).is_ok() {
                if self.start_service().is_ok() {
                    return Ok(());
                }
            }
        }

        // Fall back to direct spawn
        if is_admin() {
            self.start_direct(config_path)
        } else {
            self.start_elevated(config_path)
        }
    }

    fn start_direct(&mut self, config_path: &Path) -> Result<(), String> {
        let home_dir = config_path.parent().unwrap_or(config_path);
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-d").arg(home_dir).arg("-f").arg(config_path);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start mihomo: {}", e))?;

        self.process = Some(child);
        self.elevated = false;
        self.use_service = false;
        Ok(())
    }

    fn start_elevated(&mut self, config_path: &Path) -> Result<(), String> {
        let bin = self.binary_path.to_string_lossy().to_string();
        let cfg = config_path.to_string_lossy().to_string();
        let home_dir = config_path
            .parent()
            .unwrap_or(config_path)
            .to_string_lossy()
            .to_string();

        // Launch mihomo elevated and hidden via UAC
        let ps_cmd = format!(
            "Start-Process -FilePath '{}' -ArgumentList '-d','{}','-f','{}' -Verb RunAs -WindowStyle Hidden",
            bin.replace('\'', "''"),
            home_dir.replace('\'', "''"),
            cfg.replace('\'', "''")
        );

        let status = Command::new("powershell")
            .args([
                "-WindowStyle",
                "Hidden",
                "-NonInteractive",
                "-Command",
                &ps_cmd,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags_win(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("Failed to elevate mihomo: {}", e))?
            .wait()
            .map_err(|e| e.to_string())?;

        if !status.success() {
            return Err("UAC elevation was denied".to_string());
        }

        std::thread::sleep(std::time::Duration::from_millis(2000));
        self.process = None;
        self.elevated = true;
        self.use_service = false;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if self.use_service {
            return self.stop_service();
        }

        if let Some(ref mut child) = self.process {
            child.kill().ok();
            child.wait().ok();
        } else if self.elevated {
            // Kill elevated mihomo (need elevated taskkill)
            Command::new("powershell")
                .args([
                    "-WindowStyle", "Hidden", "-NonInteractive", "-Command",
                    "Start-Process -FilePath 'taskkill' -ArgumentList '/F','/IM','mihomo.exe' -Verb RunAs -WindowStyle Hidden -Wait",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags_win(CREATE_NO_WINDOW)
                .spawn()
                .ok()
                .and_then(|mut c| c.wait().ok());
        }

        self.process = None;
        self.elevated = false;
        Ok(())
    }

    pub fn is_running(&mut self) -> bool {
        if self.use_service {
            return service_running(SERVICE_NAME);
        }

        if let Some(ref mut child) = self.process {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.process = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else if self.elevated {
            Command::new("tasklist")
                .args(["/FI", "IMAGENAME eq mihomo.exe", "/NH"])
                .creation_flags_win(CREATE_NO_WINDOW)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("mihomo.exe"))
                .unwrap_or(false)
        } else {
            false
        }
    }
}

impl Drop for MihomoManager {
    fn drop(&mut self) {
        self.stop().ok();
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn is_admin() -> bool {
    Command::new("net")
        .arg("session")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags_win(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn service_exists(name: &str) -> bool {
    Command::new("sc")
        .args(["query", name])
        .creation_flags_win(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn service_running(name: &str) -> bool {
    Command::new("sc")
        .args(["query", name])
        .creation_flags_win(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

trait CommandExtWin {
    fn creation_flags_win(&mut self, flags: u32) -> &mut Self;
}

impl CommandExtWin for Command {
    fn creation_flags_win(&mut self, _flags: u32) -> &mut Self {
        #[cfg(windows)]
        self.creation_flags(_flags);
        self
    }
}

// ── Mihomo config generator ───────────────────────────────────────────────────

pub struct MihomoRoutingRule {
    pub kind: String,
    pub value: String,
    pub action: String,
}

pub struct MihomoConfig<'a> {
    pub socks_addr: &'a str,
    pub mixed_port: u16,
    pub tun_stack: &'a str,
    pub dns_redirect: bool,
    pub ipv6: bool,
    pub routing_rules: &'a [MihomoRoutingRule],
}

pub fn generate_config(cfg: &MihomoConfig) -> String {
    let parts: Vec<&str> = cfg.socks_addr.splitn(2, ':').collect();
    let server = parts.first().copied().unwrap_or("127.0.0.1");
    let server_port: u16 = parts
        .get(1)
        .copied()
        .unwrap_or("1080")
        .parse()
        .unwrap_or(1080);

    let port = cfg.mixed_port;
    let tun_stack = cfg.tun_stack;
    let ipv6 = cfg.ipv6;

    // Build custom rules before the catch-all MATCH rule.
    let mut custom_rules = String::new();
    for rule in cfg.routing_rules {
        match rule.kind.as_str() {
            "domain" => {
                custom_rules.push_str(&format!(
                    "  - DOMAIN-SUFFIX,{},{}\n",
                    rule.value, rule.action
                ));
            }
            "process" => {
                // Use only the filename part (e.g. "Steam.exe" from a full path)
                let exe_name = std::path::Path::new(&rule.value)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&rule.value);
                custom_rules.push_str(&format!("  - PROCESS-NAME,{},{}\n", exe_name, rule.action));
            }
            _ => {}
        }
    }

    format!(
        r#"mixed-port: {port}
allow-lan: false
ipv6: {ipv6}
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
find-process-mode: strict

sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8090]
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  override-destination: true

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.ru"
    - "*.su"
    - "*.рф"
    - "*.lan"
    - "*.local"
    - "localhost"
    - "*.localhost"
    - "time.windows.com"
    - "time.nist.gov"
    - "time.apple.com"
    - "+.pool.ntp.org"
    - "+.stun.*.*"
    - "+.stun.*.*.*"
  nameserver:
    - 77.88.8.8
    - 77.88.8.1
    - 8.8.8.8
    - 1.1.1.1

tun:
  enable: true
  stack: {tun_stack}
  device: Meta
  dns-hijack:
    - any:53
  auto-route: true
  auto-detect-interface: true

proxies:
  - name: whisp-server
    type: socks5
    server: {server}
    port: {server_port}
    udp: true

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - whisp-server

rules:
  - DOMAIN-SUFFIX,ru,DIRECT
  - DOMAIN-SUFFIX,su,DIRECT
  - DOMAIN-SUFFIX,gov,DIRECT
{custom_rules}  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - GEOIP,RU,DIRECT,no-resolve
  - MATCH,PROXY
"#
    )
}
