use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
#[cfg(windows)]
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x00004000;

const SERVICE_NAME: &str = "WhisperaGW";
const SERVICE_DISPLAY: &str = "Whispera Gateway";

pub struct GoClientManager {
    binary_path: PathBuf,
    process: Option<Child>,
    use_service: bool,
}

pub struct GoClientConfig<'a> {
    /// Full whispera:// connection key — used in normal mode.
    /// Leave empty when using server_addr + ml_token (ML mode).
    pub conn_key: &'a str,
    /// server host:port — used in ML mode (when conn_key is empty).
    pub server_addr: &'a str,
    /// ML auth token — passed as -phantom-key PSK in ML mode.
    pub ml_token: &'a str,
    pub socks_addr: &'a str,
    pub kill_switch: bool,
    /// ML-recommended transport (e.g. "tcp", "vkwebrtc", "meek", "shadowsocks").
    pub transport: &'a str,
}

impl GoClientManager {
    pub fn new(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            process: None,
            use_service: false,
        }
    }

    /// Install Windows Service for whispera-go-client.
    /// Must be called with admin rights (e.g. from installer).
    pub fn install_service(&self, cfg: &GoClientConfig) -> Result<(), String> {
        let bin = self.binary_path.to_string_lossy().to_string();

        let key_part = if !cfg.conn_key.is_empty() {
            format!("-key \"{}\"", cfg.conn_key)
        } else {
            let mut s = format!("-server \"{}\"", cfg.server_addr);
            if !cfg.ml_token.is_empty() {
                s.push_str(&format!(" -user-key \"{}\"", cfg.ml_token));
            }
            s
        };
        let mut args = format!("{} -socks \"{}\" -no-tun", key_part, cfg.socks_addr);
        if cfg.kill_switch {
            args.push_str(" -kill-switch");
        }
        if !cfg.transport.is_empty() {
            args.push_str(&format!(" -transport {}", cfg.transport));
        }

        let bin_path = format!("\"{}\" {}", bin.replace('"', "\\\""), args);

        // Delete existing service if present
        let _ = Command::new("sc")
            .args(["delete", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output();

        let status = Command::new("sc")
            .args([
                "create",
                SERVICE_NAME,
                "binPath=",
                &bin_path,
                "type=",
                "own",
                "start=",
                "demand",
                "DisplayName=",
                SERVICE_DISPLAY,
                "error=",
                "ignore",
            ])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("sc create failed: {}", e))?;

        if !status.status.success() {
            let err = String::from_utf8_lossy(&status.stderr).to_string();
            return Err(format!("Service install failed: {}", err));
        }

        // Set description
        let _ = Command::new("sc")
            .args([
                "description",
                SERVICE_NAME,
                "Whispera VPN gateway tunnel process",
            ])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output();

        Ok(())
    }

    pub fn uninstall_service(&mut self) -> Result<(), String> {
        let _ = self.stop_service();
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

        // 1060 = service not installed, 1056 = already running — both OK to continue
        if out.status.success()
            || String::from_utf8_lossy(&out.stdout).contains("RUNNING")
            || String::from_utf8_lossy(&out.stderr).contains("1056")
        {
            self.use_service = true;
            return Ok(());
        }

        Err(format!(
            "sc start failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }

    fn stop_service(&mut self) -> Result<(), String> {
        Command::new("sc")
            .args(["stop", SERVICE_NAME])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .ok();
        // Give SCM time to stop
        std::thread::sleep(std::time::Duration::from_millis(1500));
        // Force-kill if still running
        Command::new("taskkill")
            .args(["/F", "/IM", "whispera-go-client.exe"])
            .creation_flags_win(CREATE_NO_WINDOW)
            .output()
            .ok();
        self.use_service = false;
        Ok(())
    }

    pub fn start(&mut self, cfg: &GoClientConfig) -> Result<(), String> {
        if self.is_running() {
            self.stop()?;
        }

        // Try service first if it appears to be registered
        if service_exists(SERVICE_NAME) {
            // Update service binary path with new config (re-install)
            if self.install_service(cfg).is_ok() {
                if self.start_service().is_ok() {
                    return Ok(());
                }
            }
        }

        // Fall back to direct spawn with hidden window + low priority
        self.start_direct(cfg)
    }

    fn start_direct(&mut self, cfg: &GoClientConfig) -> Result<(), String> {
        let mut cmd = Command::new(&self.binary_path);

        if !cfg.conn_key.is_empty() {
            // Normal mode: full whispera:// key
            cmd.arg("-key").arg(cfg.conn_key);
        } else if !cfg.server_addr.is_empty() {
            // ML mode: server address + optional user PSK token
            cmd.arg("-server").arg(cfg.server_addr);
            if !cfg.ml_token.is_empty() {
                cmd.arg("-user-key").arg(cfg.ml_token);
            }
        } else {
            return Err("No connection key or server address provided".to_string());
        }

        cmd.arg("-socks").arg(cfg.socks_addr);
        cmd.arg("-no-tun");

        if cfg.kill_switch {
            cmd.arg("-kill-switch");
        }

        if !cfg.transport.is_empty() {
            cmd.arg("-transport").arg(cfg.transport);
        }

        let log_path = self
            .binary_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("go-client.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map(Stdio::from)
            .unwrap_or(Stdio::null());
        let log_file2 = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map(Stdio::from)
            .unwrap_or(Stdio::null());

        cmd.stdout(log_file).stderr(log_file2);

        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start go-client: {}", e))?;

        self.process = Some(child);
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
        }
        self.process = None;
        Ok(())
    }

    pub fn is_running(&mut self) -> bool {
        if self.use_service {
            return service_running(SERVICE_NAME);
        }
        match &mut self.process {
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => {
                    self.process = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            },
            None => false,
        }
    }
}

impl Drop for GoClientManager {
    fn drop(&mut self) {
        self.stop().ok();
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

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

// Extension trait to allow cross-platform compilation
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
