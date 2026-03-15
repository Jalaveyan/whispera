use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
#[cfg(windows)]
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x00004000;

pub struct MlServerManager {
    binary_path: PathBuf,
    log_path: PathBuf,
    process: Option<Child>,
}

impl MlServerManager {
    pub fn new(binary_path: PathBuf, log_path: PathBuf) -> Self {
        Self {
            binary_path,
            log_path,
            process: None,
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }
        if !self.binary_path.exists() {
            return Err(format!(
                "ML server binary not found: {}",
                self.binary_path.display()
            ));
        }

        let log_out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map(Stdio::from)
            .unwrap_or(Stdio::null());
        let log_err = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map(Stdio::from)
            .unwrap_or(Stdio::null());

        let mut cmd = Command::new(&self.binary_path);
        cmd.stdout(log_out).stderr(log_err);

        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start ML server: {}", e))?;
        self.process = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(ref mut child) = self.process {
            child.kill().ok();
            child.wait().ok();
        }
        self.process = None;

        // Force-kill leftover process by name on Windows
        #[cfg(windows)]
        {
            Command::new("taskkill")
                .args(["/F", "/IM", "whispera-ml-server.exe"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .ok();
        }

        Ok(())
    }

    pub fn is_running(&mut self) -> bool {
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

    /// Returns up to `n` tail lines of the ML server log.
    pub fn get_log_tail(&self, n: usize) -> String {
        if let Ok(content) = std::fs::read_to_string(&self.log_path) {
            let all: Vec<&str> = content.lines().collect();
            let start = if all.len() > n { all.len() - n } else { 0 };
            all[start..].join("\n")
        } else {
            String::new()
        }
    }

    pub fn binary_exists(&self) -> bool {
        self.binary_path.exists()
    }
}

impl Drop for MlServerManager {
    fn drop(&mut self) {
        self.stop().ok();
    }
}
