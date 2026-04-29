//! Agent abstraction for different AI coding tools.
//!
//! cplt can sandbox multiple AI coding agents — currently GitHub Copilot CLI
//! and OpenCode. Each agent has different binary names, config directories,
//! and runtime requirements, but shares the same core sandbox infrastructure.

use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Supported AI coding agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    /// GitHub Copilot CLI (default).
    Copilot,
    /// OpenCode (anomalyco/opencode) — open source AI coding agent.
    OpenCode,
    /// Plain sandboxed shell — no AI agent, just a secure shell session.
    Shell,
}

impl Agent {
    /// The binary name to search for in PATH.
    pub fn binary_name(&self) -> &'static str {
        match self {
            Agent::Copilot => "copilot",
            Agent::OpenCode => "opencode",
            Agent::Shell => "shell",
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Agent::Copilot => "Copilot",
            Agent::OpenCode => "OpenCode",
            Agent::Shell => "Shell",
        }
    }

    /// Whether this agent uses Node.js SEA extraction that needs pre-sandbox setup.
    /// Copilot uses SEA packaging which extracts to ~/Library/Caches/copilot/pkg/.
    /// OpenCode is distributed via npm or standalone binary — no SEA extraction needed.
    pub fn needs_sea_extraction(&self) -> bool {
        matches!(self, Agent::Copilot)
    }

    /// Extra arguments injected before the user's args.
    /// Copilot needs --no-auto-update to prevent writes to ~/.copilot/pkg inside sandbox.
    pub fn extra_args(&self) -> &'static [&'static str] {
        match self {
            Agent::Copilot => &["--no-auto-update"],
            Agent::OpenCode | Agent::Shell => &[],
        }
    }

    /// Whether this agent needs macOS Keychain access for auth tokens.
    /// Copilot stores GitHub auth tokens in the Keychain.
    /// OpenCode uses API keys from env vars or config files.
    pub fn needs_keychain(&self) -> bool {
        matches!(self, Agent::Copilot)
    }

    /// Whether this agent needs access to ~/.copilot directory.
    pub fn needs_copilot_dir(&self) -> bool {
        matches!(self, Agent::Copilot)
    }

    /// Config directories under $HOME that need read/write access.
    /// Returns (relative_path, needs_write).
    pub fn config_dirs(&self, home: &Path) -> Vec<AgentDir> {
        match self {
            Agent::Copilot => {
                vec![
                    // ~/.copilot is handled separately in emit_home_access
                    // (needs map-executable for native modules)
                ]
            }
            Agent::Shell => vec![],
            Agent::OpenCode => {
                // Respect XDG_CONFIG_HOME for config dir
                let config_base = std::env::var("XDG_CONFIG_HOME")
                    .ok()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".config"));
                let config_dir = config_base.join("opencode");

                // Respect XDG_DATA_HOME for data dir (sessions, SQLite DB)
                let data_base = std::env::var("XDG_DATA_HOME")
                    .ok()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".local/share"));
                let data_dir = data_base.join("opencode");

                vec![
                    AgentDir {
                        path: config_dir,
                        write: false,
                        map_exec: false,
                        process_exec: false,
                    },
                    AgentDir {
                        path: data_dir,
                        write: true,
                        map_exec: false,
                        // Explicitly deny exec on writable data dir
                        process_exec: false,
                    },
                ]
            }
        }
    }

    /// Environment variable names this agent may need for authentication.
    /// These are NOT added to the default allowlist — they must be
    /// explicitly passed via --pass-env or agent config.
    /// Note: OpenCode also supports GitHub Copilot as a provider via
    /// `/connect` — no env key needed for that flow (auth stored in auth.json).
    pub fn auth_env_hint(&self) -> &'static [&'static str] {
        match self {
            // Copilot tokens are in the default allowlist (accepted trade-off)
            Agent::Copilot => &[],
            // OpenCode third-party provider API keys — user must opt in.
            // Copilot provider uses device flow + auth.json, no env var needed.
            Agent::OpenCode => &[
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
                "GEMINI_API_KEY",
                "OPENROUTER_API_KEY",
                "GROQ_API_KEY",
            ],
            Agent::Shell => &[],
        }
    }

    /// Resolve the agent binary, walking PATH and skipping cplt aliases.
    ///
    /// For Copilot: prefers standalone binaries over VS Code editor shims.
    /// For OpenCode: straightforward PATH search.
    /// For Shell: uses $SHELL or falls back to /bin/zsh (macOS) or /bin/bash.
    pub fn resolve_binary(&self) -> Result<PathBuf, String> {
        if matches!(self, Agent::Shell) {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| {
                if cfg!(target_os = "macos") {
                    "/bin/zsh".to_string()
                } else {
                    "/bin/bash".to_string()
                }
            });
            let path = PathBuf::from(&shell);
            if path.is_file() {
                return Ok(path);
            }
            return Err(format!("Shell not found: {shell}"));
        }

        let binary_name = self.binary_name();
        let self_exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(&p).ok());

        let path_var = std::env::var("PATH").unwrap_or_default();

        // For Copilot, track editor shims as fallback
        let mut editor_shim: Option<PathBuf> = None;

        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join(binary_name);

            if !candidate.is_file() {
                continue;
            }

            let resolved = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
            if self_exe.as_ref() == Some(&resolved) {
                continue; // skip cplt aliased as this binary
            }

            // Copilot-specific: prefer standalone over editor shims
            if matches!(self, Agent::Copilot) && is_editor_shim(&resolved) {
                if editor_shim.is_none() {
                    editor_shim = Some(resolved);
                }
                continue;
            }

            return Ok(resolved);
        }

        if let Some(shim) = editor_shim {
            return Ok(shim);
        }

        let install_hint = match self {
            Agent::Copilot => {
                "If you installed cplt as a 'copilot' alias, the real Copilot CLI \
                 must also be in PATH (e.g. brew install --cask copilot-cli)."
            }
            Agent::OpenCode => {
                "Install OpenCode: npm i -g opencode-ai, or brew install anomalyco/tap/opencode"
            }
            Agent::Shell => unreachable!("Shell is resolved via $SHELL above"),
        };

        Err(format!(
            "{} not found in PATH. {install_hint}",
            self.display_name()
        ))
    }

    /// Auto-detect which agent to use based on what's available in PATH.
    /// Returns Copilot if found (backward compat), else OpenCode.
    /// Returns None if neither is found.
    pub fn auto_detect() -> Option<Agent> {
        let path_var = std::env::var("PATH").unwrap_or_default();
        let self_exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(&p).ok());

        let mut found_copilot = false;
        let mut found_opencode = false;

        for dir in path_var.split(':') {
            if !found_copilot {
                let candidate = PathBuf::from(dir).join("copilot");
                if candidate.is_file() {
                    let resolved =
                        std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    if self_exe.as_ref() != Some(&resolved) {
                        found_copilot = true;
                    }
                }
            }
            if !found_opencode {
                let candidate = PathBuf::from(dir).join("opencode");
                if candidate.is_file() {
                    let resolved =
                        std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    if self_exe.as_ref() != Some(&resolved) {
                        found_opencode = true;
                    }
                }
            }
        }

        if found_copilot {
            Some(Agent::Copilot)
        } else if found_opencode {
            Some(Agent::OpenCode)
        } else {
            None
        }
    }
}

impl FromStr for Agent {
    type Err = String;

    fn from_str(s: &str) -> Result<Agent, String> {
        match s.to_lowercase().as_str() {
            "copilot" => Ok(Agent::Copilot),
            "opencode" => Ok(Agent::OpenCode),
            "shell" | "sh" | "bash" | "zsh" => Ok(Agent::Shell),
            _ => Err(format!(
                "Unknown agent '{s}'. Supported: copilot, opencode, shell"
            )),
        }
    }
}

/// A directory an agent needs access to in the sandbox.
#[derive(Debug, Clone)]
pub struct AgentDir {
    pub path: PathBuf,
    pub write: bool,
    pub map_exec: bool,
    pub process_exec: bool,
}

/// Check if a copilot binary is a VS Code/Cursor/editor shim script.
fn is_editor_shim(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content.starts_with("#!") && content.contains("copilotCLIShim.js")
}

impl std::fmt::Display for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_agent_names() {
        assert_eq!(Agent::from_str("copilot").unwrap(), Agent::Copilot);
        assert_eq!(Agent::from_str("Copilot").unwrap(), Agent::Copilot);
        assert_eq!(Agent::from_str("opencode").unwrap(), Agent::OpenCode);
        assert_eq!(Agent::from_str("OpenCode").unwrap(), Agent::OpenCode);
        assert!(Agent::from_str("unknown").is_err());
    }

    #[test]
    fn copilot_binary_name() {
        assert_eq!(Agent::Copilot.binary_name(), "copilot");
    }

    #[test]
    fn opencode_binary_name() {
        assert_eq!(Agent::OpenCode.binary_name(), "opencode");
    }

    #[test]
    fn copilot_needs_sea_extraction() {
        assert!(Agent::Copilot.needs_sea_extraction());
        assert!(!Agent::OpenCode.needs_sea_extraction());
    }

    #[test]
    fn copilot_extra_args() {
        assert_eq!(Agent::Copilot.extra_args(), &["--no-auto-update"]);
        assert!(Agent::OpenCode.extra_args().is_empty());
    }

    #[test]
    fn copilot_needs_keychain() {
        assert!(Agent::Copilot.needs_keychain());
        assert!(!Agent::OpenCode.needs_keychain());
    }

    #[test]
    fn opencode_config_dirs_xdg_default() {
        let home = Path::new("/Users/test");
        let dirs = Agent::OpenCode.config_dirs(home);
        assert!(dirs.len() >= 2, "should have config + data dirs");
        // Config dir is read-only, data dir is writable
        let config_dir = dirs
            .iter()
            .find(|d| d.path.to_str().unwrap().contains("config"))
            .unwrap();
        let data_dir = dirs
            .iter()
            .find(|d| d.path.to_str().unwrap().contains("share"))
            .unwrap();
        assert!(!config_dir.write, "config dir should be read-only");
        assert!(data_dir.write, "data dir should be writable");
        // Neither should be executable
        assert!(dirs.iter().all(|d| !d.process_exec && !d.map_exec));
    }

    #[test]
    fn copilot_has_no_extra_config_dirs() {
        let home = Path::new("/Users/test");
        let dirs = Agent::Copilot.config_dirs(home);
        assert!(
            dirs.is_empty(),
            "copilot dirs are handled in emit_home_access"
        );
    }

    #[test]
    fn opencode_auth_env_hints() {
        let hints = Agent::OpenCode.auth_env_hint();
        assert!(hints.contains(&"ANTHROPIC_API_KEY"));
        assert!(hints.contains(&"OPENAI_API_KEY"));
    }

    #[test]
    fn display_names() {
        assert_eq!(format!("{}", Agent::Copilot), "Copilot");
        assert_eq!(format!("{}", Agent::OpenCode), "OpenCode");
    }
}
