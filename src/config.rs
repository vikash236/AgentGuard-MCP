use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SandboxConfigSection {
    pub jail_root: Option<PathBuf>,
    pub enforce_path_canonicalization: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RedactorConfigSection {
    pub enable_redaction: Option<bool>,
    pub entropy_threshold: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GatewayConfigSection {
    pub port: Option<u16>,
    pub target_url: Option<String>,
    pub require_bearer_token: Option<bool>,
    pub token: Option<String>,
    pub max_requests_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PolicyConfigSection {
    pub audit_log_file: Option<PathBuf>,
    pub allowed_tools: Option<Vec<String>>,
}

/// Native TOML Configuration structure for AgentGuard-MCP (`agentguard.toml`).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AgentGuardConfig {
    pub sandbox: Option<SandboxConfigSection>,
    pub redactor: Option<RedactorConfigSection>,
    pub gateway: Option<GatewayConfigSection>,
    pub policy: Option<PolicyConfigSection>,
}

impl AgentGuardConfig {
    /// Load and parse an `agentguard.toml` configuration file.
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: AgentGuardConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_agentguard_toml() {
        let toml_str = r#"
        [sandbox]
        jail_root = "./sandbox"
        enforce_path_canonicalization = true

        [redactor]
        enable_redaction = true

        [gateway]
        port = 9090
        target_url = "http://127.0.0.1:3000"
        max_requests_per_minute = 100

        [policy]
        audit_log_file = "./audit.log"
        "#;

        let config: AgentGuardConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.sandbox.as_ref().unwrap().jail_root,
            Some(PathBuf::from("./sandbox"))
        );
        assert_eq!(
            config.redactor.as_ref().unwrap().enable_redaction,
            Some(true)
        );
        assert_eq!(config.gateway.as_ref().unwrap().port, Some(9090));
        assert_eq!(
            config.policy.as_ref().unwrap().audit_log_file,
            Some(PathBuf::from("./audit.log"))
        );
    }
}
