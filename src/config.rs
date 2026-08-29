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

use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PolicyConfigSection {
    pub audit_log_file: Option<PathBuf>,
    pub allowed_tools: Option<Vec<String>>,
    pub denied_tools: Option<Vec<String>>,
    pub argument_rules: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PromptFirewallConfigSection {
    pub enable_firewall: Option<bool>,
    pub custom_patterns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NetworkGuardConfigSection {
    pub enable_network_guard: Option<bool>,
    pub block_private_ips: Option<bool>,
    pub block_cloud_metadata: Option<bool>,
    pub allowed_domains: Option<Vec<String>>,
    pub denied_domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ApprovalConfigSection {
    pub enable_approval: Option<bool>,
    pub require_tools: Option<Vec<String>>,
    pub timeout_seconds: Option<u64>,
}

/// Native TOML Configuration structure for AgentGuard-MCP (`agentguard.toml`).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AgentGuardConfig {
    pub sandbox: Option<SandboxConfigSection>,
    pub redactor: Option<RedactorConfigSection>,
    pub gateway: Option<GatewayConfigSection>,
    pub policy: Option<PolicyConfigSection>,
    pub prompt_firewall: Option<PromptFirewallConfigSection>,
    pub network_guard: Option<NetworkGuardConfigSection>,
    pub approval: Option<ApprovalConfigSection>,
}

impl AgentGuardConfig {
    /// Load and parse an `agentguard.toml` configuration file.
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: AgentGuardConfig = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Check file modification timestamp and reload if updated.
    #[allow(dead_code)]
    pub fn reload_if_modified(
        path: &Path,
        last_modified: &mut Option<std::time::SystemTime>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let metadata = std::fs::metadata(path)?;
        let modified = metadata.modified()?;

        if last_modified.as_ref() == Some(&modified) {
            return Ok(None);
        }

        *last_modified = Some(modified);
        let new_config = Self::load_from_file(path)?;
        Ok(Some(new_config))
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

        [network_guard]
        enable_network_guard = true
        block_private_ips = true
        block_cloud_metadata = true
        allowed_domains = ["api.github.com"]

        [approval]
        enable_approval = true
        require_tools = ["delete_file", "execute_command"]
        timeout_seconds = 45
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
        assert_eq!(
            config.network_guard.as_ref().unwrap().enable_network_guard,
            Some(true)
        );
        assert_eq!(
            config.approval.as_ref().unwrap().require_tools,
            Some(vec!["delete_file".to_string(), "execute_command".to_string()])
        );
    }
}
