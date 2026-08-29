use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// Callback type for programmatic / testing approval hooks.
pub type ApprovalHook = Arc<dyn Fn(&str, &serde_json::Value) -> bool + Send + Sync>;

/// Human-In-The-Loop (HITL) Interactive Tool Approval Engine.
#[derive(Clone)]
pub struct ApprovalEngine {
    pub require_tools: Vec<String>,
    pub timeout_seconds: u64,
    pub hook: Option<ApprovalHook>,
}

impl std::fmt::Debug for ApprovalEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalEngine")
            .field("require_tools", &self.require_tools)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("hook_set", &self.hook.is_some())
            .finish()
    }
}

impl Default for ApprovalEngine {
    fn default() -> Self {
        Self::new(
            vec![
                "execute_command".to_string(),
                "bash".to_string(),
                "sh".to_string(),
                "delete_file".to_string(),
                "remove_file".to_string(),
                "drop_table".to_string(),
            ],
            30,
        )
    }
}

impl ApprovalEngine {
    pub fn new(require_tools: Vec<String>, timeout_seconds: u64) -> Self {
        Self {
            require_tools,
            timeout_seconds,
            hook: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_hook(mut self, hook: ApprovalHook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Check if the specified tool requires human approval.
    pub fn requires_approval(&self, tool_name: &str) -> bool {
        let name_lower = tool_name.to_lowercase();
        self.require_tools.iter().any(|t| {
            let t_lower = t.to_lowercase();
            t_lower == "*" || t_lower == name_lower
        })
    }

    /// Request interactive approval for tool execution.
    pub async fn request_approval(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
    ) -> Result<(), String> {
        if !self.requires_approval(tool_name) {
            return Ok(());
        }

        // If programmatic / test hook is registered, evaluate it
        if let Some(ref hook) = self.hook {
            if hook(tool_name, params) {
                eprintln!("[agentguard-approval] APPROVED tool '{tool_name}' via approval hook");
                return Ok(());
            } else {
                return Err(format!(
                    "ApprovalDenied: Tool execution for '{tool_name}' was denied by approval hook"
                ));
            }
        }

        let args_str = params
            .get("arguments")
            .map(|a| a.to_string())
            .unwrap_or_else(|| "{}".to_string());

        eprintln!("\n========================================================");
        eprintln!("[agentguard-approval] ⚠️  HUMAN APPROVAL REQUIRED");
        eprintln!("[agentguard-approval] Tool Name : {tool_name}");
        eprintln!("[agentguard-approval] Arguments : {args_str}");
        eprintln!(
            "[agentguard-approval] Allow this operation? [y/N] ({}s timeout): ",
            self.timeout_seconds
        );
        eprintln!("========================================================");

        let timeout_dur = Duration::from_secs(self.timeout_seconds);

        // Attempt interactive console read
        let approval_result = timeout(timeout_dur, async {
            tokio::task::spawn_blocking(prompt_console_user)
                .await
                .unwrap_or(false)
        })
        .await;

        match approval_result {
            Ok(true) => {
                eprintln!("[agentguard-approval] ✅ Operator GRANTED permission for '{tool_name}'");
                Ok(())
            }
            Ok(false) => {
                eprintln!("[agentguard-approval] ❌ Operator DENIED permission for '{tool_name}'");
                Err(format!(
                    "ApprovalDenied: Operator rejected tool execution for '{tool_name}'"
                ))
            }
            Err(_) => {
                eprintln!(
                    "[agentguard-approval] ⏱️  Approval TIMED OUT after {}s for '{tool_name}'",
                    self.timeout_seconds
                );
                Err(format!(
                    "ApprovalTimedOut: No operator response within {}s for tool '{tool_name}'",
                    self.timeout_seconds
                ))
            }
        }
    }
}

/// Prompt console user directly on the active TTY / console device
fn prompt_console_user() -> bool {
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::io::{BufRead, BufReader};

        if let Ok(file) = OpenOptions::new().read(true).open("CONIN$") {
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                let trimmed = line.trim().to_lowercase();
                return trimmed == "y" || trimmed == "yes";
            }
        }
        false
    }

    #[cfg(not(windows))]
    {
        use std::fs::OpenOptions;
        use std::io::{BufRead, BufReader};

        if let Ok(file) = OpenOptions::new().read(true).open("/dev/tty") {
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                let trimmed = line.trim().to_lowercase();
                return trimmed == "y" || trimmed == "yes";
            }
        }
        false
    }
}

#[allow(dead_code)]
pub type SharedApprovalEngine = Arc<ApprovalEngine>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_approval_not_required_for_benign_tools() {
        let engine = ApprovalEngine::default();
        assert!(!engine.requires_approval("read_file"));
        assert!(!engine.requires_approval("search_docs"));

        let res = engine
            .request_approval("read_file", &serde_json::json!({}))
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_approval_required_for_destructive_tools() {
        let engine = ApprovalEngine::default();
        assert!(engine.requires_approval("execute_command"));
        assert!(engine.requires_approval("delete_file"));
        assert!(engine.requires_approval("bash"));
    }

    #[tokio::test]
    async fn test_approval_hook_granted_and_denied() {
        let granted_engine = ApprovalEngine::default().with_hook(Arc::new(|_tool, _params| true));
        let res_ok = granted_engine
            .request_approval("execute_command", &serde_json::json!({"cmd": "ls"}))
            .await;
        assert!(res_ok.is_ok());

        let denied_engine = ApprovalEngine::default().with_hook(Arc::new(|_tool, _params| false));
        let res_err = denied_engine
            .request_approval("execute_command", &serde_json::json!({"cmd": "rm -rf /"}))
            .await;
        assert!(res_err.is_err());
        assert!(res_err.unwrap_err().contains("ApprovalDenied"));
    }
}
