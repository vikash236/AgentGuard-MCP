use agentguard_auditor::McpTool;

/// Automated Sandbox Isolation Policy Generator.
pub struct PolicyGenerator;

impl PolicyGenerator {
    /// Generate an `agentguard.toml` security policy for a set of MCP tools.
    pub fn generate_policy(tools: &[McpTool]) -> String {
        let mut has_path_tools = false;
        let mut tool_names = Vec::new();

        for tool in tools {
            tool_names.push(format!("\"{}\"", tool.name));
            if let Some(ref schema) = tool.input_schema {
                let schema_str = schema.to_string().to_lowercase();
                if schema_str.contains("path")
                    || schema_str.contains("file")
                    || schema_str.contains("dir")
                {
                    has_path_tools = true;
                }
            }
        }

        let mut out = String::new();
        out.push_str("# ====================================================\n");
        out.push_str("# AgentGuard-MCP Security Policy (agentguard.toml)\n");
        out.push_str("# Generated automatically by `agentguard generate-policy` \n");
        out.push_str("# ====================================================\n\n");

        out.push_str("[sandbox]\n");
        if has_path_tools {
            out.push_str("jail_root = \"./sandbox\"\n");
            out.push_str("enforce_path_canonicalization = true\n\n");
        } else {
            out.push_str("jail_root = \"./\"\n");
            out.push_str("enforce_path_canonicalization = false\n\n");
        }

        out.push_str("[redactor]\n");
        out.push_str("enable_redaction = true\n");
        out.push_str("entropy_threshold = 4.5\n\n");

        out.push_str("[gateway]\n");
        out.push_str("max_requests_per_minute = 60\n");
        out.push_str("require_bearer_token = true\n\n");

        out.push_str("[allowed_tools]\n");
        out.push_str(&format!("manifest_tools = [{}]\n", tool_names.join(", ")));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_generator() {
        let tools = vec![McpTool {
            name: "read_file".to_string(),
            description: Some("Read file contents".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            })),
        }];

        let policy = PolicyGenerator::generate_policy(&tools);
        assert!(policy.contains("jail_root = \"./sandbox\""));
        assert!(policy.contains("enable_redaction = true"));
        assert!(policy.contains("\"read_file\""));
    }
}
