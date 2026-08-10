use crate::config::PolicyConfigSection;
use regex::Regex;
use std::collections::{HashMap, HashSet};

#[derive(Debug, thiserror::Error)]
pub enum PolicyViolationError {
    #[error("Tool '{0}' is explicitly forbidden by denylist policy")]
    ToolDenied(String),
    #[error("Tool '{0}' is not in the allowed tools list")]
    ToolNotAllowed(String),
    #[error("Argument '{arg}' value '{val}' violates pattern '{pattern}'")]
    ArgumentConstraintViolation {
        arg: String,
        val: String,
        pattern: String,
    },
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    allowed_tools: Option<HashSet<String>>,
    denied_tools: Option<HashSet<String>>,
    argument_rules: HashMap<String, Regex>,
}

impl PolicyEngine {
    pub fn new(section: &PolicyConfigSection) -> Result<Self, regex::Error> {
        let allowed_tools = section
            .allowed_tools
            .as_ref()
            .map(|list| list.iter().cloned().collect());
        let denied_tools = section
            .denied_tools
            .as_ref()
            .map(|list| list.iter().cloned().collect());

        let mut argument_rules = HashMap::new();
        if let Some(ref rules) = section.argument_rules {
            for (arg_name, pattern_str) in rules {
                let re = Regex::new(pattern_str)?;
                argument_rules.insert(arg_name.clone(), re);
            }
        }

        Ok(Self {
            allowed_tools,
            denied_tools,
            argument_rules,
        })
    }

    pub fn evaluate_tool_call(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
    ) -> Result<(), PolicyViolationError> {
        // 1. Check denied tools
        if self.denied_tools.as_ref().is_some_and(|d| d.contains(tool_name)) {
            return Err(PolicyViolationError::ToolDenied(tool_name.to_string()));
        }

        // 2. Check allowed tools
        if self.allowed_tools.as_ref().is_some_and(|a| !a.contains(tool_name)) {
            return Err(PolicyViolationError::ToolNotAllowed(tool_name.to_string()));
        }

        // 3. Check argument regex rules
        if !self.argument_rules.is_empty() {
            let args_obj = params.get("arguments");
            if let Some(args_map) = args_obj.and_then(|a| a.as_object()) {
                for (arg_name, re) in &self.argument_rules {
                    if let Some(val) = args_map.get(arg_name) {
                        let val_str = val.as_str().unwrap_or("");
                        if !re.is_match(val_str) {
                            return Err(PolicyViolationError::ArgumentConstraintViolation {
                                arg: arg_name.clone(),
                                val: val_str.to_string(),
                                pattern: re.as_str().to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_policy_engine_denied_tools() {
        let section = PolicyConfigSection {
            denied_tools: Some(vec!["delete_file".to_string()]),
            ..Default::default()
        };
        let engine = PolicyEngine::new(&section).unwrap();

        let params = json!({ "name": "delete_file", "arguments": {} });
        let res = engine.evaluate_tool_call("delete_file", &params);
        assert!(matches!(res, Err(PolicyViolationError::ToolDenied(_))));

        let safe_res = engine.evaluate_tool_call("read_file", &params);
        assert!(safe_res.is_ok());
    }

    #[test]
    fn test_policy_engine_allowed_tools() {
        let section = PolicyConfigSection {
            allowed_tools: Some(vec!["read_file".to_string()]),
            ..Default::default()
        };
        let engine = PolicyEngine::new(&section).unwrap();

        let params = json!({});
        assert!(engine.evaluate_tool_call("read_file", &params).is_ok());
        assert!(matches!(
            engine.evaluate_tool_call("write_file", &params),
            Err(PolicyViolationError::ToolNotAllowed(_))
        ));
    }

    #[test]
    fn test_policy_engine_argument_rules() {
        let mut argument_rules = HashMap::new();
        argument_rules.insert("path".to_string(), r"^/safe/.*".to_string());

        let section = PolicyConfigSection {
            argument_rules: Some(argument_rules),
            ..Default::default()
        };
        let engine = PolicyEngine::new(&section).unwrap();

        let valid_params = json!({
            "name": "read_file",
            "arguments": { "path": "/safe/data.txt" }
        });
        assert!(engine.evaluate_tool_call("read_file", &valid_params).is_ok());

        let invalid_params = json!({
            "name": "read_file",
            "arguments": { "path": "/etc/passwd" }
        });
        assert!(matches!(
            engine.evaluate_tool_call("read_file", &invalid_params),
            Err(PolicyViolationError::ArgumentConstraintViolation { .. })
        ));
    }
}
