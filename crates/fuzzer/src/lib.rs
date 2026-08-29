pub mod payloads;
pub mod policy;
pub mod report;

pub use payloads::{FuzzVector, VectorCategory, generate_all_vectors};
pub use policy::PolicyGenerator;
pub use report::{FuzzFinding, FuzzReport, FuzzSeverity};

use agentguard_auditor::{McpTool, ToolManifest};
use agentguard_jail::PathJail;
use std::path::Path;

/// Automated MCP Security Red-Teaming Fuzzer Engine.
pub struct FuzzerEngine;

impl FuzzerEngine {
    /// Fuzz an MCP tool manifest JSON file against security test vectors.
    pub fn fuzz_manifest(manifest_path: &Path) -> Result<FuzzReport, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(manifest_path)?;
        let manifest = ToolManifest::parse(&contents)?;
        let vectors = generate_all_vectors();
        let mut report = FuzzReport::new();

        let temp_dir = std::env::temp_dir().join("agentguard_fuzzer_runtime");
        let _ = std::fs::create_dir_all(&temp_dir);
        let jail = PathJail::new(&temp_dir).ok();

        for tool in &manifest.tools {
            Self::fuzz_tool(tool, &vectors, jail.as_ref(), &mut report);
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(report)
    }

    fn fuzz_tool(
        tool: &McpTool,
        vectors: &[FuzzVector],
        jail: Option<&PathJail>,
        report: &mut FuzzReport,
    ) {
        for vector in vectors {
            report.total_tests += 1;

            if let Some(ref schema) = tool.input_schema {
                let schema_str = schema.to_string().to_lowercase();

                match vector.category {
                    VectorCategory::PathTraversal => {
                        // Dynamically test payload against PathJail
                        let mut dynamic_blocked = false;
                        if let Some(j) = jail {
                            let simulated_args = serde_json::json!({
                                "path": vector.payload,
                                "file": vector.payload,
                                "target": vector.payload,
                                "input_path": vector.payload
                            });
                            dynamic_blocked = j.inspect_json_arguments(&simulated_args).is_err();
                        }

                        if (schema_str.contains("path")
                            || schema_str.contains("file")
                            || schema_str.contains("dir"))
                            && !schema_str.contains("pattern")
                        {
                            report.add_finding(FuzzFinding {
                                tool_name: tool.name.clone(),
                                vector_name: vector.name.to_string(),
                                category: "Path Traversal Risk".to_string(),
                                severity: FuzzSeverity::High,
                                description: format!(
                                    "Tool '{}' schema accepts unconstrained path parameters. Vector '{}' (Dynamic Jail Defense: {})",
                                    tool.name,
                                    vector.name,
                                    if dynamic_blocked { "Enforced" } else { "Bypass Risk" }
                                ),
                                sample_payload: vector.payload.clone(),
                            });
                        }
                    }
                    VectorCategory::CommandInjection => {
                        if (tool.name.contains("shell")
                            || tool.name.contains("cmd")
                            || tool.name.contains("exec")
                            || schema_str.contains("command"))
                            && !schema_str.contains("enum")
                        {
                            report.add_finding(FuzzFinding {
                                tool_name: tool.name.clone(),
                                vector_name: vector.name.to_string(),
                                category: "Command Injection Risk".to_string(),
                                severity: FuzzSeverity::Critical,
                                description: format!(
                                    "Shell execution tool '{}' lacks argument enum constraints for vector '{}'",
                                    tool.name, vector.name
                                ),
                                sample_payload: vector.payload.clone(),
                            });
                        }
                    }
                    VectorCategory::PromptInjection => {
                        if tool.description.as_ref().is_some_and(|desc| {
                            desc.contains("<!--")
                                || desc.to_lowercase().contains("ignore previous")
                                || desc.to_lowercase().contains("system prompt")
                        }) {
                            report.add_finding(FuzzFinding {
                                tool_name: tool.name.clone(),
                                vector_name: vector.name.to_string(),
                                category: "Prompt Injection Risk".to_string(),
                                severity: FuzzSeverity::High,
                                description: format!(
                                    "Tool description for '{}' contains prompt override directives for vector '{}'",
                                    tool.name, vector.name
                                ),
                                sample_payload: vector.payload.clone(),
                            });
                        }
                    }
                    VectorCategory::BoundaryStress => {
                        if schema_str.contains("\"type\":\"string\"")
                            && !schema_str.contains("maxlength")
                        {
                            report.add_finding(FuzzFinding {
                                tool_name: tool.name.clone(),
                                vector_name: vector.name.to_string(),
                                category: "Unconstrained String Stress".to_string(),
                                severity: FuzzSeverity::Medium,
                                description: format!(
                                    "Tool '{}' string parameters lack maxLength constraints for vector '{}'",
                                    tool.name, vector.name
                                ),
                                sample_payload: format!(
                                    "Payload size: {} chars",
                                    vector.payload.len()
                                ),
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_vectors_generated() {
        let vectors = generate_all_vectors();
        assert!(vectors.len() >= 10);
    }

    #[test]
    fn test_dynamic_fuzzer_execution() {
        let vectors = generate_all_vectors();
        let tool = McpTool {
            name: "read_file".to_string(),
            description: Some("Reads a file from disk".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                }
            })),
        };
        let mut report = FuzzReport::new();
        let temp_dir = std::env::temp_dir().join("agentguard_fuzzer_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let jail = PathJail::new(&temp_dir).ok();

        FuzzerEngine::fuzz_tool(&tool, &vectors, jail.as_ref(), &mut report);
        assert!(report.total_tests >= 10);
        assert!(!report.findings.is_empty());
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
