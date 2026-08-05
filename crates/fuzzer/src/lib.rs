pub mod payloads;
pub mod policy;
pub mod report;

pub use payloads::{generate_all_vectors, FuzzVector, VectorCategory};
pub use policy::PolicyGenerator;
pub use report::{FuzzFinding, FuzzReport, FuzzSeverity};

use agentguard_auditor::{McpTool, ToolManifest};
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

        for tool in &manifest.tools {
            Self::fuzz_tool(tool, &vectors, &mut report);
        }

        Ok(report)
    }

    fn fuzz_tool(tool: &McpTool, vectors: &[FuzzVector], report: &mut FuzzReport) {
        for vector in vectors {
            report.total_tests += 1;

            if let Some(ref schema) = tool.input_schema {
                let schema_str = schema.to_string().to_lowercase();

                match vector.category {
                    VectorCategory::PathTraversal => {
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
                                    "Tool '{}' accepts unconstrained path parameters vulnerable to vector '{}'",
                                    tool.name, vector.name
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
                            desc.contains("<!--") || desc.to_lowercase().contains("ignore previous")
                        }) {
                            report.add_finding(FuzzFinding {
                                tool_name: tool.name.clone(),
                                vector_name: vector.name.to_string(),
                                category: "Prompt Injection Risk".to_string(),
                                severity: FuzzSeverity::High,
                                description: format!(
                                    "Tool description for '{}' contains prompt override directives",
                                    tool.name
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
                                    "Tool '{}' string parameters lack maxLength constraints",
                                    tool.name
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
}
