//! # AgentGuard Auditor
//!
//! Static security auditor for MCP (Model Context Protocol) tool manifests.
//!
//! Parses tool definitions from `tools/list` JSON-RPC responses or bare tool
//! arrays and evaluates each tool against a set of security rules designed to
//! detect dangerous patterns: missing input validation, unconstrained shell
//! parameters, path traversal risks, and prompt injection in descriptions.

pub mod report;
pub mod rules;
pub mod schema;

pub use schema::ToolManifest;
pub type McpTool = schema::ToolDefinition;

use std::path::Path;

use report::{format_findings_human, format_findings_json, Finding};
use rules::run_all_rules;

/// Audit errors.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("failed to read manifest file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse manifest JSON: {0}")]
    Parse(#[from] schema::ParseError),
}

/// Run a full audit against the manifest at `path`.
///
/// Returns `Ok(true)` if any Critical or High severity findings were detected,
/// `Ok(false)` if the manifest is clean or only has Medium/Low findings.
///
/// All human-readable output is written to **stderr** (stdout is reserved for
/// JSON-RPC protocol frames in proxy mode).
pub fn run_audit(path: &Path, json_output: bool) -> Result<bool, AuditError> {
    let contents = std::fs::read_to_string(path)?;
    let manifest = ToolManifest::parse(&contents)?;

    let mut all_findings: Vec<Finding> = Vec::new();

    for tool in &manifest.tools {
        let findings = run_all_rules(tool);
        all_findings.extend(findings);
    }

    if json_output {
        let json = format_findings_json(&all_findings);
        // JSON output goes to stdout for piping.
        println!("{json}");
    } else {
        let output = format_findings_human(&all_findings, manifest.tools.len());
        eprint!("{output}");
    }

    let has_critical_or_high = all_findings.iter().any(|f| {
        matches!(
            f.severity,
            report::Severity::Critical | report::Severity::High
        )
    });

    Ok(has_critical_or_high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_audit_returns_error_for_missing_file() {
        let result = run_audit(Path::new("nonexistent.json"), false);
        assert!(result.is_err());
    }
}
