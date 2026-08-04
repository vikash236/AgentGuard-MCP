//! Findings formatter for audit results.
//!
//! Supports two output modes:
//! - **Human-readable** (default): Colored stderr output with severity badges.
//! - **JSON**: Machine-parseable findings array for CI integration.

use serde::Serialize;
use std::fmt;

/// Severity level for an audit finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// A single audit finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Rule identifier (e.g., "AUDIT-001").
    pub rule_id: String,

    /// Severity level.
    pub severity: Severity,

    /// Name of the tool that triggered this finding.
    pub tool_name: String,

    /// Human-readable description of the issue.
    pub message: String,

    /// Suggested remediation.
    pub remediation: String,
}

/// Format findings as a human-readable report string.
///
/// Output is designed for stderr display with clear visual hierarchy.
pub fn format_findings_human(findings: &[Finding], tool_count: usize) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "\n=== AgentGuard Audit Report ===\n  Tools scanned: {tool_count}\n  Findings: {}\n\n",
        findings.len()
    ));

    if findings.is_empty() {
        out.push_str("  ✓ No security issues found.\n\n");
        return out;
    }

    // Group by severity for readability.
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| a.severity.cmp(&b.severity));

    for finding in &sorted {
        let badge = match finding.severity {
            Severity::Critical => "[!!]",
            Severity::High => "[! ]",
            Severity::Medium => "[~ ]",
            Severity::Low => "[. ]",
            Severity::Info => "[i ]",
        };

        out.push_str(&format!(
            "  {badge} {severity} {rule_id} ({tool})\n      {message}\n      -> {remediation}\n\n",
            severity = finding.severity,
            rule_id = finding.rule_id,
            tool = finding.tool_name,
            message = finding.message,
            remediation = finding.remediation,
        ));
    }

    // Summary line.
    let critical = sorted
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = sorted
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = sorted
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();

    out.push_str(&format!(
        "  Summary: {critical} critical, {high} high, {medium} medium\n\n"
    ));

    out
}

/// Format findings as a JSON string.
pub fn format_findings_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                rule_id: "AUDIT-001".to_string(),
                severity: Severity::Critical,
                tool_name: "exec".to_string(),
                message: "No schema".to_string(),
                remediation: "Add schema".to_string(),
            },
            Finding {
                rule_id: "AUDIT-005".to_string(),
                severity: Severity::Medium,
                tool_name: "search".to_string(),
                message: "Open additionalProperties".to_string(),
                remediation: "Set to false".to_string(),
            },
        ]
    }

    #[test]
    fn human_format_contains_all_findings() {
        let output = format_findings_human(&sample_findings(), 2);
        assert!(output.contains("AUDIT-001"));
        assert!(output.contains("AUDIT-005"));
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("MEDIUM"));
        assert!(output.contains("Tools scanned: 2"));
    }

    #[test]
    fn human_format_empty_findings() {
        let output = format_findings_human(&[], 3);
        assert!(output.contains("No security issues found"));
    }

    #[test]
    fn json_format_is_valid_json() {
        let json_str = format_findings_json(&sample_findings());
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_format_empty() {
        let json_str = format_findings_json(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }
}
