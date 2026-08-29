use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FuzzSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzFinding {
    pub tool_name: String,
    pub vector_name: String,
    pub category: String,
    pub severity: FuzzSeverity,
    pub description: String,
    pub sample_payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FuzzReport {
    pub total_tests: usize,
    pub total_vulnerabilities: usize,
    pub findings: Vec<FuzzFinding>,
}

impl FuzzReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_finding(&mut self, finding: FuzzFinding) {
        self.total_vulnerabilities += 1;
        self.findings.push(finding);
    }

    pub fn to_human_readable(&self) -> String {
        let mut out = String::new();
        out.push_str("====================================================\n");
        out.push_str("          AGENTGUARD-MCP FUZZING REPORT             \n");
        out.push_str("====================================================\n");
        out.push_str(&format!("Total Vectors Tested: {}\n", self.total_tests));
        out.push_str(&format!(
            "Vulnerabilities Flagged: {}\n\n",
            self.total_vulnerabilities
        ));

        if self.findings.is_empty() {
            out.push_str("Result: CLEAN — No security vulnerabilities flagged during fuzzing.\n");
        } else {
            for (idx, f) in self.findings.iter().enumerate() {
                out.push_str(&format!(
                    "[{}] Tool: '{}' | Vector: '{}' | Severity: {:?}\n",
                    idx + 1,
                    f.tool_name,
                    f.vector_name,
                    f.severity
                ));
                out.push_str(&format!("    Category: {}\n", f.category));
                out.push_str(&format!("    Description: {}\n", f.description));
                out.push_str(&format!("    Sample Payload: {}\n\n", f.sample_payload));
            }
        }

        out
    }
}
