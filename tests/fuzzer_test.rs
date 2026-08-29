use std::fs;
use std::process::Command;

#[test]
fn test_fuzzer_and_policy_generator_end_to_end() {
    let temp_dir = std::env::temp_dir().join("agentguard_fuzzer_e2e_test");
    let _ = fs::create_dir_all(&temp_dir);

    let manifest_path = temp_dir.join("test_manifest.json");
    let manifest_json = serde_json::json!({
        "tools": [
            {
                "name": "shell_execute",
                "description": "Execute shell command",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string" }
                    }
                }
            },
            {
                "name": "file_reader",
                "description": "Read file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    }
                }
            }
        ]
    });
    fs::write(
        &manifest_path,
        serde_json::to_string(&manifest_json).unwrap(),
    )
    .unwrap();

    // 1. Test FuzzerEngine directly
    let report = agentguard_fuzzer::FuzzerEngine::fuzz_manifest(&manifest_path).unwrap();
    assert!(report.total_tests > 0);
    assert!(
        report.total_vulnerabilities > 0,
        "Vulnerabilities should be detected for unconstrained manifest"
    );

    // 2. Test PolicyGenerator CLI subcommand
    let build_status = Command::new("cargo")
        .args(["build", "--bin", "agentguard"])
        .status()
        .expect("Failed to build agentguard binary");
    assert!(build_status.success());

    let exe_path = if cfg!(windows) {
        "target/debug/agentguard.exe"
    } else {
        "target/debug/agentguard"
    };

    let policy_path = temp_dir.join("agentguard.toml");
    let output = Command::new(exe_path)
        .args([
            "generate-policy",
            manifest_path.to_str().unwrap(),
            "--output",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run generate-policy");

    assert!(output.status.success());
    assert!(policy_path.exists());
    let policy_content = fs::read_to_string(&policy_path).unwrap();
    assert!(policy_content.contains("jail_root = \"./sandbox\""));
    assert!(policy_content.contains("\"shell_execute\""));
    assert!(policy_content.contains("\"file_reader\""));

    let _ = fs::remove_dir_all(&temp_dir);
}
