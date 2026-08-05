use std::fs;
use std::process::{Command, Stdio};

#[test]
fn test_config_loader_and_audit_logger_integration() {
    let temp_dir = std::env::temp_dir().join("agentguard_config_logger_e2e_test");
    let _ = fs::create_dir_all(&temp_dir);

    let sandbox_path = temp_dir.join("sandbox");
    let _ = fs::create_dir_all(&sandbox_path);
    let log_file = temp_dir.join("audit.log");

    let config_path = temp_dir.join("agentguard.toml");
    let config_content = format!(
        r#"
        [sandbox]
        jail_root = "{}"
        enforce_path_canonicalization = true

        [redactor]
        enable_redaction = true

        [policy]
        audit_log_file = "{}"
        "#,
        sandbox_path.to_str().unwrap().replace('\\', "/"),
        log_file.to_str().unwrap().replace('\\', "/")
    );
    fs::write(&config_path, config_content).unwrap();

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

    let child_cmd = if cfg!(windows) { "cmd" } else { "cat" };
    let child_args: &[&str] = if cfg!(windows) { &["/C", "more"] } else { &[] };

    let mut proxy_args = vec!["proxy", "--config", config_path.to_str().unwrap(), "--", child_cmd];
    proxy_args.extend_from_slice(child_args);

    let mut child = Command::new(exe_path)
        .args(&proxy_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agentguard proxy with config file");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);

    // Send path traversal attack
    let evil_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "../../Windows/System32/cmd.exe"
            }
        }
    });

    use std::io::Write;
    writeln!(stdin, "{}", serde_json::to_string(&evil_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut response_line = String::new();
    use std::io::BufRead;
    reader.read_line(&mut response_line).unwrap();

    assert!(response_line.contains("SecurityViolation"));

    drop(stdin);
    let _ = child.kill();

    assert!(log_file.exists(), "Audit log file should be generated");
    let log_contents = fs::read_to_string(&log_file).unwrap();
    assert!(log_contents.contains("path_jail_violation"));
    assert!(log_contents.contains("HIGH"));

    let _ = fs::remove_dir_all(&temp_dir);
}
