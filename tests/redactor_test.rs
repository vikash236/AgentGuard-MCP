use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn test_proxy_redacts_stdout_secrets() {
    let temp_root = std::env::temp_dir().join("agentguard_redactor_e2e_test");
    let _ = fs::create_dir_all(&temp_root);

    let build_status = Command::new("cargo")
        .args(["build", "--bin", "agentguard"])
        .status()
        .expect("Failed to build agentguard binary");
    assert!(build_status.success(), "agentguard binary build failed");

    let exe_path = if cfg!(windows) {
        "target/debug/agentguard.exe"
    } else {
        "target/debug/agentguard"
    };

    let child_cmd = if cfg!(windows) { "cmd" } else { "cat" };
    let child_args: &[&str] = if cfg!(windows) { &["/C", "more"] } else { &[] };

    let mut proxy_args = vec![
        "proxy",
        "--jail",
        temp_root.to_str().unwrap(),
        "--redact",
        "--",
        child_cmd,
    ];
    proxy_args.extend_from_slice(child_args);

    let mut child = Command::new(exe_path)
        .args(&proxy_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agentguard proxy process with --redact");

    let mut stdin = child.stdin.take().expect("Failed to open child stdin");
    let stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut reader = BufReader::new(stdout);

    // Send payload containing an AWS Access Key ID in JSON response
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": "Server env: AKIAIOSFODNN7EXAMPLE"
        }
    });

    writeln!(stdin, "{}", serde_json::to_string(&payload).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut output_line = String::new();
    reader.read_line(&mut output_line).unwrap();

    assert!(!output_line.is_empty(), "Proxy should output redacted response frame");
    assert!(
        output_line.contains("[REDACTED]"),
        "Secrets should be masked with [REDACTED]: {}",
        output_line
    );
    assert!(
        !output_line.contains("AKIAIOSFODNN7EXAMPLE"),
        "Raw AWS Key must NOT appear in stdout frame: {}",
        output_line
    );

    drop(stdin);
    let _ = child.kill();
    let _ = fs::remove_dir_all(&temp_root);
}
