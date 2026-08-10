use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn test_proxy_policy_engine_denied_tools() {
    let temp_dir = std::env::temp_dir().join("agentguard_policy_e2e_test");
    let _ = fs::create_dir_all(&temp_dir);

    let sandbox_path = temp_dir.join("sandbox");
    let _ = fs::create_dir_all(&sandbox_path);

    let config_path = temp_dir.join("agentguard.toml");
    let config_content = format!(
        r#"
        [sandbox]
        jail_root = "{}"

        [policy]
        denied_tools = ["forbidden_tool"]
        "#,
        sandbox_path.to_str().unwrap().replace('\\', "/")
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
        .expect("Failed to start agentguard proxy with policy engine");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Send forbidden tool call
    let forbidden_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "forbidden_tool",
            "arguments": {}
        }
    });

    writeln!(stdin, "{}", serde_json::to_string(&forbidden_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();

    assert!(
        response_line.contains("PolicyViolation"),
        "Proxy should reject forbidden tool call: {response_line}"
    );

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&temp_dir);
}
