use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn test_proxy_network_guard_blocks_ssrf() {
    let temp_dir = std::env::temp_dir().join("agentguard_network_guard_e2e_test");
    let _ = fs::create_dir_all(&temp_dir);

    let sandbox_path = temp_dir.join("sandbox");
    let _ = fs::create_dir_all(&sandbox_path);

    let config_path = temp_dir.join("agentguard.toml");
    let config_content = format!(
        r#"
        [sandbox]
        jail_root = "{}"

        [network_guard]
        enable_network_guard = true
        block_private_ips = true
        block_cloud_metadata = true
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
        .expect("Failed to start agentguard proxy with network guard");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // 1. Send SSRF cloud metadata attack payload
    let ssrf_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fetch_url",
            "arguments": {
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            }
        }
    });

    writeln!(stdin, "{}", serde_json::to_string(&ssrf_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();

    assert!(
        response_line.contains("NetworkViolation") && response_line.contains("Cloud metadata"),
        "Proxy should block cloud metadata SSRF: {response_line}"
    );

    // 2. Send localhost / loopback SSRF payload
    let localhost_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "fetch_url",
            "arguments": {
                "url": "http://127.0.0.1:8080/admin/secrets"
            }
        }
    });

    writeln!(stdin, "{}", serde_json::to_string(&localhost_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut response_line2 = String::new();
    reader.read_line(&mut response_line2).unwrap();

    assert!(
        response_line2.contains("NetworkViolation") && response_line2.contains("loopback"),
        "Proxy should block loopback SSRF: {response_line2}"
    );

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&temp_dir);
}
