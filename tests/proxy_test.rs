use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn test_proxy_blocks_path_traversal() {
    let temp_root = std::env::temp_dir().join("agentguard_proxy_e2e_test");
    let _ = fs::create_dir_all(&temp_root);

    let inside_file = temp_root.join("safe.txt");
    let _ = fs::write(&inside_file, "safe content");

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
        .expect("Failed to start agentguard proxy process");

    let mut stdin = child.stdin.take().expect("Failed to open child stdin");
    let stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut reader = BufReader::new(stdout);

    // Test 1: Send safe tools/call
    let safe_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "safe.txt"
            }
        }
    });

    writeln!(stdin, "{}", serde_json::to_string(&safe_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line1 = String::new();
    reader.read_line(&mut line1).unwrap();
    assert!(
        !line1.is_empty(),
        "Proxy should forward safe frame to child"
    );
    let parsed1: serde_json::Value = serde_json::from_str(&line1).expect("Valid JSON");
    assert_eq!(parsed1["id"], 1);

    // Test 2: Send dangerous tools/call with path traversal
    let evil_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "../../Windows/System32/cmd.exe"
            }
        }
    });

    writeln!(stdin, "{}", serde_json::to_string(&evil_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line2 = String::new();
    reader.read_line(&mut line2).unwrap();
    assert!(
        !line2.is_empty(),
        "Proxy should return intercepted error response"
    );
    let parsed2: serde_json::Value = serde_json::from_str(&line2).expect("Valid JSON error");
    assert_eq!(parsed2["id"], 2);
    assert_eq!(parsed2["error"]["code"], -32602);
    assert!(
        parsed2["error"]["message"]
            .as_str()
            .unwrap()
            .contains("SecurityViolation")
    );

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&temp_root);
}
