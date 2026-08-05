use agentguard_jail::PathJail;
use agentguard_redactor::SecretRedactor;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Run the Stdio JSON-RPC proxy for an MCP server subprocess.
pub async fn run_proxy(
    jail_root: PathBuf,
    enable_redactor: bool,
    command: String,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let jail = PathJail::new(&jail_root)?;
    eprintln!(
        "[agentguard] Stdio proxy active. Sandbox root: '{}'",
        jail.root().display()
    );
    if enable_redactor {
        eprintln!("[agentguard] Secret redactor ENABLED (regex + Shannon entropy scanner active)");
    }
    eprintln!(
        "[agentguard] Spawning MCP server: {} {}",
        command,
        args.join(" ")
    );

    let redactor = if enable_redactor {
        Some(Arc::new(SecretRedactor::new()))
    } else {
        None
    };

    let mut child = Command::new(&command)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("Failed to open child stdin"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("Failed to open child stdout"))?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("Failed to open child stderr"))?;

    // Forward child stderr to parent stderr
    tokio::spawn(async move {
        let mut reader = BufReader::new(child_stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            eprintln!("[mcp-server] {}", line);
        }
    });

    // Forward child stdout to parent stdout (with optional secret redaction)
    tokio::spawn(async move {
        let mut reader = BufReader::new(child_stdout).lines();
        let mut stdout = tokio::io::stdout();
        while let Ok(Some(mut line)) = reader.next_line().await {
            if let Some(ref redactor) = redactor {
                if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(&line) {
                    let n = redactor.redact_json(&mut json_val);
                    if n > 0 {
                        eprintln!("[agentguard-redactor] REDACTED {n} secret(s) in stdout payload");
                        if let Ok(redacted_str) = serde_json::to_string(&json_val) {
                            line = redacted_str;
                        }
                    }
                } else {
                    let (redacted_str, n) = redactor.redact_text(&line);
                    if n > 0 {
                        eprintln!("[agentguard-redactor] REDACTED {n} secret(s) in text payload");
                        line = redacted_str;
                    }
                }
            }

            if let Err(e) = stdout.write_all(format!("{line}\n").as_bytes()).await {
                eprintln!("[agentguard] Error writing to stdout: {e}");
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    // Main loop: Intercept parent stdin -> inspect -> forward to child stdin
    let mut stdin_reader = BufReader::new(tokio::io::stdin()).lines();

    while let Ok(Some(line)) = stdin_reader.next_line().await {
        if line.trim().is_empty() {
            continue;
        }

        if let Some(err_resp) = handle_incoming_frame(&jail, &line) {
            let mut stdout = tokio::io::stdout();
            let resp_str = serde_json::to_string(&err_resp)?;
            stdout.write_all(format!("{resp_str}\n").as_bytes()).await?;
            stdout.flush().await?;
            continue; // Intercepted and blocked: DO NOT forward frame
        }

        // Forward approved or non-tool frame to child process stdin
        if let Err(e) = child_stdin.write_all(format!("{line}\n").as_bytes()).await {
            eprintln!("[agentguard] Error writing to child stdin: {e}");
            break;
        }
        child_stdin.flush().await?;
    }

    let status = child.wait().await?;
    eprintln!("[agentguard] Child process exited with status: {status}");
    Ok(())
}

fn handle_incoming_frame(jail: &PathJail, line: &str) -> Option<serde_json::Value> {
    let msg: serde_json::Value = serde_json::from_str(line).ok()?;

    if msg.get("method").and_then(|m| m.as_str()) != Some("tools/call") {
        return None;
    }

    let params = msg.get("params")?;

    if let Err(jail_err) = jail.inspect_json_arguments(params) {
        let req_id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
        eprintln!("[agentguard-jail] REJECTED tool call: {jail_err}");

        let err_resp = serde_json::json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": format!("SecurityViolation: {jail_err}")
            }
        });
        return Some(err_resp);
    }

    None
}
