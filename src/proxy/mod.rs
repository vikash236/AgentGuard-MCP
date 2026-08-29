use crate::approval::ApprovalEngine;
use crate::audit_logger::AuditLogger;
use crate::metrics::SharedMetrics;
use crate::network_guard::NetworkGuard;
use crate::policy_engine::PolicyEngine;
use crate::prompt_firewall::PromptFirewall;
use agentguard_jail::PathJail;
use agentguard_redactor::SecretRedactor;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Run the Stdio JSON-RPC proxy for an MCP server subprocess.
#[allow(clippy::too_many_arguments)]
pub async fn run_proxy(
    jail_root: PathBuf,
    enable_redactor: bool,
    audit_logger: Arc<AuditLogger>,
    metrics: Option<SharedMetrics>,
    policy_engine: Option<Arc<PolicyEngine>>,
    prompt_firewall: Option<Arc<PromptFirewall>>,
    network_guard: Option<Arc<NetworkGuard>>,
    approval_engine: Option<Arc<ApprovalEngine>>,
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
    if metrics.is_some() {
        eprintln!("[agentguard] Metrics Collector ENABLED");
    }
    if policy_engine.is_some() {
        eprintln!("[agentguard] Policy Engine ENABLED");
    }
    if prompt_firewall.is_some() {
        eprintln!("[agentguard] Prompt Injection Firewall ENABLED");
    }
    if network_guard.is_some() {
        eprintln!("[agentguard] Network Guard & SSRF Firewall ENABLED");
    }
    if approval_engine.is_some() {
        eprintln!("[agentguard] Human-in-the-Loop (HITL) Approval Engine ENABLED");
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

    let logger_clone = audit_logger.clone();
    let metrics_clone_stdout = metrics.clone();
    let prompt_firewall_clone_stdout = prompt_firewall.clone();

    // Forward child stdout to parent stdout (with secret redaction & outbound prompt injection sanitization)
    tokio::spawn(async move {
        let mut reader = BufReader::new(child_stdout).lines();
        let mut stdout = tokio::io::stdout();
        while let Ok(Some(mut line)) = reader.next_line().await {
            // Outbound Prompt Injection Defense (Second-order prompt injection in tool outputs)
            if let Some(ref firewall) = prompt_firewall_clone_stdout
                && let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(&line)
                && let Some(attack_reason) = firewall.sanitize_payload(&mut json_val)
            {
                eprintln!(
                    "[agentguard-firewall] SANITIZED prompt injection in tool output: {attack_reason}"
                );
                logger_clone.log_event(
                    "prompt_injection_in_output",
                    "HIGH",
                    &format!("Sanitized prompt injection in tool output: {attack_reason}"),
                );
                if let Some(ref m) = metrics_clone_stdout {
                    m.inc_prompt_injections();
                }
                if let Ok(sanitized_str) = serde_json::to_string(&json_val) {
                    line = sanitized_str;
                }
            }

            if let Some(ref redactor) = redactor {
                if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(&line) {
                    let n = redactor.redact_json(&mut json_val);
                    if n > 0 {
                        eprintln!("[agentguard-redactor] REDACTED {n} secret(s) in stdout payload");
                        logger_clone.log_event(
                            "secret_redaction",
                            "MEDIUM",
                            &format!("REDACTED {n} secret(s) in stdout payload"),
                        );
                        if let Some(ref m) = metrics_clone_stdout {
                            m.inc_redactions();
                        }
                        if let Ok(redacted_str) = serde_json::to_string(&json_val) {
                            line = redacted_str;
                        }
                    }
                } else {
                    let (redacted_str, n) = redactor.redact_text(&line);
                    if n > 0 {
                        eprintln!("[agentguard-redactor] REDACTED {n} secret(s) in text payload");
                        logger_clone.log_event(
                            "secret_redaction",
                            "MEDIUM",
                            &format!("REDACTED {n} secret(s) in text payload"),
                        );
                        if let Some(ref m) = metrics_clone_stdout {
                            m.inc_redactions();
                        }
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

    let mut stdin_reader = BufReader::new(tokio::io::stdin()).lines();

    while let Ok(Some(line)) = stdin_reader.next_line().await {
        if line.trim().is_empty() {
            continue;
        }

        // Intercept and evaluate incoming frames
        if let Some(error_response) = handle_incoming_frame(
            &jail,
            &line,
            &audit_logger,
            metrics.as_ref(),
            policy_engine.as_deref(),
            prompt_firewall.as_deref(),
            network_guard.as_deref(),
            approval_engine.as_deref(),
        )
        .await
        {
            let mut stdout = tokio::io::stdout();
            let resp_str = serde_json::to_string(&error_response).unwrap_or_default();
            let _ = stdout.write_all(format!("{resp_str}\n").as_bytes()).await;
            let _ = stdout.flush().await;
            continue; // Intercepted and blocked: DO NOT forward frame
        }

        // Forward approved frame to child process stdin
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

#[allow(clippy::too_many_arguments, clippy::collapsible_if)]
async fn handle_incoming_frame(
    jail: &PathJail,
    line: &str,
    logger: &AuditLogger,
    metrics: Option<&SharedMetrics>,
    policy_engine: Option<&PolicyEngine>,
    prompt_firewall: Option<&PromptFirewall>,
    network_guard: Option<&NetworkGuard>,
    approval_engine: Option<&ApprovalEngine>,
) -> Option<serde_json::Value> {
    let msg: serde_json::Value = serde_json::from_str(line).ok()?;
    let method = msg.get("method").and_then(|m| m.as_str())?;
    let params = msg.get("params").unwrap_or(&serde_json::Value::Null);
    let req_id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);

    // 1. Evaluate Prompt Injection Firewall across all method parameters
    if !params.is_null() {
        if let Some(attack_reason) = prompt_firewall.and_then(|f| f.inspect_payload(params)) {
            eprintln!(
                "[agentguard-firewall] BLOCKED Prompt Injection attack in '{method}': {attack_reason}"
            );
            logger.log_event(
                "prompt_injection_blocked",
                "CRITICAL",
                &format!("BLOCKED Prompt Injection attack in '{method}': {attack_reason}"),
            );
            if let Some(m) = metrics {
                m.inc_prompt_injections();
            }

            let err_resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": format!("PromptInjectionBlocked: {attack_reason}")
                }
            });
            return Some(err_resp);
        }
    }

    // 2. Multi-method Network Guard (SSRF / Egress URL inspection)
    if !params.is_null() {
        if let Some(guard) = network_guard {
            if let Err(net_err) = guard.inspect_payload_async(params).await {
                eprintln!("[agentguard-network] BLOCKED egress violation in '{method}': {net_err}");
                logger.log_event(
                    "network_violation_blocked",
                    "CRITICAL",
                    &format!("BLOCKED egress violation in '{method}': {net_err}"),
                );
                if let Some(m) = metrics {
                    m.inc_network_violations();
                }

                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": format!("NetworkViolation: {net_err}")
                    }
                });
                return Some(err_resp);
            }
        }
    }

    // 3. Multi-method Path Jail inspection
    if !params.is_null() {
        if let Err(jail_err) = jail.inspect_json_arguments(params) {
            eprintln!("[agentguard-jail] BLOCKED path traversal in '{method}': {jail_err}");
            logger.log_event(
                "path_jail_violation",
                "HIGH",
                &format!("BLOCKED path traversal in '{method}': {jail_err}"),
            );
            if let Some(m) = metrics {
                m.inc_jail_violations();
            }

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
    }

    // 4. Specific inspection for tools/call (Policy Engine and HITL Approval)
    if method == "tools/call" {
        let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");

        // 4a. Evaluate Policy Engine
        if let Some(engine) = policy_engine {
            if let Err(policy_err) = engine.evaluate_tool_call(tool_name, params) {
                eprintln!("[agentguard-policy] REJECTED tool call '{tool_name}': {policy_err}");
                logger.log_event(
                    "policy_violation",
                    "HIGH",
                    &format!("REJECTED tool call '{tool_name}': {policy_err}"),
                );
                if let Some(m) = metrics {
                    m.inc_policy_violations();
                }

                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": format!("PolicyViolation: {policy_err}")
                    }
                });
                return Some(err_resp);
            }
        }

        // 4b. Evaluate Human-In-The-Loop Approval Engine
        if let Some(approval) = approval_engine {
            if approval.requires_approval(tool_name) {
                if let Some(m) = metrics {
                    m.inc_approvals_prompted();
                }

                match approval.request_approval(tool_name, params).await {
                    Ok(()) => {
                        eprintln!("[agentguard-approval] GRANTED execution for '{tool_name}'");
                        logger.log_event(
                            "approval_granted",
                            "LOW",
                            &format!("Operator GRANTED execution for '{tool_name}'"),
                        );
                        if let Some(m) = metrics {
                            m.inc_approvals_granted();
                        }
                    }
                    Err(approval_err) => {
                        eprintln!(
                            "[agentguard-approval] DENIED or TIMED OUT for '{tool_name}': {approval_err}"
                        );
                        logger.log_event(
                            "approval_denied",
                            "HIGH",
                            &format!("DENIED or TIMED OUT for '{tool_name}': {approval_err}"),
                        );
                        if let Some(m) = metrics {
                            m.inc_approvals_rejected();
                        }
                        let err_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32602,
                                "message": format!("ApprovalDenied: {approval_err}")
                            }
                        });
                        return Some(err_resp);
                    }
                }
            }
        }
    }

    None
}
