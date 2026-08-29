mod approval;
mod audit_logger;
mod config;
mod gateway;
mod metrics;
mod network_guard;
mod policy_engine;
mod prompt_firewall;
mod proxy;

use agentguard_jail::PathJail;
use agentguard_redactor::SecretRedactor;
use approval::ApprovalEngine;
use audit_logger::AuditLogger;
use clap::{Parser, Subcommand};
use config::AgentGuardConfig;
use metrics::MetricsCollector;
use network_guard::NetworkGuard;
use policy_engine::PolicyEngine;
use prompt_firewall::PromptFirewall;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

/// AgentGuard-MCP — Runtime security harness for AI agent tool execution.
#[derive(Parser)]
#[command(name = "agentguard", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit an MCP tool manifest for security risks.
    Audit {
        /// Path to the MCP tool manifest JSON file.
        manifest: PathBuf,

        /// Output format: "human" (default) or "json".
        #[arg(long, default_value = "human")]
        format: String,
    },

    /// Run stdio JSON-RPC security proxy for an MCP server process.
    Proxy {
        /// Path to agentguard.toml configuration file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Structured JSON audit log file path.
        #[arg(long)]
        audit_log: Option<PathBuf>,

        /// Path root for path chroot jail.
        #[arg(long, value_name = "PATH")]
        jail: Option<PathBuf>,

        /// Enable real-time secret redactor.
        #[arg(long)]
        redact: bool,

        /// Enable metrics collector.
        #[arg(long)]
        metrics: bool,

        /// Enable prompt injection firewall.
        #[arg(long)]
        prompt_firewall: bool,

        /// Enable SSRF and network egress guardrails.
        #[arg(long)]
        network_guard: bool,

        /// Enable Human-in-the-Loop (HITL) interactive approval engine.
        #[arg(long)]
        approval: bool,

        /// Executable command to launch MCP server.
        #[arg(required = true)]
        command: String,

        /// Arguments passed to the target MCP server command.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run HTTP/SSE Gateway Proxy for remote MCP servers.
    Gateway {
        /// Path to agentguard.toml configuration file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Structured JSON audit log file path.
        #[arg(long)]
        audit_log: Option<PathBuf>,

        /// Host interface to bind HTTP gateway proxy server (default: 127.0.0.1).
        #[arg(long)]
        host: Option<String>,

        /// Local port to bind HTTP gateway proxy server.
        #[arg(long)]
        port: Option<u16>,

        /// Target remote MCP server HTTP base URL (e.g. http://127.0.0.1:3000).
        #[arg(long)]
        target: Option<String>,

        /// Optional Bearer token for client authentication.
        #[arg(long)]
        token: Option<String>,

        /// Optional max requests per minute rate limit per client.
        #[arg(long)]
        rate_limit: Option<u32>,

        /// Trust client-supplied X-Forwarded-For headers for rate limiting.
        #[arg(long)]
        trust_proxy_headers: bool,

        /// Optional path root for path chroot jail.
        #[arg(long, value_name = "PATH")]
        jail: Option<PathBuf>,

        /// Enable real-time secret redactor.
        #[arg(long)]
        redact: bool,

        /// Enable metrics endpoint.
        #[arg(long)]
        metrics: bool,

        /// Enable prompt injection firewall.
        #[arg(long)]
        prompt_firewall: bool,

        /// Enable SSRF and network egress guardrails.
        #[arg(long)]
        network_guard: bool,
    },

    /// Dynamically fuzz an MCP tool manifest against security attack vectors.
    Fuzz {
        /// Path to the MCP tool manifest JSON file.
        manifest: PathBuf,

        /// Output format: "human" (default) or "json".
        #[arg(long, default_value = "human")]
        format: String,
    },

    /// Generate an agentguard.toml security isolation policy for an MCP manifest.
    GeneratePolicy {
        /// Path to the MCP tool manifest JSON file.
        manifest: PathBuf,

        /// Output configuration file path (default stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit { manifest, format } => {
            let output_json = format == "json";

            match agentguard_auditor::run_audit(&manifest, output_json) {
                Ok(has_critical_or_high) => {
                    if has_critical_or_high {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(2);
                }
            }
        }
        Commands::Proxy {
            config,
            audit_log,
            jail,
            redact,
            metrics,
            prompt_firewall,
            network_guard,
            approval,
            command,
            args,
        } => {
            let loaded_config = if let Some(ref cfg_path) = config {
                match AgentGuardConfig::load_from_file(cfg_path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[agentguard] Error loading config '{:?}': {e}", cfg_path);
                        process::exit(1);
                    }
                }
            } else {
                AgentGuardConfig::default()
            };

            // Resolve jail root path
            let final_jail_path = jail.or_else(|| {
                loaded_config
                    .sandbox
                    .as_ref()
                    .and_then(|s| s.jail_root.clone())
            });

            let jail_path = match final_jail_path {
                Some(p) => p,
                None => {
                    eprintln!(
                        "[agentguard] Error: --jail <PATH> or [sandbox].jail_root in config is required for proxy mode"
                    );
                    process::exit(1);
                }
            };

            // Resolve redactor status
            let final_redact = redact
                || loaded_config
                    .redactor
                    .as_ref()
                    .and_then(|r| r.enable_redaction)
                    .unwrap_or(false);

            // Resolve audit log path
            let final_log_path = audit_log.or_else(|| {
                loaded_config
                    .policy
                    .as_ref()
                    .and_then(|p| p.audit_log_file.clone())
            });
            let logger = Arc::new(AuditLogger::new(final_log_path));
            let metrics_collector = if metrics {
                Some(Arc::new(MetricsCollector::new()))
            } else {
                None
            };

            let policy_engine_obj = if let Some(ref p) = loaded_config.policy {
                match PolicyEngine::new(p) {
                    Ok(pe) => Some(Arc::new(pe)),
                    Err(e) => {
                        eprintln!("[agentguard] Error in policy engine rules: {e}");
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            let enable_firewall = prompt_firewall
                || loaded_config
                    .prompt_firewall
                    .as_ref()
                    .and_then(|pf| pf.enable_firewall)
                    .unwrap_or(false);

            let prompt_firewall_obj = if enable_firewall {
                let custom_pats = loaded_config
                    .prompt_firewall
                    .as_ref()
                    .and_then(|pf| pf.custom_patterns.as_deref());
                match PromptFirewall::new(custom_pats) {
                    Ok(pf) => Some(Arc::new(pf)),
                    Err(e) => {
                        eprintln!("[agentguard] Error in prompt firewall patterns: {e}");
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            let enable_net = network_guard
                || loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.enable_network_guard)
                    .unwrap_or(false);

            let network_guard_obj = if enable_net {
                let block_priv = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.block_private_ips)
                    .unwrap_or(true);
                let block_meta = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.block_cloud_metadata)
                    .unwrap_or(true);
                let allowed_doms = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.allowed_domains.clone())
                    .unwrap_or_default();
                let denied_doms = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.denied_domains.clone())
                    .unwrap_or_default();
                Some(Arc::new(NetworkGuard::new(
                    block_priv,
                    block_meta,
                    allowed_doms,
                    denied_doms,
                )))
            } else {
                None
            };

            let enable_appr = approval
                || loaded_config
                    .approval
                    .as_ref()
                    .and_then(|a| a.enable_approval)
                    .unwrap_or(false);

            let approval_engine_obj = if enable_appr {
                let req_tools = loaded_config
                    .approval
                    .as_ref()
                    .and_then(|a| a.require_tools.clone())
                    .unwrap_or_else(|| {
                        vec![
                            "execute_command".to_string(),
                            "bash".to_string(),
                            "sh".to_string(),
                            "delete_file".to_string(),
                            "remove_file".to_string(),
                            "drop_table".to_string(),
                        ]
                    });
                let timeout_s = loaded_config
                    .approval
                    .as_ref()
                    .and_then(|a| a.timeout_seconds)
                    .unwrap_or(30);
                Some(Arc::new(ApprovalEngine::new(req_tools, timeout_s)))
            } else {
                None
            };

            if let Err(e) = proxy::run_proxy(
                jail_path,
                final_redact,
                logger,
                metrics_collector,
                policy_engine_obj,
                prompt_firewall_obj,
                network_guard_obj,
                approval_engine_obj,
                command,
                args,
            )
            .await
            {
                eprintln!("[agentguard] Error: {e}");
                process::exit(1);
            }
        }
        Commands::Gateway {
            config,
            audit_log,
            host,
            port,
            target,
            token,
            rate_limit,
            trust_proxy_headers,
            jail,
            redact,
            metrics,
            prompt_firewall,
            network_guard,
        } => {
            let loaded_config = if let Some(ref cfg_path) = config {
                match AgentGuardConfig::load_from_file(cfg_path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[agentguard] Error loading config '{:?}': {e}", cfg_path);
                        process::exit(1);
                    }
                }
            } else {
                AgentGuardConfig::default()
            };

            let final_host =
                host.or_else(|| loaded_config.gateway.as_ref().and_then(|g| g.host.clone()));

            let final_port = port
                .or_else(|| loaded_config.gateway.as_ref().and_then(|g| g.port))
                .unwrap_or(8080);

            let final_target = target.or_else(|| {
                loaded_config
                    .gateway
                    .as_ref()
                    .and_then(|g| g.target_url.clone())
            });

            let target_url = match final_target {
                Some(t) => t,
                None => {
                    eprintln!(
                        "[agentguard] Error: --target <URL> or [gateway].target_url in config is required for gateway mode"
                    );
                    process::exit(1);
                }
            };

            let final_token =
                token.or_else(|| loaded_config.gateway.as_ref().and_then(|g| g.token.clone()));

            let final_rate_limit = rate_limit.or_else(|| {
                loaded_config
                    .gateway
                    .as_ref()
                    .and_then(|g| g.max_requests_per_minute)
            });

            let final_trust_proxy = trust_proxy_headers
                || loaded_config
                    .gateway
                    .as_ref()
                    .and_then(|g| g.trust_proxy_headers)
                    .unwrap_or(false);

            let final_jail_path = jail.or_else(|| {
                loaded_config
                    .sandbox
                    .as_ref()
                    .and_then(|s| s.jail_root.clone())
            });

            let jail_obj = if let Some(j_path) = final_jail_path {
                match PathJail::new(&j_path) {
                    Ok(j) => Some(j),
                    Err(e) => {
                        eprintln!("[agentguard] Invalid jail root path: {e}");
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            let final_redact = redact
                || loaded_config
                    .redactor
                    .as_ref()
                    .and_then(|r| r.enable_redaction)
                    .unwrap_or(false);

            let redactor_obj = if final_redact {
                Some(Arc::new(SecretRedactor::new()))
            } else {
                None
            };

            let final_log_path = audit_log.or_else(|| {
                loaded_config
                    .policy
                    .as_ref()
                    .and_then(|p| p.audit_log_file.clone())
            });
            let logger = Arc::new(AuditLogger::new(final_log_path));
            let metrics_collector = if metrics {
                Some(Arc::new(MetricsCollector::new()))
            } else {
                None
            };

            let policy_engine_obj = if let Some(ref p) = loaded_config.policy {
                match PolicyEngine::new(p) {
                    Ok(pe) => Some(Arc::new(pe)),
                    Err(e) => {
                        eprintln!("[agentguard] Error in policy engine rules: {e}");
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            let enable_firewall = prompt_firewall
                || loaded_config
                    .prompt_firewall
                    .as_ref()
                    .and_then(|pf| pf.enable_firewall)
                    .unwrap_or(false);

            let prompt_firewall_obj = if enable_firewall {
                let custom_pats = loaded_config
                    .prompt_firewall
                    .as_ref()
                    .and_then(|pf| pf.custom_patterns.as_deref());
                match PromptFirewall::new(custom_pats) {
                    Ok(pf) => Some(Arc::new(pf)),
                    Err(e) => {
                        eprintln!("[agentguard] Error in prompt firewall patterns: {e}");
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            let enable_net = network_guard
                || loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.enable_network_guard)
                    .unwrap_or(false);

            let network_guard_obj = if enable_net {
                let block_priv = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.block_private_ips)
                    .unwrap_or(true);
                let block_meta = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.block_cloud_metadata)
                    .unwrap_or(true);
                let allowed_doms = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.allowed_domains.clone())
                    .unwrap_or_default();
                let denied_doms = loaded_config
                    .network_guard
                    .as_ref()
                    .and_then(|n| n.denied_domains.clone())
                    .unwrap_or_default();
                Some(Arc::new(NetworkGuard::new(
                    block_priv,
                    block_meta,
                    allowed_doms,
                    denied_doms,
                )))
            } else {
                None
            };

            let gateway_config = gateway::GatewayConfig {
                host: final_host,
                port: final_port,
                target_url,
                token: final_token,
                rate_limit: final_rate_limit,
                trust_proxy_headers: final_trust_proxy,
                jail: jail_obj,
                redactor: redactor_obj,
                audit_logger: logger,
                metrics: metrics_collector,
                policy_engine: policy_engine_obj,
                prompt_firewall: prompt_firewall_obj,
                network_guard: network_guard_obj,
            };

            if let Err(e) = gateway::run_gateway(gateway_config).await {
                eprintln!("[agentguard] Gateway error: {e}");
                process::exit(1);
            }
        }
        Commands::Fuzz { manifest, format } => {
            match agentguard_fuzzer::FuzzerEngine::fuzz_manifest(&manifest) {
                Ok(report) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    } else {
                        print!("{}", report.to_human_readable());
                    }
                    if report.total_vulnerabilities > 0 {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("fuzz error: {e}");
                    process::exit(2);
                }
            }
        }
        Commands::GeneratePolicy { manifest, output } => {
            let contents = match std::fs::read_to_string(&manifest) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error reading manifest: {e}");
                    process::exit(2);
                }
            };
            let parsed_manifest = match agentguard_auditor::ToolManifest::parse(&contents) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("error parsing manifest: {e}");
                    process::exit(2);
                }
            };

            let policy =
                agentguard_fuzzer::PolicyGenerator::generate_policy(&parsed_manifest.tools);
            if let Some(out_path) = output {
                if let Err(e) = std::fs::write(&out_path, &policy) {
                    eprintln!("error writing policy file: {e}");
                    process::exit(2);
                }
                eprintln!(
                    "[agentguard] Policy generated successfully at '{}'",
                    out_path.display()
                );
            } else {
                print!("{policy}");
            }
        }
    }
}
