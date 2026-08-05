mod gateway;
mod proxy;

use agentguard_jail::PathJail;
use agentguard_redactor::SecretRedactor;
use clap::{Parser, Subcommand};
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
        /// Path root for path chroot jail.
        #[arg(long, value_name = "PATH")]
        jail: PathBuf,

        /// Enable real-time secret redactor (regex + Shannon entropy scanning).
        #[arg(long)]
        redact: bool,

        /// Executable command to launch MCP server.
        #[arg(required = true)]
        command: String,

        /// Arguments passed to the target MCP server command.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run HTTP/SSE Gateway Proxy for remote MCP servers.
    Gateway {
        /// Local port to bind HTTP gateway proxy server.
        #[arg(long, default_value_t = 8080)]
        port: u16,

        /// Target remote MCP server HTTP base URL (e.g. http://127.0.0.1:3000).
        #[arg(long)]
        target: String,

        /// Optional Bearer token for client authentication.
        #[arg(long)]
        token: Option<String>,

        /// Optional max requests per minute rate limit per client.
        #[arg(long)]
        rate_limit: Option<u32>,

        /// Optional path root for path chroot jail.
        #[arg(long, value_name = "PATH")]
        jail: Option<PathBuf>,

        /// Enable real-time secret redactor.
        #[arg(long)]
        redact: bool,
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
            jail,
            redact,
            command,
            args,
        } => {
            if let Err(e) = proxy::run_proxy(jail, redact, command, args).await {
                eprintln!("[agentguard] Error: {e}");
                process::exit(1);
            }
        }
        Commands::Gateway {
            port,
            target,
            token,
            rate_limit,
            jail,
            redact,
        } => {
            let jail_obj = if let Some(j_path) = jail {
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

            let redactor_obj = if redact {
                Some(Arc::new(SecretRedactor::new()))
            } else {
                None
            };

            let config = gateway::GatewayConfig {
                port,
                target_url: target,
                token,
                rate_limit,
                jail: jail_obj,
                redactor: redactor_obj,
            };

            if let Err(e) = gateway::run_gateway(config).await {
                eprintln!("[agentguard] Gateway error: {e}");
                process::exit(1);
            }
        }
    }
}
