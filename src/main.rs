mod proxy;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

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
    }
}
