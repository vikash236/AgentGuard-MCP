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
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit { manifest, format } => {
            let output_json = format == "json";

            match agentguard_auditor::run_audit(&manifest, output_json) {
                Ok(has_critical_or_high) => {
                    if has_critical_or_high {
                        process::exit(1);
                    }
                    // Exit 0: clean or only medium/low findings.
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(2);
                }
            }
        }
    }
}
