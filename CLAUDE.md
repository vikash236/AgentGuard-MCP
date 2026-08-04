# CLAUDE.md — Agent Briefing for AgentGuard-MCP

## Build & Test Commands
- **Build project:** `cargo build`
- **Release build:** `cargo build --release`
- **Run tests:** `cargo test`
- **Lint check:** `cargo clippy -- -D warnings`
- **Format code:** `cargo fmt`

## Architecture Standards
- **Core language:** Rust (2021 edition)
- **Async Runtime:** `tokio` for non-blocking stdio/HTTP stream handling
- **Zero-allocation:** Use zero-copy JSON parsing where possible (`serde_json::Value` borrowing or `simd-json`)
- **Error handling:** `thiserror` for library crates, `anyhow` for CLI binary

## Handoff & State Tracking
- Check `.agent/specs/active/current.md` for active tasks.
- Log completed features in `.agent/memory/execution.log`.
