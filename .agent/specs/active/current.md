# Active Workstreams — AgentGuard-MCP

## Completed: Phase 0 — Schema Auditor & Project Scaffold

- [x] Initialize Cargo workspace (`Cargo.toml` with `crates/auditor`, `crates/jail`, `crates/redactor`).
- [x] Implement MCP tool manifest JSON schema parser.
- [x] Create security audit rule evaluator (check for missing regex bounds, unconstrained shell params).
- [x] Implement `agentguard audit <manifest.json>` CLI subcommand.

## Next Phase: Phase 1 — Stdio Proxy & Path Jail

- [ ] Implement Tokio async JSON-RPC stdio stream interceptor (`src/proxy/`).
- [ ] Implement path canonicalization and chroot enforcement (`crates/jail/`).
- [ ] Add `agentguard proxy --jail <root> -- <command>` CLI subcommand.
- [ ] Integration tests with mock MCP server.
