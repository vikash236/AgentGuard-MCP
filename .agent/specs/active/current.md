# Active Workstreams — AgentGuard-MCP

## Completed: Phase 0 — Schema Auditor & Project Scaffold

- [x] Initialize Cargo workspace (`Cargo.toml` with `crates/auditor`, `crates/jail`, `crates/redactor`).
- [x] Implement MCP tool manifest JSON schema parser.
- [x] Create security audit rule evaluator (check for missing regex bounds, unconstrained shell params).
- [x] Implement `agentguard audit <manifest.json>` CLI subcommand.

## Completed: Phase 1 — Stdio Proxy & Path Jail

- [x] Implement Tokio async JSON-RPC stdio stream interceptor (`src/proxy/`).
- [x] Implement path canonicalization and chroot enforcement (`crates/jail/`).
- [x] Add `agentguard proxy --jail <root> -- <command>` CLI subcommand.
- [x] Integration tests with mock MCP server (`tests/proxy_test.rs`).

## Completed: Phase 2 — Secret Redactor

- [x] Implement Regex & Entropy-based secret scanning in payload streams (`crates/redactor/`).
- [x] Add masking support (`[REDACTED]`) for sensitive credentials/keys (`.env` keys, API tokens, JWT, RSA/SSH keys).
- [x] Integrate redactor into proxy stdio pipeline (`agentguard proxy --redact`).

## Completed: Phase 3 — HTTP/SSE Gateway Proxy

- [x] Support remote MCP servers over SSE / HTTP websockets proxy (`src/gateway/`).
- [x] Implement bearer token authentication (`--token`) and sliding window rate limiting (`--rate-limit`).
- [x] Integrate path jail (`--jail`) and secret redactor (`--redact`) into HTTP gateway pipeline.

## Next Phase: Phase 4 — Fuzzing & Dynamic Sandbox

- [ ] Automated red-teaming tool feeding path traversal and injection payloads.
- [ ] Sandbox isolation policy generator.
