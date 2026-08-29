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

## Completed: Phase 4 — Fuzzing & Dynamic Sandbox

- [x] Automated red-teaming tool feeding path traversal, command injection, prompt injection, and boundary stress payloads (`crates/fuzzer/`).
- [x] Automated sandbox isolation policy generator (`agentguard generate-policy <manifest.json>`).
- [x] Integration test suite (`tests/fuzzer_test.rs`).

## Completed: Phase 5 — Policy Configuration Engine & Structured Audit Logger

- [x] Implement TOML configuration loader (`agentguard.toml`) (`src/config.rs`).
- [x] Implement thread-safe structured JSON security audit logger (`src/audit_logger.rs`).
- [x] Add `--config <PATH>` and `--audit-log <PATH>` options to CLI (`src/main.rs`).
- [x] Integration test suite (`tests/config_and_logger_test.rs`).

## Completed: Phase 6 — Test Hygiene, Dynamic Hot-Reload & Prometheus Metrics

- [x] Fix child process cleanup (`.wait()`) across test files to eliminate `clippy::zombie_processes` warnings.
- [x] Implement thread-safe telemetry metrics collector (`src/metrics.rs`).
- [x] Add dynamic policy configuration reload helper (`src/config.rs`).
- [x] Expose `/metrics` Prometheus endpoint in HTTP Gateway & telemetry in stdio proxy (`src/gateway/mod.rs`, `src/proxy/mod.rs`, `src/main.rs`).
- [x] Add integration test suite (`tests/metrics_and_hot_reload_test.rs`).

## Completed: Phase 7 — Dynamic Tool Call Policy Engine & Argument Guardrails

- [x] Implement `PolicyEngine` struct (`src/policy_engine.rs`) for tool allowlists, blocklists, and argument regex constraints.
- [x] Extend `PolicyConfigSection` (`src/config.rs`) with `denied_tools` and `argument_rules`.
- [x] Add `policy_violations_count` telemetry counter (`src/metrics.rs`).
- [x] Integrate policy engine evaluation into stdio proxy (`src/proxy/mod.rs`) and HTTP gateway (`src/gateway/mod.rs`).
- [x] Add E2E integration test suite (`tests/policy_engine_test.rs`).

## Completed: Phase 8 — Prompt Injection Firewall & LLM Guardrails

- [x] Implement `PromptFirewall` struct (`src/prompt_firewall.rs`) with pre-compiled regex set and payload string walker.
- [x] Add `PromptFirewallConfigSection` (`src/config.rs`) for custom injection detection rules.
- [x] Add `prompt_injections_count` telemetry counter (`src/metrics.rs`).
- [x] Integrate prompt firewall inspection into stdio proxy (`src/proxy/mod.rs`), HTTP gateway (`src/gateway/mod.rs`), and CLI (`src/main.rs`).
- [x] Add E2E integration test suite (`tests/prompt_firewall_test.rs`).

## Completed: Phase 9 — SSRF & Network Egress Guardrails

- [x] Implement `NetworkGuard` struct (`src/network_guard.rs`) for detecting and blocking SSRF targets, private RFC1918 subnets, cloud metadata (`169.254.169.254`), and domain allowlist/denylist enforcement.
- [x] Add `NetworkGuardConfigSection` (`src/config.rs`) for configuring network egress policies.
- [x] Add `network_violations_count` telemetry counter (`src/metrics.rs`).
- [x] Integrate network guard evaluation into stdio proxy (`src/proxy/mod.rs`), HTTP gateway (`src/gateway/mod.rs`), and CLI (`src/main.rs`).
- [x] Add E2E integration test suite (`tests/network_guard_test.rs`).

## Completed: Phase 10 — Human-in-the-Loop (HITL) Interactive Approval Engine

- [x] Implement `ApprovalEngine` struct (`src/approval.rs`) with direct console prompting (`CONIN$` / `/dev/tty`), async timeouts, and programmatic approval hooks.
- [x] Add `ApprovalConfigSection` (`src/config.rs`) for configuring sensitive tool lists and timeout durations.
- [x] Add `approvals_prompted_count`, `approvals_granted_count`, `approvals_rejected_count` telemetry counters (`src/metrics.rs`).
- [x] Integrate approval engine into stdio proxy (`src/proxy/mod.rs`) and CLI (`src/main.rs`).
- [x] Add E2E integration test suite (`tests/approval_test.rs`).

## Completed: Security Hardening & Evaluator Remediation

- [x] Outbound tool response Prompt Firewall sanitization (`[UNTRUSTED_CONTENT_FLAGGED_BY_AGENTGUARD: ...]`) on stdio proxy stdout and gateway HTTP responses.
- [x] Multi-method JSON-RPC frame inspection across `tools/call`, `resources/read`, and `prompts/get`.
- [x] Dynamic live payload execution against `PathJail` in `FuzzerEngine`.
- [x] SSRF NetworkGuard Tokio async DNS resolution & alternate numeric/IPv4-mapped IPv6 decoding.
- [x] PathJail recursive percent-decoding (`percent_decode_recursive`) & Windows drive letter detection (`is_drive_letter_path`).
- [x] HTTP Gateway default `127.0.0.1` bind, peer `SocketAddr` rate limiting with LRU memory bounding, and protected `/metrics`.
- [x] SHA-256 hash chaining in `AuditLogger`.
- [x] Anchored regex rules in `PolicyEngine` and wildcard tool matching in `ApprovalEngine`.
- [x] Expanded `SecretRedactor` patterns and base64 slash handling.
- [x] GitHub Actions automated CI workflow (`.github/workflows/ci.yml`).







