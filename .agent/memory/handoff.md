# Context Handoff Contract

## Current Status
- Phase 0 (Static Manifest Auditor) **complete**. Fully functional `agentguard audit` CLI.
- Cargo workspace established with `crates/auditor`, `crates/jail` (stub), `crates/redactor` (stub).
- 31 unit tests passing, clippy clean.

## Completed in Phase 0
- Schema parser: JSON-RPC envelope, shorthand `{"tools":[...]}`, and bare array formats.
- 6 audit rules: AUDIT-001 (missing schema), AUDIT-002 (unconstrained strings), AUDIT-003 (shell tools), AUDIT-004 (path traversal params), AUDIT-005 (open additionalProperties), AUDIT-006 (description prompt injection).
- Report formatter: human-readable (stderr) and JSON (stdout) output modes.
- Exit code semantics: 0=clean, 1=critical/high findings, 2=parse error.

## Next Steps (Phase 1: Stdio Proxy & Path Jail)
- Implement `src/proxy/` Tokio async JSON-RPC stdio stream interceptor.
- Implement `crates/jail/` path canonicalization and chroot enforcement.
- Add `agentguard proxy --jail <root> -- <command>` CLI subcommand.
