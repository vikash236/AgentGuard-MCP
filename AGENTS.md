# AgentGuard-MCP — Agent Instructions

> **Project Goal:** High-performance, zero-latency runtime security proxy and static auditor for Anthropic's Model Context Protocol (MCP).

## 🤖 Unified Multi-AI Workflow

Whether you are Gemini, Claude, Codex, or any other LLM assistant, you are participating in a continuous, unified multi-agent development session.

### Rules for All AI Assistants:
1. **Seamless Handoff:** Pick up execution exactly where the previous AI assistant left off by inspecting `.agent/memory/execution.log` and `.agent/memory/handoff.md`.
2. **Single Blueprint:** Follow the active specs in `.agent/specs/active/` and update status when completing tasks.
3. **Rust Systems Standards:** All core logic must be zero-allocation where possible, asynchronous via `tokio`, and thoroughly unit-tested.

## Quick Start for Agents

1. **Active specs & tasks?** → Read `.agent/specs/active/current.md`
2. **Execution history?** → Read `.agent/memory/execution.log`
3. **Architecture catalog?** → Read `.agent/specs/active/catalog.md`

## Architecture Overview

| Module | Location | Purpose |
|--------|----------|---------|
| `auditor` | `crates/auditor/` | Static JSON-RPC schema scanner for dangerous tool manifests |
| `jail` | `crates/jail/` | Path canonicalization and chroot isolation enforcer |
| `proxy` | `src/proxy/` | High-speed Tokio stdio/HTTP JSON-RPC stream interceptor |
| `redactor` | `crates/redactor/` | Regex & entropy payload secret redactor |

## Rules & Policies

| Policy | Path |
|--------|------|
| Token Efficiency | `.agent/rules/token-efficiency.md` |
| Security Guardrails | `.agent/rules/security-guardrails.md` |
| Project Structure | `.agent/rules/project-structure.md` |
| Context Hygiene | `.agent/rules/context-hygiene.md` |
