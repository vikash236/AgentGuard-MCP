# AgentGuard-MCP

**Runtime security harness for AI agent tool execution over the Model Context Protocol.**

AgentGuard-MCP is a zero-overhead Rust proxy that sits between any MCP client (Claude Desktop, Cursor, custom agents) and any MCP server — intercepting, inspecting, and enforcing security policy on every tool call before it touches your operating system.

```
   AI Agent                AgentGuard-MCP                    MCP Server
   ────────     JSON-RPC    ──────────────     Sanitized      ──────────
   │ Claude │ ──────────→ │ ┌──────────┐ │ ──────────────→ │ Target  │
   │ Cursor │   tool_call  │ │ Auditor  │ │   safe_call     │ Server  │
   │ Custom │ ←────────── │ │ Jail     │ │ ←────────────── │         │
   ────────     response   │ │ Redactor │ │    result       ──────────
                           │ └──────────┘ │
                           ──────────────
                           Blocks:
                           ✗ Path traversal   → rejected
                           ✗ Shell injection  → sanitized
                           ✗ Secret leakage   → redacted
                           ✗ Unsafe manifests → flagged
```

---

## Why This Exists

### The Problem: Tool-Calling Agents Have Collapsed the Trust Boundary

In 2025–2026, AI agents stopped being chatbots and became **system operators**. Protocols like Anthropic's Model Context Protocol (MCP) grant agents direct access to filesystems, shell execution, databases, and APIs. This is powerful — and catastrophically dangerous when left unsecured.

**The attack surface is not theoretical. It is actively being exploited:**

| Incident | Impact |
|----------|--------|
| **CVE-2025-54135** (Cursor IDE, CVSS 9.8) | Malicious prompts hidden in repository files achieved Remote Code Execution on developer machines through the IDE's AI agent |
| **CVE-2025-53773** (GitHub Copilot, CVSS 9.6) | Externally fetched content containing injected instructions led to arbitrary code execution within developer environments |
| **Mexican Government Breach** (Dec 2025 – Feb 2026) | Attackers weaponized AI agent tool-calling (Claude Code, GPT-4.1) to breach nine agencies, exfiltrating 195 million records / 150 GB — the AI automated vulnerability scanning, command execution, and data extraction |
| **ClawHavoc** (Feb 2026) | 824 malicious "skills" on the OpenClaw marketplace distributed macOS stealer malware to thousands of AI agent deployments via supply chain poisoning |

In **May 2026**, the NSA and CISA — alongside Five Eyes partners — published formal advisories warning that MCP "collapses the trust boundary between AI agents, servers, and enterprise tools into a single implicit trust domain." Securing this boundary is now a **national security priority**.

### Why Traditional AppSec Doesn't Cover This

Traditional application security assumes a human operator making deliberate API calls. MCP breaks this assumption in three fundamental ways:

1. **The Confused Deputy Problem.** An AI agent holds legitimate credentials to call `read_file` or `exec_command`. An attacker doesn't need to steal those credentials — they just need to trick the agent into *using them on the wrong targets* via prompt injection. The agent becomes an unwitting proxy for the attacker.

2. **Dynamic Tool Discovery.** Unlike static APIs, MCP agents discover and invoke tools at runtime. A poisoned tool manifest can advertise a benign `search_docs` tool whose description contains hidden instructions that override the agent's behavior.

3. **Context Window as Attack Surface.** Tool outputs flow back into the agent's context. A `read_file` call that returns content containing embedded prompt injections can hijack the agent's subsequent reasoning and tool calls — creating *second-order injection chains*.

**The core insight:** Securing MCP requires intercepting the *tool-call boundary* — the exact moment between "the agent decided to call a tool" and "the OS executed it." That boundary is where AgentGuard-MCP operates.

---

## Architecture

Four modules, each designed to stop a specific attack chain:

| Module | Attack It Stops | How |
|--------|----------------|-----|
| **Auditor** (`crates/auditor/`) | Tool poisoning via malicious manifests | Parses MCP tool definitions and flags missing input validation schemas, unconstrained `exec` parameters, and dangerous API surface patterns — *before* the server is ever connected |
| **Jail** (`crates/jail/`) | Path traversal (`../../etc/passwd`, `C:\Windows\System32`) | Canonicalizes all file paths and enforces chroot-style confinement to a declared project root. Symlink resolution prevents escape via junction points |
| **Proxy** (`src/proxy/`) | Command injection via shell metacharacters (`;`, `&&`, `$(...)`, `` ` ``) | Intercepts JSON-RPC streams over stdio/HTTP, inspects tool arguments against configurable deny-lists, and strips or rejects dangerous patterns before forwarding |
| **Redactor** (`crates/redactor/`) | Credential exfiltration via tool outputs | Scans tool return values for AWS keys, JWT tokens, SSH private keys, and `.env` file contents using regex + Shannon entropy detection, replacing matches with `[REDACTED]` before they enter the agent's context window |

### Where AgentGuard-MCP Fits in the Ecosystem

Existing tools address *parts* of the MCP security problem, but none cover the full attack lifecycle:

| Tool | Strength | Gap AgentGuard Fills |
|------|----------|---------------------|
| `mcp-context-protector` (Trail of Bits) | Output sanitization, trust-on-first-use pinning | No runtime argument inspection, no path jailing, no static manifest audit |
| `pipelock` | Network-level exfiltration detection | No filesystem or shell injection enforcement |
| `nilbox` | VM-grade isolation sandbox | Heavy-weight (full VM), no tool-argument-level policy |
| Enterprise gateways (ThinkWatch, Cortex) | RBAC, rate limiting, audit logging | Closed-source, enterprise-only, not developer-local |

**AgentGuard-MCP's niche:** A lightweight, zero-dependency, developer-local security harness providing defense-in-depth across the *entire* tool-call lifecycle — from static schema auditing through runtime argument enforcement to output redaction — without requiring containers, VMs, or cloud infrastructure.

---

## Why Rust

This is not "Rust for Rust's sake." The requirements demand it:

- **Zero-copy JSON-RPC interception.** The proxy sits in the hot path of every tool call. Adding latency to an interactive coding session is unacceptable. Rust's `serde_json` with zero-allocation buffering keeps overhead under 1ms per call.
- **Memory safety without a GC.** The proxy handles untrusted input (tool arguments, server responses) on every message. A buffer overflow in the proxy *is* a security vulnerability. Rust eliminates this class of bugs at compile time.
- **Async stdio multiplexing.** MCP's stdio transport requires precise byte-level stream management. Tokio's async I/O provides the exact primitive needed without Node.js or Python asyncio overhead.
- **Single static binary.** `cargo build --release` produces one binary with zero runtime dependencies. Users run `agentguard proxy -- npx server` — no Python venvs, no Docker, no Node modules.

---

## Technical Skills Demonstrated

Each component maps to a specific systems-security competency:

| Component | Competency |
|-----------|-----------|
| JSON-RPC stream interceptor | Protocol-level engineering, async I/O, byte-stream parsing |
| Path canonicalization + chroot jail | OS filesystem security, symlink attack prevention, Windows/POSIX portability |
| Regex + entropy secret scanner | Applied cryptography awareness, DFA pattern matching, false-positive tuning |
| Static manifest auditor | Schema analysis, security-by-design evaluation, threat modeling |
| Full proxy architecture | Defense-in-depth thinking, chokepoint identification, zero-trust design |

---

## Quick Start

```bash
# Audit an MCP server manifest for unsafe tool definitions
agentguard audit manifest.json

# Proxy a stdio MCP server with path jailing and secret redaction
agentguard proxy --jail /path/to/project -- npx @modelcontextprotocol/server-filesystem
```

### 30-Minute Path to First Demo

1. **Understand the protocol:** Read the [MCP specification](https://spec.modelcontextprotocol.io/) — specifically the JSON-RPC message format over stdio.
2. **Build a vulnerable target:** Create a mock MCP server with a deliberately unsafe `read_file` tool (no path validation).
3. **Interpose AgentGuard:** Route the client through AgentGuard's proxy and watch it block `../../etc/passwd` in real-time.
4. **Record the proof:** Capture a terminal recording showing the blocked exploit.

---

## Roadmap

| Phase | Title | Status |
|-------|-------|--------|
| **P0** | Static Manifest Auditor — CLI scanner for MCP tool definitions | 🔄 Active |
| **P1** | Stdio Proxy & Path Jail — Tokio JSON-RPC interceptor with chroot enforcement | ⏳ Pending |
| **P2** | Secret Redactor — Real-time regex + entropy payload scanner | ⏳ Pending |
| **P3** | HTTP/SSE Gateway — Support for remote MCP servers over SSE/WebSocket | ⏳ Pending |
| **P4** | Fuzzing & Red Team — Automated path traversal and injection payload generator | ⏳ Pending |

---

## References

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [NSA Cybersecurity Information Sheet: MCP Security Design Considerations (May 2026)](https://www.nsa.gov/)
- [CISA/Five Eyes: Careful Adoption of Agentic AI Services (May 2026)](https://www.cisa.gov/)
- [CVE-2025-54135 — Cursor IDE RCE via prompt injection](https://nvd.nist.gov/)
- [CVE-2025-53773 — GitHub Copilot RCE via fetched content injection](https://nvd.nist.gov/)

## License

[MIT](LICENSE)
