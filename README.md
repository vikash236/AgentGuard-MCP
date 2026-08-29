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

AgentGuard-MCP provides defense-in-depth across the entire AI agent tool-calling lifecycle:

| Module | Attack It Stops | How |
|--------|----------------|-----|
| **Auditor** (`crates/auditor/`) | Tool poisoning via malicious manifests | Parses MCP tool definitions and flags missing input validation schemas, unconstrained `exec` parameters, and dangerous API surface patterns before connection |
| **Jail** (`crates/jail/`) | Path traversal (`../../etc/passwd`, `C:\Windows\System32`) | Canonicalizes all file paths and enforces chroot-style confinement to a declared project root with symlink escape prevention |
| **Proxy** (`src/proxy/`) | Command injection & protocol tampering | Intercepts JSON-RPC streams over stdio with sub-millisecond overhead and zero stdout pollution |
| **Redactor** (`crates/redactor/`) | Credential exfiltration via tool outputs | Scans tool return values for AWS keys, JWT tokens, SSH private keys, and `.env` credentials using regex + Shannon entropy detection |
| **Gateway** (`src/gateway/`) | Remote MCP server exposure & abuse | HTTP/SSE reverse proxy with Bearer authentication and sliding-window rate limiting |
| **Fuzzer** (`crates/fuzzer/`) | Zero-day vulnerabilities & untested schemas | Automated red-teaming mutation engine & sandbox policy generator |
| **Policy Engine** (`src/policy_engine.rs`) | Unauthorized tool execution | Enforces tool allowlists, denylists, and per-argument regex guardrails |
| **Prompt Firewall** (`src/prompt_firewall.rs`) | Direct & indirect prompt injection | Blocks instruction overrides, jailbreak personas, and ChatML/Llama delimiter hijacking |
| **Network Guard** (`src/network_guard.rs`) | SSRF & unauthorized egress | Blocks private RFC1918 IPs, cloud metadata endpoints (`169.254.169.254`), and enforces domain allowlists |
| **Approval Engine** (`src/approval.rs`) | Destructive autonomous operations | Human-in-the-Loop interactive terminal prompt with configurable timeouts for high-risk actions |

---

## Quick Start

```bash
# 1. Audit an MCP server manifest for unsafe tool definitions
agentguard audit manifest.json

# 2. Proxy a stdio MCP server with full security guardrails
agentguard proxy \
  --jail /path/to/project \
  --redact \
  --prompt-firewall \
  --network-guard \
  --approval \
  -- npx @modelcontextprotocol/server-filesystem /path/to/project

# 3. Run HTTP/SSE Gateway Proxy with authentication & rate limiting
agentguard gateway \
  --target http://127.0.0.1:3000 \
  --port 8080 \
  --token secret-bearer-token \
  --rate-limit 120 \
  --jail /path/to/project \
  --prompt-firewall \
  --network-guard

# 4. Fuzz an MCP manifest against security attack vectors
agentguard fuzz manifest.json

# 5. Generate a locked-down agentguard.toml policy
agentguard generate-policy manifest.json --output agentguard.toml
```

---

## Roadmap

| Phase | Title | Status |
|-------|-------|--------|
| **P0** | Static Manifest Auditor — CLI scanner for MCP tool definitions | ✅ Complete |
| **P1** | Stdio Proxy & Path Jail — Tokio JSON-RPC interceptor with chroot enforcement | ✅ Complete |
| **P2** | Secret Redactor — Real-time regex + entropy payload scanner | ✅ Complete |
| **P3** | HTTP/SSE Gateway — Support for remote MCP servers over SSE/WebSocket | ✅ Complete |
| **P4** | Fuzzing & Red Team — Automated mutation engine & policy generator | ✅ Complete |
| **P5** | Policy Config Engine & Audit Logger — TOML loader & structured JSON logger | ✅ Complete |
| **P6** | Prometheus Metrics & Dynamic Hot-Reload — `/metrics` endpoint & telemetry | ✅ Complete |
| **P7** | Dynamic Tool Call Policy Engine — Tool allowlists/denylists & argument regex | ✅ Complete |
| **P8** | Prompt Injection Firewall — LLM jailbreak & delimiter hijacking detector | ✅ Complete |
| **P9** | SSRF & Network Egress Guardrails — Cloud metadata & private IP protection | ✅ Complete |
| **P10** | Human-In-The-Loop Approval Engine — Interactive confirmation & safety gates | ✅ Complete |

---

## References

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [NSA Cybersecurity Information Sheet: MCP Security Design Considerations (May 2026)](https://www.nsa.gov/)
- [CISA/Five Eyes: Careful Adoption of Agentic AI Services (May 2026)](https://www.cisa.gov/)
- [CVE-2025-54135 — Cursor IDE RCE via prompt injection](https://nvd.nist.gov/)
- [CVE-2025-53773 — GitHub Copilot RCE via fetched content injection](https://nvd.nist.gov/)

## License

[MIT](LICENSE)

