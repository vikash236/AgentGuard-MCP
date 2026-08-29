# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of **AgentGuard-MCP** seriously. If you discover a security vulnerability, please do **NOT** open a public issue.

Instead, please report security vulnerabilities via:
1. **GitHub Security Advisories**: Navigate to the [Security Advisories tab](https://github.com/vikash236/AgentGuard-MCP/security/advisories) on GitHub and click "New draft advisory".
2. **Email**: Contact `security@agentguard-mcp.internal` (or repository maintainers).

Please include:
- A clear description of the vulnerability.
- Steps or a minimal proof-of-concept (JSON-RPC payload or MCP interaction) to reproduce the behavior.
- Impact assessment and affected components (Proxy, Gateway, Redactor, Jail, Firewall, NetworkGuard).

We will acknowledge receipt within 48 hours and work with you on a coordinated disclosure timeline.

---

## Security Architecture & Defense-in-Depth

AgentGuard-MCP enforces multi-layered guardrails across Model Context Protocol (MCP) interactions:

| Component | Layer | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Path Jail** | Runtime (`crates/jail`) | Recursive percent-decoding, absolute canonicalization, Windows drive letter bounding, and forbidden parent traversal blocking. |
| **Network Guard** | Runtime (`src/network_guard`) | Asynchronous fail-closed DNS resolution, private IP / RFC-1918 blocking, alternate integer/hex/octal/shortened notation decoding, and IPv4-mapped IPv6 cloud metadata protection. |
| **Prompt Firewall** | Runtime (`src/prompt_firewall`) | Inbound & outbound in-place recursive JSON tree sanitization for instruction overrides, system tags, and delimiter injections. |
| **Secret Redactor** | Runtime (`crates/redactor`) | Regex pattern redaction for credentials (API keys, tokens, DB URIs) and Shannon entropy scanning for high-entropy secrets. |
| **Policy Engine** | Runtime (`src/policy_engine`) | Anchored regex argument constraints and strict tool authorization policies. |
| **Audit Logger** | Auditing (`src/audit_logger`) | Running cryptographic SHA-256 hash chaining for tamper-evident event logging. |

---

## Threat Model & Known Architectural Boundaries

1. **DNS Rebinding (TOCTOU)**:
   - *Current Defense*: `validate_url_async` resolves domain names to IP addresses with a 2-second timeout and fails closed before permitting requests.
   - *Residual Boundary*: If a downstream tool resolves DNS independently without socket/IP pinning, an adversary controlling a sub-second TTL DNS record can theoretically rebind between proxy inspection and tool connection. Complete mitigation requires egress forward proxy socket pinning.

2. **Streaming SSE Fragmentation**:
   - *Current Defense*: Line-aware parsing extracts and sanitizes structured JSON payloads within `data: {...}` lines.
   - *Residual Boundary*: Large JSON events fractured across TCP chunk boundaries mid-line fall back to raw-text pattern scanning until full line assembly.

3. **Audit Log Integrity Scope**:
   - Running SHA-256 hash chains guarantee tamper evidence against partial row truncation, row splicing, or reordering. Complete log regeneration remains possible only for actors with write access to the host file system.
