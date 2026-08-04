# AgentGuard-MCP Agent Board

> Core proxy & auditor → `README.md`. This board manages multi-AI workstreams and specs.

## Board Structure

| Path | Purpose |
|------|---------|
| `specs/active/current.md` | Active workstreams and current phase checklist |
| `specs/active/next.md` | Execution priority order |
| `specs/active/catalog.md` | Master phase blueprint catalog |
| `specs/active/details/` | Detailed technical specifications per phase |
| `memory/execution.log` | Timestamped log of execution milestones |
| `memory/handoff.md` | Multi-agent context handoff document |
| `policy/` | Threat models, security rules, and validation matrices |
| `rules/` | Token efficiency, security guardrails, context hygiene |
| `skills/` | Custom agent skills (`security-guard`) |
| `wiki/` | Architecture deep-dives & JSON-RPC protocol specs |

## Priority Phases
- **Phase 0 (Schema Auditor):** Static CLI scanner for MCP manifest files.
- **Phase 1 (Stdio Proxy Jail):** Tokio-based stdio JSON-RPC stream interceptor with path-jailing.
- **Phase 2 (Secret Redactor):** Real-time payload regex/entropy scanner.
