# Master Phase Blueprint Catalog — AgentGuard-MCP

| Phase | Title | Description | Status |
|-------|-------|-------------|--------|
| **P0** | Static Manifest Auditor | CLI tool to audit MCP server manifest declarations for unsafe schemas | Complete |
| **P1** | Stdio Proxy & Path Jail | Tokio-based JSON-RPC proxy enforcing path-chrooting and argument escaping | Complete |
| **P2** | Secret Redactor | Real-time payload regex and entropy scanner for `.env` credentials | Complete |
| **P3** | HTTP/SSE Gateway Proxy | Support for remote MCP servers over SSE / HTTP web sockets | Complete |
| **P4** | Fuzzing & Dynamic Sandbox | Automated red-teaming tool feeding path traversal and injection payloads | Complete |
| **P5** | Policy Config Engine & Audit Logger | Native TOML configuration parser and structured JSON security event logging | Complete |
