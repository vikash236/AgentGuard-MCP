//! # AgentGuard Redactor
//!
//! Regex and Shannon entropy-based secret redactor for MCP tool outputs.
//! Scans tool return values for AWS keys, JWT tokens, SSH private keys,
//! and `.env` file contents, replacing matches with `[REDACTED]`.
//!
//! **Status:** Stub — implementation pending in Phase 2.
