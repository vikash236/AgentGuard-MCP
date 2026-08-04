# GEMINI.md — Agent Guidelines for AgentGuard-MCP

## Overview
You are working on **AgentGuard-MCP**, a Rust-based security proxy and manifest auditor for Anthropic's Model Context Protocol (MCP).

## Rules of Engagement
- Always read `.agent/specs/active/current.md` before making code changes.
- Ensure all path manipulation uses canonicalized absolute paths (`std::fs::canonicalize`).
- Keep stdout clean: MCP stdio proxy communicates via stdin/stdout, so diagnostic logs MUST go to stderr or a dedicated log file.
- Update `.agent/memory/execution.log` after completing tasks.
