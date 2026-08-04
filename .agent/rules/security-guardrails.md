# Security Guardrails

1. **Path Canonicalization:** Never open or resolve a file path without converting it to a canonicalized absolute path (`std::fs::canonicalize`).
2. **Path Jail Verification:** Verify `target_path.starts_with(jail_root_path)` before granting file read/write permissions.
3. **No Unescaped Command Spawning:** Shell tools must sanitize arguments or execute commands directly via `std::process::Command::new(binary)` without invoking `sh -c` or `cmd.exe /C`.
4. **Stderr Logging Only:** Stdout is reserved exclusively for raw JSON-RPC protocol frames when operating as a stdio proxy.
