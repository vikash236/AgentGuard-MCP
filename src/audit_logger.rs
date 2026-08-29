use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A structured cryptographic JSON security audit record with SHA-256 hash chaining.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub timestamp_unix_secs: u64,
    pub event_type: String,
    pub severity: String,
    pub details: String,
    pub prev_hash: String,
    pub hash: String,
}

/// Thread-safe structured JSON security audit logger with hash-chain integrity.
pub struct AuditLogger {
    file_path: Option<PathBuf>,
    state: Mutex<LoggerState>,
}

struct LoggerState {
    sequence: u64,
    last_hash: String,
}

impl AuditLogger {
    /// Create a new `AuditLogger`. If `file_path` is `None`, events are ignored.
    pub fn new(file_path: Option<PathBuf>) -> Self {
        Self {
            file_path,
            state: Mutex::new(LoggerState {
                sequence: 0,
                last_hash: GENESIS_HASH.to_string(),
            }),
        }
    }

    /// Record a security audit event and append to the hash chain.
    pub fn log_event(&self, event_type: &str, severity: &str, details: &str) {
        let timestamp_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut state = self.state.lock().unwrap();
        state.sequence += 1;
        let seq = state.sequence;
        let prev = state.last_hash.clone();

        // Calculate SHA-256 hash of (sequence || timestamp || event_type || severity || details || prev_hash)
        let mut hasher = Sha256::new();
        hasher.update(seq.to_le_bytes());
        hasher.update(timestamp_unix_secs.to_le_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(severity.as_bytes());
        hasher.update(details.as_bytes());
        hasher.update(prev.as_bytes());
        let current_hash = format!("{:x}", hasher.finalize());

        state.last_hash = current_hash.clone();

        let record = AuditRecord {
            sequence: seq,
            timestamp_unix_secs,
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            details: details.to_string(),
            prev_hash: prev,
            hash: current_hash,
        };

        if let Some(ref path) = self.file_path
            && let Ok(json_str) = serde_json::to_string(&record)
            && let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path)
        {
            let _ = writeln!(file, "{json_str}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_audit_logger_hash_chaining() {
        let temp_log = std::env::temp_dir().join("test_audit_hash.log");
        let logger = AuditLogger::new(Some(temp_log.clone()));

        logger.log_event("path_jail_violation", "HIGH", "Path escape ../secret.txt");
        logger.log_event(
            "prompt_injection_blocked",
            "CRITICAL",
            "Ignore previous instructions",
        );

        assert!(temp_log.exists());
        let contents = fs::read_to_string(&temp_log).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let rec1: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        let rec2: AuditRecord = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(rec1.sequence, 1);
        assert_eq!(rec1.prev_hash, GENESIS_HASH);
        assert_eq!(rec2.sequence, 2);
        assert_eq!(rec2.prev_hash, rec1.hash);

        let _ = fs::remove_file(&temp_log);
    }
}
