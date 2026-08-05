use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A structured JSON security audit record.
#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub timestamp_unix_secs: u64,
    pub event_type: String,
    pub severity: String,
    pub details: String,
}

/// Thread-safe structured JSON security audit logger.
pub struct AuditLogger {
    file_path: Option<PathBuf>,
    lock: Mutex<()>,
}

impl AuditLogger {
    /// Create a new `AuditLogger`. If `file_path` is `None`, events are ignored.
    pub fn new(file_path: Option<PathBuf>) -> Self {
        Self {
            file_path,
            lock: Mutex::new(()),
        }
    }

    /// Record a security audit event.
    pub fn log_event(&self, event_type: &str, severity: &str, details: &str) {
        let timestamp_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = AuditRecord {
            timestamp_unix_secs,
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            details: details.to_string(),
        };

        if let Some(ref path) = self.file_path
            && let Ok(json_str) = serde_json::to_string(&record)
        {
            let _guard = self.lock.lock().unwrap();
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{json_str}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_audit_logger() {
        let temp_log = std::env::temp_dir().join("test_audit.log");
        let logger = AuditLogger::new(Some(temp_log.clone()));

        logger.log_event("path_jail_violation", "HIGH", "Path escape ../secret.txt");

        assert!(temp_log.exists());
        let contents = fs::read_to_string(&temp_log).unwrap();
        assert!(contents.contains("path_jail_violation"));
        assert!(contents.contains("HIGH"));

        let _ = fs::remove_file(&temp_log);
    }
}
