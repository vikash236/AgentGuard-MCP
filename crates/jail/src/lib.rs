pub mod error;

pub use error::JailError;
use std::path::{Component, Path, PathBuf};

/// Path canonicalization and chroot-style isolation enforcer for MCP tool calls.
#[derive(Debug, Clone)]
pub struct PathJail {
    root: PathBuf,
}

impl PathJail {
    /// Create a new `PathJail` rooted at `root_path`.
    /// The root path will be canonicalized and checked for existence.
    pub fn new(root_path: impl AsRef<Path>) -> Result<Self, JailError> {
        let path = root_path.as_ref();
        let canonical_root = std::fs::canonicalize(path)?;
        Ok(Self {
            root: canonical_root,
        })
    }

    /// Access the canonicalized jail root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Canonicalize a requested target path and verify it is strictly within the jail root.
    pub fn canonicalize_and_check(&self, target: impl AsRef<Path>) -> Result<PathBuf, JailError> {
        let raw_target = target.as_ref();

        // Standardize URI scheme if present (e.g. file:///path/to/file)
        let path_str = raw_target.to_string_lossy();
        let clean_path = if let Some(stripped) = path_str.strip_prefix("file://") {
            #[cfg(windows)]
            let stripped = stripped.trim_start_matches('/');
            PathBuf::from(stripped)
        } else {
            raw_target.to_path_buf()
        };

        let resolved_input = if clean_path.is_absolute() {
            clean_path
        } else {
            self.root.join(clean_path)
        };

        // Normalize textually first to eliminate . and ..
        let normalized = normalize_path(&resolved_input);

        // Try canonicalizing existing path or deepest existing parent
        let canonical_path = canonicalize_best_effort(&normalized)?;

        if canonical_path.starts_with(&self.root) {
            Ok(canonical_path)
        } else {
            Err(JailError::PathOutsideJail {
                requested: raw_target.to_path_buf(),
                jail_root: self.root.clone(),
            })
        }
    }

    /// Deeply inspect JSON parameters for `tools/call` requests.
    pub fn inspect_json_arguments(&self, value: &serde_json::Value) -> Result<(), JailError> {
        self.inspect_value(value, None)
    }

    fn inspect_value(&self, value: &serde_json::Value, key: Option<&str>) -> Result<(), JailError> {
        match value {
            serde_json::Value::String(s) => {
                if s.trim().is_empty() {
                    return Ok(());
                }

                let decoded = percent_decode_recursive(s);
                let is_path_key = key.is_some_and(is_known_path_key);

                let looks_like_path = is_path_key
                    || s.starts_with('/')
                    || s.starts_with('\\')
                    || s.starts_with('.')
                    || s.contains("../")
                    || s.contains("..\\")
                    || s.contains("://")
                    || is_drive_letter_path(s)
                    || decoded.starts_with('/')
                    || decoded.starts_with('\\')
                    || decoded.starts_with('.')
                    || decoded.contains("../")
                    || decoded.contains("..\\")
                    || is_drive_letter_path(&decoded);

                if looks_like_path {
                    // Check decoded path first, then original path
                    self.canonicalize_and_check(&decoded)?;
                    if decoded != *s {
                        self.canonicalize_and_check(s)?;
                    }
                }
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    self.inspect_value(v, Some(k))?;
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.inspect_value(item, key)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn is_drive_letter_path(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_known_path_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("path")
        || lower.contains("file")
        || lower.contains("dir")
        || lower.contains("folder")
        || lower.contains("target")
        || lower.contains("dest")
        || lower.contains("src")
        || lower.contains("source")
        || lower.contains("location")
        || lower.contains("root")
        || lower.contains("uri")
        || lower.contains("output")
        || lower.contains("input")
}

/// Recursively percent-decode a string up to 5 iterations to catch nested encoding.
fn percent_decode_recursive(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..5 {
        let decoded = percent_decode_once(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex_val) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            result.push(hex_val);
            i += 3;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(result).unwrap_or_else(|_| input.to_string())
}

/// Textually normalize a path without resolving symlinks (resolving . and .. components).
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if let Some(last) = components.last() {
                    if matches!(last, Component::Normal(_)) {
                        components.pop();
                    } else {
                        components.push(component);
                    }
                } else {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    components.into_iter().collect()
}

/// Best effort canonicalization: canonicalizes the longest existing ancestor path
/// and appends the non-existent trailing components.
fn canonicalize_best_effort(path: &Path) -> Result<PathBuf, JailError> {
    if let Ok(can) = std::fs::canonicalize(path) {
        return Ok(can);
    }

    // Path or part of path doesn't exist yet. Find existing ancestor.
    let mut stack = Vec::new();
    let mut current = path.to_path_buf();

    while !current.exists() {
        if let Some(file_name) = current.file_name() {
            stack.push(file_name.to_os_string());
            if !current.pop() {
                break;
            }
        } else {
            break;
        }
    }

    if current.exists() {
        let mut canonical = std::fs::canonicalize(&current)?;
        for component in stack.into_iter().rev() {
            canonical.push(component);
        }
        Ok(canonical)
    } else {
        Err(JailError::InvalidPath(format!(
            "Path '{}' does not exist and no existing ancestor could be found",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_jail_allow_valid_path() {
        let temp_dir = std::env::temp_dir().join("agentguard_jail_test_allow");
        let _ = fs::create_dir_all(&temp_dir);
        let sub_file = temp_dir.join("inside.txt");
        let _ = fs::write(&sub_file, "hello");

        let jail = PathJail::new(&temp_dir).expect("Jail init should succeed");
        let result = jail.canonicalize_and_check("inside.txt");
        assert!(result.is_ok(), "Relative inside path should be allowed");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_jail_block_parent_traversal() {
        let temp_dir = std::env::temp_dir().join("agentguard_jail_test_block");
        let _ = fs::create_dir_all(&temp_dir);

        let jail = PathJail::new(&temp_dir).expect("Jail init should succeed");
        let result = jail.canonicalize_and_check("../outside.txt");
        assert!(
            matches!(result, Err(JailError::PathOutsideJail { .. })),
            "Parent traversal path must be blocked"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_jail_inspect_json_arguments() {
        let temp_dir = std::env::temp_dir().join("agentguard_jail_test_json");
        let _ = fs::create_dir_all(&temp_dir);

        let jail = PathJail::new(&temp_dir).expect("Jail init should succeed");

        let safe_payload = serde_json::json!({
            "path": "safe.txt",
            "count": 5
        });
        assert!(jail.inspect_json_arguments(&safe_payload).is_ok());

        let evil_payload = serde_json::json!({
            "path": "../../etc/passwd",
            "mode": "read"
        });
        assert!(jail.inspect_json_arguments(&evil_payload).is_err());

        // Test percent-encoded traversal
        let encoded_payload = serde_json::json!({
            "custom_location": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        });
        assert!(jail.inspect_json_arguments(&encoded_payload).is_err());

        // Test double-encoded traversal
        let double_encoded = serde_json::json!({
            "input_file": "%252e%252e%252foutside.txt"
        });
        assert!(jail.inspect_json_arguments(&double_encoded).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
