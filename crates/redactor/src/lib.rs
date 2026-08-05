pub mod entropy;

use entropy::shannon_entropy;
use regex::{Regex, RegexSet};

/// Replacement placeholder for detected secrets.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Real-time regex and Shannon entropy payload secret redactor.
pub struct SecretRedactor {
    patterns: Vec<Regex>,
    regex_set: RegexSet,
    entropy_threshold: f64,
    min_entropy_len: usize,
}

impl Default for SecretRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretRedactor {
    /// Create a new `SecretRedactor` with pre-compiled security pattern rules.
    pub fn new() -> Self {
        let pattern_strs = vec![
            // AWS Access Key ID
            r"\bAKIA[0-9A-Z]{16}\b",
            // AWS Secret Key assignment
            r#"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
            // OpenAI API Keys (legacy sk-... and project sk-proj-...)
            r"\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,128}\b",
            // GitHub Access Tokens
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b",
            r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b",
            // JWT Tokens
            r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",
            // RSA / SSH Private Key Blocks
            r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----",
            // `.env` Secret Key Assignments
            r#"(?i)\b(?:API_KEY|SECRET_KEY|SECRET|PASSWORD|AUTH_TOKEN|PRIVATE_KEY|ACCESS_TOKEN)\s*=\s*['"]?([^\s'"]{8,})['"]?"#,
        ];

        let regex_set = RegexSet::new(&pattern_strs).expect("Valid regex set");
        let patterns = pattern_strs
            .into_iter()
            .map(|p| Regex::new(p).expect("Valid regex"))
            .collect();

        Self {
            patterns,
            regex_set,
            entropy_threshold: 4.5,
            min_entropy_len: 20,
        }
    }

    /// Redact secrets in plain text input. Returns `(redacted_text, count_of_redactions)`.
    pub fn redact_text(&self, input: &str) -> (String, usize) {
        if input.trim().is_empty() {
            return (input.to_string(), 0);
        }

        let mut count = 0;
        let mut current_text = input.to_string();

        // 1. Regex Pattern Matching
        if self.regex_set.is_match(&current_text) {
            for re in &self.patterns {
                let matches = re.find_iter(&current_text).count();
                if matches > 0 {
                    count += matches;
                    current_text = re.replace_all(&current_text, REDACTED_PLACEHOLDER).to_string();
                }
            }
        }

        // 2. High-Entropy Token Heuristic
        let mut final_words = Vec::new();
        let words: Vec<&str> = current_text.split_whitespace().collect();

        for word in words {
            let clean_word = word.trim_matches(|c| matches!(c, '"' | '\'' | ',' | ';' | '(' | ')'));
            if clean_word == REDACTED_PLACEHOLDER {
                final_words.push(word.to_string());
                continue;
            }

            if clean_word.len() >= self.min_entropy_len
                && !clean_word.starts_with("http://")
                && !clean_word.starts_with("https://")
                && !clean_word.contains('/')
                && !clean_word.contains('\\')
            {
                let entropy = shannon_entropy(clean_word);
                if entropy >= self.entropy_threshold {
                    count += 1;
                    let redacted_word = word.replace(clean_word, REDACTED_PLACEHOLDER);
                    final_words.push(redacted_word);
                    continue;
                }
            }
            final_words.push(word.to_string());
        }

        (final_words.join(" "), count)
    }

    /// Recursively redact string fields in JSON values in-place. Returns count of redactions made.
    pub fn redact_json(&self, value: &mut serde_json::Value) -> usize {
        let mut count = 0;
        match value {
            serde_json::Value::String(s) => {
                let (redacted, n) = self.redact_text(s);
                if n > 0 {
                    *s = redacted;
                    count += n;
                }
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    // If key indicates a sensitive field name, redact string value unconditionally
                    if is_sensitive_key(k)
                        && matches!(v, serde_json::Value::String(s) if s != REDACTED_PLACEHOLDER && !s.is_empty())
                    {
                        *v = serde_json::Value::String(REDACTED_PLACEHOLDER.to_string());
                        count += 1;
                        continue;
                    }
                    count += self.redact_json(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    count += self.redact_json(item);
                }
            }
            _ => {}
        }
        count
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "api_key"
            | "apikey"
            | "secret"
            | "secret_key"
            | "password"
            | "passwd"
            | "token"
            | "auth_token"
            | "private_key"
            | "access_token"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_aws_key() {
        let redactor = SecretRedactor::new();
        let input = "Found AWS credential: AKIAIOSFODNN7EXAMPLE in environment";
        let (output, count) = redactor.redact_text(input);
        assert_eq!(count, 1);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_redact_openai_key() {
        let redactor = SecretRedactor::new();
        let input = "sk-proj-abc123def456ghi789jkl012mno345pqr678";
        let (output, count) = redactor.redact_text(input);
        assert_eq!(count, 1);
        assert_eq!(output, "[REDACTED]");
    }

    #[test]
    fn test_redact_github_token() {
        let redactor = SecretRedactor::new();
        let input = "Token ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let (output, count) = redactor.redact_text(input);
        assert_eq!(count, 1);
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_rsa_private_key() {
        let redactor = SecretRedactor::new();
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let (output, count) = redactor.redact_text(input);
        assert!(count >= 1);
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_json_sensitive_keys() {
        let redactor = SecretRedactor::new();
        let mut json_val = serde_json::json!({
            "status": "success",
            "config": {
                "api_key": "super_secret_value_12345",
                "timeout": 30
            }
        });
        let count = redactor.redact_json(&mut json_val);
        assert_eq!(count, 1);
        assert_eq!(json_val["config"]["api_key"], "[REDACTED]");
        assert_eq!(json_val["config"]["timeout"], 30);
    }
}
