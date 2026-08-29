use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

/// Network Guard for detecting and blocking SSRF and unauthorized network egress.
#[derive(Debug, Clone)]
pub struct NetworkGuard {
    block_private_ips: bool,
    block_cloud_metadata: bool,
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
    url_regex: Regex,
}

impl Default for NetworkGuard {
    fn default() -> Self {
        Self::new(true, true, Vec::new(), Vec::new())
    }
}

#[allow(clippy::collapsible_if)]
impl NetworkGuard {
    pub fn new(
        block_private_ips: bool,
        block_cloud_metadata: bool,
        allowed_domains: Vec<String>,
        denied_domains: Vec<String>,
    ) -> Self {
        let url_regex = Regex::new(
            r#"(?i)\b(https?|ftp|file|gopher|dict|tftp|ldap|data)://([^\s/$.?#\(\)\[\]\{\}"'<>]+)(?:[^\s"'<>]*)?"#,
        )
        .expect("Invalid URL regex");

        Self {
            block_private_ips,
            block_cloud_metadata,
            allowed_domains,
            denied_domains,
            url_regex,
        }
    }

    /// Recursively inspect JSON-RPC arguments for disallowed URLs or SSRF targets.
    pub fn inspect_payload(&self, value: &serde_json::Value) -> Result<(), String> {
        let mut urls = Vec::new();
        self.extract_urls_from_value(value, &mut urls);

        for url in urls {
            self.validate_url(&url)?;
        }

        Ok(())
    }

    fn extract_urls_from_value(&self, value: &serde_json::Value, urls: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => {
                for cap in self.url_regex.find_iter(s) {
                    urls.push(cap.as_str().to_string());
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.extract_urls_from_value(item, urls);
                }
            }
            serde_json::Value::Object(map) => {
                for (_k, v) in map {
                    self.extract_urls_from_value(v, urls);
                }
            }
            _ => {}
        }
    }

    /// Validate a single URL against SSRF, cloud metadata, scheme, and domain rules.
    pub fn validate_url(&self, raw_url: &str) -> Result<(), String> {
        let lower = raw_url.to_lowercase();

        // 1. Enforce allowed schemes: only http and https are allowed for egress
        if lower.starts_with("file://") {
            return Err(format!("Blocked unsafe protocol 'file://' in URL: {raw_url}"));
        }
        if lower.starts_with("gopher://") || lower.starts_with("dict://") || lower.starts_with("ldap://") || lower.starts_with("data://") {
            return Err(format!("Blocked dangerous protocol in URL: {raw_url}"));
        }
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            return Err(format!("Unsupported protocol in URL: {raw_url}"));
        }

        // 2. Extract host
        let host = match self.extract_host(raw_url) {
            Some(h) => h.to_lowercase(),
            None => return Err(format!("Invalid or unparseable host in URL: {raw_url}")),
        };

        // 3. Check for localhost / loopback names
        if self.block_private_ips
            && (host == "localhost"
                || host.ends_with(".localhost")
                || host == "127.0.0.1"
                || host == "::1"
                || host == "[::1]")
        {
            return Err(format!("SSRF blocked: Attempt to access localhost/loopback address in URL: {raw_url}"));
        }

        // 4. Check for Cloud Metadata endpoints (AWS, GCP, Azure, OpenStack, Oracle)
        if self.block_cloud_metadata
            && (host == "169.254.169.254"
                || host == "metadata.google.internal"
                || host == "metadata.goog"
                || host == "instance-data"
                || host.contains("169.254.169.254"))
        {
            return Err(format!("SSRF blocked: Cloud metadata service target in URL: {raw_url}"));
        }

        // 5. Check if host is an IP address and inspect IP ranges
        let clean_ip_str = host.trim_matches('[').trim_matches(']');
        if self.block_private_ips {
            if let Ok(ip) = clean_ip_str.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(ipv4) => {
                        if ipv4.is_loopback() {
                            return Err(format!("SSRF blocked: IPv4 loopback address '{ipv4}' in URL: {raw_url}"));
                        }
                        if ipv4.is_private() {
                            return Err(format!("SSRF blocked: Private RFC1918 IPv4 address '{ipv4}' in URL: {raw_url}"));
                        }
                        if ipv4.is_link_local() {
                            return Err(format!("SSRF blocked: Link-local IPv4 address '{ipv4}' in URL: {raw_url}"));
                        }
                        if ipv4.is_unspecified() || ipv4.is_broadcast() || ipv4.is_multicast() {
                            return Err(format!("SSRF blocked: Reserved/Multicast IPv4 address '{ipv4}' in URL: {raw_url}"));
                        }
                    }
                    IpAddr::V6(ipv6) => {
                        if ipv6.is_loopback() {
                            return Err(format!("SSRF blocked: IPv6 loopback address '{ipv6}' in URL: {raw_url}"));
                        }
                        if ipv6.is_unspecified() || ipv6.is_multicast() {
                            return Err(format!("SSRF blocked: Reserved/Multicast IPv6 address '{ipv6}' in URL: {raw_url}"));
                        }
                        let octets = ipv6.octets();
                        // fe80::/10 link local
                        if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                            return Err(format!("SSRF blocked: Link-local IPv6 address '{ipv6}' in URL: {raw_url}"));
                        }
                        // fc00::/7 unique local (private)
                        if (octets[0] & 0xfe) == 0xfc {
                            return Err(format!("SSRF blocked: Unique Local IPv6 address '{ipv6}' in URL: {raw_url}"));
                        }
                    }
                }
            }
        }

        // 6. Check denied domains
        for denied in &self.denied_domains {
            let denied_lower = denied.to_lowercase();
            if host == denied_lower || host.ends_with(&format!(".{denied_lower}")) {
                return Err(format!("Network policy violation: Target domain '{host}' is in denied_domains"));
            }
        }

        // 7. Check allowed domains (if non-empty)
        if !self.allowed_domains.is_empty() {
            let mut is_allowed = false;
            for allowed in &self.allowed_domains {
                let allowed_lower = allowed.to_lowercase();
                if host == allowed_lower || host.ends_with(&format!(".{allowed_lower}")) {
                    is_allowed = true;
                    break;
                }
            }
            if !is_allowed {
                return Err(format!("Network policy violation: Target domain '{host}' is not in allowed_domains"));
            }
        }

        Ok(())
    }

    fn extract_host<'a>(&self, url: &'a str) -> Option<&'a str> {
        let after_scheme = if let Some(idx) = url.find("://") {
            &url[idx + 3..]
        } else {
            url
        };

        // Strip path, query, fragment
        let host_and_port = after_scheme.split(['/', '?', '#']).next()?;

        // Strip userinfo (user:pass@host)
        let host_port_only = if let Some(idx) = host_and_port.rfind('@') {
            &host_and_port[idx + 1..]
        } else {
            host_and_port
        };

        // If IPv6 literal like [::1]:8080
        if let Some(rest) = host_port_only.strip_prefix('[') {
            if let Some(end_bracket) = rest.find(']') {
                return Some(&host_port_only[..=end_bracket + 1]);
            }
        }

        // Strip port (:8080)
        let host = if let Some(colon_idx) = host_port_only.find(':') {
            &host_port_only[..colon_idx]
        } else {
            host_port_only
        };

        if host.is_empty() {
            None
        } else {
            Some(host)
        }
    }
}

#[allow(dead_code)]
pub type SharedNetworkGuard = Arc<NetworkGuard>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_cloud_metadata() {
        let guard = NetworkGuard::default();
        let payload = serde_json::json!({
            "name": "fetch_url",
            "arguments": {
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"
            }
        });
        let result = guard.inspect_payload(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cloud metadata"));
    }

    #[test]
    fn test_blocks_localhost_and_private_ips() {
        let guard = NetworkGuard::default();
        
        assert!(guard.validate_url("http://127.0.0.1:8080/admin").is_err());
        assert!(guard.validate_url("http://localhost:3000/api").is_err());
        assert!(guard.validate_url("http://192.168.1.1/router").is_err());
        assert!(guard.validate_url("http://10.0.0.5:9000/internal").is_err());
        assert!(guard.validate_url("http://172.16.5.1/secret").is_err());
        assert!(guard.validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_allows_public_https_urls() {
        let guard = NetworkGuard::default();
        assert!(guard.validate_url("https://api.github.com/repos/rust-lang/rust").is_ok());
        assert!(guard.validate_url("https://docs.rs/serde/latest/serde/").is_ok());
    }

    #[test]
    fn test_allowed_and_denied_domains() {
        let guard = NetworkGuard::new(
            true,
            true,
            vec!["github.com".to_string(), "crates.io".to_string()],
            vec!["malicious.github.com".to_string()],
        );

        assert!(guard.validate_url("https://github.com/anthropic").is_ok());
        assert!(guard.validate_url("https://api.github.com/user").is_ok());
        assert!(guard.validate_url("https://crates.io/api/v1/crates").is_ok());
        
        // Denied domain should fail
        assert!(guard.validate_url("https://malicious.github.com/payload").is_err());
        // Domain not in allowed list should fail
        assert!(guard.validate_url("https://google.com/search").is_err());
    }
}
