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

    /// Recursively inspect JSON-RPC arguments for disallowed URLs with live fail-closed DNS resolution.
    pub async fn inspect_payload_async(&self, value: &serde_json::Value) -> Result<(), String> {
        let mut urls = Vec::new();
        self.extract_urls_from_value(value, &mut urls);

        for url in urls {
            self.validate_url_async(&url).await?;
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

    /// Validate a single URL with active DNS resolution against SSRF and rebinding (asynchronous).
    pub async fn validate_url_async(&self, raw_url: &str) -> Result<(), String> {
        let (host, _lower) = self.pre_validate_url(raw_url)?;

        // 1. Check numeric/IP host representation directly
        if let Some(ip) = parse_ip_or_numeric_host(&host) {
            self.validate_ip(ip, raw_url)?;
        } else if self.block_private_ips || self.block_cloud_metadata {
            // 2. Perform DNS resolution on domain name with fail-closed timeout
            let lookup_target = format!("{host}:80");
            match tokio::time::timeout(
                std::time::Duration::from_millis(2000),
                tokio::net::lookup_host(&lookup_target),
            )
            .await
            {
                Ok(Ok(addrs)) => {
                    let mut count = 0;
                    for socket_addr in addrs {
                        count += 1;
                        self.validate_ip(socket_addr.ip(), raw_url)?;
                    }
                    if count == 0 {
                        return Err(format!(
                            "SSRF blocked: DNS resolution returned no IP records for host '{host}' in URL: {raw_url}"
                        ));
                    }
                }
                Ok(Err(e)) => {
                    return Err(format!(
                        "SSRF blocked: DNS resolution failed for host '{host}' in URL: {raw_url} ({e})"
                    ));
                }
                Err(_) => {
                    return Err(format!(
                        "SSRF blocked: DNS resolution timed out for host '{host}' in URL: {raw_url}"
                    ));
                }
            }
        }

        // 3. Domain rule verification
        self.validate_domain_rules(&host)?;

        Ok(())
    }

    fn pre_validate_url(&self, raw_url: &str) -> Result<(String, String), String> {
        let lower = raw_url.to_lowercase();

        // 1. Enforce allowed schemes: only http and https are allowed for egress
        if lower.starts_with("file://") {
            return Err(format!(
                "Blocked unsafe protocol 'file://' in URL: {raw_url}"
            ));
        }
        if lower.starts_with("gopher://")
            || lower.starts_with("dict://")
            || lower.starts_with("ldap://")
            || lower.starts_with("data://")
        {
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
            return Err(format!(
                "SSRF blocked: Attempt to access localhost/loopback address in URL: {raw_url}"
            ));
        }

        // 4. Check for Cloud Metadata endpoints (AWS, GCP, Azure, OpenStack, Oracle)
        if self.block_cloud_metadata
            && (host == "169.254.169.254"
                || host == "metadata.google.internal"
                || host == "metadata.goog"
                || host == "instance-data"
                || host.contains("169.254.169.254"))
        {
            return Err(format!(
                "SSRF blocked: Cloud metadata service target in URL: {raw_url}"
            ));
        }

        Ok((host, lower))
    }

    fn validate_ip(&self, ip: IpAddr, raw_url: &str) -> Result<(), String> {
        let effective_ip = match ip {
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                // Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d)
                if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        octets[12], octets[13], octets[14], octets[15],
                    ))
                } else {
                    IpAddr::V6(v6)
                }
            }
            IpAddr::V4(v4) => IpAddr::V4(v4),
        };

        if self.block_cloud_metadata {
            if let IpAddr::V4(v4) = effective_ip {
                if v4 == std::net::Ipv4Addr::new(169, 254, 169, 254) {
                    return Err(format!(
                        "SSRF blocked: Cloud metadata IP '{v4}' in URL: {raw_url}"
                    ));
                }
            }
        }

        if self.block_private_ips {
            match effective_ip {
                IpAddr::V4(ipv4) => {
                    if ipv4.is_loopback() {
                        return Err(format!(
                            "SSRF blocked: IPv4 loopback address '{ipv4}' in URL: {raw_url}"
                        ));
                    }
                    if ipv4.is_private() {
                        return Err(format!(
                            "SSRF blocked: Private RFC1918 IPv4 address '{ipv4}' in URL: {raw_url}"
                        ));
                    }
                    if ipv4.is_link_local() {
                        return Err(format!(
                            "SSRF blocked: Link-local IPv4 address '{ipv4}' in URL: {raw_url}"
                        ));
                    }
                    if ipv4.is_unspecified() || ipv4.is_broadcast() || ipv4.is_multicast() {
                        return Err(format!(
                            "SSRF blocked: Reserved/Multicast IPv4 address '{ipv4}' in URL: {raw_url}"
                        ));
                    }
                }
                IpAddr::V6(ipv6) => {
                    if ipv6.is_loopback() {
                        return Err(format!(
                            "SSRF blocked: IPv6 loopback address '{ipv6}' in URL: {raw_url}"
                        ));
                    }
                    if ipv6.is_unspecified() || ipv6.is_multicast() {
                        return Err(format!(
                            "SSRF blocked: Reserved/Multicast IPv6 address '{ipv6}' in URL: {raw_url}"
                        ));
                    }
                    let octets = ipv6.octets();
                    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                        return Err(format!(
                            "SSRF blocked: Link-local IPv6 address '{ipv6}' in URL: {raw_url}"
                        ));
                    }
                    if (octets[0] & 0xfe) == 0xfc {
                        return Err(format!(
                            "SSRF blocked: Unique Local IPv6 address '{ipv6}' in URL: {raw_url}"
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_domain_rules(&self, host: &str) -> Result<(), String> {
        // Check denied domains
        for denied in &self.denied_domains {
            let denied_lower = denied.to_lowercase();
            if host == denied_lower || host.ends_with(&format!(".{denied_lower}")) {
                return Err(format!(
                    "Network policy violation: Target domain '{host}' is in denied_domains"
                ));
            }
        }

        // Check allowed domains (if non-empty)
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
                return Err(format!(
                    "Network policy violation: Target domain '{host}' is not in allowed_domains"
                ));
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

        if host.is_empty() { None } else { Some(host) }
    }
}

/// Parse standard and alternate numeric IP host encodings (decimal, hex, octal, shortened dotted, IPv4-mapped IPv6).
fn parse_ip_or_numeric_host(host_str: &str) -> Option<IpAddr> {
    let clean = host_str.trim_matches('[').trim_matches(']');

    // 1. Direct standard IP parse
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return Some(ip);
    }

    // 2. Single integer (decimal or hex)
    if let Ok(num) = clean.parse::<u32>() {
        return Some(IpAddr::V4(std::net::Ipv4Addr::from(num)));
    }
    if (clean.starts_with("0x") || clean.starts_with("0X"))
        && clean.len() > 2
        && let Ok(num) = u32::from_str_radix(&clean[2..], 16)
    {
        return Some(IpAddr::V4(std::net::Ipv4Addr::from(num)));
    }

    // 3. Dot-separated numeric parts with octal/hex/decimal or shortened format (e.g. 127.1, 0177.0.0.1)
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() >= 2 && parts.len() <= 4 {
        let mut parsed_parts = Vec::new();
        for p in &parts {
            let part_num = if p.starts_with("0x") || p.starts_with("0X") {
                u32::from_str_radix(&p[2..], 16).ok()?
            } else if p.starts_with('0')
                && p.len() > 1
                && p.chars().all(|c| ('0'..='7').contains(&c))
            {
                u32::from_str_radix(p, 8).ok()?
            } else {
                p.parse::<u32>().ok()?
            };
            parsed_parts.push(part_num);
        }

        match parsed_parts.len() {
            4 if parsed_parts.iter().all(|&n| n <= 255) => {
                return Some(IpAddr::V4(std::net::Ipv4Addr::new(
                    parsed_parts[0] as u8,
                    parsed_parts[1] as u8,
                    parsed_parts[2] as u8,
                    parsed_parts[3] as u8,
                )));
            }
            2 if parsed_parts[0] <= 255 && parsed_parts[1] <= 0x00ffffff => {
                let oct1 = parsed_parts[0] as u8;
                let rest = parsed_parts[1];
                let oct2 = ((rest >> 16) & 0xff) as u8;
                let oct3 = ((rest >> 8) & 0xff) as u8;
                let oct4 = (rest & 0xff) as u8;
                return Some(IpAddr::V4(std::net::Ipv4Addr::new(oct1, oct2, oct3, oct4)));
            }
            3 if parsed_parts[0] <= 255
                && parsed_parts[1] <= 255
                && parsed_parts[2] <= 0x0000ffff =>
            {
                let oct1 = parsed_parts[0] as u8;
                let oct2 = parsed_parts[1] as u8;
                let rest = parsed_parts[2];
                let oct3 = ((rest >> 8) & 0xff) as u8;
                let oct4 = (rest & 0xff) as u8;
                return Some(IpAddr::V4(std::net::Ipv4Addr::new(oct1, oct2, oct3, oct4)));
            }
            _ => {}
        }
    }

    None
}

#[allow(dead_code)]
pub type SharedNetworkGuard = Arc<NetworkGuard>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blocks_cloud_metadata() {
        let guard = NetworkGuard::default();
        let payload = serde_json::json!({
            "name": "fetch_url",
            "arguments": {
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"
            }
        });
        let result = guard.inspect_payload_async(&payload).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("metadata"));
    }

    #[tokio::test]
    async fn test_blocks_localhost_and_private_ips() {
        let guard = NetworkGuard::default();

        assert!(guard.validate_url_async("http://127.0.0.1:8080/admin").await.is_err());
        assert!(guard.validate_url_async("http://localhost:3000/api").await.is_err());
        assert!(guard.validate_url_async("http://192.168.1.1/router").await.is_err());
        assert!(guard.validate_url_async("http://10.0.0.5:9000/internal").await.is_err());
        assert!(guard.validate_url_async("http://172.16.5.1/secret").await.is_err());
        assert!(guard.validate_url_async("file:///etc/passwd").await.is_err());
    }

    #[tokio::test]
    async fn test_blocks_ipv4_mapped_ipv6_and_alternate_encodings() {
        let guard = NetworkGuard::default();

        // IPv4-mapped IPv6 metadata
        assert!(
            guard
                .validate_url_async("http://[::ffff:169.254.169.254]/latest/meta-data/")
                .await
                .is_err()
        );
        // Decimal metadata (2852039166 = 169.254.169.254)
        assert!(guard.validate_url_async("http://2852039166/").await.is_err());
        // Hex loopback (0x7f000001 = 127.0.0.1)
        assert!(guard.validate_url_async("http://0x7f000001/").await.is_err());
        // Octal loopback (0177.0.0.1 = 127.0.0.1)
        assert!(guard.validate_url_async("http://0177.0.0.1/").await.is_err());
        // Shortened dotted form (127.1 = 127.0.0.1)
        assert!(guard.validate_url_async("http://127.1/").await.is_err());
    }

    #[tokio::test]
    async fn test_async_dns_resolution_blocks_loopback() {
        let guard = NetworkGuard::default();
        let res = guard
            .validate_url_async("http://localhost:8080/secret")
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_allows_public_https_urls() {
        let guard = NetworkGuard::default();
        assert!(
            guard
                .validate_url_async("https://api.github.com/repos/rust-lang/rust")
                .await
                .is_ok()
        );
        assert!(
            guard
                .validate_url_async("https://docs.rs/serde/latest/serde/")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_allowed_and_denied_domains() {
        let guard = NetworkGuard::new(
            true,
            true,
            vec!["github.com".to_string(), "crates.io".to_string()],
            vec!["malicious.github.com".to_string()],
        );

        assert!(guard.validate_url_async("https://github.com/anthropic").await.is_ok());
        assert!(guard.validate_url_async("https://api.github.com/user").await.is_ok());
        assert!(
            guard
                .validate_url_async("https://crates.io/api/v1/crates")
                .await
                .is_ok()
        );

        // Denied domain should fail
        assert!(
            guard
                .validate_url_async("https://malicious.github.com/payload")
                .await
                .is_err()
        );
        // Domain not in allowed list should fail
        assert!(guard.validate_url_async("https://google.com/search").await.is_err());
    }
}
