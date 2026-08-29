use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MetricsCollector {
    requests_intercepted: AtomicU64,
    redactions_count: AtomicU64,
    jail_violations_count: AtomicU64,
    policy_violations_count: AtomicU64,
    prompt_injections_count: AtomicU64,
    network_violations_count: AtomicU64,
    approvals_prompted_count: AtomicU64,
    approvals_granted_count: AtomicU64,
    approvals_rejected_count: AtomicU64,
    auth_failures_count: AtomicU64,
    rate_limit_rejections: AtomicU64,
    total_latency_us: AtomicU64,
}

#[derive(Serialize)]
pub struct MetricsSnapshot {
    pub requests_intercepted: u64,
    pub redactions_count: u64,
    pub jail_violations_count: u64,
    pub policy_violations_count: u64,
    pub prompt_injections_count: u64,
    pub network_violations_count: u64,
    pub approvals_prompted_count: u64,
    pub approvals_granted_count: u64,
    pub approvals_rejected_count: u64,
    pub auth_failures_count: u64,
    pub rate_limit_rejections: u64,
    pub total_latency_us: u64,
    pub average_latency_us: f64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_requests(&self) {
        self.requests_intercepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_redactions(&self) {
        self.redactions_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_jail_violations(&self) {
        self.jail_violations_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_policy_violations(&self) {
        self.policy_violations_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_prompt_injections(&self) {
        self.prompt_injections_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_network_violations(&self) {
        self.network_violations_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_approvals_prompted(&self) {
        self.approvals_prompted_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_approvals_granted(&self) {
        self.approvals_granted_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_approvals_rejected(&self) {
        self.approvals_rejected_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_failures(&self) {
        self.auth_failures_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limit_rejections(&self) {
        self.rate_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn record_latency(&self, duration_us: u64) {
        self.total_latency_us
            .fetch_add(duration_us, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let reqs = self.requests_intercepted.load(Ordering::Relaxed);
        let lat = self.total_latency_us.load(Ordering::Relaxed);
        let avg_lat = if reqs > 0 {
            lat as f64 / reqs as f64
        } else {
            0.0
        };

        MetricsSnapshot {
            requests_intercepted: reqs,
            redactions_count: self.redactions_count.load(Ordering::Relaxed),
            jail_violations_count: self.jail_violations_count.load(Ordering::Relaxed),
            policy_violations_count: self.policy_violations_count.load(Ordering::Relaxed),
            prompt_injections_count: self.prompt_injections_count.load(Ordering::Relaxed),
            network_violations_count: self.network_violations_count.load(Ordering::Relaxed),
            approvals_prompted_count: self.approvals_prompted_count.load(Ordering::Relaxed),
            approvals_granted_count: self.approvals_granted_count.load(Ordering::Relaxed),
            approvals_rejected_count: self.approvals_rejected_count.load(Ordering::Relaxed),
            auth_failures_count: self.auth_failures_count.load(Ordering::Relaxed),
            rate_limit_rejections: self.rate_limit_rejections.load(Ordering::Relaxed),
            total_latency_us: lat,
            average_latency_us: avg_lat,
        }
    }

    pub fn to_prometheus(&self) -> String {
        let snap = self.snapshot();
        format!(
            "# HELP agentguard_requests_intercepted_total Total JSON-RPC requests intercepted\n\
             # TYPE agentguard_requests_intercepted_total counter\n\
             agentguard_requests_intercepted_total {}\n\n\
             # HELP agentguard_redactions_total Total payload secrets redacted\n\
             # TYPE agentguard_redactions_total counter\n\
             agentguard_redactions_total {}\n\n\
             # HELP agentguard_jail_violations_total Total path jail access violations blocked\n\
             # TYPE agentguard_jail_violations_total counter\n\
             agentguard_jail_violations_total {}\n\n\
             # HELP agentguard_policy_violations_total Total policy engine violations blocked\n\
             # TYPE agentguard_policy_violations_total counter\n\
             agentguard_policy_violations_total {}\n\n\
             # HELP agentguard_prompt_injections_total Total prompt injection attack attempts blocked\n\
             # TYPE agentguard_prompt_injections_total counter\n\
             agentguard_prompt_injections_total {}\n\n\
             # HELP agentguard_network_violations_total Total SSRF and network policy violations blocked\n\
             # TYPE agentguard_network_violations_total counter\n\
             agentguard_network_violations_total {}\n\n\
             # HELP agentguard_approvals_prompted_total Total tool calls requiring human approval\n\
             # TYPE agentguard_approvals_prompted_total counter\n\
             agentguard_approvals_prompted_total {}\n\n\
             # HELP agentguard_approvals_granted_total Total tool calls approved by operator\n\
             # TYPE agentguard_approvals_granted_total counter\n\
             agentguard_approvals_granted_total {}\n\n\
             # HELP agentguard_approvals_rejected_total Total tool calls rejected or timed out\n\
             # TYPE agentguard_approvals_rejected_total counter\n\
             agentguard_approvals_rejected_total {}\n\n\
             # HELP agentguard_auth_failures_total Total authentication failures\n\
             # TYPE agentguard_auth_failures_total counter\n\
             agentguard_auth_failures_total {}\n\n\
             # HELP agentguard_rate_limit_rejections_total Total rate limit rejections\n\
             # TYPE agentguard_rate_limit_rejections_total counter\n\
             agentguard_rate_limit_rejections_total {}\n\n\
             # HELP agentguard_total_latency_microseconds Total cumulative latency in microseconds\n\
             # TYPE agentguard_total_latency_microseconds counter\n\
             agentguard_total_latency_microseconds {}\n",
            snap.requests_intercepted,
            snap.redactions_count,
            snap.jail_violations_count,
            snap.policy_violations_count,
            snap.prompt_injections_count,
            snap.network_violations_count,
            snap.approvals_prompted_count,
            snap.approvals_granted_count,
            snap.approvals_rejected_count,
            snap.auth_failures_count,
            snap.rate_limit_rejections,
            snap.total_latency_us
        )
    }
}

pub type SharedMetrics = Arc<MetricsCollector>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new();
        collector.inc_requests();
        collector.inc_redactions();
        collector.inc_jail_violations();
        collector.inc_network_violations();
        collector.inc_approvals_prompted();
        collector.inc_approvals_granted();
        collector.record_latency(150);

        let snap = collector.snapshot();
        assert_eq!(snap.requests_intercepted, 1);
        assert_eq!(snap.redactions_count, 1);
        assert_eq!(snap.jail_violations_count, 1);
        assert_eq!(snap.network_violations_count, 1);
        assert_eq!(snap.approvals_prompted_count, 1);
        assert_eq!(snap.approvals_granted_count, 1);
        assert_eq!(snap.total_latency_us, 150);

        let prom = collector.to_prometheus();
        assert!(prom.contains("agentguard_requests_intercepted_total 1"));
        assert!(prom.contains("agentguard_network_violations_total 1"));
        assert!(prom.contains("agentguard_approvals_prompted_total 1"));
    }
}
