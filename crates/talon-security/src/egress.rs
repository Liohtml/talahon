//! Outbound URL policy (SSRF guard) for `web_fetch` and webhooks.
//!
//! Default policy: only `http`/`https`; deny loopback, link-local
//! (169.254.0.0/16 incl. cloud metadata), RFC1918, CGNAT, ULA, multicast,
//! unspecified, `localhost`/`*.internal`/`metadata.google.internal` hostnames,
//! non-default ports unless allowed, userinfo in URL. Hostnames are resolved
//! and *every* resolved address is checked (DNS-rebinding safe callers should
//! connect to the returned addresses).

use std::net::{IpAddr, SocketAddr};

use talon_core::Result;

#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    /// Hosts always allowed (exact or `*.suffix`).
    pub allow_hosts: Vec<String>,
    /// Hosts always denied (exact or `*.suffix`).
    pub deny_hosts: Vec<String>,
    /// Permit private / internal addresses (e.g. for an internal TI server).
    pub allow_private: bool,
}

#[allow(unused_variables, clippy::todo)]
impl EgressPolicy {
    /// Policy from `TALON_EGRESS_ALLOW` / `TALON_EGRESS_DENY` (comma lists)
    /// and `TALON_EGRESS_ALLOW_PRIVATE`.
    pub fn from_env(env: &talon_core::env::EnvFile) -> Self {
        todo!()
    }

    /// Is this IP acceptable as a destination?
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        todo!()
    }

    /// Validate a URL syntactically and by host policy (no DNS).
    pub fn check_url(&self, url: &str) -> Result<url::Url> {
        todo!()
    }

    /// `check_url` + resolve + verify every address. Returns the addresses
    /// the caller should connect to.
    pub async fn resolve_and_check(&self, url: &str) -> Result<(url::Url, Vec<SocketAddr>)> {
        todo!()
    }
}
