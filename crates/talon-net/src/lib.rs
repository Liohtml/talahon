//! # talon-net — hardened HTTP serving
//!
//! `axum::serve` applies no header-read timeout and no connection cap, so a
//! client that opens many connections and never finishes its request headers
//! (slowloris) can exhaust the host's file descriptors and stall every lane,
//! IPC, SQLite and container spawns. [`serve`] replaces it for every Talon
//! listener (CoPilot HTTP API, LLM gateway, Emacs bridge) with:
//!
//! - HTTP/1.1 only, with a header-read timeout that also bounds idle
//!   keep-alive connections (HTTP/2 prior-knowledge connections could be held
//!   open without ever sending a request),
//! - a global connection cap and a per-peer-IP connection cap (excess
//!   connections are closed immediately, before any parsing),
//! - `ConnectInfo<SocketAddr>` in request extensions, so handlers can keep
//!   using axum's `ConnectInfo` extractor,
//! - accept-error back-off (e.g. `EMFILE`) instead of a hot loop,
//! - graceful shutdown on a [`CancellationToken`], bounded by a grace period.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

/// Connection limits for [`serve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    /// Maximum simultaneously open connections.
    pub max_connections: usize,
    /// Maximum simultaneously open connections from one peer IP.
    pub max_connections_per_ip: usize,
    /// Time a client has to send complete HTTP/1 request headers.
    pub header_read_timeout: Duration,
    /// Unused since HTTP/2 is disabled (kept for API compatibility).
    pub http2_keep_alive_interval: Duration,
    /// How long in-flight connections may drain after shutdown starts.
    pub shutdown_grace: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            max_connections_per_ip: 64,
            header_read_timeout: Duration::from_secs(15),
            http2_keep_alive_interval: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// Tracks open connections per peer IP.
#[derive(Debug, Default)]
struct PeerCounts(Mutex<HashMap<IpAddr, usize>>);

impl PeerCounts {
    fn try_acquire(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<PeerGuard> {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(PeerGuard {
            counts: Arc::clone(self),
            ip,
        })
    }
}

/// Releases one per-IP slot on drop.
struct PeerGuard {
    counts: Arc<PeerCounts>,
    ip: IpAddr,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut map = self.counts.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Serve `router` on `listener` until `shutdown` is cancelled.
///
/// Returns once the listener has stopped and open connections have drained
/// (or the grace period elapsed).
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: ServerLimits,
    shutdown: CancellationToken,
) {
    let global = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let peers = Arc::new(PeerCounts::default());
    let graceful = GracefulShutdown::new();
    // Connection tasks are tracked so they can be aborted when the grace
    // period runs out (long-lived SSE streams would otherwise outlive the
    // server).
    let mut connections = tokio::task::JoinSet::new();

    // HTTP/1.1 only (hyper's plain HTTP/1 server, which never switches to
    // HTTP/2 on a prior-knowledge preface). HTTP/2 connections have no
    // header-read timeout: a client that sends the preface and answers PINGs
    // but never opens a stream would hold a connection slot forever. Every
    // Talon client (CoPilot, the agent's gateway client, Emacs) speaks
    // HTTP/1.1; SSE works over it.
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .keep_alive(true);
    let builder = Arc::new(builder);

    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => break,
            res = listener.accept() => res,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                // EMFILE/ENFILE and friends: back off instead of spinning.
                tracing::warn!(error = %e, "accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(global_permit) = Arc::clone(&global).try_acquire_owned() else {
            tracing::warn!(%peer, "connection limit reached; closing connection");
            drop(stream);
            continue;
        };
        let Some(peer_guard) = peers.try_acquire(peer.ip(), limits.max_connections_per_ip.max(1))
        else {
            tracing::warn!(%peer, "per-IP connection limit reached; closing connection");
            drop(stream);
            continue;
        };
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(error = %e, "set_nodelay failed");
        }

        let svc = router
            .clone()
            .map_request(move |mut req: http::Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                req
            });
        let hyper_svc = TowerToHyperService::new(svc);
        let conn = builder.serve_connection(TokioIo::new(stream), hyper_svc);
        let conn = graceful.watch(conn);
        // Reap finished connections so the set stays small.
        while connections.try_join_next().is_some() {}
        connections.spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(%peer, error = %e, "connection ended with error");
            }
            drop(peer_guard);
            drop(global_permit);
        });
    }

    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(limits.shutdown_grace) => {
            tracing::warn!("graceful shutdown timed out; dropping open connections");
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

/// Convenience: bind `addr`, spawn [`serve`] on it and return the bound
/// address (useful with port 0).
pub async fn bind_and_serve(
    addr: SocketAddr,
    router: Router,
    limits: ServerLimits,
    shutdown: CancellationToken,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(serve(listener, router, limits, shutdown));
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn peer_ip(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
        addr.ip().to_string()
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/ip", get(peer_ip))
    }

    async fn start(limits: ServerLimits) -> (SocketAddr, CancellationToken) {
        let token = CancellationToken::new();
        let addr = bind_and_serve("127.0.0.1:0".parse().unwrap(), app(), limits, token.clone())
            .await
            .unwrap();
        (addr, token)
    }

    #[tokio::test]
    async fn serves_requests_with_connect_info() {
        let (addr, token) = start(ServerLimits::default()).await;
        let body = reqwest::get(format!("http://{addr}/ip"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "127.0.0.1");
        token.cancel();
    }

    #[tokio::test]
    async fn slow_headers_are_cut_off() {
        let (addr, token) = start(ServerLimits {
            header_read_timeout: Duration::from_millis(300),
            ..ServerLimits::default()
        })
        .await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
        assert!(
            read.is_ok(),
            "server must close a connection with incomplete headers"
        );
        token.cancel();
    }

    #[tokio::test]
    async fn http2_prior_knowledge_is_not_served() {
        let (addr, token) = start(ServerLimits {
            header_read_timeout: Duration::from_millis(300),
            ..ServerLimits::default()
        })
        .await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        // HTTP/2 connection preface followed by an empty SETTINGS frame.
        s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
        assert!(
            !buf.starts_with(&[0, 0]),
            "server must not answer with HTTP/2 frames"
        );
        assert!(
            read.is_ok(),
            "an h2 preface must not keep the connection open"
        );
        token.cancel();
    }

    #[tokio::test]
    async fn idle_keep_alive_connections_are_closed() {
        let (addr, token) = start(ServerLimits {
            header_read_timeout: Duration::from_millis(300),
            ..ServerLimits::default()
        })
        .await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = s.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
        // Stay idle on the kept-alive connection: the server must close it.
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest)).await;
        assert!(read.is_ok(), "idle keep-alive connection must be closed");
        token.cancel();
    }

    #[tokio::test]
    async fn per_ip_cap_closes_excess_connections() {
        let (addr, token) = start(ServerLimits {
            max_connections_per_ip: 2,
            header_read_timeout: Duration::from_secs(30),
            ..ServerLimits::default()
        })
        .await;
        let _a = TcpStream::connect(addr).await.unwrap();
        let _b = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
            .await
            .expect("excess connection must be closed promptly")
            .unwrap_or(0);
        assert_eq!(n, 0);
        token.cancel();
    }

    #[tokio::test]
    async fn connections_outliving_the_grace_period_are_aborted() {
        let token = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/hang",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                "never"
            }),
        );
        let server = tokio::spawn(serve(
            listener,
            app,
            ServerLimits {
                shutdown_grace: Duration::from_millis(200),
                ..ServerLimits::default()
            },
            token.clone(),
        ));
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /hang HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        token.cancel();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve must return after the grace period")
            .unwrap();
        let mut buf = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
            .await
            .expect("hanging connection must be closed")
            .unwrap_or(0);
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn shutdown_stops_accepting() {
        let (addr, token) = start(ServerLimits::default()).await;
        token.cancel();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(reqwest::get(format!("http://{addr}/")).await.is_err());
    }
}
