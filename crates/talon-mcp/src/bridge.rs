//! Byte-level relay between one connection (e.g. an accepted
//! `UnixStream`) and a server process's stdio. The privileged supervisor
//! (`talon-agent supervise`) uses this to expose each MCP server, running
//! as its own `mcp-*` user, on `/run/talon/mcp/<server>.sock` for the
//! unprivileged agent. Message framing and limits are enforced by the
//! client on the other end; the relay itself is transparent.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Relay until the session ends:
/// - connection -> `server_stdin` until the connection reaches EOF, then
///   `server_stdin` is closed (the server sees EOF and should exit);
/// - `server_stdout` -> connection until the server closes its stdout,
///   then the connection's write side is shut down.
///
/// Returns when the server's output ends (normally after its stdin was
/// closed). If the server dies first, the connection is closed right away
/// even if the client keeps its side open. Returns the number of bytes
/// relayed `(to_server, to_client)`.
pub async fn bridge<S, W, R>(stream: S, server_stdin: W, server_stdout: R) -> io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let (mut sock_r, mut sock_w) = tokio::io::split(stream);
    let up = async move {
        let mut server_stdin = server_stdin;
        let n = tokio::io::copy(&mut sock_r, &mut server_stdin).await;
        let _ = server_stdin.shutdown().await;
        drop(server_stdin);
        n
    };
    let down = async move {
        let mut server_stdout = server_stdout;
        let n = tokio::io::copy(&mut server_stdout, &mut sock_w).await;
        let _ = sock_w.shutdown().await;
        n
    };
    tokio::pin!(up, down);
    tokio::select! {
        to_client = &mut down => {
            // Server output ended; stop relaying input (dropping `up`
            // closes the server's stdin).
            Ok((0, to_client?))
        }
        to_server = &mut up => {
            let to_server = to_server.unwrap_or(0);
            let to_client = down.await?;
            Ok((to_server, to_client))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    #[tokio::test]
    async fn relays_both_directions_and_propagates_eof() {
        // "socket": client <-> bridge
        let (client, sock) = tokio::io::duplex(1024);
        // server stdin/stdout pipes
        let (stdin_w, mut stdin_r) = tokio::io::duplex(1024);
        let (mut stdout_w, stdout_r) = tokio::io::duplex(1024);
        let relay = tokio::spawn(bridge(sock, stdin_w, stdout_r));

        let (client_r, mut client_w) = tokio::io::split(client);
        client_w.write_all(b"{\"id\":1}\n").await.unwrap();
        let mut buf = vec![0u8; 9];
        stdin_r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"{\"id\":1}\n");

        stdout_w.write_all(b"{\"result\":1}\n").await.unwrap();
        let mut lines = BufReader::new(client_r).lines();
        assert_eq!(lines.next_line().await.unwrap().unwrap(), "{\"result\":1}");

        // Client EOF -> server stdin EOF.
        client_w.shutdown().await.unwrap();
        let mut rest = Vec::new();
        stdin_r.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        // Server exits -> relay finishes, client sees EOF.
        drop(stdout_w);
        let (up, down) = tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!((up, down), (9, 13));
        assert!(lines.next_line().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn server_death_closes_connection_even_if_client_stays() {
        let (client, sock) = tokio::io::duplex(1024);
        let (stdin_w, _stdin_r) = tokio::io::duplex(1024);
        let (stdout_w, stdout_r) = tokio::io::duplex(1024);
        let relay = tokio::spawn(bridge(sock, stdin_w, stdout_r));
        drop(stdout_w);
        let res = tokio::time::timeout(Duration::from_secs(2), relay).await;
        assert!(res.is_ok(), "relay hung after server death");
        let (client_r, _client_w) = tokio::io::split(client);
        let mut lines = BufReader::new(client_r).lines();
        assert!(lines.next_line().await.unwrap().is_none());
    }
}
