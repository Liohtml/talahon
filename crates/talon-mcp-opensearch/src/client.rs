//! Bounded, read-only HTTP client for the OpenSearch REST API.
//!
//! Guarantees, independent of what a tool asks for:
//! - only `GET` and `POST` exist ([`Verb`]); there is no way to send
//!   `PUT`/`DELETE`;
//! - paths are [`RequestPath`]s, and the final URL is checked to still have
//!   exactly that path below the configured base URL;
//! - redirects are not followed (credentials never travel to another URL);
//! - every request has a whole-request timeout and every response body a
//!   size limit that is enforced while streaming, not after buffering;
//! - credentials are attached per request and never logged.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use serde::de::IgnoredAny;
use serde_json::Value;
use url::Url;

use crate::config::{Config, ConfigError, Credentials, host_for_log};
use crate::error::ToolError;
use crate::path::RequestPath;

/// Largest error body that is parsed for its structured `error` reasons.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The HTTP methods this client can send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `GET`.
    Get,
    /// `POST` (search and analyze bodies; both are read-only APIs).
    Post,
}

/// What a successful response body must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A JSON document (validated, returned as received).
    Json,
    /// Plain text (`_cat` APIs).
    Text,
}

/// OpenSearch REST client. Cheap to share behind an `Arc`.
pub struct OpenSearchClient {
    http: reqwest::Client,
    hosts: Vec<Url>,
    credentials: Option<Credentials>,
    max_response_bytes: usize,
    /// Index of the host that answered last; tried first next time.
    preferred: AtomicUsize,
}

impl std::fmt::Debug for OpenSearchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenSearchClient")
            .field(
                "hosts",
                &self.hosts.iter().map(host_for_log).collect::<Vec<_>>(),
            )
            .field("authenticated", &self.credentials.is_some())
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl OpenSearchClient {
    /// Build a client from `config`.
    pub fn new(config: &Config) -> Result<Self, ConfigError> {
        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("talon-opensearch-mcp/", env!("CARGO_PKG_VERSION")))
            .timeout(config.timeout)
            .connect_timeout(config.timeout.min(MAX_CONNECT_TIMEOUT))
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(90));

        builder = match &config.proxy {
            // Like the Python server, only an explicitly configured proxy is
            // used; HTTPS_PROXY & co. from the environment are ignored.
            None => builder.no_proxy(),
            Some(proxy) => {
                builder.proxy(
                    reqwest::Proxy::all(proxy).map_err(|_| ConfigError::Invalid {
                        var: "OPENSEARCH_PROXY",
                        reason: "not a usable proxy URL".into(),
                    })?,
                )
            }
        };

        if let Some(path) = &config.ca_certs {
            let invalid = |reason: &str| ConfigError::Invalid {
                var: "OPENSEARCH_CA_CERTS",
                reason: reason.into(),
            };
            let pem =
                std::fs::read(path).map_err(|e| invalid(&format!("cannot read file: {e}")))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| invalid("not a PEM certificate bundle"))?;
            if certs.is_empty() {
                return Err(invalid("contains no certificate"));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        if !config.verify_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let http = builder.build().map_err(|_| ConfigError::Invalid {
            var: "OPENSEARCH_HOSTS",
            reason: "could not initialise the HTTP client".into(),
        })?;
        Ok(Self {
            http,
            hosts: config.hosts.clone(),
            credentials: config.credentials.clone(),
            max_response_bytes: config.max_response_bytes,
            preferred: AtomicUsize::new(0),
        })
    }

    /// Send one request and return the response body as text.
    ///
    /// Hosts are tried in order, starting with the one that answered last;
    /// only a connection failure moves on to the next host.
    pub async fn request(
        &self,
        verb: Verb,
        path: &RequestPath,
        body: Option<&Value>,
        expect: Expect,
    ) -> Result<String, ToolError> {
        let count = self.hosts.len();
        let start = self.preferred.load(Ordering::Relaxed) % count.max(1);
        let mut last = ToolError::Connection;
        for offset in 0..count {
            let index = (start + offset) % count;
            let url = build_url(&self.hosts[index], path)?;
            match self.send(verb, url, body, expect).await {
                Err(ToolError::Connection) => {
                    tracing::warn!(
                        host = %host_for_log(&self.hosts[index]),
                        "OpenSearch host unreachable"
                    );
                    last = ToolError::Connection;
                }
                other => {
                    self.preferred.store(index, Ordering::Relaxed);
                    return other;
                }
            }
        }
        Err(last)
    }

    async fn send(
        &self,
        verb: Verb,
        url: Url,
        body: Option<&Value>,
        expect: Expect,
    ) -> Result<String, ToolError> {
        let method = match verb {
            Verb::Get => reqwest::Method::GET,
            Verb::Post => reqwest::Method::POST,
        };
        let mut request = self.http.request(method, url).header(
            ACCEPT,
            match expect {
                Expect::Json => "application/json",
                Expect::Text => "text/plain",
            },
        );
        if let Some(creds) = &self.credentials {
            request = request.basic_auth(&creds.username, Some(&creds.password));
        }
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body).map_err(|_| ToolError::Internal)?;
            request = request.header(CONTENT_TYPE, "application/json").body(bytes);
        }

        let mut response = request.send().await.map_err(map_transport_error)?;
        let status = response.status();
        if !status.is_success() {
            let body = read_body(&mut response, MAX_ERROR_BODY_BYTES)
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
            return Err(ToolError::Status {
                status: status.as_u16(),
                body,
            });
        }

        let bytes = read_body(&mut response, self.max_response_bytes).await?;
        let text = String::from_utf8(bytes).map_err(|_| ToolError::InvalidResponse)?;
        if expect == Expect::Json {
            // Validate without building a tree; the text is passed on as
            // received so key order and number formatting stay intact.
            serde_json::from_str::<IgnoredAny>(&text).map_err(|_| ToolError::InvalidResponse)?;
            return Ok(text.trim().to_string());
        }
        Ok(text)
    }
}

/// Read a response body, failing with [`ToolError::TooLarge`] as soon as
/// more than `limit` bytes are announced or received.
async fn read_body(response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>, ToolError> {
    let too_large = ToolError::TooLarge { limit };
    let announced = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if announced.is_some_and(|n| usize::try_from(n).map_or(true, |n| n > limit)) {
        return Err(too_large);
    }
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
        if out.len().saturating_add(chunk.len()) > limit {
            return Err(too_large);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn map_transport_error(e: reqwest::Error) -> ToolError {
    // `reqwest::Error` can carry the URL; it is deliberately not logged.
    // A connect timeout counts as a connection failure, so that a host which
    // silently drops packets does not block fail-over to the next one.
    if e.is_connect() {
        ToolError::Connection
    } else if e.is_timeout() {
        ToolError::Timeout
    } else if e.is_body() || e.is_decode() {
        ToolError::InvalidResponse
    } else if e.is_request() {
        // Connection reset while sending etc.: the request did not go through.
        ToolError::Connection
    } else {
        ToolError::Internal
    }
}

/// `base` + `path`, verified to be exactly that: same origin, no query, no
/// fragment, and a path that the URL parser did not reinterpret.
fn build_url(base: &Url, path: &RequestPath) -> Result<Url, ToolError> {
    let expected = format!("{}{}", base.path().trim_end_matches('/'), path.as_str());
    let mut url = base.clone();
    url.set_path(&expected);
    let unchanged = url.path() == expected
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin() == base.origin();
    if !unchanged {
        return Err(ToolError::InvalidArgument(
            "value cannot be used in a request path".into(),
        ));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::Segment;

    fn base(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn urls_keep_the_base_prefix_and_encoded_segments() {
        let idx = Segment::index("we ird/../x?y#z%41").unwrap();
        let path = RequestPath::from_segment(&idx).word("_search");
        let url = build_url(&base("https://os.example:9200/prefix"), &path).unwrap();
        assert_eq!(
            url.as_str(),
            "https://os.example:9200/prefix/we%20ird%2F..%2Fx%3Fy%23z%2541/_search"
        );
        let url = build_url(
            &base("https://os.example:9200/"),
            &RequestPath::fixed(&["_cat", "indices"]),
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://os.example:9200/_cat/indices");
    }

    #[test]
    fn doc_ids_cannot_leave_their_segment() {
        let idx = Segment::index("idx").unwrap();
        for raw in [
            "../../_cluster/settings",
            "a?pretty",
            "a#frag",
            "%2e%2e",
            "a\\b",
            "@evil.example",
            "//evil.example/x",
        ] {
            let id = Segment::doc_id(raw).unwrap();
            let path = RequestPath::from_segment(&idx).word("_doc").segment(&id);
            let url = build_url(&base("https://os.example:9200"), &path).unwrap();
            assert_eq!(url.host_str(), Some("os.example"), "{raw}");
            assert_eq!(
                url.path_segments().map(Iterator::count),
                Some(3),
                "{raw}: {url}"
            );
            assert!(url.path().starts_with("/idx/_doc/"), "{raw}: {url}");
            assert!(url.query().is_none() && url.fragment().is_none(), "{raw}");
        }
    }
}
