//! The MCP tools: the read-only subset of `opensearch-mcp-server` 2.1.9.
//!
//! Tool names, argument names and input schemas are those the Python server
//! advertises in `tools/list`, so prompts and the anonymizing proxy work
//! with either server. Write tools (`create_index`, `delete_index`,
//! `index_document`, `delete_document`, `delete_by_query`, `put_alias`,
//! `delete_alias`, `create_data_stream`, `delete_data_stream`) and the
//! free-form `general_api_request` are deliberately not offered.
//!
//! | Tool | Request |
//! |---|---|
//! | `list_indices` | `GET /_cat/indices` |
//! | `get_index` | `GET /{index}` |
//! | `search_documents` | `POST /{index}/_search` |
//! | `get_document` | `GET /{index}/_doc/{id}` |
//! | `get_cluster_health` | `GET /_cluster/health` |
//! | `get_cluster_stats` | `GET /_cluster/stats` |
//! | `list_aliases` | `GET /_cat/aliases` |
//! | `get_alias` | `GET /{index}/_alias` |
//! | `get_data_stream` | `GET /_data_stream[/{name}]` |
//! | `analyze_text` | `POST [/{index}]/_analyze` |

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};

use crate::client::{Expect, OpenSearchClient, Verb};
use crate::error::ToolError;
use crate::path::{RequestPath, Segment};

/// Names of the served tools, in `tools/list` order.
pub const TOOL_NAMES: [&str; 10] = [
    "list_indices",
    "get_index",
    "search_documents",
    "get_document",
    "get_cluster_health",
    "get_cluster_stats",
    "list_aliases",
    "get_alias",
    "get_data_stream",
    "analyze_text",
];

/// The only cluster name this server knows (the Python server's name for
/// the single cluster configured through `OPENSEARCH_HOSTS`).
pub const DEFAULT_CLUSTER: &str = "default";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    ListIndices,
    GetIndex,
    SearchDocuments,
    GetDocument,
    GetClusterHealth,
    GetClusterStats,
    ListAliases,
    GetAlias,
    GetDataStream,
    AnalyzeText,
}

const KINDS: [Kind; 10] = [
    Kind::ListIndices,
    Kind::GetIndex,
    Kind::SearchDocuments,
    Kind::GetDocument,
    Kind::GetClusterHealth,
    Kind::GetClusterStats,
    Kind::ListAliases,
    Kind::GetAlias,
    Kind::GetDataStream,
    Kind::AnalyzeText,
];

/// One OpenSearch tool bound to a client.
pub struct OpenSearchTool {
    kind: Kind,
    client: Arc<OpenSearchClient>,
}

impl std::fmt::Debug for OpenSearchTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenSearchTool")
            .field("name", &self.kind.name())
            .finish()
    }
}

/// All tools, in `tools/list` order, sharing `client`.
pub fn all_tools(client: Arc<OpenSearchClient>) -> Vec<Arc<dyn Tool>> {
    KINDS
        .iter()
        .map(|&kind| {
            Arc::new(OpenSearchTool {
                kind,
                client: Arc::clone(&client),
            }) as Arc<dyn Tool>
        })
        .collect()
}

// --- schemas (as advertised by opensearch-mcp-server 2.1.9) ---------------

fn nullable(inner: Value, description: &str) -> Value {
    json!({
        "anyOf": [inner, {"type": "null"}],
        "default": null,
        "description": description,
    })
}

fn string(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn string_list() -> Value {
    json!({"type": "array", "items": {"type": "string"}})
}

fn schema(properties: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let mut props = Map::new();
    for (name, value) in properties {
        props.insert(name.to_string(), value);
    }
    props.insert(
        "cluster".to_string(),
        nullable(
            json!({"type": "string"}),
            "Optional cluster name. Uses the default cluster if omitted.",
        ),
    );
    let mut schema = json!({
        "type": "object",
        "properties": props,
        "additionalProperties": false,
    });
    if !required.is_empty() {
        schema["required"] = json!(required);
    }
    schema
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::ListIndices => "list_indices",
            Self::GetIndex => "get_index",
            Self::SearchDocuments => "search_documents",
            Self::GetDocument => "get_document",
            Self::GetClusterHealth => "get_cluster_health",
            Self::GetClusterStats => "get_cluster_stats",
            Self::ListAliases => "list_aliases",
            Self::GetAlias => "get_alias",
            Self::GetDataStream => "get_data_stream",
            Self::AnalyzeText => "analyze_text",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::ListIndices => "List all indices.",
            Self::GetIndex => {
                "Returns information (mappings, settings, aliases) about one or more indices."
            }
            Self::SearchDocuments => "Search for documents.",
            Self::GetDocument => "Get a document by ID.",
            Self::GetClusterHealth => "Returns basic information about the health of the cluster.",
            Self::GetClusterStats => "Returns high-level overview of cluster statistics.",
            Self::ListAliases => "List all aliases.",
            Self::GetAlias => "Get alias information for a specific index.",
            Self::GetDataStream => {
                "Get information about one or more data streams.\n\n\
                 Retrieves configuration, mappings, settings, and other information\n\
                 about the specified data streams."
            }
            Self::AnalyzeText => {
                "Analyze text to see how it would be tokenized.\n\n\
                 Use this tool to understand how OpenSearch tokenizes and\n\
                 transforms text using analyzers. This is essential for debugging search\n\
                 queries and understanding why certain documents match or don't match."
            }
        }
    }

    fn parameters(self) -> Value {
        let index = || ("index", string("Name of the index"));
        match self {
            Self::ListIndices
            | Self::GetClusterHealth
            | Self::GetClusterStats
            | Self::ListAliases => schema(vec![], &[]),
            Self::GetIndex | Self::GetAlias => schema(vec![index()], &["index"]),
            Self::SearchDocuments => schema(
                vec![
                    index(),
                    (
                        "body",
                        json!({
                            "type": "object",
                            "additionalProperties": true,
                            "description": "Search query",
                        }),
                    ),
                ],
                &["index", "body"],
            ),
            Self::GetDocument => schema(
                vec![index(), ("id", string("Document ID"))],
                &["index", "id"],
            ),
            Self::GetDataStream => schema(
                vec![(
                    "name",
                    nullable(
                        json!({"type": "string"}),
                        "Name of the data stream(s) to retrieve.\n  \
                         Can be a comma-separated list or wildcard pattern.\n  \
                         If not provided, retrieves all data streams.",
                    ),
                )],
                &[],
            ),
            Self::AnalyzeText => schema(
                vec![
                    ("text", string("The text to analyze")),
                    (
                        "index",
                        nullable(
                            json!({"type": "string"}),
                            "Index name to use its configured analyzer. If not specified,\n   \
                             uses cluster-level analysis with built-in analyzers only.",
                        ),
                    ),
                    (
                        "analyzer",
                        nullable(
                            json!({"type": "string"}),
                            "Name of the analyzer to use (e.g., 'standard'). If index is \
                             specified, you can use\n     custom analyzers defined in that index.",
                        ),
                    ),
                    (
                        "tokenizer",
                        nullable(
                            json!({"type": "string"}),
                            "Tokenizer to use for custom analysis chain. Cannot be\n      \
                             used together with 'analyzer'.",
                        ),
                    ),
                    (
                        "filter",
                        nullable(
                            string_list(),
                            "List of token filters to apply (e.g., ['lowercase', 'stop']).\n   \
                             Used with 'tokenizer' for custom analysis chain.",
                        ),
                    ),
                    (
                        "char_filter",
                        nullable(
                            string_list(),
                            "List of character filters to apply before tokenization.\n        \
                             Used with 'tokenizer' for custom analysis chain.",
                        ),
                    ),
                    (
                        "explain",
                        json!({
                            "type": "boolean",
                            "default": false,
                            "description": "If True, returns detailed information about each token\n    \
                                            including all token attributes and filter transformations.\n    \
                                            Useful for debugging complex analyzer chains.",
                        }),
                    ),
                    (
                        "attributes",
                        nullable(
                            string_list(),
                            "List of token attributes to return when explain=True\n       \
                             (e.g., ['keyword', 'type']). If not specified, all\n       \
                             attributes are returned.",
                        ),
                    ),
                ],
                &["text"],
            ),
        }
    }
}

// --- argument access ------------------------------------------------------

/// Typed access to a `tools/call` argument object. Unknown arguments are
/// rejected (the schemas say `additionalProperties: false`).
struct Args<'a> {
    map: &'a Map<String, Value>,
}

fn invalid(message: impl Into<String>) -> ToolError {
    ToolError::InvalidArgument(message.into())
}

impl<'a> Args<'a> {
    fn new(args: &'a Value, allowed: &[&str]) -> Result<Self, ToolError> {
        let map = args
            .as_object()
            .ok_or_else(|| invalid("arguments must be an object"))?;
        if let Some(unknown) = map
            .keys()
            .find(|k| *k != "cluster" && !allowed.contains(&k.as_str()))
        {
            // The name is model-supplied: bound it before echoing it back.
            let shown: String = unknown.chars().take(64).collect();
            return Err(invalid(format!("unexpected argument '{shown}'")));
        }
        let args = Self { map };
        match args.opt_str("cluster")? {
            None => Ok(args),
            Some(DEFAULT_CLUSTER) => Ok(args),
            Some(other) => Err(ToolError::UnknownCluster(other.chars().take(64).collect())),
        }
    }

    /// The value of `name`; absent and `null` are both "not given".
    fn get(&self, name: &str) -> Option<&'a Value> {
        self.map.get(name).filter(|v| !v.is_null())
    }

    fn opt_str(&self, name: &str) -> Result<Option<&'a str>, ToolError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(invalid(format!("'{name}' must be a string"))),
        }
    }

    fn req_str(&self, name: &str) -> Result<&'a str, ToolError> {
        self.opt_str(name)?
            .ok_or_else(|| invalid(format!("missing required argument '{name}'")))
    }

    fn opt_bool(&self, name: &str) -> Result<bool, ToolError> {
        match self.get(name) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(invalid(format!("'{name}' must be a boolean"))),
        }
    }

    fn opt_str_list(&self, name: &str) -> Result<Option<&'a Vec<Value>>, ToolError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Array(items)) if items.iter().all(Value::is_string) => Ok(Some(items)),
            Some(_) => Err(invalid(format!("'{name}' must be a list of strings"))),
        }
    }

    /// A required JSON object. Models regularly send objects as a
    /// JSON-encoded string; that form is accepted too.
    fn req_object(&self, name: &str) -> Result<Value, ToolError> {
        match self.get(name) {
            None => Err(invalid(format!("missing required argument '{name}'"))),
            Some(v @ Value::Object(_)) => Ok(v.clone()),
            Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
                Ok(v @ Value::Object(_)) => Ok(v),
                _ => Err(invalid(format!("'{name}' must be a JSON object"))),
            },
            Some(_) => Err(invalid(format!("'{name}' must be a JSON object"))),
        }
    }
}

// --- execution ------------------------------------------------------------

impl OpenSearchTool {
    async fn run(&self, args: &Value) -> Result<String, ToolError> {
        let client = &self.client;
        match self.kind {
            Kind::ListIndices => {
                Args::new(args, &[])?;
                let path = RequestPath::fixed(&["_cat", "indices"]);
                client.request(Verb::Get, &path, None, Expect::Text).await
            }
            Kind::ListAliases => {
                Args::new(args, &[])?;
                let path = RequestPath::fixed(&["_cat", "aliases"]);
                client.request(Verb::Get, &path, None, Expect::Text).await
            }
            Kind::GetClusterHealth => {
                Args::new(args, &[])?;
                let path = RequestPath::fixed(&["_cluster", "health"]);
                client.request(Verb::Get, &path, None, Expect::Json).await
            }
            Kind::GetClusterStats => {
                Args::new(args, &[])?;
                let path = RequestPath::fixed(&["_cluster", "stats"]);
                client.request(Verb::Get, &path, None, Expect::Json).await
            }
            Kind::GetIndex => {
                let a = Args::new(args, &["index"])?;
                let index = Segment::index(a.req_str("index")?)?;
                let path = RequestPath::from_segment(&index);
                client.request(Verb::Get, &path, None, Expect::Json).await
            }
            Kind::GetAlias => {
                let a = Args::new(args, &["index"])?;
                let index = Segment::index(a.req_str("index")?)?;
                let path = RequestPath::from_segment(&index).word("_alias");
                client.request(Verb::Get, &path, None, Expect::Json).await
            }
            Kind::SearchDocuments => {
                let a = Args::new(args, &["index", "body"])?;
                let index = Segment::index(a.req_str("index")?)?;
                let body = a.req_object("body")?;
                let path = RequestPath::from_segment(&index).word("_search");
                client
                    .request(Verb::Post, &path, Some(&body), Expect::Json)
                    .await
            }
            Kind::GetDocument => {
                let a = Args::new(args, &["index", "id"])?;
                let index = Segment::index(a.req_str("index")?)?;
                let id = Segment::doc_id(a.req_str("id")?)?;
                let path = RequestPath::from_segment(&index).word("_doc").segment(&id);
                client.request(Verb::Get, &path, None, Expect::Json).await
            }
            Kind::GetDataStream => {
                let a = Args::new(args, &["name"])?;
                let mut path = RequestPath::fixed(&["_data_stream"]);
                // Like the Python server, an empty name means "all".
                if let Some(name) = a.opt_str("name")?.filter(|n| !n.is_empty()) {
                    path = path.segment(&Segment::data_stream(name)?);
                }
                client.request(Verb::Get, &path, None, Expect::Json).await
            }
            Kind::AnalyzeText => {
                let a = Args::new(
                    args,
                    &[
                        "text",
                        "index",
                        "analyzer",
                        "tokenizer",
                        "filter",
                        "char_filter",
                        "explain",
                        "attributes",
                    ],
                )?;
                // Same body the Python client builds: empty options are left out.
                let mut body = Map::new();
                body.insert("text".into(), json!(a.req_str("text")?));
                for key in ["analyzer", "tokenizer"] {
                    if let Some(v) = a.opt_str(key)?.filter(|v| !v.is_empty()) {
                        body.insert(key.into(), json!(v));
                    }
                }
                for key in ["filter", "char_filter"] {
                    if let Some(v) = a.opt_str_list(key)?.filter(|v| !v.is_empty()) {
                        body.insert(key.into(), json!(v));
                    }
                }
                if a.opt_bool("explain")? {
                    body.insert("explain".into(), json!(true));
                }
                if let Some(v) = a.opt_str_list("attributes")?.filter(|v| !v.is_empty()) {
                    body.insert("attributes".into(), json!(v));
                }
                let path = match a.opt_str("index")?.filter(|i| !i.is_empty()) {
                    Some(index) => RequestPath::from_segment(&Segment::index(index)?),
                    None => RequestPath::fixed(&[]),
                }
                .word("_analyze");
                let body = Value::Object(body);
                client
                    .request(Verb::Post, &path, Some(&body), Expect::Json)
                    .await
            }
        }
    }
}

#[async_trait]
impl Tool for OpenSearchTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.kind.name().to_string(),
            description: self.kind.description().to_string(),
            parameters: self.kind.parameters(),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        let name = self.kind.name();
        match self.run(&args).await {
            Ok(text) => ToolOutput::ok(text),
            Err(e) => {
                tracing::warn!("{}", e.log_line(name));
                ToolOutput::err(e.caller_message(name))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_kinds_agree() {
        let names: Vec<&str> = KINDS.iter().map(|k| k.name()).collect();
        assert_eq!(names, TOOL_NAMES);
    }

    #[test]
    fn schemas_have_the_python_shape() {
        for kind in KINDS {
            let s = kind.parameters();
            assert_eq!(s["type"], "object", "{}", kind.name());
            assert_eq!(s["additionalProperties"], false);
            assert_eq!(
                s["properties"]["cluster"]["anyOf"],
                json!([{"type": "string"}, {"type": "null"}])
            );
            for required in s["required"].as_array().into_iter().flatten() {
                let name = required.as_str().unwrap();
                assert!(s["properties"].get(name).is_some(), "{name}");
            }
        }
        assert_eq!(
            Kind::SearchDocuments.parameters()["required"],
            json!(["index", "body"])
        );
        assert_eq!(
            Kind::GetDocument.parameters()["required"],
            json!(["index", "id"])
        );
        assert_eq!(Kind::AnalyzeText.parameters()["required"], json!(["text"]));
        assert!(Kind::ListIndices.parameters().get("required").is_none());
        assert!(Kind::GetDataStream.parameters().get("required").is_none());
    }

    #[test]
    fn args_reject_unknown_names_and_clusters() {
        let v = json!({"index": "x", "bogus": 1});
        assert!(matches!(
            Args::new(&v, &["index"]),
            Err(ToolError::InvalidArgument(m)) if m == "unexpected argument 'bogus'"
        ));
        let v = json!({"cluster": "other"});
        assert!(matches!(
            Args::new(&v, &[]),
            Err(ToolError::UnknownCluster(c)) if c == "other"
        ));
        for ok in [
            json!({}),
            json!({"cluster": null}),
            json!({"cluster": "default"}),
        ] {
            assert!(Args::new(&ok, &[]).is_ok(), "{ok}");
        }
        assert!(Args::new(&json!({"cluster": 1}), &[]).is_err());
    }

    #[test]
    fn object_arguments_may_be_json_strings() {
        let v = json!({"body": "{\"size\": 2}", "n": 5, "s": "[1]", "bad": "not json"});
        let a = Args::new(&v, &["body", "n", "s", "bad"]).unwrap();
        assert_eq!(a.req_object("body").unwrap(), json!({"size": 2}));
        for name in ["n", "s", "bad", "missing"] {
            assert!(a.req_object(name).is_err(), "{name}");
        }
    }
}
