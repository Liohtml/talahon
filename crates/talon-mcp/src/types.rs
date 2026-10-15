//! MCP protocol types (spec 2025-06-18) — only the parts Talon needs:
//! lifecycle, tools, and tool results. Deserialization is lenient: unknown
//! fields are ignored and malformed optional members degrade to `None`
//! instead of failing the whole message.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

/// The protocol revision this crate implements and requests first.
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// Protocol revisions this crate accepts, newest first. The older revisions
/// are wire-compatible for everything Talon uses (tools only).
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// True if `version` is one of [`SUPPORTED_PROTOCOL_VERSIONS`].
pub fn is_supported_protocol_version(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// Deserialize an optional value, mapping type errors to `None`.
fn lenient<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let v = Option::<Value>::deserialize(d)?;
    Ok(v.and_then(|v| serde_json::from_value(v).ok()))
}

/// `null`/garbage -> `false`.
fn lenient_bool<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Value>::deserialize(d)?
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// Name/version of a client or server (`clientInfo` / `serverInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Implementation {
    /// Programmatic name.
    #[serde(default)]
    pub name: String,
    /// Version string.
    #[serde(default)]
    pub version: String,
    /// Optional human readable title.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub title: Option<String>,
}

impl Implementation {
    /// Construct from name and version.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            title: None,
        }
    }
}

/// Capabilities a server declares. Kept as raw JSON so unknown shapes never
/// break initialization; use the helper methods.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    /// `tools` capability (`{"listChanged": bool}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    /// `logging` capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
    /// `prompts` capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Value>,
    /// `resources` capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Value>,
    /// `completions` capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completions: Option<Value>,
    /// Experimental capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

impl ServerCapabilities {
    /// Whether the server declared the `tools` capability.
    pub fn has_tools(&self) -> bool {
        self.tools.as_ref().is_some_and(|v| !v.is_null())
    }

    /// Whether the server will send `notifications/tools/list_changed`.
    pub fn tools_list_changed(&self) -> bool {
        self.tools
            .as_ref()
            .and_then(|t| t.get("listChanged"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
}

/// Result of `initialize`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// Negotiated protocol revision.
    pub protocol_version: String,
    /// Server capabilities.
    #[serde(default, deserialize_with = "lenient_caps")]
    pub capabilities: ServerCapabilities,
    /// Server name/version.
    #[serde(default, deserialize_with = "lenient_impl")]
    pub server_info: Implementation,
    /// Optional usage instructions (untrusted text!).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub instructions: Option<String>,
}

fn lenient_caps<'de, D: Deserializer<'de>>(d: D) -> Result<ServerCapabilities, D::Error> {
    Ok(lenient::<D, ServerCapabilities>(d)?.unwrap_or_default())
}

fn lenient_impl<'de, D: Deserializer<'de>>(d: D) -> Result<Implementation, D::Error> {
    Ok(lenient::<D, Implementation>(d)?.unwrap_or_default())
}

/// Behavioural hints about a tool. **Untrusted** — servers may lie.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Display title.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub title: Option<String>,
    /// Tool does not modify its environment.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub read_only_hint: Option<bool>,
    /// Tool may perform destructive updates.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub destructive_hint: Option<bool>,
    /// Repeated calls with the same args have no additional effect.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub idempotent_hint: Option<bool>,
    /// Tool interacts with an open world of external entities.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub open_world_hint: Option<bool>,
}

fn default_input_schema() -> Value {
    json!({ "type": "object", "properties": {} })
}

fn lenient_schema<'de, D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    Ok(Option::<Value>::deserialize(d)?
        .filter(Value::is_object)
        .unwrap_or_else(default_input_schema))
}

/// A tool advertised by a server in `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    /// Unique tool name on that server.
    pub name: String,
    /// Optional display title.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub title: Option<String>,
    /// Description shown to the model (untrusted text!).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub description: Option<String>,
    /// JSON Schema for the arguments (always an object; defaults to an
    /// empty object schema when missing or malformed).
    #[serde(default = "default_input_schema", deserialize_with = "lenient_schema")]
    pub input_schema: Value,
    /// Optional JSON Schema of `structuredContent`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub output_schema: Option<Value>,
    /// Optional hints.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub annotations: Option<ToolAnnotations>,
    /// Protocol `_meta`.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

impl McpTool {
    /// Minimal tool with a name, description and input schema.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: Some(description.into()),
            input_schema,
            output_schema: None,
            annotations: None,
            meta: None,
        }
    }

    /// `annotations.readOnlyHint == true`.
    pub fn is_read_only(&self) -> bool {
        self.annotations
            .as_ref()
            .and_then(|a| a.read_only_hint)
            .unwrap_or(false)
    }

    /// Title, annotation title or name.
    pub fn display_title(&self) -> &str {
        self.title
            .as_deref()
            .or_else(|| self.annotations.as_ref().and_then(|a| a.title.as_deref()))
            .unwrap_or(&self.name)
    }
}

/// One item of a tool result's `content` array.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentBlock {
    /// `{"type":"text","text":..}`
    Text {
        /// The text.
        text: String,
    },
    /// `{"type":"image","data":<base64>,"mimeType":..}`
    Image {
        /// Base64 data.
        data: String,
        /// MIME type.
        mime_type: String,
    },
    /// `{"type":"audio","data":<base64>,"mimeType":..}`
    Audio {
        /// Base64 data.
        data: String,
        /// MIME type.
        mime_type: String,
    },
    /// `{"type":"resource_link","uri":..,"name":..}`
    ResourceLink {
        /// Resource URI.
        uri: String,
        /// Resource name.
        name: String,
        /// Optional description.
        description: Option<String>,
        /// Optional MIME type.
        mime_type: Option<String>,
    },
    /// `{"type":"resource","resource":{"uri":..,"text"|"blob":..}}`
    Resource {
        /// Resource URI.
        uri: String,
        /// Optional MIME type.
        mime_type: Option<String>,
        /// Text contents (text resources).
        text: Option<String>,
        /// Base64 contents (binary resources).
        blob: Option<String>,
    },
    /// Anything else (kept verbatim).
    Other(Value),
}

impl ContentBlock {
    /// A text block.
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Classify a raw JSON content item. Never fails: unknown or malformed
    /// items become [`ContentBlock::Other`].
    pub fn from_value(v: Value) -> Self {
        fn s(v: &Value, k: &str) -> Option<String> {
            v.get(k).and_then(Value::as_str).map(str::to_string)
        }
        let kind = v.get("type").and_then(Value::as_str).unwrap_or_default();
        let parsed = match kind {
            "text" => s(&v, "text").map(|text| Self::Text { text }),
            "image" | "audio" => match (s(&v, "data"), s(&v, "mimeType")) {
                (Some(data), mime) => {
                    let mime_type = mime.unwrap_or_else(|| "application/octet-stream".into());
                    Some(if kind == "image" {
                        Self::Image { data, mime_type }
                    } else {
                        Self::Audio { data, mime_type }
                    })
                }
                _ => None,
            },
            "resource_link" => s(&v, "uri").map(|uri| Self::ResourceLink {
                name: s(&v, "name").unwrap_or_else(|| uri.clone()),
                uri,
                description: s(&v, "description"),
                mime_type: s(&v, "mimeType"),
            }),
            "resource" => v.get("resource").and_then(|r| {
                s(r, "uri").map(|uri| Self::Resource {
                    uri,
                    mime_type: s(r, "mimeType"),
                    text: s(r, "text"),
                    blob: s(r, "blob"),
                })
            }),
            _ => None,
        };
        parsed.unwrap_or(Self::Other(v))
    }

    /// JSON representation.
    pub fn to_value(&self) -> Value {
        match self {
            Self::Text { text } => json!({ "type": "text", "text": text }),
            Self::Image { data, mime_type } => {
                json!({ "type": "image", "data": data, "mimeType": mime_type })
            }
            Self::Audio { data, mime_type } => {
                json!({ "type": "audio", "data": data, "mimeType": mime_type })
            }
            Self::ResourceLink {
                uri,
                name,
                description,
                mime_type,
            } => {
                let mut m = Map::new();
                m.insert("type".into(), json!("resource_link"));
                m.insert("uri".into(), json!(uri));
                m.insert("name".into(), json!(name));
                if let Some(d) = description {
                    m.insert("description".into(), json!(d));
                }
                if let Some(t) = mime_type {
                    m.insert("mimeType".into(), json!(t));
                }
                Value::Object(m)
            }
            Self::Resource {
                uri,
                mime_type,
                text,
                blob,
            } => {
                let mut r = Map::new();
                r.insert("uri".into(), json!(uri));
                if let Some(t) = mime_type {
                    r.insert("mimeType".into(), json!(t));
                }
                if let Some(t) = text {
                    r.insert("text".into(), json!(t));
                }
                if let Some(b) = blob {
                    r.insert("blob".into(), json!(b));
                }
                json!({ "type": "resource", "resource": Value::Object(r) })
            }
            Self::Other(v) => v.clone(),
        }
    }

    /// Text rendering for the model: text verbatim, binary payloads
    /// replaced by a short placeholder.
    pub fn render(&self) -> String {
        match self {
            Self::Text { text } => text.clone(),
            Self::Image { data, mime_type } => format!(
                "[image content omitted: {mime_type}, ~{} bytes]",
                base64_decoded_len(data)
            ),
            Self::Audio { data, mime_type } => format!(
                "[audio content omitted: {mime_type}, ~{} bytes]",
                base64_decoded_len(data)
            ),
            Self::ResourceLink {
                uri,
                name,
                description,
                mime_type,
            } => {
                let mut s = format!("[resource link: {name} <{uri}>");
                if let Some(m) = mime_type {
                    s.push_str(&format!(" ({m})"));
                }
                if let Some(d) = description {
                    s.push_str(&format!(" - {d}"));
                }
                s.push(']');
                s
            }
            Self::Resource {
                uri,
                mime_type,
                text,
                blob,
            } => match (text, blob) {
                (Some(text), _) => format!("[resource {uri}]\n{text}"),
                (None, Some(blob)) => format!(
                    "[binary resource omitted: {uri} ({}), ~{} bytes]",
                    mime_type.as_deref().unwrap_or("application/octet-stream"),
                    base64_decoded_len(blob)
                ),
                (None, None) => format!("[empty resource {uri}]"),
            },
            Self::Other(v) => {
                let kind = v.get("type").and_then(Value::as_str).unwrap_or("unknown");
                format!("[unsupported content of type '{kind}' omitted]")
            }
        }
    }
}

fn base64_decoded_len(data: &str) -> usize {
    let trimmed = data.trim_end_matches('=');
    trimmed.len() * 3 / 4
}

impl Serialize for ContentBlock {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(s)
    }
}

impl<'de> Deserialize<'de> for ContentBlock {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_value(Value::deserialize(d)?))
    }
}

fn lenient_content<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<ContentBlock>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Array(items)) => items.into_iter().map(ContentBlock::from_value).collect(),
        _ => Vec::new(),
    })
}

/// Result of `tools/call`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    /// Unstructured content.
    #[serde(default, deserialize_with = "lenient_content")]
    pub content: Vec<ContentBlock>,
    /// Optional structured JSON result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    /// The tool reported an error (as opposed to a protocol error).
    #[serde(default, deserialize_with = "lenient_bool")]
    pub is_error: bool,
    /// Protocol `_meta`.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

impl CallToolResult {
    /// Successful result with one text block.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::text(text)],
            ..Self::default()
        }
    }

    /// Error result with one text block.
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::text(text)],
            is_error: true,
            ..Self::default()
        }
    }

    /// Render the whole result as text for the model.
    ///
    /// - text blocks are joined with newlines;
    /// - images/audio/binary resources become placeholders;
    /// - `structuredContent` is appended as pretty JSON unless a text block
    ///   already carries the same JSON (servers SHOULD mirror it there);
    /// - an empty result renders as `(no output)`.
    pub fn render_text(&self) -> String {
        let mut parts: Vec<String> = self.content.iter().map(ContentBlock::render).collect();
        if let Some(structured) = &self.structured_content {
            let mirrored = self.content.iter().any(|b| match b {
                ContentBlock::Text { text } => serde_json::from_str::<Value>(text)
                    .map(|v| &v == structured)
                    .unwrap_or(false),
                _ => false,
            });
            if !mirrored {
                let rendered = serde_json::to_string_pretty(structured)
                    .unwrap_or_else(|_| structured.to_string());
                if parts.is_empty() {
                    parts.push(rendered);
                } else {
                    parts.push(format!("[structured content]\n{rendered}"));
                }
            }
        }
        if parts.is_empty() {
            return if self.is_error {
                "(the tool reported an error without details)".to_string()
            } else {
                "(no output)".to_string()
            };
        }
        parts.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(is_supported_protocol_version("2025-06-18"));
        assert!(is_supported_protocol_version("2024-11-05"));
        assert!(!is_supported_protocol_version("2023-01-01"));
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], LATEST_PROTOCOL_VERSION);
    }

    #[test]
    fn initialize_result_is_lenient() {
        let r: InitializeResult = serde_json::from_value(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": true}, "logging": {}},
            "serverInfo": {"name": "srv", "version": "1.2"},
            "instructions": "use me"
        }))
        .unwrap();
        assert!(r.capabilities.has_tools());
        assert!(r.capabilities.tools_list_changed());
        assert_eq!(r.server_info.name, "srv");
        assert_eq!(r.instructions.as_deref(), Some("use me"));

        let r: InitializeResult = serde_json::from_value(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": "garbage",
            "serverInfo": 5,
            "instructions": 7
        }))
        .unwrap();
        assert!(!r.capabilities.has_tools());
        assert_eq!(r.server_info, Implementation::default());
        assert_eq!(r.instructions, None);

        let r: InitializeResult =
            serde_json::from_value(json!({"protocolVersion": "2025-03-26"})).unwrap();
        assert!(!r.capabilities.tools_list_changed());
        assert!(serde_json::from_value::<InitializeResult>(json!({})).is_err());
    }

    #[test]
    fn tool_parsing() {
        let t: McpTool = serde_json::from_value(json!({
            "name": "search",
            "title": "Search",
            "description": "Search the SIEM",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
            "annotations": {"readOnlyHint": true, "destructiveHint": "yes"},
            "_meta": {"x": 1}
        }))
        .unwrap();
        assert!(t.is_read_only());
        assert_eq!(t.display_title(), "Search");
        let a = t.annotations.as_ref().unwrap();
        assert_eq!(a.destructive_hint, None);
        assert_eq!(t.meta, Some(json!({"x": 1})));

        let t: McpTool = serde_json::from_value(json!({"name": "bare"})).unwrap();
        assert_eq!(t.input_schema, json!({"type":"object","properties":{}}));
        assert!(!t.is_read_only());
        assert_eq!(t.display_title(), "bare");

        let t: McpTool =
            serde_json::from_value(json!({"name": "x", "inputSchema": "nope", "annotations": 3}))
                .unwrap();
        assert!(t.input_schema.is_object());
        assert!(t.annotations.is_none());

        assert!(serde_json::from_value::<McpTool>(json!({"description": "no name"})).is_err());
        let back = serde_json::to_value(McpTool::new("a", "b", json!({"type":"object"}))).unwrap();
        assert_eq!(back["inputSchema"], json!({"type":"object"}));
        assert!(back.get("annotations").is_none());
    }

    #[test]
    fn content_blocks() {
        let items = json!([
            {"type": "text", "text": "hello"},
            {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"},
            {"type": "audio", "data": "AAAA", "mimeType": "audio/wav"},
            {"type": "resource_link", "uri": "file:///x", "name": "x", "mimeType": "text/plain"},
            {"type": "resource", "resource": {"uri": "file:///y", "text": "body"}},
            {"type": "resource", "resource": {"uri": "file:///z", "blob": "AAAA", "mimeType": "application/pdf"}},
            {"type": "hologram", "data": 1},
            {"type": "text"}
        ]);
        let blocks: Vec<ContentBlock> = serde_json::from_value(items.clone()).unwrap();
        assert_eq!(blocks.len(), 8);
        assert_eq!(blocks[0], ContentBlock::text("hello"));
        assert_eq!(
            blocks[1].render(),
            "[image content omitted: image/png, ~5 bytes]"
        );
        assert_eq!(
            blocks[2].render(),
            "[audio content omitted: audio/wav, ~3 bytes]"
        );
        assert_eq!(
            blocks[3].render(),
            "[resource link: x <file:///x> (text/plain)]"
        );
        assert_eq!(blocks[4].render(), "[resource file:///y]\nbody");
        assert_eq!(
            blocks[5].render(),
            "[binary resource omitted: file:///z (application/pdf), ~3 bytes]"
        );
        assert_eq!(
            blocks[6].render(),
            "[unsupported content of type 'hologram' omitted]"
        );
        assert!(matches!(blocks[7], ContentBlock::Other(_)));
        // Round trip of the known blocks.
        for (b, raw) in blocks.iter().zip(items.as_array().unwrap()).take(7) {
            assert_eq!(&b.to_value(), raw);
        }
    }

    #[test]
    fn call_result_render() {
        let r: CallToolResult = serde_json::from_value(json!({
            "content": [{"type":"text","text":"a"},{"type":"text","text":"b"}]
        }))
        .unwrap();
        assert_eq!(r.render_text(), "a\nb");
        assert!(!r.is_error);

        // structuredContent mirrored in text -> not duplicated
        let r: CallToolResult = serde_json::from_value(json!({
            "content": [{"type":"text","text":"{\"n\": 1}"}],
            "structuredContent": {"n": 1}
        }))
        .unwrap();
        assert_eq!(r.render_text(), "{\"n\": 1}");

        // structuredContent only
        let r: CallToolResult = serde_json::from_value(json!({
            "content": [],
            "structuredContent": {"n": 2}
        }))
        .unwrap();
        assert_eq!(r.render_text(), "{\n  \"n\": 2\n}");

        // structuredContent + unrelated text
        let r: CallToolResult = serde_json::from_value(json!({
            "content": [{"type":"text","text":"summary"}],
            "structuredContent": {"n": 3}
        }))
        .unwrap();
        assert_eq!(
            r.render_text(),
            "summary\n[structured content]\n{\n  \"n\": 3\n}"
        );

        // Empty / error / malformed
        let r: CallToolResult = serde_json::from_value(json!({"isError": null})).unwrap();
        assert_eq!(r.render_text(), "(no output)");
        let r: CallToolResult =
            serde_json::from_value(json!({"content": "x", "isError": true})).unwrap();
        assert!(r.is_error);
        assert_eq!(
            r.render_text(),
            "(the tool reported an error without details)"
        );

        let r = CallToolResult::error("boom");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            json!({"content":[{"type":"text","text":"boom"}],"isError":true})
        );
        assert_eq!(CallToolResult::text("x").render_text(), "x");
    }
}
