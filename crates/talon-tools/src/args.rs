//! Lenient, typed access to tool-call arguments.
//!
//! Models occasionally send numbers as strings (`"120"`), booleans as strings
//! (`"true"`), or the whole argument object double-encoded as a JSON string.
//! [`Args`] accepts those forms but still rejects values of the wrong type with
//! an error message the model can act on.

use serde_json::{Map, Value};

/// Parsed tool arguments (always a JSON object).
#[derive(Debug, Clone, Default)]
pub(crate) struct Args(Map<String, Value>);

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl Args {
    /// Accept an object, `null` (no arguments) or a string holding an object.
    pub(crate) fn parse(v: Value) -> Result<Self, String> {
        match v {
            Value::Object(m) => Ok(Self(m)),
            Value::Null => Ok(Self::default()),
            Value::String(s) if s.trim().is_empty() => Ok(Self::default()),
            Value::String(s) => match serde_json::from_str::<Value>(&s) {
                Ok(Value::Object(m)) => Ok(Self(m)),
                _ => Err("arguments must be a JSON object".to_string()),
            },
            other => Err(format!(
                "arguments must be a JSON object, got {}",
                kind(&other)
            )),
        }
    }

    /// The raw value, treating explicit `null` as absent.
    pub(crate) fn value(&self, key: &str) -> Option<&Value> {
        self.0.get(key).filter(|v| !v.is_null())
    }

    /// Required string parameter.
    pub(crate) fn str(&self, key: &str) -> Result<String, String> {
        self.opt_str(key)?
            .ok_or_else(|| format!("missing required parameter `{key}` (string)"))
    }

    /// Optional string parameter.
    pub(crate) fn opt_str(&self, key: &str) -> Result<Option<String>, String> {
        match self.value(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(v @ (Value::Number(_) | Value::Bool(_))) => Ok(Some(v.to_string())),
            Some(v) => Err(format!(
                "parameter `{key}` must be a string, got {}",
                kind(v)
            )),
        }
    }

    /// Optional boolean parameter (`true`/`false`, also as strings).
    pub(crate) fn opt_bool(&self, key: &str) -> Result<Option<bool>, String> {
        match self.value(key) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(Some(true)),
                "false" | "0" | "no" => Ok(Some(false)),
                _ => Err(format!("parameter `{key}` must be a boolean, got {s:?}")),
            },
            Some(v) => Err(format!(
                "parameter `{key}` must be a boolean, got {}",
                kind(v)
            )),
        }
    }

    /// Optional non-negative integer parameter (also accepts `"42"`).
    pub(crate) fn opt_u64(&self, key: &str) -> Result<Option<u64>, String> {
        let bad = || format!("parameter `{key}` must be a non-negative integer");
        match self.value(key) {
            None => Ok(None),
            Some(Value::Number(n)) => {
                if let Some(u) = n.as_u64() {
                    Ok(Some(u))
                } else if let Some(f) = n.as_f64() {
                    if f >= 0.0 && f.fract() == 0.0 && f <= u64::MAX as f64 {
                        Ok(Some(f as u64))
                    } else {
                        Err(bad())
                    }
                } else {
                    Err(bad())
                }
            }
            Some(Value::String(s)) => s.trim().parse::<u64>().map(Some).map_err(|_| bad()),
            Some(_) => Err(bad()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_object_null_and_encoded_string() {
        assert!(Args::parse(json!({"a": 1})).is_ok());
        assert!(Args::parse(Value::Null).is_ok());
        let a = Args::parse(json!("{\"path\":\"x\"}")).unwrap();
        assert_eq!(a.str("path").unwrap(), "x");
        assert!(Args::parse(json!([1, 2])).is_err());
        assert!(Args::parse(json!("not json")).is_err());
    }

    #[test]
    fn typed_getters() {
        let a = Args::parse(json!({
            "s": "hi", "n": 5, "ns": "7", "f": 3.0, "neg": -1, "b": true, "bs": "false",
            "nul": null, "arr": [1]
        }))
        .unwrap();
        assert_eq!(a.str("s").unwrap(), "hi");
        assert!(a.str("missing").unwrap_err().contains("missing required"));
        assert_eq!(a.opt_str("nul").unwrap(), None);
        assert!(a.opt_str("arr").is_err());
        assert_eq!(a.opt_u64("n").unwrap(), Some(5));
        assert_eq!(a.opt_u64("ns").unwrap(), Some(7));
        assert_eq!(a.opt_u64("f").unwrap(), Some(3));
        assert!(a.opt_u64("neg").is_err());
        assert_eq!(a.opt_bool("b").unwrap(), Some(true));
        assert_eq!(a.opt_bool("bs").unwrap(), Some(false));
        assert!(a.opt_bool("s").is_err());
    }
}
