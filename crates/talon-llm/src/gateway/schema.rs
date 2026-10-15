//! JSON-Schema sanitizer for schemas the gateway forwards to vLLM:
//! `response_format.json_schema.schema` and `tools[].function.parameters`.
//!
//! vLLM compiles these schemas into a grammar on the vLLM host (guided
//! decoding with `response_format`, with `tool_choice` `required`/named, or
//! with `strict` tools). One request's schema therefore costs CPU and memory
//! on the shared inference engine: a `pattern` like `^(a|aa)*$` or bounds
//! like `maxLength: 1e8` / `minItems: 1e8` can stall grammar/regex
//! compilation for every lane. The gateway therefore rebuilds each schema
//! from an **allowlist** of structural keywords ([`SCHEMA_ALLOWED_KEYWORDS`]):
//!
//! - Every other keyword is dropped (counted in the gateway's
//!   `dropped_fields` stat, never an error): `pattern`,
//!   `patternProperties`, `$ref`, `$defs`/`definitions`, `if`/`then`/`else`,
//!   `not`, `dependentSchemas`/`dependentRequired`/`dependencies`,
//!   `contentEncoding`/`contentMediaType`/`contentSchema`, `propertyNames`,
//!   `prefixItems`/`additionalItems`, `contains`, `unevaluated*`,
//!   `multipleOf`, `min/maxProperties`, `$schema`/`$id`/`$comment`/`$anchor`,
//!   `examples`, `readOnly`/`writeOnly`/`deprecated`, vendor extensions, ...
//!   Dropping a keyword only ever **loosens** the schema (the decoder may
//!   accept more, never less), with two compensations where dropping alone
//!   would tighten it: `additionalProperties` is dropped too when
//!   `patternProperties` was present, and `items` is dropped too when
//!   `prefixItems` was present.
//! - Allowed keywords with a value of the wrong shape are dropped the same
//!   way (a sub-schema that is neither an object nor a boolean becomes `{}`
//!   inside `properties` / `anyOf` / `oneOf` / `allOf`).
//! - `format` survives only with a well-known value ([`SCHEMA_ALLOWED_FORMATS`]);
//!   those map to fixed, vetted regexes inside the backends.
//! - `minLength`/`maxLength`/`minItems`/`maxItems` must be non-negative
//!   integers and are clamped to [`MAX_SCHEMA_LENGTH_BOUND`]; a minimum
//!   above its maximum is lowered to the maximum.
//! - Size caps refuse the request (`400`) instead of truncating, which
//!   would change the schema's meaning: at most [`MAX_SCHEMA_ENUM_VALUES`]
//!   `enum` values, [`MAX_SCHEMA_PROPERTIES`] `properties` (and `required`
//!   names) per object, [`MAX_SCHEMA_BRANCHES`] `anyOf`/`oneOf`/`allOf`
//!   entries.
//!
//! Values that are data rather than schemas (`enum`, `const`, `default`,
//! property names, `required` names) are kept verbatim: a property called
//! `pattern` or `format` is not a keyword.
//!
//! The caller checks [`super::policy::MAX_SCHEMA_DEPTH`] and the byte caps
//! on the raw value first, which also bounds this module's recursion.

use serde_json::{Map, Value};

use super::policy::PolicyOutcome;

/// Keywords kept in a forwarded JSON schema; everything else is dropped.
///
/// - Structure: `type`, `properties`, `required`, `additionalProperties`,
///   `items`, `anyOf`, `oneOf`, `allOf`.
/// - Values: `enum`, `const`, `nullable` (OpenAPI 3.0).
/// - Bounds: `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`
///   (numbers; the draft-4 boolean form is dropped), `minLength`,
///   `maxLength`, `minItems`, `maxItems` (clamped), `uniqueItems`.
/// - Annotations the model reads (tool schemas are rendered into the prompt
///   by the chat template): `description`, `title`, `default`.
/// - `format`, restricted to [`SCHEMA_ALLOWED_FORMATS`].
///
/// `examples` is deliberately dropped: no decoding backend uses it, it is
/// unbounded arbitrary data, and `description` carries the same hint.
pub const SCHEMA_ALLOWED_KEYWORDS: [&str; 24] = [
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "anyOf",
    "oneOf",
    "allOf",
    "enum",
    "const",
    "nullable",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "uniqueItems",
    "description",
    "title",
    "default",
    "format",
];

/// `format` values kept; any other `format` is dropped.
pub const SCHEMA_ALLOWED_FORMATS: [&str; 9] = [
    "date-time",
    "date",
    "time",
    "email",
    "uri",
    "uuid",
    "ipv4",
    "ipv6",
    "hostname",
];

/// Upper bound for `minLength`, `maxLength`, `minItems` and `maxItems`.
/// Kept small (the agent's own schemas stay below 2 000) because nested
/// bounds multiply in grammar-based guided decoding (Mythos round 3).
pub const MAX_SCHEMA_LENGTH_BOUND: u64 = 4_096;

/// Cap on the values of one `enum`.
pub const MAX_SCHEMA_ENUM_VALUES: usize = 512;

/// Cap on `properties` (and on `required` names) of one object schema.
pub const MAX_SCHEMA_PROPERTIES: usize = 256;

/// Cap on the entries of one `anyOf` / `oneOf` / `allOf`.
pub const MAX_SCHEMA_BRANCHES: usize = 64;

/// JSON-Schema `type` names.
const TYPE_NAMES: [&str; 7] = [
    "string", "number", "integer", "boolean", "object", "array", "null",
];

/// Sanitize the schema `schema` found at `at` (e.g.
/// `tools[].function.parameters`); dropped keywords are recorded in `out` as
/// `<at>.<keyword>`. Returns the rebuilt schema or the reason to refuse the
/// request.
pub(crate) fn sanitize_schema(
    schema: Value,
    at: &str,
    out: &mut PolicyOutcome,
) -> Result<Value, String> {
    let mut s = Sanitizer { at, out };
    match s.subschema("", schema)? {
        Some(v) => Ok(v),
        None => Ok(Value::Object(Map::new())),
    }
}

struct Sanitizer<'a> {
    at: &'a str,
    out: &'a mut PolicyOutcome,
}

impl Sanitizer<'_> {
    fn record_drop(&mut self, keyword: &str) {
        self.out.drop_field(self.at, keyword);
    }

    /// A sub-schema under `keyword`: objects are sanitized, booleans kept,
    /// anything else is dropped (`None`, recorded).
    fn subschema(&mut self, keyword: &str, v: Value) -> Result<Option<Value>, String> {
        match v {
            Value::Bool(_) => Ok(Some(v)),
            Value::Object(map) => Ok(Some(Value::Object(self.object(map)?))),
            _ => {
                self.record_drop(keyword);
                Ok(None)
            }
        }
    }

    /// A sub-schema that must stay in place (an entry of `properties`,
    /// `anyOf`, ...): an invalid one becomes the empty schema `{}`.
    fn subschema_or_empty(&mut self, keyword: &str, v: Value) -> Result<Value, String> {
        Ok(self
            .subschema(keyword, v)?
            .unwrap_or_else(|| Value::Object(Map::new())))
    }

    fn object(&mut self, input: Map<String, Value>) -> Result<Map<String, Value>, String> {
        // Keywords whose meaning depends on a keyword that is dropped.
        let pattern_properties = input.contains_key("patternProperties");
        let prefix_items = input.contains_key("prefixItems");
        let mut clean = Map::new();
        let mut min_length = None;
        let mut max_length = None;
        let mut min_items = None;
        let mut max_items = None;

        for (key, value) in input {
            match key.as_str() {
                "type" => {
                    if is_valid_type(&value) {
                        clean.insert(key, value);
                    } else {
                        self.record_drop(&key);
                    }
                }
                "description" | "title" => {
                    if value.is_string() {
                        clean.insert(key, value);
                    } else {
                        self.record_drop(&key);
                    }
                }
                // Data, not schemas: kept verbatim (bounded by the byte cap).
                "const" | "default" => {
                    clean.insert(key, value);
                }
                "nullable" | "uniqueItems" => {
                    if value.is_boolean() {
                        clean.insert(key, value);
                    } else {
                        self.record_drop(&key);
                    }
                }
                "enum" => match value {
                    Value::Array(values) => {
                        if values.len() > MAX_SCHEMA_ENUM_VALUES {
                            return Err(format!(
                                "`{}`: an `enum` may list at most {MAX_SCHEMA_ENUM_VALUES} values",
                                self.at
                            ));
                        }
                        clean.insert(key, Value::Array(values));
                    }
                    _ => self.record_drop(&key),
                },
                "required" => match value {
                    Value::Array(names) if names.iter().all(Value::is_string) => {
                        if names.len() > MAX_SCHEMA_PROPERTIES {
                            return Err(format!(
                                "`{}`: `required` may list at most {MAX_SCHEMA_PROPERTIES} names",
                                self.at
                            ));
                        }
                        clean.insert(key, Value::Array(names));
                    }
                    _ => self.record_drop(&key),
                },
                "properties" => match value {
                    Value::Object(props) => {
                        if props.len() > MAX_SCHEMA_PROPERTIES {
                            return Err(format!(
                                "`{}`: an object schema may have at most {MAX_SCHEMA_PROPERTIES} properties",
                                self.at
                            ));
                        }
                        let mut rebuilt = Map::new();
                        for (name, schema) in props {
                            let schema = self.subschema_or_empty("properties", schema)?;
                            rebuilt.insert(name, schema);
                        }
                        clean.insert(key, Value::Object(rebuilt));
                    }
                    _ => self.record_drop(&key),
                },
                // In 2020-12, `items` constrains only the elements after
                // `prefixItems`; without the dropped `prefixItems` it would
                // constrain all of them (e.g. `items: false` = empty array).
                "items" if prefix_items => self.record_drop(&key),
                // Same for `additionalProperties` next to `patternProperties`:
                // keys the patterns allowed would become additional ones.
                "additionalProperties" if pattern_properties => self.record_drop(&key),
                "items" | "additionalProperties" => {
                    if let Some(v) = self.subschema(&key, value)? {
                        clean.insert(key, v);
                    }
                }
                "anyOf" | "oneOf" | "allOf" => match value {
                    Value::Array(branches) if !branches.is_empty() => {
                        if branches.len() > MAX_SCHEMA_BRANCHES {
                            return Err(format!(
                                "`{}`: `{key}` may have at most {MAX_SCHEMA_BRANCHES} entries",
                                self.at
                            ));
                        }
                        let mut rebuilt = Vec::with_capacity(branches.len());
                        for branch in branches {
                            rebuilt.push(self.subschema_or_empty(&key, branch)?);
                        }
                        clean.insert(key, Value::Array(rebuilt));
                    }
                    _ => self.record_drop(&key),
                },
                "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                    if value.is_number() {
                        clean.insert(key, value);
                    } else {
                        self.record_drop(&key);
                    }
                }
                "minLength" | "maxLength" | "minItems" | "maxItems" => {
                    let Some(n) = length_bound(&value) else {
                        self.record_drop(&key);
                        continue;
                    };
                    match key.as_str() {
                        "minLength" => min_length = Some(n),
                        "maxLength" => max_length = Some(n),
                        "minItems" => min_items = Some(n),
                        _ => max_items = Some(n),
                    }
                }
                "format" => {
                    if value
                        .as_str()
                        .is_some_and(|f| SCHEMA_ALLOWED_FORMATS.contains(&f))
                    {
                        clean.insert(key, value);
                    } else {
                        self.record_drop(&key);
                    }
                }
                _ => self.record_drop(&key),
            }
        }

        insert_bounds(
            &mut clean,
            ("minLength", min_length),
            ("maxLength", max_length),
        );
        insert_bounds(&mut clean, ("minItems", min_items), ("maxItems", max_items));
        Ok(clean)
    }
}

/// `type`: one known type name, or a non-empty array of them.
fn is_valid_type(v: &Value) -> bool {
    let known = |t: &Value| t.as_str().is_some_and(|t| TYPE_NAMES.contains(&t));
    match v {
        Value::String(_) => known(v),
        Value::Array(types) => {
            !types.is_empty() && types.len() <= TYPE_NAMES.len() && types.iter().all(known)
        }
        _ => false,
    }
}

/// A non-negative integral length bound (`1e8` parses as a float), clamped
/// to [`MAX_SCHEMA_LENGTH_BOUND`]. `None` for anything else.
fn length_bound(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n.min(MAX_SCHEMA_LENGTH_BOUND));
    }
    let f = v.as_f64()?;
    if !(f.is_finite() && f >= 0.0 && f.fract() == 0.0) {
        return None;
    }
    // Both casts are exact: the bound is a small power of two and `f` is
    // integral in `[0, bound)` on the second branch.
    if f >= MAX_SCHEMA_LENGTH_BOUND as f64 {
        Some(MAX_SCHEMA_LENGTH_BOUND)
    } else {
        Some(f as u64)
    }
}

/// Insert a clamped `min`/`max` pair, lowering `min` to `max` when it is
/// larger (the schema would be unsatisfiable anyway).
fn insert_bounds(
    clean: &mut Map<String, Value>,
    (min_key, min): (&str, Option<u64>),
    (max_key, max): (&str, Option<u64>),
) {
    let min = match (min, max) {
        (Some(lo), Some(hi)) => Some(lo.min(hi)),
        (lo, _) => lo,
    };
    if let Some(lo) = min {
        clean.insert(min_key.into(), Value::from(lo));
    }
    if let Some(hi) = max {
        clean.insert(max_key.into(), Value::from(hi));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(schema: Value) -> (Value, PolicyOutcome) {
        let mut out = PolicyOutcome::default();
        let v = sanitize_schema(schema, "s", &mut out).unwrap();
        (v, out)
    }

    fn refused(schema: Value) -> String {
        let mut out = PolicyOutcome::default();
        sanitize_schema(schema, "s", &mut out).unwrap_err()
    }

    /// One schema using every allowlisted keyword (and every allowed
    /// `format`), with bounds inside the limits.
    fn full_schema() -> Value {
        json!({
            "type": "object",
            "title": "T",
            "description": "every allowed keyword",
            "properties": {
                "s": {"type": "string", "minLength": 1, "maxLength": MAX_SCHEMA_LENGTH_BOUND,
                      "format": "date-time", "default": "x", "nullable": true},
                "n": {"type": ["number", "null"], "minimum": -1.5, "maximum": 1e6,
                      "exclusiveMinimum": -2, "exclusiveMaximum": 1e7},
                "e": {"enum": ["a", 1, null, {"pattern": "not a keyword"}]},
                "c": {"const": {"$ref": "#/data"}},
                "a": {"type": "array", "minItems": 0, "maxItems": 10, "uniqueItems": true,
                      "items": {"anyOf": [{"type": "string"}, {"type": "integer"}]}},
                "o": {"oneOf": [{"type": "boolean"}, true], "allOf": [{"type": "boolean"}]},
                "f": {"type": "object", "additionalProperties": {"type": "string"}},
                "b": false
            },
            "required": ["s", "n"],
            "additionalProperties": false
        })
    }

    #[test]
    fn allowed_keywords_pass_unchanged() {
        let schema = full_schema();
        let (v, out) = run(schema.clone());
        assert_eq!(out.dropped_count, 0, "{:?}", out.dropped);
        assert_eq!(v, schema);
        // The documented allowlist and the sanitizer agree.
        let text = schema.to_string();
        for k in SCHEMA_ALLOWED_KEYWORDS {
            assert!(text.contains(&format!("\"{k}\":")), "{k} not covered");
        }
        for f in SCHEMA_ALLOWED_FORMATS {
            let s = json!({"type": "string", "format": f});
            assert_eq!(run(s.clone()).0, s, "{f}");
        }
    }

    #[test]
    fn disallowed_keywords_are_dropped() {
        let dropped = [
            ("pattern", json!("^(a|aa)*$")),
            ("patternProperties", json!({"^x": {"type": "string"}})),
            ("$ref", json!("#/$defs/x")),
            ("$defs", json!({"x": {"type": "string"}})),
            ("definitions", json!({"x": {"type": "string"}})),
            ("$dynamicRef", json!("#x")),
            ("$anchor", json!("x")),
            (
                "$schema",
                json!("https://json-schema.org/draft/2020-12/schema"),
            ),
            ("$id", json!("urn:x")),
            ("$comment", json!("c")),
            ("if", json!({"type": "string"})),
            ("then", json!({"minLength": 1})),
            ("else", json!({"maxLength": 1})),
            ("not", json!({"type": "null"})),
            ("dependentSchemas", json!({"a": {"required": ["b"]}})),
            ("dependentRequired", json!({"a": ["b"]})),
            ("dependencies", json!({"a": ["b"]})),
            ("contentEncoding", json!("base64")),
            ("contentMediaType", json!("application/json")),
            ("contentSchema", json!({"type": "object"})),
            ("propertyNames", json!({"pattern": "^a"})),
            ("prefixItems", json!([{"type": "string"}])),
            ("additionalItems", json!(false)),
            ("contains", json!({"type": "string"})),
            ("minContains", json!(1)),
            ("maxContains", json!(100_000_000)),
            ("unevaluatedProperties", json!(false)),
            ("unevaluatedItems", json!(false)),
            ("multipleOf", json!(1e-9)),
            ("minProperties", json!(100_000_000)),
            ("maxProperties", json!(1)),
            ("examples", json!(["x"])),
            ("readOnly", json!(true)),
            ("writeOnly", json!(true)),
            ("deprecated", json!(true)),
            ("x-guidance", json!({"lenient": true})),
            ("regex", json!("(a+)+$")),
            ("grammar", json!("root ::= \"x\"")),
        ];
        for (k, v) in &dropped {
            let (out_schema, out) = run(json!({"type": "string", *k: v.clone()}));
            assert_eq!(out_schema, json!({"type": "string"}), "{k}");
            assert_eq!(out.dropped_count, 1, "{k}");
            assert_eq!(out.dropped, vec![format!("s.{k}")]);
        }
        // All at once: only `type` is left.
        let mut all = json!({"type": "string"});
        for (k, v) in &dropped {
            all[*k] = v.clone();
        }
        let (v, out) = run(all);
        assert_eq!(v, json!({"type": "string"}));
        assert_eq!(out.dropped_count, dropped.len());
        assert!(
            !SCHEMA_ALLOWED_KEYWORDS
                .iter()
                .any(|k| dropped.iter().any(|(d, _)| d == k))
        );
    }

    /// The Mythos round-2 payloads (N-6).
    #[test]
    fn reviewer_payloads_are_neutralised() {
        let (v, out) = run(json!({
            "type": "object",
            "properties": {
                "s": {"type": "string", "pattern": "^(a|aa)*$", "maxLength": 1e8},
                "l": {"type": "array", "minItems": 1e8, "items": {"type": "string"}}
            }
        }));
        assert_eq!(
            v,
            json!({
                "type": "object",
                "properties": {
                    "s": {"type": "string", "maxLength": MAX_SCHEMA_LENGTH_BOUND},
                    "l": {"type": "array", "minItems": MAX_SCHEMA_LENGTH_BOUND, "items": {"type": "string"}}
                }
            })
        );
        assert_eq!(out.dropped, vec!["s.pattern".to_string()]);
    }

    #[test]
    fn length_bounds_are_clamped() {
        let cap = MAX_SCHEMA_LENGTH_BOUND;
        for (input, expected) in [
            (json!(1e8), json!(cap)),
            (json!(100_000), json!(cap)),
            (json!(u64::MAX), json!(cap)),
            (json!(1e300), json!(cap)),
            (json!(cap), json!(cap)),
            (json!(cap - 1), json!(cap - 1)),
            (json!(12.0), json!(12)),
            (json!(0), json!(0)),
        ] {
            for k in ["minLength", "maxLength", "minItems", "maxItems"] {
                let (v, out) = run(json!({k: input.clone()}));
                assert_eq!(v, json!({k: expected.clone()}), "{k}={input}");
                assert_eq!(out.dropped_count, 0);
            }
        }
        // Not a non-negative integer: dropped.
        for bad in [
            json!(-1),
            json!(1.5),
            json!(-1e8),
            json!("5"),
            json!(null),
            json!([3]),
        ] {
            for k in ["minLength", "maxLength", "minItems", "maxItems"] {
                let (v, out) = run(json!({"type": "string", k: bad.clone()}));
                assert_eq!(v, json!({"type": "string"}), "{k}={bad}");
                assert_eq!(out.dropped, vec![format!("s.{k}")]);
            }
        }
        // A minimum never exceeds its maximum (or the cap).
        let (v, _) = run(json!({"minLength": 1e8, "maxLength": 10, "minItems": 50, "maxItems": 5}));
        assert_eq!(
            v,
            json!({"minLength": 10, "maxLength": 10, "minItems": 5, "maxItems": 5})
        );
        let (v, _) = run(json!({"minItems": 1e8, "maxItems": 1e9}));
        assert_eq!(v, json!({"minItems": cap, "maxItems": cap}));
        let (v, _) = run(json!({"minLength": 3, "maxLength": 1e8}));
        assert_eq!(v, json!({"minLength": 3, "maxLength": cap}));
    }

    #[test]
    fn formats_are_restricted() {
        for f in [
            json!("regex"),
            json!("uri-reference"),
            json!("iri"),
            json!("json-pointer"),
            json!("duration"),
            json!("idn-email"),
            json!("DATE-TIME"),
            json!(5),
        ] {
            let (v, out) = run(json!({"type": "string", "format": f.clone()}));
            assert_eq!(v, json!({"type": "string"}), "{f}");
            assert_eq!(out.dropped, vec!["s.format".to_string()]);
        }
    }

    #[test]
    fn enum_property_and_branch_caps() {
        let values: Vec<Value> = (0..MAX_SCHEMA_ENUM_VALUES).map(|i| json!(i)).collect();
        let ok = json!({"enum": values});
        assert_eq!(run(ok.clone()).0, ok);
        let values: Vec<Value> = (0..=MAX_SCHEMA_ENUM_VALUES).map(|i| json!(i)).collect();
        assert!(refused(json!({"enum": values})).contains("enum"));

        let props = |n: usize| -> Map<String, Value> {
            (0..n)
                .map(|i| (format!("p{i}"), json!({"type": "string"})))
                .collect()
        };
        let ok = json!({"type": "object", "properties": props(MAX_SCHEMA_PROPERTIES)});
        assert_eq!(run(ok.clone()).0, ok);
        let err =
            refused(json!({"type": "object", "properties": props(MAX_SCHEMA_PROPERTIES + 1)}));
        assert!(err.contains("properties"), "{err}");

        let names: Vec<String> = (0..=MAX_SCHEMA_PROPERTIES)
            .map(|i| format!("p{i}"))
            .collect();
        assert!(refused(json!({"required": names})).contains("required"));

        for k in ["anyOf", "oneOf", "allOf"] {
            let ok = json!({k: vec![json!({"type": "string"}); MAX_SCHEMA_BRANCHES]});
            assert_eq!(run(ok.clone()).0, ok, "{k}");
            let err = refused(json!({k: vec![json!({"type": "string"}); MAX_SCHEMA_BRANCHES + 1]}));
            assert!(err.contains(k), "{err}");
        }

        // Caps apply at every nesting level.
        let values: Vec<Value> = (0..=MAX_SCHEMA_ENUM_VALUES).map(|i| json!(i)).collect();
        let nested = json!({"type": "object", "properties": {"a": {"type": "array",
            "items": {"anyOf": [{"type": "string"}, {"enum": values}]}}}});
        assert!(refused(nested).contains("enum"));
        let nested = json!({"type": "array", "items": {"type": "object", "properties": props(MAX_SCHEMA_PROPERTIES + 1)}});
        assert!(refused(nested).contains("properties"));
    }

    #[test]
    fn nested_schemas_are_sanitized() {
        let evil = json!({"type": "string", "pattern": "^(a|aa)*$", "maxLength": 1e8, "$ref": "#"});
        let clean = json!({"type": "string", "maxLength": MAX_SCHEMA_LENGTH_BOUND});
        let (v, out) = run(json!({
            "type": "object",
            "properties": {"p": evil, "q": {"type": "object", "properties": {"r": evil}}},
            "additionalProperties": evil,
            "anyOf": [evil, {"type": "null"}],
            "oneOf": [{"type": "null"}, evil],
            "allOf": [evil],
            "items": {"type": "array", "items": evil}
        }));
        assert_eq!(
            v,
            json!({
                "type": "object",
                "properties": {"p": clean, "q": {"type": "object", "properties": {"r": clean}}},
                "additionalProperties": clean,
                "anyOf": [clean, {"type": "null"}],
                "oneOf": [{"type": "null"}, clean],
                "allOf": [clean],
                "items": {"type": "array", "items": clean}
            })
        );
        // 7 copies × (`pattern` + `$ref`).
        assert_eq!(out.dropped_count, 14);
        assert!(
            out.dropped
                .iter()
                .all(|d| d == "s.pattern" || d == "s.$ref")
        );
    }

    /// Property names, `required` names and `enum`/`const`/`default` values
    /// are data: a property called `pattern` (the Grep/Glob tools have one)
    /// is not the `pattern` keyword.
    #[test]
    fn property_names_and_values_are_not_keywords() {
        let schema = json!({
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regular expression to search for."},
                "format": {"type": "string", "enum": ["text", "raw"]},
                "$ref": {"type": "string"},
                "not": {"type": "boolean", "default": {"pattern": "x"}},
                "if": {"const": {"$defs": {}, "pattern": "(a+)+$"}}
            },
            "required": ["pattern", "$ref", "if"]
        });
        let (v, out) = run(schema.clone());
        assert_eq!(out.dropped_count, 0, "{:?}", out.dropped);
        assert_eq!(v, schema);
    }

    /// Dropping a keyword must only loosen the schema; where it would
    /// tighten it, the dependent keyword goes too.
    #[test]
    fn drops_never_tighten_the_schema() {
        let (v, out) = run(json!({
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "patternProperties": {"^x_": {"type": "integer"}},
            "additionalProperties": false
        }));
        assert_eq!(
            v,
            json!({"type": "object", "properties": {"a": {"type": "string"}}})
        );
        assert_eq!(out.dropped_count, 2);
        let (v, out) = run(json!({
            "type": "array",
            "prefixItems": [{"type": "string"}, {"type": "integer"}],
            "items": false
        }));
        assert_eq!(v, json!({"type": "array"}));
        assert_eq!(out.dropped_count, 2);
        // Without them, `additionalProperties` / `items` stay.
        let s = json!({"type": "object", "additionalProperties": false,
            "properties": {"l": {"type": "array", "items": false}}});
        assert_eq!(run(s.clone()).0, s);
    }

    #[test]
    fn malformed_values_are_dropped() {
        for (input, expected, drops) in [
            (json!({"type": "str"}), json!({}), 1),
            (json!({"type": []}), json!({}), 1),
            (json!({"type": ["string", "regex"]}), json!({}), 1),
            (json!({"type": 5}), json!({}), 1),
            (json!({"description": 5, "title": {}}), json!({}), 2),
            (json!({"properties": 5}), json!({}), 1),
            (
                json!({"properties": {"a": 5, "b": "x", "c": true}}),
                json!({"properties": {"a": {}, "b": {}, "c": true}}),
                2,
            ),
            (json!({"anyOf": []}), json!({}), 1),
            (json!({"oneOf": {"type": "string"}}), json!({}), 1),
            (
                json!({"allOf": [5, false]}),
                json!({"allOf": [{}, false]}),
                1,
            ),
            // Draft-4 tuple form: dropped (looser), like `prefixItems`.
            (json!({"items": [{"type": "string"}]}), json!({}), 1),
            (json!({"additionalProperties": "x"}), json!({}), 1),
            (json!({"nullable": "yes", "uniqueItems": 1}), json!({}), 2),
            (json!({"minimum": "1", "maximum": null}), json!({}), 2),
            // Draft-4 boolean exclusive bounds.
            (
                json!({"exclusiveMinimum": true, "exclusiveMaximum": false}),
                json!({}),
                2,
            ),
            (json!({"enum": "a"}), json!({}), 1),
            (json!({"required": ["a", 1]}), json!({}), 1),
            (json!({"required": "a"}), json!({}), 1),
        ] {
            let (v, out) = run(input.clone());
            assert_eq!(v, expected, "{input}");
            assert_eq!(out.dropped_count, drops, "{input}: {:?}", out.dropped);
        }
        // Boolean schemas are valid anywhere a schema is.
        let s = json!({"items": true, "additionalProperties": false, "anyOf": [true, false]});
        assert_eq!(run(s.clone()).0, s);
        assert_eq!(run(json!(true)).0, json!(true));
    }

    /// The agent's TriageReport schemas (`talon-intel`) pass unchanged:
    /// they use only allowlisted keywords (no `pattern` — the ATT&CK id is
    /// constrained by `minLength`/`maxLength`, and `TriageReport::validate`
    /// checks the format after decoding) and bounds far below the clamp.
    #[test]
    fn triage_report_schema_survives_unchanged() {
        use talon_intel::report;
        for schema in [report::json_schema(), report::guided_json_schema()] {
            let (v, out) = run(schema.clone());
            assert_eq!(out.dropped_count, 0, "{:?}", out.dropped);
            assert_eq!(v, schema);
            let text = schema.to_string();
            for k in ["\"pattern\":", "\"$ref\":", "\"format\":", "\"$defs\":"] {
                assert!(!text.contains(k), "{k} in TriageReport schema");
            }
        }
    }
}
