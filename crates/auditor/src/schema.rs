//! MCP tool manifest schema types and parser.
//!
//! Supports two input formats:
//! 1. **Bare tool array**: `[{name, description, inputSchema}, ...]`
//! 2. **JSON-RPC envelope**: `{"jsonrpc":"2.0", "result": {"tools": [...]}}`

use serde::Deserialize;
use serde_json::Value;

/// Errors that can occur during manifest parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("unrecognized manifest format: expected a tools array or a JSON-RPC tools/list response")]
    UnrecognizedFormat,

    #[error("manifest contains no tools")]
    EmptyManifest,
}

/// A single MCP tool definition from a `tools/list` response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    /// Unique tool name (1–128 chars, letters/digits/underscores/hyphens/dots).
    pub name: String,

    /// Human-readable description of what the tool does.
    #[serde(default)]
    pub description: Option<String>,

    /// JSON Schema object defining the tool's expected input parameters.
    /// If missing or null, the tool accepts arbitrary unvalidated arguments.
    #[serde(default)]
    pub input_schema: Option<Value>,
}

/// Parsed tool manifest containing one or more tool definitions.
#[derive(Debug)]
pub struct ToolManifest {
    pub tools: Vec<ToolDefinition>,
}

/// Internal: JSON-RPC envelope for `tools/list` response.
#[derive(Deserialize)]
struct JsonRpcToolsResponse {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    result: Option<JsonRpcToolsResult>,
}

#[derive(Deserialize)]
struct JsonRpcToolsResult {
    tools: Vec<ToolDefinition>,
}

impl ToolManifest {
    /// Parse a manifest from a JSON string.
    ///
    /// Tries the JSON-RPC envelope format first, then falls back to a bare
    /// tool array. Returns an error if neither format matches or if the
    /// manifest contains no tools.
    pub fn parse(json: &str) -> Result<Self, ParseError> {
        let value: Value = serde_json::from_str(json)?;

        // Strategy 1: JSON-RPC envelope with result.tools
        if value.is_object() {
            if let Ok(envelope) = serde_json::from_value::<JsonRpcToolsResponse>(value.clone())
                && let Some(result) = envelope.result
            {
                if result.tools.is_empty() {
                    return Err(ParseError::EmptyManifest);
                }
                return Ok(ToolManifest {
                    tools: result.tools,
                });
            }

            // Strategy 1b: Object with top-level "tools" key (shorthand manifest).
            if let Some(tools_val) = value.get("tools")
                && let Ok(tools) = serde_json::from_value::<Vec<ToolDefinition>>(tools_val.clone())
            {
                if tools.is_empty() {
                    return Err(ParseError::EmptyManifest);
                }
                return Ok(ToolManifest { tools });
            }
        }

        // Strategy 2: Bare array of tool definitions.
        if value.is_array() {
            let tools: Vec<ToolDefinition> = serde_json::from_value(value)?;
            if tools.is_empty() {
                return Err(ParseError::EmptyManifest);
            }
            return Ok(ToolManifest { tools });
        }

        Err(ParseError::UnrecognizedFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_array() {
        let json = r#"[
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }
            }
        ]"#;

        let manifest = ToolManifest::parse(json).unwrap();
        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "read_file");
        assert!(manifest.tools[0].input_schema.is_some());
    }

    #[test]
    fn parse_jsonrpc_envelope() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search",
                        "description": "Search documents",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": { "type": "string" }
                            }
                        }
                    }
                ]
            }
        }"#;

        let manifest = ToolManifest::parse(json).unwrap();
        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "search");
    }

    #[test]
    fn parse_shorthand_object() {
        let json = r#"{
            "tools": [
                {
                    "name": "echo",
                    "inputSchema": { "type": "object" }
                }
            ]
        }"#;

        let manifest = ToolManifest::parse(json).unwrap();
        assert_eq!(manifest.tools.len(), 1);
    }

    #[test]
    fn parse_empty_array_fails() {
        let json = "[]";
        let result = ToolManifest::parse(json);
        assert!(matches!(result, Err(ParseError::EmptyManifest)));
    }

    #[test]
    fn parse_invalid_json_fails() {
        let result = ToolManifest::parse("not json");
        assert!(matches!(result, Err(ParseError::InvalidJson(_))));
    }

    #[test]
    fn parse_unrecognized_format_fails() {
        let json = r#"{"foo": "bar"}"#;
        let result = ToolManifest::parse(json);
        assert!(matches!(result, Err(ParseError::UnrecognizedFormat)));
    }

    #[test]
    fn tool_with_missing_input_schema() {
        let json = r#"[{"name": "dangerous_tool"}]"#;
        let manifest = ToolManifest::parse(json).unwrap();
        assert!(manifest.tools[0].input_schema.is_none());
        assert!(manifest.tools[0].description.is_none());
    }
}
