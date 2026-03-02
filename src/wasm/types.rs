use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct WasmRequest<'a> {
    pub client_ip: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub headers: HashMap<&'a str, &'a str>,
    pub body: Option<&'a str>,
    /// Profile-level parameters forwarded to the WASM module (e.g. paranoia_level).
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub params: &'a HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WasmDecision {
    pub allow: bool,
    pub status: Option<u16>,
    pub message: Option<String>,
    pub rule_id: Option<String>,
}

impl WasmDecision {
    pub fn allow() -> Self {
        Self {
            allow: true,
            status: Some(200),
            message: None,
            rule_id: None,
        }
    }

    pub fn block(status: u16, message: impl Into<String>) -> Self {
        Self {
            allow: false,
            status: Some(status),
            message: Some(message.into()),
            rule_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_request() {
        let params = HashMap::new();
        let req = WasmRequest {
            client_ip: "192.168.1.1",
            method: "GET",
            path: "/api/test",
            query: Some("foo=bar"),
            user_agent: Some("test"),
            headers: HashMap::new(),
            body: None,
            params: &params,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn deserialize_decision() {
        let json = r#"{"allow":false,"status":403,"message":"blocked"}"#;
        let decision: WasmDecision = serde_json::from_str(json).unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.status, Some(403));
    }

    #[test]
    fn deserialize_decision_minimal() {
        let json = r#"{"allow":true}"#;
        let decision: WasmDecision = serde_json::from_str(json).unwrap();
        assert!(decision.allow);
        assert_eq!(decision.status, None);
    }
}
