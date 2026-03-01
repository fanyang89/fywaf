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
}

#[derive(Debug, Clone, Deserialize)]
pub struct WasmDecision {
    pub allow: bool,
    #[serde(default = "default_status")]
    pub status: u16,
    pub message: Option<String>,
    pub rule_id: Option<String>,
}

fn default_status() -> u16 {
    200
}

impl WasmDecision {
    pub fn allow() -> Self {
        Self {
            allow: true,
            status: 200,
            message: None,
            rule_id: None,
        }
    }

    pub fn block(status: u16, message: impl Into<String>) -> Self {
        Self {
            allow: false,
            status,
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
        let req = WasmRequest {
            client_ip: "192.168.1.1",
            method: "GET",
            path: "/api/test",
            query: Some("foo=bar"),
            user_agent: Some("test"),
            headers: HashMap::new(),
            body: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn deserialize_decision() {
        let json = r#"{"allow":false,"status":403,"message":"blocked"}"#;
        let decision: WasmDecision = serde_json::from_str(json).unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.status, 403);
    }

    #[test]
    fn deserialize_decision_minimal() {
        let json = r#"{"allow":true}"#;
        let decision: WasmDecision = serde_json::from_str(json).unwrap();
        assert!(decision.allow);
        assert_eq!(decision.status, 200);
    }
}
