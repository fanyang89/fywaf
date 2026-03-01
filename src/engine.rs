use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::wasm::{WasmRequest, WasmVm};

#[derive(Debug)]
pub struct WafEngine {
    vm: WasmVm,
}

#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub client_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub user_agent: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub profile_id: String,
    pub allow: bool,
    pub status_code: u16,
    pub message: Option<String>,
    pub rule_id: Option<String>,
}

impl WafEngine {
    pub fn from_config(cfg: &AppConfig, base_path: &Path) -> Result<Self> {
        let mut vm = WasmVm::new()?;

        for profile in &cfg.profiles {
            let wasm_path = base_path.join(&profile.wasm_path);
            vm.load_module(&profile.id, &wasm_path).with_context(|| {
                format!("failed to load wasm module for profile {}", profile.id)
            })?;
        }

        Ok(Self { vm })
    }

    pub fn decide(&self, profile_id: &str, req: &RequestMeta) -> Result<Decision> {
        let client_ip = req.client_ip.to_string();
        let headers: HashMap<&str, &str> = req
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let wasm_req = WasmRequest {
            client_ip: &client_ip,
            method: &req.method,
            path: &req.path,
            query: req.query.as_deref(),
            user_agent: req.user_agent.as_deref(),
            headers,
            body: req.body.as_deref(),
        };

        let wasm_decision = self
            .vm
            .decide(profile_id, &wasm_req)
            .with_context(|| format!("wasm decide failed for profile {}", profile_id))?;

        Ok(Decision {
            profile_id: profile_id.to_string(),
            allow: wasm_decision.allow,
            status_code: wasm_decision.status,
            message: wasm_decision.message,
            rule_id: wasm_decision.rule_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_meta_construction() {
        let req = RequestMeta {
            client_ip: "192.168.1.1".parse().unwrap(),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: Some("foo=bar".to_string()),
            user_agent: Some("test-agent".to_string()),
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: None,
        };

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/test");
        assert_eq!(req.query, Some("foo=bar".to_string()));
    }
}
