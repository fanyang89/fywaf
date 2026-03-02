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

    /// Test-only constructor: build an engine from a pre-populated `WasmVm`.
    #[cfg(test)]
    pub(crate) fn from_wasm_vm(vm: WasmVm) -> Self {
        Self { vm }
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

        // Validate the status code is a legal HTTP status (100–599).
        // Fall back to 200 for allow and 403 for block when the module omits
        // or returns an invalid value.
        let status_code = match wasm_decision.status {
            Some(s) if (100..=599).contains(&s) => s,
            _ => {
                if wasm_decision.allow {
                    200
                } else {
                    403
                }
            }
        };

        Ok(Decision {
            profile_id: profile_id.to_string(),
            allow: wasm_decision.allow,
            status_code,
            message: wasm_decision.message,
            rule_id: wasm_decision.rule_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::test_fixtures::{ALLOW_ALL_WAT, BLOCK_ALL_WAT};

    fn make_req(path: &str) -> RequestMeta {
        RequestMeta {
            client_ip: "192.168.1.1".parse().unwrap(),
            method: "GET".to_string(),
            path: path.to_string(),
            query: None,
            user_agent: None,
            headers: HashMap::new(),
            body: None,
        }
    }

    fn engine_with_wat(profile_id: &str, wat: &[u8]) -> WafEngine {
        let mut vm = WasmVm::new().unwrap();
        vm.load_module_from_bytes(profile_id, wat).unwrap();
        WafEngine::from_wasm_vm(vm)
    }

    #[test]
    fn request_meta_construction() {
        let req = make_req("/api/test");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/test");
    }

    #[test]
    fn decide_allow_propagates_correctly() {
        let engine = engine_with_wat("p", ALLOW_ALL_WAT);
        let decision = engine.decide("p", &make_req("/")).unwrap();
        assert!(decision.allow);
        assert_eq!(decision.status_code, 200);
        assert_eq!(decision.profile_id, "p");
    }

    #[test]
    fn decide_block_propagates_correctly() {
        let engine = engine_with_wat("p", BLOCK_ALL_WAT);
        let decision = engine.decide("p", &make_req("/")).unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.status_code, 403);
        assert_eq!(decision.message.as_deref(), Some("blocked"));
        assert_eq!(decision.rule_id.as_deref(), Some("blk"));
    }

    #[test]
    fn invalid_status_defaults_to_403_on_block() {
        // A WAT module that returns allow=false with status=0 (invalid).
        // The engine should default to 403.
        let wat = br#"(module
  (memory (export "memory") 2)
  (func (export "get_req_ptr") (result i32) i32.const 0)
  (func (export "get_result_ptr") (result i32) i32.const 65536)
  (data (i32.const 65536) "{\"allow\":false,\"status\":0}")
  (func (export "decide") (param i32) (result i32) i32.const 26)
)"#;
        let engine = engine_with_wat("p", wat);
        let decision = engine.decide("p", &make_req("/")).unwrap();
        assert!(!decision.allow);
        assert_eq!(
            decision.status_code, 403,
            "invalid status should default to 403 for blocks"
        );
    }

    #[test]
    fn missing_status_defaults_to_200_on_allow() {
        let wat = br#"(module
  (memory (export "memory") 2)
  (func (export "get_req_ptr") (result i32) i32.const 0)
  (func (export "get_result_ptr") (result i32) i32.const 65536)
  (data (i32.const 65536) "{\"allow\":true}")
  (func (export "decide") (param i32) (result i32) i32.const 14)
)"#;
        let engine = engine_with_wat("p", wat);
        let decision = engine.decide("p", &make_req("/")).unwrap();
        assert!(decision.allow);
        assert_eq!(
            decision.status_code, 200,
            "missing status should default to 200 for allows"
        );
    }
}
