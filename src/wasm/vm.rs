use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use wasmtime::{Engine, Linker, Module, Store};

use super::types::{WasmDecision, WasmRequest};

pub struct WasmModule {
    module: Module,
}

pub struct WasmVm {
    engine: Engine,
    modules: HashMap<String, WasmModule>,
}

impl std::fmt::Debug for WasmVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmVm")
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl WasmVm {
    pub fn new() -> Result<Self> {
        let engine = Engine::default();
        Ok(Self {
            engine,
            modules: HashMap::new(),
        })
    }

    pub fn load_module(&mut self, profile_id: &str, wasm_path: &Path) -> Result<()> {
        let wasm_bytes = std::fs::read(wasm_path)
            .with_context(|| format!("failed to read wasm file: {}", wasm_path.display()))?;

        let module = Module::from_binary(&self.engine, &wasm_bytes)
            .with_context(|| format!("failed to compile wasm module: {}", wasm_path.display()))?;

        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "abort",
            |_msg: i32, _file: i32, _line: i32, _col: i32| {
                tracing::warn!("wasm abort called");
            },
        )?;

        let mut store = Store::new(&self.engine, ());
        let instance = linker.instantiate(&mut store, &module)?;
        let mut instance_exports = instance.exports(&mut store);

        let has_memory = instance_exports.any(|e| e.name() == "memory");
        let has_decide = instance_exports.any(|e| e.name() == "decide");

        if !has_memory {
            bail!("wasm module must export 'memory'");
        }
        if !has_decide {
            bail!("wasm module must export 'decide' function");
        }

        self.modules
            .insert(profile_id.to_string(), WasmModule { module });
        Ok(())
    }

    pub fn decide(&self, profile_id: &str, req: &WasmRequest) -> Result<WasmDecision> {
        let module = self
            .modules
            .get(profile_id)
            .ok_or_else(|| anyhow::anyhow!("profile not found: {}", profile_id))?;

        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "abort",
            |_msg: i32, _file: i32, _line: i32, _col: i32| {},
        )?;

        let mut store = Store::new(&self.engine, ());
        let instance = linker.instantiate(&mut store, &module.module)?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .context("memory export not found")?;

        let decide_func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "decide")
            .context("decide function not found or has wrong signature")?;

        let req_json = serde_json::to_string(req).context("failed to serialize request")?;
        let req_bytes = req_json.as_bytes();
        let req_len = req_bytes.len() as i32;

        let mem_size = memory.data_size(&store);
        let req_ptr = 0i32;
        let result_ptr = req_len + 4;

        if result_ptr + 65536 > mem_size as i32 {
            memory
                .grow(&mut store, 2)
                .context("failed to grow memory")?;
        }

        memory
            .write(&mut store, req_ptr as usize, req_bytes)
            .context("failed to write request to memory")?;

        let result_len = decide_func
            .call(&mut store, (req_ptr, req_len))
            .context("failed to call decide function")?;

        if result_len <= 0 {
            bail!("decide function returned invalid length: {}", result_len);
        }

        let mut result_bytes = vec![0u8; result_len as usize];
        memory
            .read(&store, result_ptr as usize, &mut result_bytes)
            .context("failed to read result from memory")?;

        let result_json = String::from_utf8(result_bytes).context("result is not valid utf-8")?;

        let decision: WasmDecision = serde_json::from_str(&result_json)
            .with_context(|| format!("failed to parse decision: {}", result_json))?;

        Ok(decision)
    }

    pub fn has_profile(&self, profile_id: &str) -> bool {
        self.modules.contains_key(profile_id)
    }
}

impl Default for WasmVm {
    fn default() -> Self {
        Self::new().expect("failed to create WasmVm")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn wasm_vm_creation() {
        let vm = WasmVm::new();
        assert!(vm.is_ok());
    }

    #[test]
    fn missing_profile() {
        let vm = WasmVm::new().unwrap();
        let req = WasmRequest {
            client_ip: "127.0.0.1",
            method: "GET",
            path: "/",
            query: None,
            user_agent: None,
            headers: HashMap::new(),
            body: None,
        };
        let result = vm.decide("nonexistent", &req);
        assert!(result.is_err());
    }
}
