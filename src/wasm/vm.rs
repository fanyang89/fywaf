use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use wasmtime::{Engine, Linker, Module, Store};

use super::types::{WasmDecision, WasmRequest};

// Fuel limit per request to prevent CPU DoS from infinite loops.
const WASM_FUEL_PER_CALL: u64 = 1_000_000;

// WASM linear memory page size (spec-defined, 64 KiB).
const WASM_PAGE_SIZE: u64 = 65536;

// Place the request at the start of the second page to avoid overlapping
// the module's data segments (stack/heap/statics) which reside in the first page.
const REQ_BASE_OFFSET: i32 = WASM_PAGE_SIZE as i32;

// Maximum allowed result length returned by `decide`. Matches the guest's
// RESULT_BUF_LEN (one page / 64 KiB), so a larger value is always a bug or attack.
const MAX_RESULT_LEN: i32 = WASM_PAGE_SIZE as i32;

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
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
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
        store.set_fuel(WASM_FUEL_PER_CALL)?;
        let instance = linker.instantiate(&mut store, &module)?;

        // Collect all export names to avoid consuming the iterator twice.
        let exports: HashSet<String> = instance
            .exports(&mut store)
            .map(|e| e.name().to_string())
            .collect();

        if !exports.contains("memory") {
            bail!("wasm module must export 'memory'");
        }
        if !exports.contains("decide") {
            bail!("wasm module must export 'decide' function");
        }
        if !exports.contains("get_result_ptr") {
            bail!("wasm module must export 'get_result_ptr' function");
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

        // NOTE: A new Store and Instance are created per request. This is
        // functionally correct but may become a throughput bottleneck under
        // high load; consider pooling instances when performance is critical.
        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "abort",
            |_msg: i32, _file: i32, _line: i32, _col: i32| {},
        )?;

        let mut store = Store::new(&self.engine, ());
        store.set_fuel(WASM_FUEL_PER_CALL)?;
        let instance = linker.instantiate(&mut store, &module.module)?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .context("memory export not found")?;

        let decide_func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "decide")
            .context("decide function not found or has wrong signature")?;

        let get_result_ptr_func = instance
            .get_typed_func::<(), i32>(&mut store, "get_result_ptr")
            .context("get_result_ptr function not found or has wrong signature")?;

        let req_json = serde_json::to_string(req).context("failed to serialize request")?;
        let req_bytes = req_json.as_bytes();
        let req_len = req_bytes.len() as i32;
        let req_ptr = REQ_BASE_OFFSET;

        // Ensure memory is large enough for the request plus a full page for
        // the result buffer (the module writes results into its own static buffer
        // which is also expected to fit within linear memory).
        let required_bytes = (req_ptr as u64)
            .checked_add(req_bytes.len() as u64)
            .and_then(|n| n.checked_add(WASM_PAGE_SIZE))
            .context("request size overflow")?;
        let mem_size = memory.data_size(&store) as u64;
        if required_bytes > mem_size {
            let extra_bytes = required_bytes - mem_size;
            let pages_to_grow = extra_bytes.div_ceil(WASM_PAGE_SIZE);
            memory
                .grow(&mut store, pages_to_grow)
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
        if result_len > MAX_RESULT_LEN {
            bail!(
                "decide function returned result length {} exceeding maximum {}",
                result_len,
                MAX_RESULT_LEN
            );
        }

        // The module writes the result into its own buffer (e.g. a static array)
        // and exposes its location via get_result_ptr.
        let result_ptr = get_result_ptr_func
            .call(&mut store, ())
            .context("failed to call get_result_ptr")?;

        if result_ptr < 0 {
            bail!("get_result_ptr returned negative pointer: {}", result_ptr);
        }

        // Validate that the entire result range is within linear memory.
        let mem_size = memory.data_size(&store) as u64;
        let result_end = (result_ptr as u64)
            .checked_add(result_len as u64)
            .context("result pointer + length overflows")?;
        if result_end > mem_size {
            bail!(
                "result [{}, {}) is out of bounds (memory size: {})",
                result_ptr,
                result_end,
                mem_size
            );
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
