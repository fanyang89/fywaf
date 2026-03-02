use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use wasmtime::{Engine, Linker, Module, Store};

use super::types::{WasmDecision, WasmRequest};

// Fuel limit per request to prevent CPU DoS from infinite loops.
const WASM_FUEL_PER_CALL: u64 = 1_000_000;

// WASM linear memory page size (spec-defined, 64 KiB).
const WASM_PAGE_SIZE: u64 = 65536;

// Maximum allowed result length returned by `decide`. Matches the guest's
// RESULT_BUF_LEN (one page / 64 KiB), so a larger value is always a bug or attack.
const MAX_RESULT_LEN: i32 = WASM_PAGE_SIZE as i32;

// Maximum serialized request JSON size written to the guest buffer.
// Guests must allocate at least this many bytes for their request buffer.
// Requests that serialize to more bytes are rejected without invoking the WASM module.
const MAX_REQUEST_JSON_LEN: usize = WASM_PAGE_SIZE as usize; // 64 KiB

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

    fn load_module_from_bytes(&mut self, profile_id: &str, wasm_bytes: &[u8]) -> Result<()> {
        // Module::new accepts both binary .wasm and text .wat formats.
        let module = Module::new(&self.engine, wasm_bytes).context("failed to compile wasm module")?;

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

        // Validate required exports and their signatures at load time so
        // miscompiled or incompatible modules fail fast during configuration.
        instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("wasm module must export 'memory'"))?;
        instance
            .get_typed_func::<(), i32>(&mut store, "get_req_ptr")
            .context("wasm module must export 'get_req_ptr' with signature () -> i32")?;
        instance
            .get_typed_func::<i32, i32>(&mut store, "decide")
            .context("wasm module must export 'decide' with signature (i32) -> i32")?;
        instance
            .get_typed_func::<(), i32>(&mut store, "get_result_ptr")
            .context("wasm module must export 'get_result_ptr' with signature () -> i32")?;

        self.modules
            .insert(profile_id.to_string(), WasmModule { module });
        Ok(())
    }

    pub fn load_module(&mut self, profile_id: &str, wasm_path: &Path) -> Result<()> {
        let wasm_bytes = std::fs::read(wasm_path)
            .with_context(|| format!("failed to read wasm file: {}", wasm_path.display()))?;
        self.load_module_from_bytes(profile_id, &wasm_bytes)
            .with_context(|| format!("failed to load wasm module: {}", wasm_path.display()))
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

        let get_req_ptr_func = instance
            .get_typed_func::<(), i32>(&mut store, "get_req_ptr")
            .context("get_req_ptr function not found or has wrong signature")?;

        let decide_func = instance
            .get_typed_func::<i32, i32>(&mut store, "decide")
            .context("decide function not found or has wrong signature")?;

        let get_result_ptr_func = instance
            .get_typed_func::<(), i32>(&mut store, "get_result_ptr")
            .context("get_result_ptr function not found or has wrong signature")?;

        let req_json = serde_json::to_string(req).context("failed to serialize request")?;
        let req_bytes = req_json.as_bytes();
        let req_len = req_bytes.len() as i32;

        // Reject requests whose serialized JSON exceeds the agreed host-side cap.
        // This prevents writing past the guest's static request buffer and avoids
        // unbounded memory growth allocations (potential DoS).
        if req_bytes.len() > MAX_REQUEST_JSON_LEN {
            bail!(
                "serialized request ({} bytes) exceeds the maximum allowed length ({} bytes)",
                req_bytes.len(),
                MAX_REQUEST_JSON_LEN
            );
        }

        // Ask the guest for the address of its request buffer so we never
        // write into an arbitrary hard-coded offset.
        let req_ptr = get_req_ptr_func
            .call(&mut store, ())
            .context("failed to call get_req_ptr")?;
        if req_ptr < 0 {
            bail!("get_req_ptr returned negative pointer: {}", req_ptr);
        }
        let req_ptr_u64 = req_ptr as u32 as u64;

        // Ensure memory is large enough to hold the request at the guest-provided offset.
        let req_end = req_ptr_u64
            .checked_add(req_bytes.len() as u64)
            .context("request size overflow")?;
        let mem_size = memory.data_size(&store) as u64;
        // The guest's static buffer must reside within the currently-allocated
        // memory; only the tail (for the request payload) may need growing.
        if req_ptr_u64 >= mem_size {
            bail!(
                "get_req_ptr returned pointer {} outside linear memory (size: {})",
                req_ptr,
                mem_size
            );
        }
        if req_end > mem_size {
            let extra_bytes = req_end - mem_size;
            let pages_to_grow = extra_bytes.div_ceil(WASM_PAGE_SIZE);
            memory
                .grow(&mut store, pages_to_grow)
                .context("failed to grow memory")?;
        }

        memory
            .write(&mut store, req_ptr_u64 as usize, req_bytes)
            .context("failed to write request to memory")?;

        let result_len = decide_func
            .call(&mut store, req_len)
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

        // Replenish fuel before get_result_ptr so that a module which consumed
        // all remaining fuel inside `decide` cannot cause this retrieval to fail.
        store.set_fuel(WASM_FUEL_PER_CALL)?;

        // The module writes the result into its own buffer (e.g. a static array)
        // and exposes its location via get_result_ptr.
        let result_ptr = get_result_ptr_func
            .call(&mut store, ())
            .context("failed to call get_result_ptr")?;

        if result_ptr < 0 {
            bail!("get_result_ptr returned negative pointer: {}", result_ptr);
        }
        let result_ptr_u64 = result_ptr as u32 as u64;

        // Validate that the entire result range is within linear memory.
        let mem_size = memory.data_size(&store) as u64;
        let result_end = result_ptr_u64
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
            .read(&store, result_ptr_u64 as usize, &mut result_bytes)
            .context("failed to read result from memory")?;

        let result_json = String::from_utf8(result_bytes).context("result is not valid utf-8")?;

        let decision: WasmDecision = serde_json::from_str(&result_json)
            .with_context(|| format!("failed to parse decision: {}", result_json))?;

        Ok(decision)
    }

    pub fn has_profile(&self, profile_id: &str) -> bool {
        self.modules.contains_key(profile_id)
    }

    /// Test-only entry point: load a module directly from bytes (binary WASM or WAT text).
    #[cfg(test)]
    pub(crate) fn load_module_bytes(&mut self, profile_id: &str, wasm_bytes: &[u8]) -> Result<()> {
        self.load_module_from_bytes(profile_id, wasm_bytes)
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
    use crate::wasm::test_fixtures::{ALLOW_ALL_WAT, BLOCK_ALL_WAT};
    use std::collections::HashMap;

    fn make_request() -> WasmRequest<'static> {
        WasmRequest {
            client_ip: "127.0.0.1",
            method: "GET",
            path: "/",
            query: None,
            user_agent: None,
            headers: HashMap::new(),
            body: None,
        }
    }

    #[test]
    fn wasm_vm_creation() {
        let vm = WasmVm::new();
        assert!(vm.is_ok());
    }

    #[test]
    fn missing_profile() {
        let vm = WasmVm::new().unwrap();
        let req = make_request();
        let result = vm.decide("nonexistent", &req);
        assert!(result.is_err());
    }

    #[test]
    fn decide_allow_all() {
        let mut vm = WasmVm::new().unwrap();
        vm.load_module_bytes("allow", ALLOW_ALL_WAT).unwrap();
        let decision = vm.decide("allow", &make_request()).unwrap();
        assert!(decision.allow);
        assert_eq!(decision.status, Some(200));
    }

    #[test]
    fn decide_block_all() {
        let mut vm = WasmVm::new().unwrap();
        vm.load_module_bytes("block", BLOCK_ALL_WAT).unwrap();
        let decision = vm.decide("block", &make_request()).unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.status, Some(403));
        assert_eq!(decision.message.as_deref(), Some("blocked"));
        assert_eq!(decision.rule_id.as_deref(), Some("blk"));
    }

    #[test]
    fn request_too_large_is_rejected() {
        let mut vm = WasmVm::new().unwrap();
        vm.load_module_bytes("allow", ALLOW_ALL_WAT).unwrap();
        // Build a body that causes the serialized JSON to exceed MAX_REQUEST_JSON_LEN.
        let big_body = "x".repeat(MAX_REQUEST_JSON_LEN + 1);
        let req = WasmRequest {
            client_ip: "127.0.0.1",
            method: "GET",
            path: "/",
            query: None,
            user_agent: None,
            headers: HashMap::new(),
            body: Some(&big_body),
        };
        let result = vm.decide("allow", &req);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exceeds the maximum allowed length"), "unexpected error: {msg}");
    }
}
