mod types;
mod vm;

pub use types::WasmRequest;
pub use vm::WasmVm;

/// Shared WAT fixtures for unit and integration tests.
#[cfg(test)]
pub(crate) mod test_fixtures {
    /// Minimal WAT module that always allows every request (status 200).
    /// Result buffer at page 1 (offset 65536) pre-initialized with allow JSON;
    /// `decide` returns the byte length of that JSON (27).
    pub(crate) const ALLOW_ALL_WAT: &[u8] = br#"(module
  (memory (export "memory") 2)
  (func (export "get_req_ptr") (result i32) i32.const 0)
  (func (export "get_result_ptr") (result i32) i32.const 65536)
  (data (i32.const 65536) "{\"allow\":true,\"status\":200}")
  (func (export "decide") (param i32) (result i32) i32.const 27)
)"#;

    /// Minimal WAT module that always blocks every request with 403.
    /// Result JSON: `{"allow":false,"status":403,"message":"blocked","rule_id":"blk"}` (64 bytes).
    pub(crate) const BLOCK_ALL_WAT: &[u8] = br#"(module
  (memory (export "memory") 2)
  (func (export "get_req_ptr") (result i32) i32.const 0)
  (func (export "get_result_ptr") (result i32) i32.const 65536)
  (data (i32.const 65536) "{\"allow\":false,\"status\":403,\"message\":\"blocked\",\"rule_id\":\"blk\"}")
  (func (export "decide") (param i32) (result i32) i32.const 64)
)"#;
}
