# fywaf

`fywaf` is a minimal open-source WAF that works as an HTTP/1.1 reverse proxy with WASM-based rules engine.

## Features

- Multi-site reverse proxy (`site => listen port => one upstream`)
- Per-site WAF profile binding (`site => profile`)
- **WASM-based rules engine** - each profile loads a user-provided WASM module
- Fast and secure rule execution using [wasmtime](https://wasmtime.dev/)
- Structured key-value logs via `tracing`

## Quick Start

1. Build a WASM rule module:

```bash
# Add the wasm32-unknown-unknown target (no WASI needed)
rustup target add wasm32-unknown-unknown

# Build via Cargo (recommended) using a separate crate targeting wasm32-unknown-unknown:
cargo build --target wasm32-unknown-unknown --release
# Copy the resulting .wasm file to examples/wasm/public.wasm
```

2. Run an upstream app:

```bash
python3 -m http.server 9000
```

3. Start fywaf:

```bash
cargo run -- run --config examples/config.yml
```

4. Send request through fywaf:

```bash
curl -v http://127.0.0.1:8080/
```

## Configuration

See [`examples/config.yml`](examples/config.yml):

```yaml
sites:
  - id: "blog"
    listen: "0.0.0.0:8080"
    upstream:
      url: "http://127.0.0.1:9000"
    profile: "public"

profiles:
  - id: "public"
    wasm_path: "wasm/public.wasm"
```

## WASM Module Interface

Your WASM module must export:

1. `memory` — linear memory
2. `get_req_ptr() -> i32` — returns the address of a guest-owned request buffer; the host writes the request JSON here before calling `decide`
3. `decide(req_len: i32) -> i32` — evaluates the request and returns the byte length of the decision JSON written into the result buffer
4. `get_result_ptr() -> i32` — returns the address of the result buffer; the host reads `decide`'s return-value many bytes from here

### Input Format (JSON)

```json
{
  "client_ip": "192.168.1.1",
  "method": "POST",
  "path": "/api/login",
  "query": "user=admin",
  "user_agent": "Mozilla/5.0...",
  "headers": {"content-type": "application/json"},
  "body": "{\"username\":\"admin\"}"
}
```

### Output Format (JSON)

`decide` writes the result JSON into the guest's result buffer and returns its byte length.
The host locates the buffer by calling `get_result_ptr`:

```json
{
  "allow": false,
  "status": 403,
  "message": "SQL injection detected",
  "rule_id": "block-sqli"
}
```

The `status` field is optional; the host defaults to 200 for allowed requests and 403 for blocked ones.

### Example WASM Module (Rust)

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    user_agent: Option<String>,
    body: Option<String>,
    // ... other fields
}

#[derive(Serialize)]
struct Decision {
    allow: bool,
    status: u16,
    message: Option<String>,
    rule_id: Option<String>,
}

const REQ_BUF_LEN: usize = 65536;
const RESULT_BUF_LEN: usize = 65536;
static mut REQ_BUF: [u8; REQ_BUF_LEN] = [0; REQ_BUF_LEN];
static mut RESULT_BUF: [u8; RESULT_BUF_LEN] = [0; RESULT_BUF_LEN];

/// Returns the address of the request buffer. The host writes the request JSON here.
#[no_mangle]
pub extern "C" fn get_req_ptr() -> *const u8 {
    unsafe { REQ_BUF.as_ptr() }
}

/// Called by the host with the byte length of the JSON in the request buffer.
/// Returns the byte length of the decision JSON written into RESULT_BUF.
#[no_mangle]
pub extern "C" fn decide(req_len: usize) -> i32 {
    let req_slice = unsafe { &REQ_BUF[..req_len.min(REQ_BUF_LEN)] };
    let req: Request = serde_json::from_slice(req_slice).unwrap();

    let decision = if req.path.contains("/admin") {
        Decision { allow: false, status: 403, message: Some("blocked".into()), rule_id: None }
    } else {
        Decision { allow: true, status: 200, message: None, rule_id: None }
    };

    let json = serde_json::to_string(&decision).unwrap();
    let bytes = json.as_bytes();
    // Clamp to buffer length to avoid panics on large outputs.
    let copy_len = bytes.len().min(RESULT_BUF_LEN);
    unsafe { RESULT_BUF[..copy_len].copy_from_slice(&bytes[..copy_len]); }
    copy_len as i32
}

/// The host calls this after `decide` to locate the result buffer.
#[no_mangle]
pub extern "C" fn get_result_ptr() -> *const u8 {
    unsafe { RESULT_BUF.as_ptr() }
}
```

## Notes / Current Limits

- HTTP/1.1 only
- No TLS termination
- `site` is matched by listen port
- Config reload requires restart
- Chunked request bodies are not supported
- Upstream only supports `http://...`

## License

MIT
