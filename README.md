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

Your WASM module must:

1. Export a `memory` linear memory
2. Export a `decide(req_ptr: i32, req_len: i32) -> i32` function
3. Export a `get_result_ptr() -> i32` function that returns the address of the result buffer

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

The `decide` function writes the result JSON into an internal buffer and returns its length.
The host retrieves the buffer address by calling the exported `get_result_ptr` function:

```json
{
  "allow": false,
  "status": 403,
  "message": "SQL injection detected",
  "rule_id": "block-sqli"
}
```

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

static mut RESULT_BUF: [u8; 65536] = [0; 65536];
const RESULT_BUF_LEN: usize = 65536;

#[no_mangle]
pub extern "C" fn decide(req_ptr: *const u8, req_len: usize) -> i32 {
    let req_slice = unsafe { std::slice::from_raw_parts(req_ptr, req_len) };
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
