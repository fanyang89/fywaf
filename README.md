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
# Create a simple rule module (see examples/wasm/public.rs for reference)
rustup target add wasm32-wasip2
rustc examples/wasm/public.rs --target wasm32-wasip2 -o examples/wasm/public.wasm
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

Write result to memory starting at offset `req_len + 4` and return the length:

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
    unsafe { RESULT_BUF[..bytes.len()].copy_from_slice(bytes); }
    bytes.len() as i32
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
