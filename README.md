# fywaf

`fywaf` is a minimal open-source WAF that works as an HTTP/1.1 reverse proxy.

## Features (v0.2)

- Multi-site reverse proxy (`site => listen port => one upstream`)
- Per-site WAF profile binding (`site => profile`)
- Per-profile default action and rule set
- Rule dimensions:
  - client IP / CIDR
  - HTTP method
  - path prefix
  - User-Agent substring
- Fail-fast config validation for invalid `site -> profile` mappings
- Structured key-value logs via `tracing`

## Quick Start

1. Run two upstream apps:

```bash
python3 -m http.server 9000
python3 -m http.server 9001
```

2. Start fywaf:

```bash
cargo run -- --config examples/config.yml
```

3. Send request through fywaf:

```bash
curl -v http://127.0.0.1:8080/
curl -v http://127.0.0.1:8081/admin
```

## Config

See [`examples/config.yml`](examples/config.yml).

## Notes / Current Limits

- HTTP/1.1 only
- No TLS termination
- `site` is matched by listen port
- Config reload requires restart
- Chunked request bodies are not supported in this MVP
- Upstream only supports `http://...`

## License

MIT
