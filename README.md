# fywaf

`fywaf` is a minimal open-source WAF that works as an HTTP/1.1 reverse proxy.

## Features (v0.1)

- Reverse proxy to one fixed upstream (`http://host:port`)
- Rule-based allow/block decisions
- Rule dimensions:
  - client IP / CIDR
  - HTTP method
  - path prefix
  - User-Agent substring
- Default action (`allow` or `block`) when no rule matches
- Structured key-value logs via `tracing`

## Quick Start

1. Run an upstream app:

```bash
python3 -m http.server 9000
```

2. Start fywaf:

```bash
cargo run -- --config examples/config.yml
```

3. Send request through fywaf:

```bash
curl -v http://127.0.0.1:8080/
```

## Config

See [`examples/config.yml`](examples/config.yml).

## Notes / Current Limits

- HTTP/1.1 only
- No TLS termination
- Single fixed upstream
- Config reload requires restart
- Chunked request bodies are not supported in this MVP

## License

MIT
