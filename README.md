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
  - generic conditions (`target + operator`) for method/path/query/body/header/ip
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
cargo run --bin fywaf-build -- --config examples/config.yml --out examples/rules.snapshot.bin
cargo run -- --config examples/config.yml
```

3. Send request through fywaf:

```bash
curl -v http://127.0.0.1:8080/
curl -v http://127.0.0.1:8081/admin
```

## Config

See [`examples/config.yml`](examples/config.yml).

Condition operators currently supported in `rules[].conditions`:

- `eq`
- `contains`
- `prefix`
- `suffix`
- `regex`
- `in`
- `ip_match` (for `client_ip` target)

Condition transforms currently supported in `rules[].conditions[].transforms`:

- `none`
- `lowercase`
- `url_decode`
- `compress_whitespace`
- `remove_nulls`

Compatibility report command for CRS-style rules:

```bash
cargo run --bin fywaf-compat -- --rules-dir /path/to/coreruleset/rules
```

CRS import command (v1 subset):

```bash
cargo run --bin fywaf-import-crs -- --rules-dir /path/to/coreruleset/rules --out examples/crs.import.yml --report-out examples/crs.import.report.txt
```

Then build the snapshot and point `engine.snapshot_path` to the `.bin` output:

```bash
cargo run --bin fywaf-build -- --config examples/config.yml --out examples/rules.snapshot.bin
```

## Notes / Current Limits

- HTTP/1.1 only
- No TLS termination
- `site` is matched by listen port
- Config reload requires restart
- `engine.snapshot_path` must point to a binary snapshot (`.bin`) built by `fywaf-build`
- Chunked request bodies are not supported in this MVP
- Upstream only supports `http://...`

## License

MIT
