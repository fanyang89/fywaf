use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::config::{Action, AppConfig};
use crate::engine::{RequestMeta, WafEngine};

const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
struct SiteRuntime {
    id: String,
    listen: String,
    profile_id: String,
    upstream: Arc<Upstream>,
}

pub async fn run(config: AppConfig, engine: Arc<WafEngine>) -> anyhow::Result<()> {
    let mut sites = Vec::with_capacity(config.sites.len());
    for site in config.sites {
        let upstream = Arc::new(Upstream::parse(&site.upstream.url)?);
        sites.push(SiteRuntime {
            id: site.id,
            listen: site.listen,
            profile_id: site.profile,
            upstream,
        });
    }

    let mut listeners = JoinSet::new();
    for site in sites {
        let site = Arc::new(site);
        let listener = TcpListener::bind(&site.listen)
            .await
            .with_context(|| format!("failed to bind {}", site.listen))?;
        info!(
            site_id = %site.id,
            listen = %site.listen,
            profile_id = %site.profile_id,
            upstream = %site.upstream.authority(),
            "site listener started",
        );

        let engine = Arc::clone(&engine);
        listeners.spawn(async move { accept_loop(listener, site, engine).await });
    }

    while let Some(result) = listeners.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(join_err) => return Err(anyhow::anyhow!("listener task failed: {}", join_err)),
        }
    }

    bail!("all listeners stopped unexpectedly")
}

async fn accept_loop(
    listener: TcpListener,
    site: Arc<SiteRuntime>,
    engine: Arc<WafEngine>,
) -> anyhow::Result<()> {
    loop {
        let (socket, peer) = listener.accept().await.context("accept failed")?;
        let site = Arc::clone(&site);
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(socket, peer, site, engine).await {
                warn!(client = %peer, error = %err, "connection failed");
            }
        });
    }
}

#[derive(Debug, Clone)]
struct Upstream {
    host: String,
    port: u16,
    base_path: String,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    version: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Upstream {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        let rest = raw
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("only http:// upstream is supported"))?;
        if rest.is_empty() {
            bail!("empty upstream URL");
        }

        let (authority, mut path) = match rest.split_once('/') {
            Some((auth, p)) => (auth, format!("/{}", p)),
            None => (rest, "/".to_string()),
        };

        if authority.is_empty() {
            bail!("upstream authority is empty");
        }
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if path.len() > 1 && path.ends_with('/') {
            path.pop();
        }

        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => {
                let parsed = p.parse::<u16>().context("invalid upstream port")?;
                (h.to_string(), parsed)
            }
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            bail!("upstream host is empty");
        }

        Ok(Self {
            host,
            port,
            base_path: path,
        })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    site: Arc<SiteRuntime>,
    engine: Arc<WafEngine>,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let client_ip = peer.ip();
    let request = read_http_request(&mut client).await?;
    let ua = request.headers.get("user-agent").cloned();

    let decision = engine.decide(
        &site.profile_id,
        &RequestMeta {
            client_ip,
            method: request.method.clone(),
            path: request.path.clone(),
            user_agent: ua.clone(),
        },
    )?;

    if decision.action == Action::Block {
        write_blocked_response(&mut client, decision.status_code).await?;
        info!(
            site_id = %site.id,
            profile_id = %decision.profile_id,
            client_ip = %client_ip,
            method = %request.method,
            path = %request.path,
            status = decision.status_code,
            waf_action = "block",
            matched_rule_id = decision.matched_rule_id.as_deref().unwrap_or("-"),
            latency_ms = started.elapsed().as_millis() as u64,
            "request blocked",
        );
        return Ok(());
    }

    let mut upstream_stream = TcpStream::connect((site.upstream.host.as_str(), site.upstream.port))
        .await
        .context("failed to connect to upstream")?;

    let upstream_request = build_upstream_request(&request, &site.upstream, client_ip)?;
    upstream_stream
        .write_all(&upstream_request)
        .await
        .context("failed to write request to upstream")?;
    upstream_stream
        .flush()
        .await
        .context("failed to flush upstream request")?;

    let copied = tokio::io::copy(&mut upstream_stream, &mut client)
        .await
        .context("failed to relay upstream response")?;

    info!(
        site_id = %site.id,
        profile_id = %decision.profile_id,
        client_ip = %client_ip,
        method = %request.method,
        path = %request.path,
        status = 200u16,
        waf_action = "allow",
        matched_rule_id = decision.matched_rule_id.as_deref().unwrap_or("-"),
        upstream = %site.upstream.authority(),
        response_bytes = copied,
        latency_ms = started.elapsed().as_millis() as u64,
        "request forwarded",
    );

    Ok(())
}

async fn write_blocked_response(stream: &mut TcpStream, status: u16) -> anyhow::Result<()> {
    let reason = reason_phrase(status);
    let body = format!("blocked by fywaf ({status})\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );

    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write blocked response")?;
    stream.flush().await.context("failed to flush response")?;
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Blocked",
    }
}

async fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if buffer.len() > MAX_HEADER_SIZE {
            bail!("request headers exceed {} bytes", MAX_HEADER_SIZE);
        }
        let mut chunk = [0u8; 2048];
        let read = stream.read(&mut chunk).await.context("read failed")?;
        if read == 0 {
            bail!("client closed before sending headers");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_header_end(&buffer) {
            break pos;
        }
    };

    let header_bytes = &buffer[..header_end];
    let header_text = str::from_utf8(header_bytes).context("request headers are not utf-8")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request line"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing version"))?
        .to_string();

    if parts.next().is_some() {
        bail!("invalid request line");
    }
    if !version.starts_with("HTTP/1.") {
        bail!("only HTTP/1.x is supported");
    }

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("malformed header line"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    if headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        bail!("chunked request bodies are not supported in MVP");
    }

    let content_length = headers
        .get("content-length")
        .map(|v| v.parse::<usize>().context("invalid content-length"))
        .transpose()?
        .unwrap_or(0);

    if content_length > MAX_BODY_SIZE {
        bail!("request body exceeds {} bytes", MAX_BODY_SIZE);
    }

    let already_read_body = buffer.len().saturating_sub(header_end + 4);
    let mut body = Vec::with_capacity(content_length);
    if already_read_body > 0 {
        body.extend_from_slice(&buffer[header_end + 4..]);
    }
    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let read = stream.read(&mut chunk).await.context("read body failed")?;
        if read == 0 {
            bail!("client closed while sending body");
        }
        body.extend_from_slice(&chunk[..read]);
    }

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body,
    })
}

fn build_upstream_request(
    request: &HttpRequest,
    upstream: &Upstream,
    client_ip: IpAddr,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(request.body.len() + 1024);
    let path = merge_upstream_path(&upstream.base_path, &request.path);
    out.extend_from_slice(
        format!("{} {} {}\r\n", request.method, path, request.version).as_bytes(),
    );
    out.extend_from_slice(format!("Host: {}\r\n", upstream.authority()).as_bytes());

    for (k, v) in &request.headers {
        if is_hop_by_hop(k) || k == "host" || k == "x-forwarded-for" {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    let xff = match request.headers.get("x-forwarded-for") {
        Some(existing) if !existing.is_empty() => format!("{existing}, {client_ip}"),
        _ => client_ip.to_string(),
    };
    out.extend_from_slice(format!("x-forwarded-for: {xff}\r\n").as_bytes());
    out.extend_from_slice(b"Connection: close\r\n");

    if !request.body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", request.body.len()).as_bytes());
    } else if !request.headers.contains_key("content-length") {
        out.extend_from_slice(b"Content-Length: 0\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&request.body);

    if out.len() > MAX_HEADER_SIZE + MAX_BODY_SIZE + 1024 {
        bail!("upstream request is too large");
    }

    Ok(out)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn merge_upstream_path(base_path: &str, incoming: &str) -> String {
    let incoming_path = if incoming.starts_with('/') {
        incoming.to_string()
    } else {
        format!("/{incoming}")
    };
    if base_path == "/" {
        incoming_path
    } else if incoming_path == "/" {
        base_path.to_string()
    } else {
        format!("{base_path}{incoming_path}")
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_upstream_url() {
        let up = Upstream::parse("http://127.0.0.1:9000/api").unwrap();
        assert_eq!(up.host, "127.0.0.1");
        assert_eq!(up.port, 9000);
        assert_eq!(up.base_path, "/api");
    }

    #[test]
    fn merge_path() {
        assert_eq!(merge_upstream_path("/", "/a"), "/a");
        assert_eq!(merge_upstream_path("/api", "/v1"), "/api/v1");
        assert_eq!(merge_upstream_path("/api", "/"), "/api");
    }

    #[test]
    fn header_end_detected() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(data), Some(23));
    }
}
