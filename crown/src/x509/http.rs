//! A minimal HTTP/1.1 client for PKI URL fetching, the analogue of OpenSSL's
//! `OSSL_HTTP_get`/`OSSL_HTTP_transfer`: downloading CRLs from
//! `crlDistributionPoints`/`freshestCRL` URLs, certificates from `caIssuers`
//! and posting OCSP requests.
//!
//! Only plain `http://` URLs are supported: PKI payloads are signed by their
//! issuer, so the transport does not need TLS (OpenSSL's `OSSL_HTTP` makes
//! the same split; `https` URLs fail with a dedicated error). Redirects (301,
//! 302, 303, 307 and 308) are followed up to five hops, chunked transfer
//! encoding is decoded, and response bodies are capped to guard against
//! runaway servers.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{CryptoError, CryptoResult};

/// Largest accepted response body (the header block is capped separately).
pub const MAX_RESPONSE_SIZE: usize = 16 << 20;
/// Largest accepted header block.
const MAX_HEADER_SIZE: usize = 64 << 10;
/// Redirect hops before giving up.
const MAX_REDIRECTS: usize = 5;
/// Connect/read/write timeout when none is given.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A parsed `http://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// The host (without port; brackets stripped from IPv6 literals).
    pub host: String,
    /// The port (80 for URLs without an explicit one).
    pub port: u16,
    /// The request path including any query string (never empty).
    pub path: String,
}

/// An HTTP response with the body fully read.
#[derive(Debug, Clone)]
pub struct Response {
    /// The status code (e.g. 200).
    pub status: u16,
    /// The `Content-Type` header, when present.
    pub content_type: Option<String>,
    /// The response body (decoded from chunked encoding when needed).
    pub body: Vec<u8>,
    headers: Vec<(String, String)>,
}

/// Parse an `http://` URL into its pieces. `https://` is rejected with a
/// dedicated error; anything else fails as invalid.
pub fn parse_url(url: &str) -> CryptoResult<Url> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        if url.contains("://") {
            CryptoError::StrError("http: only plain http:// URLs are supported")
        } else {
            CryptoError::StrError("http: invalid URL")
        }
    })?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, String::from("/")),
    };
    // Userinfo is allowed by RFC 3986 but never used by PKI URLs; skip it.
    let authority = authority
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(authority);
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed
            .find(']')
            .ok_or(CryptoError::StrError("http: invalid IPv6 authority"))?;
        let port = bracketed[closing + 1..]
            .strip_prefix(':')
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|_| CryptoError::StrError("http: invalid port"))?;
        (String::from(&bracketed[..closing]), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| CryptoError::StrError("http: invalid port"))?;
                (String::from(host), Some(port))
            }
            None => (String::from(authority), None),
        }
    };
    if host.is_empty() {
        return Err(CryptoError::StrError("http: empty host"));
    }
    Ok(Url {
        host,
        port: port.unwrap_or(80),
        path,
    })
}

/// `GET url`, following redirects.
pub fn get(url: &str, timeout: Option<Duration>) -> CryptoResult<Response> {
    request(url, "GET", None, None, timeout)
}

/// `POST body` with a `Content-Type`, following redirects.
pub fn post(
    url: &str,
    content_type: &str,
    body: &[u8],
    timeout: Option<Duration>,
) -> CryptoResult<Response> {
    request(url, "POST", Some(content_type), Some(body), timeout)
}

fn request(
    url: &str,
    method: &str,
    mut content_type: Option<&str>,
    mut body: Option<&[u8]>,
    timeout: Option<Duration>,
) -> CryptoResult<Response> {
    let mut url = String::from(url);
    let mut method = String::from(method);
    for _ in 0..=MAX_REDIRECTS {
        let response = once(&url, &method, content_type, body, timeout)?;
        if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            return Ok(response);
        }
        let location = response
            .header("location")
            .map(String::from)
            .ok_or(CryptoError::StrError("http: redirect without location"))?;
        url = resolve_redirect(&url, &location)?;
        // 301/302/303 switch the method to GET and drop the body.
        if matches!(response.status, 301..=303) {
            method = String::from("GET");
            content_type = None;
            body = None;
        }
    }
    Err(CryptoError::StrError("http: too many redirects"))
}

/// Resolve a `Location` header against the current URL (absolute or
/// same-origin relative). Redirects to `https` fail explicitly.
fn resolve_redirect(base: &str, location: &str) -> CryptoResult<String> {
    if location.starts_with("https://") {
        return Err(CryptoError::StrError(
            "http: redirect to https is not supported",
        ));
    }
    if let Some(rest) = location.strip_prefix("http://") {
        return Ok(format!("http://{rest}"));
    }
    let base = parse_url(base)?;
    if location.starts_with('/') {
        return Ok(format!("http://{}:{}{location}", base.host, base.port));
    }
    // A bare relative path replaces the last path segment.
    let directory = match base.path.rfind('/') {
        Some(index) => &base.path[..=index],
        None => "/",
    };
    Ok(format!(
        "http://{}:{}{directory}{location}",
        base.host, base.port
    ))
}

/// One request/response exchange without redirect handling.
fn once(
    url: &str,
    method: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    timeout: Option<Duration>,
) -> CryptoResult<Response> {
    let parsed = parse_url(url)?;
    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
    let mut stream = connect(&parsed, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| CryptoError::StrError("http: cannot set read timeout"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| CryptoError::StrError("http: cannot set write timeout"))?;
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: crown\r\nAccept: */*\r\nConnection: close\r\n",
        method,
        parsed.path,
        host_header(&parsed),
    );
    if let Some(content_type) = content_type {
        request.push_str("Content-Type: ");
        request.push_str(content_type);
        request.push_str("\r\n");
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| CryptoError::StrError("http: failed to send request"))?;
    if let Some(body) = body {
        stream
            .write_all(body)
            .map_err(|_| CryptoError::StrError("http: failed to send request body"))?;
    }
    let mut raw = Vec::new();
    (&mut stream)
        .take((MAX_HEADER_SIZE + MAX_RESPONSE_SIZE) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| CryptoError::StrError("http: failed to read response"))?;
    parse_response(&raw)
}

/// The `Host` header value: IPv6 literals stay bracketed, the default port is
/// omitted.
fn host_header(url: &Url) -> String {
    if url.host.contains(':') {
        format!("[{}]:{}", url.host, url.port)
    } else if url.port == 80 {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    }
}

fn connect(url: &Url, timeout: Duration) -> CryptoResult<TcpStream> {
    let addresses = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|_| CryptoError::StrError("http: name resolution failed"))?;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, timeout) {
            return Ok(stream);
        }
    }
    Err(CryptoError::StrError("http: connect failed"))
}

impl Response {
    /// A response header value by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn parse_response(raw: &[u8]) -> CryptoResult<Response> {
    let split =
        find_headers_end(raw).ok_or(CryptoError::StrError("http: truncated response headers"))?;
    let head = core::str::from_utf8(&raw[..split])
        .map_err(|_| CryptoError::StrError("http: invalid response headers"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(CryptoError::StrError("http: empty response"))?;
    let status = status_line
        .strip_prefix("HTTP/")
        .and_then(|rest| rest.split_once(' '))
        .and_then(|(_, code)| code.split(' ').next())
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(CryptoError::StrError("http: invalid status line"))?;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((String::from(name.trim()), String::from(value.trim())));
        }
    }
    let header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let body = &raw[split + 4..];
    let chunked = header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        decode_chunked(body)?
    } else if let Some(length) = header("content-length") {
        let length: usize = length
            .trim()
            .parse()
            .map_err(|_| CryptoError::StrError("http: invalid content-length"))?;
        if length > MAX_RESPONSE_SIZE {
            return Err(CryptoError::StrError("http: response too large"));
        }
        if body.len() < length {
            return Err(CryptoError::StrError("http: truncated response body"));
        }
        body[..length].to_vec()
    } else {
        // Connection: close implies the body ends at EOF.
        body.to_vec()
    };
    let content_type = header("content-type").map(String::from);
    Ok(Response {
        status,
        content_type,
        body,
        headers,
    })
}

fn find_headers_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_chunked(mut body: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = body.windows(2).position(|window| window == b"\r\n") else {
            return Err(CryptoError::StrError("http: truncated chunked body"));
        };
        let size_line = core::str::from_utf8(&body[..line_end])
            .map_err(|_| CryptoError::StrError("http: invalid chunk size"))?;
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| CryptoError::StrError("http: invalid chunk size"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if out.len() + size > MAX_RESPONSE_SIZE {
            return Err(CryptoError::StrError("http: response too large"));
        }
        if body.len() < size + 2 {
            return Err(CryptoError::StrError("http: truncated chunked body"));
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size..];
        if !body.starts_with(b"\r\n") {
            return Err(CryptoError::StrError("http: missing chunk terminator"));
        }
        body = &body[2..];
    }
}
