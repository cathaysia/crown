//! Tests for the minimal HTTP/1.1 client (`crown::x509::http`).
//!
//! A local `TcpListener` plays both a well-behaved and a misbehaving server:
//! fixed-length and chunked bodies, redirects, request echo and error cases.
//! No external network access is involved.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crown::x509::http;

/// A fake server: every accepted connection is answered by `handler(request)`.
struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start(handler: impl Fn(&str) -> Vec<u8> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(read) = stream.read(&mut chunk) else {
                        break;
                    };
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    if let Some(end) = find_headers_end(&buffer) {
                        let head = String::from_utf8_lossy(&buffer[..end]).to_string();
                        if buffer.len() >= end + 4 + content_length(&head) {
                            break;
                        }
                    }
                }
                let request = String::from_utf8_lossy(&buffer).to_string();
                log.lock().unwrap().push(request.clone());
                let response = handler(&request);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        Server { port, requests }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn find_headers_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[test]
fn get_reads_a_content_length_body() {
    let server = Server::start(|_| {
        response(
            "200 OK",
            "Content-Type: application/pkix-crl\r\n",
            b"crl-bytes",
        )
    });
    let result = http::get(&server.url("/root.crl"), Some(Duration::from_secs(5))).expect("GET");
    assert_eq!(result.status, 200);
    assert_eq!(result.body, b"crl-bytes");
    assert_eq!(result.content_type.as_deref(), Some("application/pkix-crl"));

    let request = &server.requests()[0];
    assert!(
        request.starts_with("GET /root.crl HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(
        request.contains(&format!("Host: 127.0.0.1:{}\r\n", server.port)),
        "{request}"
    );
    assert!(request.contains("Connection: close\r\n"), "{request}");
    assert!(!request.contains("Content-Length"), "{request}");
}

#[test]
fn get_decodes_chunked_bodies() {
    let server = Server::start(|_| {
        let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        out.extend_from_slice(b"5\r\nhello\r\n");
        out.extend_from_slice(b"6\r\n world\r\n");
        out.extend_from_slice(b"0\r\n\r\n");
        out
    });
    let result = http::get(&server.url("/chunked"), None).expect("GET chunked");
    assert_eq!(result.status, 200);
    assert_eq!(result.body, b"hello world");
}

#[test]
fn get_follows_redirects() {
    let server = Server::start(|request| {
        if request.starts_with("GET /old ") {
            response("302 Found", "Location: /new\r\n", b"")
        } else if request.starts_with("GET /new ") {
            response("200 OK", "", b"moved-body")
        } else {
            response("404 Not Found", "", b"")
        }
    });
    let result = http::get(&server.url("/old"), None).expect("GET with redirect");
    assert_eq!(result.status, 200);
    assert_eq!(result.body, b"moved-body");
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "one redirect hop: {requests:?}");
    assert!(requests[1].starts_with("GET /new HTTP/1.1\r\n"));
}

#[test]
fn post_redirect_switches_to_get_without_the_body() {
    let server = Server::start(|request| {
        if request.starts_with("POST /submit ") {
            response("303 See Other", "Location: /result\r\n", b"")
        } else {
            response("200 OK", "", b"done")
        }
    });
    let result = http::post(
        &server.url("/submit"),
        "application/ocsp-request",
        b"payload",
        None,
    )
    .expect("POST with redirect");
    assert_eq!(result.body, b"done");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /submit HTTP/1.1"));
    assert!(
        requests[1].starts_with("GET /result HTTP/1.1"),
        "{:?}",
        requests[1]
    );
    assert!(!requests[1].contains("Content-Length"), "{:?}", requests[1]);
    assert!(!requests[1].contains("payload"), "{:?}", requests[1]);
}

#[test]
fn post_sends_the_body_and_content_type() {
    let server = Server::start(|request| {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or("");
        response("200 OK", "", body.as_bytes())
    });
    let payload = b"\x30\x03\x02\x01\x01"; // a tiny DER-ish payload
    let result = http::post(
        &server.url("/ocsp"),
        "application/ocsp-request",
        payload,
        None,
    )
    .expect("POST");
    assert_eq!(result.status, 200);
    assert_eq!(result.body, payload);

    let request = &server.requests()[0];
    assert!(request.starts_with("POST /ocsp HTTP/1.1\r\n"), "{request}");
    assert!(
        request.contains("Content-Type: application/ocsp-request\r\n"),
        "{request}"
    );
    assert!(
        request.contains(&format!("Content-Length: {}\r\n", payload.len())),
        "{request}"
    );
}

#[test]
fn https_and_oversized_responses_are_rejected() {
    for url in [
        "https://example.com/crl",
        "ftp://example.com/crl",
        "not a url",
        "http://",
    ] {
        assert!(
            http::parse_url(url).is_err(),
            "{url} must not parse as a plain-HTTP URL"
        );
        assert!(http::get(url, None).is_err(), "{url} must not be fetched");
    }

    // A redirect to https fails explicitly.
    let server = Server::start(|_| response("302 Found", "Location: https://x/y\r\n", b""));
    let error = http::get(&server.url("/a"), None).unwrap_err();
    assert!(
        error.to_string().contains("https"),
        "unexpected error: {error}"
    );

    // An advertised over-limit body is refused before reading it.
    let server =
        Server::start(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n".to_vec());
    assert!(http::get(&server.url("/huge"), None).is_err());

    // A truncated body (short Content-Length) fails too.
    let server = Server::start(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort".to_vec());
    assert!(http::get(&server.url("/short"), None).is_err());
}

#[test]
fn parse_url_splits_authority_and_path() {
    let url = http::parse_url("http://example.com/a/b?x=1").unwrap();
    assert_eq!(url.host, "example.com");
    assert_eq!(url.port, 80);
    assert_eq!(url.path, "/a/b?x=1");

    let url = http::parse_url("http://example.com:8080").unwrap();
    assert_eq!(url.port, 8080);
    assert_eq!(url.path, "/");

    let url = http::parse_url("http://[::1]:8000/crl").unwrap();
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, 8000);
    assert_eq!(url.path, "/crl");

    // Userinfo is tolerated and stripped.
    let url = http::parse_url("http://user:pass@example.com/crl").unwrap();
    assert_eq!(url.host, "example.com");
}

#[test]
fn ocsp_post_to_parses_the_responder_reply() {
    let response_bytes = std::fs::read("tests/data/pki/ocsp_response_good.der").unwrap();
    let server = Server::start(move |request| {
        assert!(request.starts_with("POST /ocsp HTTP/1.1"), "{request}");
        response(
            "200 OK",
            "Content-Type: application/ocsp-response\r\n",
            &response_bytes,
        )
    });
    let request_bytes = std::fs::read("tests/data/pki/ocsp_request.der").unwrap();
    let request = crown::ocsp::OcspRequest::parse(&request_bytes).unwrap();
    let reply = request
        .post_to(&server.url("/ocsp"), Some(Duration::from_secs(5)))
        .expect("POST the OCSP request");
    assert_eq!(reply.status.name(), "successful");
    assert!(reply.basic().is_ok());

    // A non-200 reply is an error, not a parse failure.
    let server = Server::start(|_| response("500 Internal Server Error", "", b""));
    let error = request.post_to(&server.url("/ocsp"), None).unwrap_err();
    assert!(
        error.to_string().contains("HTTP"),
        "unexpected error: {error}"
    );
}
