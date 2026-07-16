//! Minimal std-only HTTP/1.1 client. `http://host:port` only — for TLS, put
//! a terminating proxy in front (same stance as the server).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::Error;

const MAX_RESPONSE: u64 = 4 * 1024 * 1024 * 1024;

pub(crate) struct Http {
    base: String,
    token: Option<String>,
    timeout: Duration,
}

impl Http {
    pub(crate) fn new(base: &str, token: Option<String>, timeout: Duration) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            timeout,
        }
    }

    pub(crate) fn request(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let rest = self
            .base
            .strip_prefix("http://")
            .ok_or_else(|| Error::Url("only http:// URLs are supported (use a TLS proxy)".into()))?;
        let host_port = rest.split('/').next().unwrap_or(rest);
        let addr = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{host_port}:80")
        };

        let mut stream = TcpStream::connect(&addr).map_err(|e| Error::Io(e.to_string()))?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let mut req = format!("{method} {path} HTTP/1.1\r\nhost: {host_port}\r\nconnection: close\r\n");
        if let Some(token) = &self.token {
            req.push_str(&format!("authorization: Bearer {token}\r\n"));
        }
        if let Some(ct) = content_type {
            req.push_str(&format!("content-type: {ct}\r\n"));
        }
        req.push_str(&format!("content-length: {}\r\n\r\n", body.map_or(0, |b| b.len())));

        stream.write_all(req.as_bytes()).map_err(|e| Error::Io(e.to_string()))?;
        if let Some(body) = body {
            stream.write_all(body).map_err(|e| Error::Io(e.to_string()))?;
        }
        stream.flush().map_err(|e| Error::Io(e.to_string()))?;

        let mut raw = Vec::new();
        stream
            .take(MAX_RESPONSE)
            .read_to_end(&mut raw)
            .map_err(|e| Error::Io(e.to_string()))?;

        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| Error::Protocol("malformed HTTP response".into()))?;
        let head = String::from_utf8_lossy(&raw[..header_end]);
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| Error::Protocol("malformed status line".into()))?;
        let payload = raw[header_end + 4..].to_vec();

        if !(200..300).contains(&status) {
            let body = serde_json::from_slice::<serde_json::Value>(&payload).ok();
            let field = |k: &str| {
                body.as_ref()
                    .and_then(|v| v.get(k))
                    .and_then(|s| s.as_str())
                    .map(str::to_string)
            };
            let message =
                field("error").unwrap_or_else(|| String::from_utf8_lossy(&payload).to_string());
            return Err(Error::Status { status, message, code: field("code"), hint: field("hint") });
        }
        Ok(payload)
    }
}
