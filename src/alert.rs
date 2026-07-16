//! Outbound webhook alerting for policy violations. Delivery is best-effort and
//! `http://`-only, matching the server's std-only / no-in-process-TLS model:
//! point the webhook at a local forwarder (Caddy, a tiny relay) that terminates
//! TLS to Slack/PagerDuty/etc., the same way inbound TLS is terminated in front.

use anyhow::{Result, anyhow};
use serde_json::Value;

/// POST `payload` as JSON to an `http://host[:port][/path]` webhook.
pub fn post_webhook(url: &str, payload: &Value) -> Result<()> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        anyhow!("webhook must be http:// (terminate TLS in a local forwarder): {url}")
    })?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let base = format!("http://{host_port}");
    let body = serde_json::to_vec(payload)?;
    crate::sync::http_request(
        &base,
        "POST",
        path,
        None,
        &[("content-type", "application/json")],
        Some(&body),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_non_http() {
        assert!(post_webhook("https://example.com/h", &json!({})).is_err());
        assert!(post_webhook("ftp://x", &json!({})).is_err());
    }

    #[test]
    fn posts_json_to_http_target() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Drain the full request (headers + content-length body) before
            // responding, else closing with unread bytes RSTs the client.
            let mut data = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                    let clen: usize = headers
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if data.len() >= end + 4 + clen {
                        break;
                    }
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
            String::from_utf8_lossy(&data).into_owned()
        });

        post_webhook(&format!("http://{addr}/hook"), &json!({"event": "v"})).unwrap();
        let req = server.join().unwrap();
        assert!(req.starts_with("POST /hook"), "request line: {req}");
        assert!(req.contains("content-type: application/json"));
        assert!(req.contains("\"event\":\"v\""));
    }
}
