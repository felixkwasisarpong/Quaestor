//! The transport. Moves bytes, makes no judgements.
//!
//! Every decision in this file is delegated to [`crate::gateway::Gateway`],
//! which has no sockets in it and is tested without one. What lives here is
//! the part that cannot be tested without a socket: parsing a request into
//! [`Incoming`], relaying the result, and honouring the commit sequence in
//! the right order.
//!
//! # The sequence this file exists to get right
//!
//! ```text
//!   Outcome::Forward ─ connect ─ commit_spend ─ write ─ relay the response
//!            failed at connect ──▶ on_forward_failed(NeverConnected)   release
//!            commit_spend failed ─▶ do not write; NeverConnected        release
//!            failed after write ──▶ on_forward_failed(MaybeDelivered)  keep
//! ```
//!
//! # Why every gateway call goes through `spawn_blocking`
//!
//! The ledger underneath the gateway is the `postgres` crate's blocking
//! client, which owns a runtime and drives it with `block_on`. Calling it
//! from a tokio worker does not merely stall that worker: it panics, with
//! "cannot start a runtime from within a runtime".
//!
//! This module's documentation used to claim the work happened on a blocking
//! thread while the code locked the gateway inline in an `async fn`. The
//! comment described a design; the code did something else; and no test
//! noticed because every test used the in-memory ledger. The one
//! configuration anybody would deploy was the one configuration never
//! exercised. See `BUGS.md` #017.
//!
//! `Proxy::with_gateway` is now the only way in, so the handoff is not
//! something a future call site can forget.
//!
//! The gateway is behind a `Mutex`, so calls serialize. Reservations for one
//! principal serialize in the database anyway — that is the correctness
//! argument in `quaestor-ledger` — but this lock also serializes *different*
//! principals, which the database would not. It is the first thing to
//! revisit under real load.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming as HyperIncoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use quaestor_core::Timestamp;

use crate::chaos;
use crate::gateway::{Gateway, Incoming, Outcome, Reach, Refusal};
use crate::{MANDATE_HEADER, PAYMENT_HEADER, RECEIPT_HEADER};

/// The largest response body the proxy will buffer to look for a challenge.
///
/// A `402` body is a short JSON document. Anything larger is not one, and
/// buffering an unbounded upstream response into memory on an agent's say-so
/// is a denial of service with extra steps.
pub const MAX_CHALLENGE_BODY: usize = 64 * 1024;

/// Hop-by-hop headers, which belong to one connection and must not be
/// copied onto the next. RFC 9110 §7.6.1.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] hyper::Error),
    #[error("the gateway lock was poisoned by a panic in another request")]
    Poisoned,
}

/// A clock, so tests can hold time still.
///
/// The gateway never reads a clock; every entry point takes `now`. This is
/// where the reading happens, once, at the edge, which is what makes a
/// decision replayable.
pub trait Clock: Send + Sync + core::fmt::Debug {
    fn now(&self) -> Timestamp;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        Timestamp(i64::try_from(millis).unwrap_or(i64::MAX))
    }
}

/// Everything a connection handler needs.
#[derive(Debug, Clone)]
pub struct Proxy {
    gateway: Arc<Mutex<Gateway>>,
    clock: Arc<dyn Clock>,
}

impl Proxy {
    pub fn new(gateway: Gateway, clock: Arc<dyn Clock>) -> Proxy {
        Proxy {
            gateway: Arc::new(Mutex::new(gateway)),
            clock,
        }
    }

    pub fn gateway(&self) -> Arc<Mutex<Gateway>> {
        Arc::clone(&self.gateway)
    }

    /// Run one piece of gateway work on a blocking thread.
    ///
    /// The only way this module is allowed to touch the gateway. See the
    /// module documentation for what happens when a call site does it
    /// inline instead.
    async fn with_gateway<T, F>(&self, f: F) -> Result<T, ProxyError>
    where
        F: FnOnce(&mut Gateway) -> T + Send + 'static,
        T: Send + 'static,
    {
        let gateway = Arc::clone(&self.gateway);
        tokio::task::spawn_blocking(move || {
            let mut guard = gateway.lock().map_err(|_| ProxyError::Poisoned)?;
            Ok(f(&mut guard))
        })
        .await
        .map_err(|e| ProxyError::Io(std::io::Error::other(e.to_string())))?
    }

    /// Serve until the process ends.
    pub async fn serve(self, addr: SocketAddr) -> Result<(), ProxyError> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        self.serve_on(listener).await
    }

    /// Serve on a listener the caller already bound, so a test can learn the
    /// port before anything connects.
    pub async fn serve_on(self, listener: tokio::net::TcpListener) -> Result<(), ProxyError> {
        loop {
            let (stream, _peer) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let service = hyper::service::service_fn(move |req| {
                    let me = me.clone();
                    async move { me.handle(req).await }
                });
                // One bad connection is not the server's problem.
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    }

    /// One request, start to finish.
    pub async fn handle(
        &self,
        req: Request<HyperIncoming>,
    ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        Ok(match self.route(req).await {
            Ok(r) => r,
            // A transport failure is not a verdict. It is reported as one
            // more thing that did not happen, which is the same shape as
            // every other refusal here.
            Err(e) => json_response(
                StatusCode::BAD_GATEWAY,
                &serde_json::json!({ "error": "upstream_failed", "detail": e.to_string() }),
                None,
            ),
        })
    }

    async fn route(
        &self,
        req: Request<HyperIncoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let now = self.clock.now();

        let method = req.method().clone();
        let target = req.uri().to_string();
        let authorization = header(&req, "authorization");
        let payment = header(&req, PAYMENT_HEADER);
        let mandate = header(&req, MANDATE_HEADER);

        let outcome = {
            // Owned, because the work moves to another thread. The borrowed
            // `Incoming` is rebuilt on the far side.
            let (m, t) = (method.as_str().to_owned(), target.clone());
            self.with_gateway(move |g| {
                g.on_request(
                    &Incoming {
                        method: &m,
                        target: &t,
                        authorization: authorization.as_deref(),
                        payment: payment.as_deref(),
                        mandate: mandate.as_deref(),
                    },
                    now,
                )
            })
            .await?
        };

        match outcome {
            Outcome::Refuse(refusal) => Ok(refusal_response(&refusal)),
            Outcome::Passthrough { principal } => {
                self.relay_and_watch_for_challenge(req, &principal, &method, &target, now)
                    .await
            }
            Outcome::Forward { intent_id, receipt } => {
                self.forward_payment(req, &intent_id, &receipt, now).await
            }
        }
    }

    /// No payment on this one. Relay it, and read a `402` on the way back.
    async fn relay_and_watch_for_challenge(
        &self,
        req: Request<HyperIncoming>,
        principal: &str,
        method: &Method,
        target: &str,
        now: Timestamp,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let upstream = self.send_upstream(req).await?;
        let (parts, body) = upstream.into_parts();
        let bytes = collect_capped(body, MAX_CHALLENGE_BODY).await?;

        if parts.status == StatusCode::PAYMENT_REQUIRED {
            let (p, m, t) = (
                principal.to_owned(),
                method.as_str().to_owned(),
                target.to_owned(),
            );
            let body = bytes.clone();
            self.with_gateway(move |g| g.record_challenge(&p, &m, &t, &body, now))
                .await?;
        }

        Ok(rebuild(parts, bytes))
    }

    /// Authorized. Connect, commit, write — in that order, for the reason in
    /// [`crate::gateway`].
    async fn forward_payment(
        &self,
        req: Request<HyperIncoming>,
        intent_id: &str,
        receipt: &quaestor_receipt::Receipt,
        now: Timestamp,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let (parts, body) = req.into_parts();
        let body_bytes = collect_capped(body, MAX_CHALLENGE_BODY).await?;

        let Some(authority) = parts.uri.authority().cloned() else {
            self.forward_failed(intent_id, Reach::NeverConnected, now)
                .await?;
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({
                    "error": "not_absolute",
                    "detail": "a proxied request needs an absolute target",
                }),
                None,
            ));
        };

        // 1. Connect. Nothing has been written, so a failure here releases.
        let port = authority.port_u16().unwrap_or(80);
        let stream = match tokio::net::TcpStream::connect((authority.host(), port)).await {
            Ok(s) => s,
            Err(e) => {
                self.forward_failed(intent_id, Reach::NeverConnected, now)
                    .await?;
                return Ok(json_response(
                    StatusCode::BAD_GATEWAY,
                    &serde_json::json!({
                        "error": "upstream_unreachable",
                        "detail": e.to_string(),
                        "spend": "released",
                    }),
                    Some(receipt),
                ));
            }
        };

        // The connection is open and nothing has been written to it.
        chaos::at("connect.after");

        // 2. Commit the spend. An error means we must not write.
        {
            let id = intent_id.to_owned();
            let committed = self
                .with_gateway(move |g| g.commit_spend(&id, now).map_err(|e| e.to_string()))
                .await?;
            if let Err(e) = committed {
                self.forward_failed(intent_id, Reach::NeverConnected, now)
                    .await?;
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &serde_json::json!({
                        "error": "unavailable",
                        "detail": format!("the spend could not be committed: {e}"),
                        "spend": "released",
                    }),
                    Some(receipt),
                ));
            }
        }

        // The spend is committed and the payment has still not left. The
        // deliberate cost of capturing before the write; see `quaestor_chaos`.
        chaos::at("capture.after");

        // 3. Write. Past this line the authorization is out of our hands.
        let outgoing = rebuild_request(parts, body_bytes);
        match send_on(stream, outgoing).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                let bytes = collect_capped(body, MAX_CHALLENGE_BODY).await?;
                let mut out = rebuild(parts, bytes);
                attach_receipt(out.headers_mut(), receipt);
                Ok(out)
            }
            Err(e) => {
                // Bytes went out. Whether the origin kept them is not
                // knowable from here, and the spend stays committed.
                self.forward_failed(intent_id, Reach::MaybeDelivered, now)
                    .await?;
                Ok(json_response(
                    StatusCode::BAD_GATEWAY,
                    &serde_json::json!({
                        "error": "upstream_failed_after_send",
                        "detail": e.to_string(),
                        "spend": "captured",
                        "note": "the payment may have reached the origin; \
                                 the budget stays committed",
                    }),
                    Some(receipt),
                ))
            }
        }
    }

    async fn forward_failed(
        &self,
        intent_id: &str,
        reach: Reach,
        now: Timestamp,
    ) -> Result<bool, ProxyError> {
        let id = intent_id.to_owned();
        self.with_gateway(move |g| g.on_forward_failed(&id, reach, now))
            .await
    }

    async fn send_upstream(
        &self,
        req: Request<HyperIncoming>,
    ) -> Result<Response<HyperIncoming>, ProxyError> {
        let (parts, body) = req.into_parts();
        let bytes = collect_capped(body, MAX_CHALLENGE_BODY).await?;
        let Some(authority) = parts.uri.authority().cloned() else {
            return Err(ProxyError::Io(std::io::Error::other(
                "a proxied request needs an absolute target",
            )));
        };
        let port = authority.port_u16().unwrap_or(80);
        let stream = tokio::net::TcpStream::connect((authority.host(), port)).await?;
        send_on(stream, rebuild_request(parts, bytes)).await
    }
}

/// One request over one fresh connection.
///
/// Deliberately not pooled. A pooled connection is shared state between two
/// agents' payments, and the first version of this should be obviously
/// correct rather than fast.
async fn send_on(
    stream: tokio::net::TcpStream,
    req: Request<Full<Bytes>>,
) -> Result<Response<HyperIncoming>, ProxyError> {
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender.send_request(req).await?)
}

// ---------------------------------------------------------------------------

fn header<B>(req: &Request<B>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Read a body, refusing to buffer more than `cap`.
async fn collect_capped(body: HyperIncoming, cap: usize) -> Result<Bytes, ProxyError> {
    let collected = body.collect().await?.to_bytes();
    if collected.len() > cap {
        return Err(ProxyError::Io(std::io::Error::other(format!(
            "body of {} bytes exceeds the {cap}-byte cap",
            collected.len()
        ))));
    }
    Ok(collected)
}

fn rebuild(parts: hyper::http::response::Parts, body: Bytes) -> Response<Full<Bytes>> {
    let mut out = Response::new(Full::new(body));
    *out.status_mut() = parts.status;
    *out.version_mut() = parts.version;
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        out.headers_mut().append(name.clone(), value.clone());
    }
    out
}

fn rebuild_request(parts: hyper::http::request::Parts, body: Bytes) -> Request<Full<Bytes>> {
    // Origin form: the path and query only. An absolute URI in the request
    // line is how you talk to a proxy, not how a proxy talks to an origin.
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), ToString::to_string);

    let mut out = Request::new(Full::new(body));
    *out.method_mut() = parts.method;
    *out.uri_mut() = path.parse().unwrap_or_default();

    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        // The gateway's own credential is between the agent and the
        // gateway. Forwarding it upstream hands a resource server a token
        // that spends this principal's budget.
        if name == hyper::header::AUTHORIZATION || name.as_str() == MANDATE_HEADER {
            continue;
        }
        out.headers_mut().append(name.clone(), value.clone());
    }
    if let Some(authority) = parts.uri.authority() {
        if let Ok(v) = HeaderValue::from_str(authority.as_str()) {
            out.headers_mut().insert(hyper::header::HOST, v);
        }
    }
    out
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

fn refusal_response(refusal: &Refusal) -> Response<Full<Bytes>> {
    let status =
        StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_response(status, &refusal.body(), refusal.receipt.as_ref())
}

fn json_response(
    status: StatusCode,
    body: &serde_json::Value,
    receipt: Option<&quaestor_receipt::Receipt>,
) -> Response<Full<Bytes>> {
    let text = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let mut out = Response::new(Full::new(Bytes::from(text)));
    *out.status_mut() = status;
    out.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(r) = receipt {
        attach_receipt(out.headers_mut(), r);
    }
    out
}

/// Hand the agent the signed record of the decision, refusals included.
///
/// A denial the agent cannot prove it received is a denial somebody will
/// later argue about.
fn attach_receipt(headers: &mut hyper::HeaderMap, receipt: &quaestor_receipt::Receipt) {
    let Ok(json) = serde_json::to_string(receipt) else {
        return;
    };
    let encoded = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(json)
    };
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(RECEIPT_HEADER.as_bytes()),
        HeaderValue::from_str(&encoded),
    ) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_not_relayed() {
        for name in HOP_BY_HOP {
            let h = HeaderName::from_bytes(name.as_bytes()).expect("valid");
            assert!(is_hop_by_hop(&h), "{name} should not be relayed");
        }
        assert!(!is_hop_by_hop(&hyper::header::CONTENT_TYPE));
    }

    #[test]
    fn the_gateway_credential_does_not_go_upstream() {
        let req = Request::builder()
            .method("GET")
            .uri("http://origin.example/report?x=1")
            .header("authorization", "Bearer sk_felix")
            .header(MANDATE_HEADER, "abc")
            .header("accept", "application/json")
            .body(())
            .expect("valid");
        let (parts, ()) = req.into_parts();
        let out = rebuild_request(parts, Bytes::new());

        assert!(out.headers().get("authorization").is_none());
        assert!(out.headers().get(MANDATE_HEADER).is_none());
        assert_eq!(
            out.headers().get("accept").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn the_request_line_is_rewritten_to_origin_form() {
        let req = Request::builder()
            .method("GET")
            .uri("http://origin.example:8080/a/b?x=1")
            .body(())
            .expect("valid");
        let (parts, ()) = req.into_parts();
        let out = rebuild_request(parts, Bytes::new());

        assert_eq!(out.uri().to_string(), "/a/b?x=1");
        assert_eq!(
            out.headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok()),
            Some("origin.example:8080")
        );
    }

    #[test]
    fn a_clock_is_read_once_at_the_edge() {
        // Not a behaviour test so much as a statement: the type below is the
        // only thing in this crate that may read a clock.
        let t = SystemClock.now();
        assert!(t.as_millis() > 1_700_000_000_000, "a plausible epoch");
    }
}
