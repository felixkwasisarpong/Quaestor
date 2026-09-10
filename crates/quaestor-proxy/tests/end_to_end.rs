//! The proxy in front of a real origin, over real sockets.
//!
//! The decisions are tested in `gateway.rs`, without any of this. What is
//! asserted here is the thing that cannot be asserted there: that a refusal
//! actually stops the bytes. A gateway that returns `Refuse` while the
//! transport forwards anyway is a correct library in front of an open door,
//! so the origin counts its requests and the tests check the count.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use common::*;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use quaestor_core::Timestamp;
use quaestor_ledger::HoldState;
use quaestor_proxy::http::{Clock, Proxy};
use quaestor_proxy::{Gateway, Identities};
use quaestor_receipt::Receipt;

/// A clock the test controls, because the gateway's decisions are a function
/// of `now` and a test that drifts is a test that flakes.
#[derive(Debug)]
struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// What the origin saw.
#[derive(Debug, Default)]
struct OriginLog {
    requests: Vec<RecordedRequest>,
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
    had_payment: bool,
    authorization: Option<String>,
    mandate: Option<String>,
}

#[derive(Debug, Clone)]
struct Origin {
    addr: SocketAddr,
    log: Arc<Mutex<OriginLog>>,
    demand: u128,
    pay_to: String,
}

impl Origin {
    fn count(&self) -> usize {
        self.log.lock().expect("not poisoned").requests.len()
    }

    fn last(&self) -> RecordedRequest {
        self.log
            .lock()
            .expect("not poisoned")
            .requests
            .last()
            .cloned()
            .expect("at least one request")
    }
}

/// A resource server that charges for one page.
async fn spawn_origin(demand: u128, pay_to: &str) -> Origin {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = Origin {
        addr,
        log: Arc::clone(&log),
        demand,
        pay_to: pay_to.to_owned(),
    };

    let served = origin.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let served = served.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let served = served.clone();
                        async move {
                            let had_payment = req.headers().contains_key("x-payment");
                            served.log.lock().expect("not poisoned").requests.push(
                                RecordedRequest {
                                    path: req.uri().to_string(),
                                    had_payment,
                                    authorization: header_of(&req, "authorization"),
                                    mandate: header_of(&req, "x-quaestor-mandate"),
                                },
                            );

                            let response = if had_payment {
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("x-payment-response", "settled")
                                    .body(Full::new(Bytes::from_static(b"the paid report")))
                            } else {
                                Response::builder()
                                    .status(StatusCode::PAYMENT_REQUIRED)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(challenge_body(
                                        &served.pay_to,
                                        served.demand,
                                    ))))
                            };
                            response.map_err(|e| std::io::Error::other(e.to_string()))
                        }
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    origin
}

fn header_of<B>(req: &Request<B>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// The proxy, listening, with the ledger still visible to the test.
async fn spawn_proxy(gateway: Gateway) -> (SocketAddr, Arc<Mutex<Gateway>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let proxy = Proxy::new(gateway, Arc::new(FixedClock(NOW)));
    let handle = proxy.gateway();
    tokio::spawn(async move {
        let _ = proxy.serve_on(listener).await;
    });
    (addr, handle)
}

/// One request from the agent to the proxy, in absolute form, as a client
/// configured to use a proxy would send it.
async fn agent_request(
    proxy: SocketAddr,
    target: &str,
    token: Option<&str>,
    payment: Option<&str>,
) -> Response<Bytes> {
    let stream = tokio::net::TcpStream::connect(proxy)
        .await
        .expect("connect");
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method("GET").uri(target);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    if let Some(p) = payment {
        builder = builder.header("x-payment", p);
    }
    let req = builder.body(Full::new(Bytes::new())).expect("request");

    let res = sender.send_request(req).await.expect("send");
    let (parts, body) = res.into_parts();
    let bytes = body.collect().await.expect("body").to_bytes();
    Response::from_parts(parts, bytes)
}

fn receipt_from(res: &Response<Bytes>) -> Option<Receipt> {
    let raw = res.headers().get("x-quaestor-receipt")?.to_str().ok()?;
    let json = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    serde_json::from_slice(&json).ok()
}

fn gateway_for(holds: SharedHolds, ids: Identities) -> Gateway {
    gateway_with(Box::new(holds), ids)
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_challenge_the_origin_issued_is_what_the_payment_is_checked_against() {
    let origin = spawn_origin(1_000_000, MERCHANT).await;
    let holds = SharedHolds::new();
    let (proxy, _) = spawn_proxy(gateway_for(holds.clone(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    // 1. No payment. The origin charges, and the proxy relays the challenge
    //    unchanged while quietly remembering it.
    let first = agent_request(proxy, &target, Some(TOKEN), None).await;
    assert_eq!(first.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(
        String::from_utf8_lossy(first.body()).contains("accepts"),
        "the agent gets the real challenge, not our summary of it"
    );

    // 2. The agent pays. The proxy checks it against the origin's demand,
    //    not the agent's copy of it, and forwards.
    let paid = agent_request(
        proxy,
        &target,
        Some(TOKEN),
        Some(&honest_payment(1_000_000, 1)),
    )
    .await;

    assert_eq!(paid.status(), StatusCode::OK);
    assert_eq!(paid.body().as_ref(), b"the paid report");
    assert_eq!(origin.count(), 2);
    assert!(origin.last().had_payment);
    assert_eq!(origin.last().path, "/report", "rewritten to origin form");

    let receipt = receipt_from(&paid).expect("the decision comes back with the response");
    receipt.verify_signature().expect("signed");
    assert_eq!(receipt.amount, usdc(1_000_000));

    assert_eq!(
        holds.state_of(&intent_id_for(1)),
        Some(HoldState::Captured),
        "the spend was committed before the bytes went out"
    );
}

#[tokio::test]
async fn a_refused_payment_does_not_reach_the_origin() {
    // The claim the whole crate exists to support. Everything else is a
    // library, and a library is something an agent can decline to call.
    // An origin that wants six USDC, against a five USDC daily budget.
    let origin = spawn_origin(6_000_000, MERCHANT).await;
    let holds = SharedHolds::new();
    let (proxy, _) = spawn_proxy(gateway_for(holds.clone(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    agent_request(proxy, &target, Some(TOKEN), None).await;
    assert_eq!(origin.count(), 1, "the challenge itself is free");

    let denied = agent_request(
        proxy,
        &target,
        Some(TOKEN),
        Some(&honest_payment(6_000_000, 1)),
    )
    .await;

    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        origin.count(),
        1,
        "the origin must never have seen the payment"
    );
    assert_eq!(holds.row_count(), 0, "and nothing was reserved");

    let body = String::from_utf8_lossy(denied.body()).to_string();
    assert!(body.contains("denied"), "{body}");
    assert!(body.contains("budget"), "the agent is told why: {body}");

    let receipt = receipt_from(&denied).expect("a refusal is evidence too");
    receipt.verify_signature().expect("signed");
}

#[tokio::test]
async fn a_payment_for_a_challenge_the_proxy_never_saw_is_stopped_at_the_door() {
    let origin = spawn_origin(1_000_000, MERCHANT).await;
    let (proxy, _) = spawn_proxy(gateway_for(SharedHolds::new(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    let res = agent_request(
        proxy,
        &target,
        Some(TOKEN),
        Some(&honest_payment(1_000_000, 1)),
    )
    .await;

    assert_eq!(res.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(origin.count(), 0, "not one byte");
}

#[tokio::test]
async fn an_unauthenticated_request_never_touches_the_origin() {
    let origin = spawn_origin(1_000_000, MERCHANT).await;
    let (proxy, _) = spawn_proxy(gateway_for(SharedHolds::new(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    let res = agent_request(proxy, &target, None, None).await;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(origin.count(), 0);
    assert!(receipt_from(&res).is_none(), "no principal, no receipt");
}

#[tokio::test]
async fn the_gateway_credential_is_not_handed_to_the_resource_server() {
    // The token spends this principal's budget. Relaying it upstream would
    // give every origin the agent visits the ability to do so.
    let origin = spawn_origin(1_000_000, MERCHANT).await;
    let (proxy, _) = spawn_proxy(gateway_for(SharedHolds::new(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    agent_request(proxy, &target, Some(TOKEN), None).await;
    agent_request(
        proxy,
        &target,
        Some(TOKEN),
        Some(&honest_payment(1_000_000, 1)),
    )
    .await;

    for r in origin.log.lock().expect("not poisoned").requests.iter() {
        assert!(r.authorization.is_none(), "credential leaked: {r:?}");
        assert!(r.mandate.is_none(), "mandate leaked: {r:?}");
    }
}

#[tokio::test]
async fn an_origin_that_cannot_be_reached_gives_the_budget_back() {
    // Nothing was written, so nothing was spent. Without this, a flaky
    // origin costs an agent its daily allowance one failed connection at a
    // time.
    let holds = SharedHolds::new();
    let (proxy, gateway) = spawn_proxy(gateway_for(holds.clone(), identities())).await;

    // A port nothing is listening on. Record the challenge directly, so the
    // test is about the failed connection and not about shutdown timing.
    let dead = "http://127.0.0.1:9/report";
    {
        let mut g = gateway.lock().expect("not poisoned");
        g.record_challenge(
            "felix",
            "GET",
            dead,
            &challenge_body(MERCHANT, 1_000_000),
            NOW,
        );
    }

    let res = agent_request(
        proxy,
        dead,
        Some(TOKEN),
        Some(&honest_payment(1_000_000, 1)),
    )
    .await;

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let body = String::from_utf8_lossy(res.body()).to_string();
    assert!(body.contains("\"spend\":\"released\""), "{body}");
    assert_eq!(
        holds.state_of(&intent_id_for(1)),
        Some(HoldState::Released),
        "the hold goes back when the payment provably never left"
    );
}

#[tokio::test]
async fn one_agents_budget_is_not_another_agents_budget() {
    let origin = spawn_origin(2_000_000, MERCHANT).await;
    let holds = SharedHolds::new();
    let (proxy, _) = spawn_proxy(gateway_for(holds.clone(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    // felix works through his 5 USDC daily cap in 2 USDC steps.
    agent_request(proxy, &target, Some(TOKEN), None).await;
    for nonce in 1..=2_u8 {
        let res = agent_request(
            proxy,
            &target,
            Some(TOKEN),
            Some(&honest_payment(2_000_000, nonce)),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "payment {nonce}");
    }
    let over = agent_request(
        proxy,
        &target,
        Some(TOKEN),
        Some(&honest_payment(2_000_000, 3)),
    )
    .await;
    assert_eq!(
        over.status(),
        StatusCode::FORBIDDEN,
        "6 USDC does not fit in a 5 USDC day"
    );

    // ama has her own cap, and his exhaustion is not hers.
    agent_request(proxy, &target, Some(OTHER_TOKEN), None).await;
    let hers = agent_request(
        proxy,
        &target,
        Some(OTHER_TOKEN),
        Some(&honest_payment(2_000_000, 4)),
    )
    .await;
    assert_eq!(
        hers.status(),
        StatusCode::OK,
        "separate principals, separate budgets"
    );

    assert_eq!(holds.row_count(), 3, "two of his and one of hers");
}

#[tokio::test]
async fn a_request_with_no_payment_is_relayed_untouched() {
    let origin = spawn_origin(1_000_000, MERCHANT).await;
    let (proxy, _) = spawn_proxy(gateway_for(SharedHolds::new(), identities())).await;
    let target = format!("http://{}/anything?q=1", origin.addr);

    let res = agent_request(proxy, &target, Some(TOKEN), None).await;

    assert_eq!(res.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(origin.last().path, "/anything?q=1");
    assert_eq!(origin.count(), 1);
}

#[tokio::test]
async fn a_replayed_payment_is_refused_and_the_origin_is_billed_once() {
    let origin = spawn_origin(1_000_000, MERCHANT).await;
    let holds = SharedHolds::new();
    let (proxy, _) = spawn_proxy(gateway_for(holds.clone(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    agent_request(proxy, &target, Some(TOKEN), None).await;
    let once = honest_payment(1_000_000, 1);

    let first = agent_request(proxy, &target, Some(TOKEN), Some(&once)).await;
    assert_eq!(first.status(), StatusCode::OK);

    let again = agent_request(proxy, &target, Some(TOKEN), Some(&once)).await;
    assert_eq!(again.status(), StatusCode::FORBIDDEN);
    assert_eq!(origin.count(), 2, "the replay never reached the origin");
    assert_eq!(holds.row_count(), 1, "and it was charged once");
}

#[tokio::test]
async fn a_gateway_with_no_credentials_configured_refuses_everyone() {
    // An empty table must mean nobody, not everybody. The failure mode of
    // the other reading is an open payment proxy on someone's network.
    let origin = spawn_origin(1_000_000, MERCHANT).await;
    let (proxy, _) = spawn_proxy(gateway_for(SharedHolds::new(), Identities::new())).await;
    let target = format!("http://{}/report", origin.addr);

    let res = agent_request(proxy, &target, Some(TOKEN), None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(origin.count(), 0);
}

#[tokio::test]
async fn the_ledger_and_the_transport_agree_on_what_was_spent() {
    // A last sanity check across the whole stack: three payments, one
    // refused, and the ledger holds exactly the two that went out.
    let origin = spawn_origin(2_000_000, MERCHANT).await;
    let holds = SharedHolds::new();
    let (proxy, _) = spawn_proxy(gateway_for(holds.clone(), identities())).await;
    let target = format!("http://{}/report", origin.addr);

    for nonce in 1..=3_u8 {
        agent_request(proxy, &target, Some(TOKEN), None).await;
        agent_request(
            proxy,
            &target,
            Some(TOKEN),
            Some(&honest_payment(2_000_000, nonce)),
        )
        .await;
    }

    // 2 + 2 fits inside the 5 USDC daily cap. The third does not.
    assert_eq!(holds.state_of(&intent_id_for(1)), Some(HoldState::Captured));
    assert_eq!(holds.state_of(&intent_id_for(2)), Some(HoldState::Captured));
    assert_eq!(holds.state_of(&intent_id_for(3)), None, "never reserved");
    assert_eq!(holds.row_count(), 2);

    let paid = origin
        .log
        .lock()
        .expect("not poisoned")
        .requests
        .iter()
        .filter(|r| r.had_payment)
        .count();
    assert_eq!(paid, 2, "the origin was paid exactly what the ledger says");
}
