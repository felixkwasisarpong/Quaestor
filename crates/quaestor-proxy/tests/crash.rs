//! Kill the process, on purpose, in the middle of a payment.
//!
//! Run with:
//!
//! ```bash
//! QUAESTOR_TEST_PG="host=/tmp/pgsock port=5433 user=quaestor dbname=quaestor_test" \
//!   cargo test -p quaestor-proxy --features chaos --test crash -- --test-threads=1
//! ```
//!
//! Without `QUAESTOR_TEST_PG` these skip rather than fail, for the same
//! reason the ledger's concurrency tests do: a green suite that proved
//! nothing is worse than a red one.
//!
//! # What makes this different from the other tests
//!
//! Everything else in this workspace tests a decision. This tests what is
//! *left over*. The proxy is a real child process talking to a real
//! Postgres, it is killed with `abort` at a named point inside the real code
//! path, and then it is restarted and the surviving state is read by
//! `quaestor-chaos`, which uses its own SQL rather than the ledger's.
//!
//! Single-threaded on purpose: the cases share one database and one port.

#![cfg(feature = "chaos")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use quaestor_chaos::invariants::{check, HoldRow, Observed};
use quaestor_chaos::points::{Point, POINTS};
use quaestor_core::Timestamp;
use quaestor_receipt::Receipt;

/// `ed_key(0xAA)` as hex, which is what the fixtures sign with.
const RECEIPT_KEY_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn pg() -> Option<String> {
    std::env::var("QUAESTOR_TEST_PG")
        .ok()
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// A resource server that remembers exactly who paid it
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct OriginState {
    /// Intent ids the origin actually received an authorization for.
    ///
    /// Derived here, from the payment header itself, rather than taken from
    /// anything Quaestor wrote down. That independence is the point: this is
    /// the ground truth the invariants are checked against.
    paid: BTreeSet<String>,
    /// Sleep this long before answering, so a test can kill the proxy after
    /// the write and before the response.
    hang_ms: u64,
}

#[derive(Clone)]
struct Origin {
    addr: std::net::SocketAddr,
    state: Arc<Mutex<OriginState>>,
    demand: u128,
}

impl Origin {
    fn paid(&self) -> BTreeSet<String> {
        self.state.lock().expect("not poisoned").paid.clone()
    }

    fn set_hang(&self, ms: u64) {
        self.state.lock().expect("not poisoned").hang_ms = ms;
    }

    fn wait_for_payment(&self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if !self.paid().is_empty() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

/// The intent id the gateway derives from a payment: `x402:` and the
/// authorization's nonce. Recomputed here from the header so the origin's
/// record is independent of the proxy's.
fn intent_of(payment_header: &str) -> Option<String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(payment_header.trim())
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let nonce = v
        .get("payload")?
        .get("authorization")?
        .get("nonce")?
        .as_str()?;
    Some(format!("x402:{}", nonce.trim_start_matches("0x")))
}

async fn spawn_origin(demand: u128) -> Origin {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let state = Arc::new(Mutex::new(OriginState::default()));
    let origin = Origin {
        addr,
        state: Arc::clone(&state),
        demand,
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
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let served = served.clone();
                    async move {
                        let payment = req
                            .headers()
                            .get("x-payment")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);

                        let hang = {
                            let mut s = served.state.lock().expect("not poisoned");
                            if let Some(p) = payment.as_deref().and_then(intent_of) {
                                s.paid.insert(p);
                            }
                            s.hang_ms
                        };
                        if hang > 0 {
                            tokio::time::sleep(Duration::from_millis(hang)).await;
                        }

                        let r = if payment.is_some() {
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"paid")))
                        } else {
                            Response::builder()
                                .status(StatusCode::PAYMENT_REQUIRED)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(challenge_body(
                                    MERCHANT,
                                    served.demand,
                                ))))
                        };
                        r.map_err(|e| std::io::Error::other(e.to_string()))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    origin
}

// ---------------------------------------------------------------------------
// The proxy, as a process we are willing to kill
// ---------------------------------------------------------------------------

struct Proxy {
    child: Child,
    addr: std::net::SocketAddr,
}

impl Proxy {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Wait for the process to die on its own, and report how.
    fn wait_for_death(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => return None,
            }
        }
        None
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Rig {
    dir: PathBuf,
    config: PathBuf,
    receipts: PathBuf,
    marker: PathBuf,
    port: u16,
    pg: String,
}

impl Rig {
    fn new(name: &str, origin: &Origin) -> Rig {
        let mut dir = std::env::temp_dir();
        dir.push(format!("quaestor-crash-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        let policy = dir.join("policy.toml");
        std::fs::write(&policy, policy_toml()).expect("policy");

        let port = free_port();
        let config = dir.join("quaestor.toml");
        let receipts = dir.join("receipts.jsonl");

        std::fs::write(
            &config,
            format!(
                r#"
listen = "127.0.0.1:{port}"
policy = "{policy}"
receipt_log = "{receipts}"
challenge_ttl_seconds = 600

[[assets]]
network = "{NETWORK}"
address = "{USDC}"
currency = "USDC"
eip712_name = "USD Coin"
eip712_version = "2"
chain_id = {CHAIN_ID}

[[callers]]
token_env = "QUAESTOR_TOKEN_TEST"
principal = "felix"
agent = "shopper"
max_amount = "50.000000 USDC"
rails = ["x402"]
valid_for_seconds = 86400
"#,
                policy = policy.display(),
                receipts = receipts.display(),
            ),
        )
        .expect("config");

        let _ = origin;
        Rig {
            marker: dir.join("marker"),
            dir,
            config,
            receipts,
            port,
            pg: pg().expect("checked by the caller"),
        }
    }

    /// Start the proxy, optionally armed to die at `crash_at`.
    fn start(&self, crash_at: Option<&str>) -> Proxy {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_quaestor-proxy"));
        cmd.arg("--config")
            .arg(&self.config)
            .env("QUAESTOR_PG", &self.pg)
            .env("QUAESTOR_RECEIPT_KEY", RECEIPT_KEY_HEX)
            .env("QUAESTOR_TOKEN_TEST", TOKEN)
            .env(quaestor_chaos::MARKER_VAR, &self.marker)
            .env_remove(quaestor_chaos::ARM_VAR)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(point) = crash_at {
            cmd.env(quaestor_chaos::ARM_VAR, point);
        }

        let child = cmd.spawn().expect("spawn the proxy");
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port).parse().expect("addr");
        let proxy = Proxy { child, addr };
        wait_until_listening(addr, Duration::from_secs(10));
        proxy
    }

    fn crashed_at(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }

    fn clear_marker(&self) {
        let _ = std::fs::remove_file(&self.marker);
    }

    fn receipts(&self) -> Vec<Receipt> {
        let Ok(text) = std::fs::read_to_string(&self.receipts) else {
            return Vec::new();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

fn wait_until_listening(addr: std::net::SocketAddr, within: Duration) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("the proxy never started listening on {addr}");
}

// ---------------------------------------------------------------------------

async fn through_proxy(
    proxy: std::net::SocketAddr,
    target: &str,
    payment: Option<&str>,
) -> Result<Response<Bytes>, String> {
    let stream = tokio::net::TcpStream::connect(proxy)
        .await
        .map_err(|e| e.to_string())?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut b = Request::builder()
        .method("GET")
        .uri(target)
        .header("authorization", format!("Bearer {TOKEN}"));
    if let Some(p) = payment {
        b = b.header("x-payment", p);
    }
    let req = b.body(Full::new(Bytes::new())).map_err(|e| e.to_string())?;

    let res = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let (parts, body) = res.into_parts();
    let bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok(Response::from_parts(parts, bytes))
}

// The `postgres` crate is the blocking client, and a blocking client cannot
// be driven from inside a tokio worker. Every database call here goes
// through `spawn_blocking`, which is also what `quaestor-proxy` does in
// production for the same reason.

async fn wipe_database(conn: &str) {
    let conn = conn.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut c = postgres::Client::connect(&conn, postgres::NoTls).expect("connect");
        c.batch_execute(quaestor_ledger::MIGRATION)
            .expect("migrate");
        c.batch_execute("DELETE FROM holds; DELETE FROM budget_accounts;")
            .expect("wipe");
    })
    .await
    .expect("wipe task");
}

async fn read_state(conn: &str, now: Timestamp) -> Vec<HoldRow> {
    let conn = conn.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut c = postgres::Client::connect(&conn, postgres::NoTls).expect("connect");
        // Sweep first, so "nothing is stuck held" asks whether the sweep
        // works rather than whether time has passed.
        c.execute(
            "UPDATE holds SET state = 'expired', settled_at_ms = $1
             WHERE state = 'held' AND expires_at_ms <= $1",
            &[&now.as_millis()],
        )
        .expect("sweep");
        quaestor_chaos::invariants::read_holds(&mut c).expect("read holds")
    })
    .await
    .expect("read task")
}

// ---------------------------------------------------------------------------
// One case
// ---------------------------------------------------------------------------

struct Report {
    point: &'static Point,
    reached: bool,
    violations: Vec<String>,
    notes: Vec<String>,
    origin_paid: usize,
    holds: Vec<HoldRow>,
    receipts: usize,
}

async fn run_case(point: &'static Point, conn: &str) -> Report {
    let origin = spawn_origin(1_000_000).await;
    let rig = Rig::new(point.name, &origin);
    wipe_database(conn).await;
    rig.clear_marker();

    let target = format!("http://{}/report", origin.addr);
    let external = point.name == "write.after";

    // --- the run that dies ------------------------------------------------
    let mut proxy = rig.start(if external { None } else { Some(point.name) });

    // A challenge first, so the payment has something to satisfy.
    let _ = through_proxy(proxy.addr, &target, None).await;

    let payment = honest_payment_now(1_000_000, 1);

    if external {
        // No armed point: the origin holds the response open, and we kill
        // the proxy once the origin confirms the payment is in its hands.
        // This is the one window that cannot be reached from inside the
        // process, because the write and the read are one hyper call.
        origin.set_hang(5_000);
        let addr = proxy.addr;
        let t = target.clone();
        let p = payment.clone();
        let driving = tokio::spawn(async move { through_proxy(addr, &t, Some(&p)).await });

        assert!(
            origin.wait_for_payment(Duration::from_secs(10)),
            "the origin never received the payment, so this case tested nothing"
        );
        proxy.kill();
        let _ = driving.await;
    } else {
        let _ = through_proxy(proxy.addr, &target, Some(&payment)).await;
        let status = proxy.wait_for_death(Duration::from_secs(10));
        assert!(
            status.is_some(),
            "{}: the proxy did not die; the point was never reached",
            point.name
        );
    }

    let reached = external || rig.crashed_at().as_deref() == Some(point.name);
    assert!(
        reached,
        "{}: the process died somewhere else ({:?}), so the window under test \
         was never entered",
        point.name,
        rig.crashed_at()
    );

    // --- restart and look -------------------------------------------------
    let restarted = rig.start(None);
    let now = Timestamp(
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("in range"),
    );

    let holds = read_state(conn, now).await;
    let receipts = rig.receipts();
    let origin_paid = origin.paid();

    let observed = Observed {
        holds: holds.clone(),
        receipts: receipts.clone(),
        signer_key: ed_key(0xAA).verifying_key().to_bytes(),
        origin_was_paid: origin_paid.clone(),
        budgets: policy().budgets.clone(),
        now,
    };
    let (violations, notes) = check(&observed);

    drop(restarted);

    Report {
        point,
        reached,
        violations: violations
            .into_iter()
            .map(|v| format!("{}: {}", v.invariant.label(), v.detail))
            .collect(),
        notes: notes.into_iter().map(|n| n.detail).collect(),
        origin_paid: origin_paid.len(),
        holds,
        receipts: receipts.len(),
    }
}

fn print_report(r: &Report) {
    println!("\n=== {} ===", r.point.name);
    println!("  after:   {}", r.point.after);
    println!("  reached: {}", r.reached);
    println!(
        "  left:    {} hold(s), {} receipt(s), origin paid {} time(s)",
        r.holds.len(),
        r.receipts,
        r.origin_paid
    );
    for h in &r.holds {
        println!("           hold {} is {}", h.intent_id, h.state);
    }
    for n in &r.notes {
        println!("  note:    {n}");
    }
    for v in &r.violations {
        println!("  BROKEN:  {v}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_crash_point_leaves_the_system_in_a_state_we_can_defend() {
    let Some(conn) = pg() else {
        eprintln!("skipping: QUAESTOR_TEST_PG is not set");
        return;
    };

    let mut broken: Vec<String> = Vec::new();
    for point in POINTS {
        let report = run_case(point, &conn).await;
        print_report(&report);
        for v in &report.violations {
            broken.push(format!("{}: {v}", point.name));
        }
    }

    assert!(
        broken.is_empty(),
        "invariants broken:\n  {}",
        broken.join("\n  ")
    );
}

/// Separate from the sweep above because it is not about a crash *window*.
/// It is about what a restart forgets.
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_must_not_make_a_spent_authorization_spendable_again() {
    let Some(conn) = pg() else {
        eprintln!("skipping: QUAESTOR_TEST_PG is not set");
        return;
    };

    let origin = spawn_origin(1_000_000).await;
    let rig = Rig::new("replay", &origin);
    wipe_database(&conn).await;

    let target = format!("http://{}/report", origin.addr);
    let payment = honest_payment_now(1_000_000, 1);

    let mut first = rig.start(None);
    let _ = through_proxy(first.addr, &target, None).await;
    let ok = through_proxy(first.addr, &target, Some(&payment))
        .await
        .expect("the first payment goes through");
    assert_eq!(ok.status(), StatusCode::OK);

    let again = through_proxy(first.addr, &target, Some(&payment))
        .await
        .expect("answered");
    assert_eq!(
        again.status(),
        StatusCode::FORBIDDEN,
        "a replay is refused while the process is up"
    );
    first.kill();

    // Same authorization, new process.
    let _restarted = rig.start(None);
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", rig.port).parse().expect("addr");
    let _ = through_proxy(addr, &target, None).await;
    let after_restart = through_proxy(addr, &target, Some(&payment))
        .await
        .expect("answered");

    let holds = read_state(&conn, Timestamp(0)).await;
    let paid = origin.paid().len();

    assert_eq!(
        after_restart.status(),
        StatusCode::FORBIDDEN,
        "the same authorization was accepted a second time after a restart; \
         holds now: {}, origin paid {paid} times",
        holds.len()
    );
}
