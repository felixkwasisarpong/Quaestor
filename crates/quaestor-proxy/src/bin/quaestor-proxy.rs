//! `quaestor-proxy` — put this in front of an agent.
//!
//! Point the agent's HTTP client at it and every payment it attempts is
//! verified, evaluated, held and receipted before a byte reaches the
//! resource server. Payments it refuses are not forwarded.
//!
//! ```bash
//! export QUAESTOR_RECEIPT_KEY=$(openssl rand -hex 32)
//! export QUAESTOR_TOKEN_SHOPPER=$(openssl rand -hex 24)
//! quaestor-proxy --config quaestor.toml
//!
//! HTTPS_PROXY= http_proxy=http://127.0.0.1:8402 your-agent
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use quaestor_core::{AgentId, Currency, Money, PrincipalId, Rail, Timestamp};
use quaestor_policy::Policy;
use quaestor_proxy::http::{Proxy, SystemClock};
use quaestor_proxy::{
    Caller, Config, Gateway, Identities, InMemoryHolds, JsonLinesSink, PostgresHolds, ReceiptSink,
};
use quaestor_verify::mandate::{Constraint, Scope};
use quaestor_verify::x402::{AssetRegistry, AssetSpec, InMemoryNonceStore};
use serde::Deserialize;

const USAGE: &str = "\
quaestor-proxy — the spend firewall, inline

USAGE:
    quaestor-proxy --config <FILE>

OPTIONS:
    --config <FILE>    Deployment configuration, TOML.
    -h, --help         Print this.

ENVIRONMENT:
    QUAESTOR_RECEIPT_KEY   32-byte Ed25519 signing key, hex. Receipts chain
                           from a key, so a new one on every restart starts a
                           new chain. Required.
    QUAESTOR_PG            Postgres connection string. Without it the ledger
                           is in memory, which forgets every budget on
                           restart and is refused unless --config sets
                           allow_volatile_ledger.
    <caller token vars>    Named per caller by `token_env`. Tokens are read
                           from the environment and never from the config
                           file, which people commit to repositories.
";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: String,
    policy: String,
    /// Where decision receipts are appended, as JSON Lines.
    ///
    /// Required, and with no default. A gateway that signs receipts and
    /// writes them nowhere leaves the only copy of the evidence in the hands
    /// of the party it is auditing.
    receipt_log: String,
    #[serde(default)]
    challenge_ttl_seconds: Option<i64>,
    #[serde(default)]
    allow_volatile_ledger: bool,
    assets: Vec<AssetConfig>,
    callers: Vec<CallerConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetConfig {
    network: String,
    address: String,
    currency: String,
    eip712_name: String,
    eip712_version: String,
    chain_id: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerConfig {
    token_env: String,
    principal: String,
    agent: String,
    /// Ceiling on a single payment, e.g. `"5.000000 USDC"`. No default: a
    /// ceiling this file forgot to set must not become an unlimited one.
    max_amount: String,
    #[serde(default)]
    payees: Option<Vec<String>>,
    #[serde(default)]
    rails: Option<Vec<String>>,
    /// How long this credential's authority lasts, in seconds from startup.
    valid_for_seconds: i64,
    /// Ed25519 keys, hex, trusted to originate a delegation chain for this
    /// caller. Absent means this caller may present no chain at all.
    #[serde(default)]
    root_keys: Vec<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("quaestor-proxy: {e}");
        std::process::exit(2);
    }
}

/// Set everything up, then serve.
///
/// Deliberately **not** `#[tokio::main]`. The `postgres` crate's `Client` is
/// the blocking client: it owns a runtime and drives it with `block_on`, so
/// constructing one from inside another runtime's worker panics with
/// "cannot start a runtime from within a runtime".
///
/// This function had that annotation, and so opening a real ledger crashed
/// the process before it ever listened. Nothing caught it because every test
/// ran on the in-memory ledger, which meant the only setting anybody would
/// deploy was the only one never exercised. Found on day 19 by a harness
/// whose first step is to start the process twice. See `BUGS.md` #017.
///
/// So: all setup happens synchronously, out here, and the runtime is entered
/// only to serve.
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(());
    }

    let mut path = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => path = it.next().cloned(),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let path = path.ok_or("--config is required")?;

    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let file: FileConfig = toml::from_str(&text).map_err(|e| format!("{path}: {e}"))?;

    let policy_text =
        std::fs::read_to_string(&file.policy).map_err(|e| format!("{}: {e}", file.policy))?;
    let policy = Policy::parse(&policy_text).map_err(|e| format!("{}: {e}", file.policy))?;

    let key = receipt_key()?;
    let sink =
        JsonLinesSink::open(&file.receipt_log).map_err(|e| format!("{}: {e}", file.receipt_log))?;
    let resumed_at = sink.len();
    let registry = build_registry(&file.assets)?;
    let now = Timestamp(
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis(),
        )
        .map_err(|_| "the clock is beyond this program's range")?,
    );
    let identities = build_identities(&file.callers, policy.currency, now)?;

    let mut config = Config::new(policy, registry);
    if let Some(secs) = file.challenge_ttl_seconds {
        config.challenge_ttl_ms = secs
            .checked_mul(1_000)
            .ok_or("challenge_ttl_seconds is absurd")?;
    }

    let holds = open_ledger(file.allow_volatile_ledger)?;
    let public_key = key.verifying_key().to_bytes();
    let gateway = Gateway::new(
        config,
        identities,
        holds,
        Box::new(InMemoryNonceStore::default()),
        key,
        Box::new(sink),
    );

    let addr: std::net::SocketAddr = file
        .listen
        .parse()
        .map_err(|e| format!("listen {}: {e}", file.listen))?;

    println!("quaestor-proxy listening on {addr}");
    println!("receipt signing key (public): {}", hex(&public_key));
    println!(
        "receipt log: {} ({resumed_at} receipts already recorded)",
        file.receipt_log
    );
    println!();
    println!("Verify a receipt log against that key with:");
    println!(
        "    quaestor-verify-receipts --key {} receipts.jsonl",
        hex(&public_key)
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the runtime: {e}"))?;

    runtime.block_on(async move {
        Proxy::new(gateway, Arc::new(SystemClock))
            .serve(addr)
            .await
            .map_err(|e| e.to_string())
    })
}

/// The ledger, or a refusal to pretend.
///
/// An in-memory ledger forgets every budget when the process restarts, which
/// means a crash loop is an unlimited spending allowance. It stays available
/// because it is genuinely useful for a demo, and it requires saying so in
/// the configuration file, out loud, in a field named after what it does.
fn open_ledger(allow_volatile: bool) -> Result<Box<dyn quaestor_proxy::Holds>, String> {
    match std::env::var("QUAESTOR_PG") {
        Ok(conn) if !conn.is_empty() => {
            let client = postgres_client(&conn)?;
            let mut store = quaestor_ledger::Store::new(client);
            store
                .migrate()
                .map_err(|e| format!("could not apply the ledger schema: {e}"))?;
            Ok(Box::new(PostgresHolds::new(store)))
        }
        _ if allow_volatile => {
            eprintln!(
                "warning: QUAESTOR_PG is not set, so budgets live in memory and are \
                 forgotten on restart. Do not run this in front of real money."
            );
            Ok(Box::new(InMemoryHolds::new()))
        }
        _ => Err(
            "QUAESTOR_PG is not set. A budget that does not survive a restart is \
                  not a budget; set allow_volatile_ledger = true to proceed anyway."
                .to_owned(),
        ),
    }
}

fn postgres_client(conn: &str) -> Result<postgres::Client, String> {
    postgres::Client::connect(conn, postgres::NoTls)
        .map_err(|e| format!("could not reach Postgres: {e}"))
}

fn receipt_key() -> Result<SigningKey, String> {
    let hex_key = std::env::var("QUAESTOR_RECEIPT_KEY").map_err(|_| {
        "QUAESTOR_RECEIPT_KEY is not set. Receipts chain from a signing key, and a \
         key generated fresh on each start would begin a new chain every restart — \
         which is indistinguishable from someone discarding the old one."
    })?;
    let bytes = parse_hex32(hex_key.trim()).map_err(|e| format!("QUAESTOR_RECEIPT_KEY: {e}"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn build_registry(assets: &[AssetConfig]) -> Result<AssetRegistry, String> {
    if assets.is_empty() {
        return Err(
            "no assets configured, so every payment would be refused as an \
                    unknown token"
                .to_owned(),
        );
    }
    let mut registry = AssetRegistry::new();
    for a in assets {
        registry = registry.insert(
            &a.network,
            &a.address,
            AssetSpec {
                currency: currency(&a.currency)?,
                eip712_name: a.eip712_name.clone(),
                eip712_version: a.eip712_version.clone(),
                chain_id: a.chain_id,
            },
        );
    }
    Ok(registry)
}

fn build_identities(
    callers: &[CallerConfig],
    policy_currency: Currency,
    now: Timestamp,
) -> Result<Identities, String> {
    if callers.is_empty() {
        return Err("no callers configured, so nothing could authenticate".to_owned());
    }
    let mut identities = Identities::new();
    for c in callers {
        let token = std::env::var(&c.token_env).map_err(|_| {
            format!(
                "{} is not set, so caller {} has no credential",
                c.token_env, c.principal
            )
        })?;
        if token.trim().is_empty() {
            return Err(format!("{} is empty", c.token_env));
        }

        let max_amount = Money::parse(&c.max_amount, policy_currency)
            .map_err(|e| format!("caller {}: max_amount: {e}", c.principal))?;
        if max_amount.is_negative() {
            return Err(format!("caller {}: max_amount is negative", c.principal));
        }

        let not_after = Timestamp(
            now.as_millis()
                .checked_add(
                    c.valid_for_seconds
                        .checked_mul(1_000)
                        .ok_or("valid_for_seconds is absurd")?,
                )
                .ok_or("valid_for_seconds is absurd")?,
        );

        let mut root_keys = Vec::with_capacity(c.root_keys.len());
        for k in &c.root_keys {
            root_keys.push(
                parse_hex32(k.trim())
                    .map_err(|e| format!("caller {}: root key: {e}", c.principal))?,
            );
        }

        identities = identities.insert(
            token.trim(),
            Caller {
                principal: PrincipalId::new(c.principal.clone())
                    .map_err(|e| format!("principal {}: {e}", c.principal))?,
                agent: AgentId::new(c.agent.clone())
                    .map_err(|e| format!("agent {}: {e}", c.agent))?,
                scope: Scope {
                    max_amount,
                    payees: constraint(c.payees.as_deref()),
                    categories: Constraint::Any,
                    rails: rails(c.rails.as_deref())?,
                    not_after,
                },
                root_keys,
            },
        );
    }
    Ok(identities)
}

/// Absent means unrestricted; a present list means exactly that list.
///
/// The two are different grants and the difference is load-bearing. An empty
/// list in the file is an empty `Only`, which permits nothing — a strange
/// thing to write, but not the same as leaving the key out, and we do not
/// silently convert one into the other.
fn constraint(values: Option<&[String]>) -> Constraint<String> {
    match values {
        None => Constraint::Any,
        Some(list) => Constraint::Only(list.iter().map(|s| s.to_ascii_lowercase()).collect()),
    }
}

fn rails(values: Option<&[String]>) -> Result<Constraint<Rail>, String> {
    let Some(list) = values else {
        return Ok(Constraint::Any);
    };
    let mut set = std::collections::BTreeSet::new();
    for r in list {
        set.insert(match r.as_str() {
            "x402" => Rail::X402,
            "ap2" => Rail::Ap2,
            "acp" => Rail::Acp,
            "mpp" => Rail::Mpp,
            "ucp" => Rail::Ucp,
            "card" => Rail::Card,
            other => return Err(format!("unknown rail {other}")),
        });
    }
    Ok(Constraint::Only(set))
}

fn currency(code: &str) -> Result<Currency, String> {
    match code {
        "USD" => Ok(Currency::USD),
        "EUR" => Ok(Currency::EUR),
        "GBP" => Ok(Currency::GBP),
        "JPY" => Ok(Currency::JPY),
        "USDC" => Ok(Currency::USDC),
        other => Err(format!(
            "unknown currency {other}: decimals decide whether a number means one \
             dollar or one millionth of one, so this is not guessed"
        )),
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let text = core::str::from_utf8(pair).map_err(|e| e.to_string())?;
        *slot = u8::from_str_radix(text, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
