//! Emit a small receipt log plus its public key, for trying the verifier.
#![allow(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
use ed25519_dalek::SigningKey;
use quaestor_core::*;
use quaestor_receipt::Signer;

fn main() {
    let mut s = Signer::new(SigningKey::from_bytes(&[7u8; 32]));
    // Labelled, and on stderr so that `> receipts.jsonl` still produces a
    // clean log. A bare 64-character string appearing on a terminal with no
    // explanation is not a usable instruction.
    eprintln!("public key (pass this to --key):");
    eprintln!("{}", hex(&s.public_key()));
    let now = Timestamp(1_772_000_000_000);
    let usd = |m| Money::new(m, Currency::USD);
    let pol = [0xABu8; 32];

    let allow = Verdict::Allow {
        hold: Hold {
            intent: IntentId::new("i").expect("v"),
            amount: usd(100),
            expires_at: Timestamp(now.0 + 300_000),
        },
    };
    let deny = Verdict::Deny {
        reasons: vec![DenyReason::PayeeBlocked],
    };
    let esc = Verdict::Escalate {
        to: Approver {
            principal: PrincipalId::new("felix").expect("v"),
            channel: None,
        },
        reasons: vec![EscalationReason::FirstSeenPayee],
        expires_at: Timestamp(now.0 + 900_000),
    };

    for (id, payee, amt, v) in [
        ("i1", "shop.example", 1_999, &allow),
        ("i2", "known-bad.example", 5_000, &deny),
        ("i3", "new-vendor.example", 9_900, &esc),
    ] {
        let r = s.issue(id, "felix", "shopper", payee, usd(amt), v, pol, now);
        println!("{}", serde_json::to_string(&r).expect("json"));
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
