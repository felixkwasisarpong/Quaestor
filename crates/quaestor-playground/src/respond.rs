//! Turning a request into an answer, without ever panicking.
//!
//! Every failure here is a sentence, not a trap. A WebAssembly instance that
//! panics is dead until the page is reloaded, and the person who killed it
//! did so by typing something wrong into a textarea — which is the expected
//! use of a textarea.

use quaestor_core::{
    AgentId, CallContext, IdempotencyKey, IntentId, Payee, PayeeId, PaymentIntent, PrincipalId,
    Timestamp,
};
use quaestor_policy::{evaluate, Policy, Request as PolicyRequest, SpendSnapshot};

use crate::request::{self, Attenuate, Evaluate, Request};

/// The one entry point. Always returns valid UTF-8 JSON.
pub fn answer(input: &[u8]) -> Vec<u8> {
    let json = match run(input) {
        Ok(v) => v,
        Err(message) => serde_json::json!({ "error": message }),
    };
    serde_json::to_vec(&json)
        .unwrap_or_else(|_| br#"{"error":"the answer could not be serialized"}"#.to_vec())
}

fn run(input: &[u8]) -> Result<serde_json::Value, String> {
    if input.is_empty() {
        return Err("no request".to_owned());
    }
    let request: Request = serde_json::from_slice(input).map_err(|e| e.to_string())?;
    match request {
        Request::Evaluate(r) => do_evaluate(&r),
        Request::Attenuate(r) => do_attenuate(&r),
    }
}

fn do_evaluate(r: &Evaluate) -> Result<serde_json::Value, String> {
    let policy = Policy::parse(&r.policy).map_err(|e| format!("policy: {e}"))?;
    let currency = policy.currency;

    let authority = r.authority.build(currency)?;
    let amount = request::parse_amount(&r.payment.amount, currency, "payment.amount")?;

    let intent = PaymentIntent {
        id: IntentId::new("playground").map_err(|e| e.to_string())?,
        idempotency_key: IdempotencyKey::new("playground").map_err(|e| e.to_string())?,
        agent: AgentId::new("shopper").map_err(|e| e.to_string())?,
        principal: PrincipalId::new("you").map_err(|e| e.to_string())?,
        amount,
        payee: Payee {
            id: PayeeId::new(r.payment.payee.trim()).map_err(|e| format!("payee: {e}"))?,
            rail: request::rail(&r.payment.rail)?,
            category: r.payment.category.clone().filter(|c| !c.trim().is_empty()),
            domain: r.payment.domain.clone().filter(|d| !d.trim().is_empty()),
        },
        context: CallContext {
            session_id: None,
            tool_call_id: None,
            parent_intent: None,
        },
        requested_at: Timestamp(r.now_ms),
    };

    // Spend is supplied per window *label*, which is what the policy file
    // uses. A label with no entry stays absent, and the evaluator refuses on
    // it rather than assuming zero. Deleting a line here is the quickest way
    // to see what `StateUnavailable` is for.
    let mut snapshot = SpendSnapshot::new().with_payee_seen_before(r.state.payee_seen);
    let mut unknown_labels = Vec::new();
    for (label, text) in &r.state.spent {
        match policy.budgets.iter().find(|b| &b.window_label == label) {
            Some(budget) => {
                let spent = request::parse_amount(text, currency, &format!("spent.{label}"))?;
                snapshot = snapshot.with_spend(budget.window_ms, spent);
            }
            None => unknown_labels.push(label.clone()),
        }
    }
    if let Some(v) = r.state.velocity {
        snapshot = snapshot.with_velocity(v);
    }

    let verdict = evaluate(&PolicyRequest {
        intent: &intent,
        authority: &authority,
        policy: &policy,
        state: &snapshot,
        now: Timestamp(r.now_ms),
    });

    let missing: Vec<&str> = policy
        .budgets
        .iter()
        .filter(|b| !r.state.spent.contains_key(&b.window_label))
        .map(|b| b.window_label.as_str())
        .collect();

    Ok(serde_json::json!({
        "verdict": verdict,
        "summary": summarize(&verdict),
        "currency": currency.code(),
        "policy_version": hex(&policy.version_hash),
        // Said out loud, because an unexplained denial in a demo reads as a
        // broken demo rather than as the rule doing its job.
        "windows_without_a_figure": missing,
        "labels_not_in_the_policy": unknown_labels,
    }))
}

fn do_attenuate(r: &Attenuate) -> Result<serde_json::Value, String> {
    let currency = request::currency(&r.currency)?;
    let parent = r.parent.build(currency)?;
    let child = r.child.build(currency)?;

    Ok(match child.is_within(&parent) {
        Ok(()) => serde_json::json!({
            "within": true,
            "summary": "The child grants no more than the parent. This delegation is legal.",
        }),
        Err(widening) => serde_json::json!({
            "within": false,
            "widening": widening.to_string(),
            "summary": format!("Refused: {widening}"),
        }),
    })
}

/// One line a person can read, from a verdict that may carry four reasons.
fn summarize(verdict: &quaestor_core::Verdict) -> String {
    use quaestor_core::Verdict;
    match verdict {
        Verdict::Allow { .. } => "Allowed.".to_owned(),
        Verdict::Deny { reasons } => format!(
            "Denied, for {} {}.",
            reasons.len(),
            if reasons.len() == 1 {
                "reason"
            } else {
                "reasons"
            }
        ),
        Verdict::Escalate { reasons, .. } => format!(
            "A human is asked, for {} {}. If nobody answers, this resolves to denied.",
            reasons.len(),
            if reasons.len() == 1 {
                "reason"
            } else {
                "reasons"
            }
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
version = 1
currency = "USDC"

[defaults]
unattended_limit = "2.000000 USDC"
escalate_first_seen_payee = true

[[budgets]]
window = "24h"
limit = "5.000000 USDC"

[payees]
deny = ["blocked.example"]
"#;

    fn request(amount: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "op": "evaluate",
            "policy": POLICY,
            "authority": {
                "max_amount": "50.000000",
                "payees": null,
                "not_after_ms": 4_000_000_000_000_i64,
            },
            "payment": { "amount": amount, "payee": "shop.example", "rail": "x402" },
            "state": { "spent": { "24h": "0.000000" }, "payee_seen": true },
            "now_ms": 1_772_000_000_000_i64,
        });
        if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        base
    }

    fn call(v: &serde_json::Value) -> serde_json::Value {
        let bytes = answer(serde_json::to_string(v).expect("serialize").as_bytes());
        serde_json::from_slice(&bytes).expect("responses are JSON")
    }

    #[test]
    fn a_small_familiar_payment_is_allowed() {
        let out = call(&request("1.000000", serde_json::json!({})));
        assert_eq!(out["verdict"]["verdict"], "allow", "{out}");
    }

    #[test]
    fn a_blocked_payee_is_denied() {
        let out = call(&request(
            "1.000000",
            serde_json::json!({
                "payment": { "amount": "1.000000", "payee": "blocked.example", "rail": "x402" }
            }),
        ));
        assert_eq!(out["verdict"]["verdict"], "deny", "{out}");
    }

    #[test]
    fn above_the_unattended_limit_asks_a_human() {
        let out = call(&request("3.000000", serde_json::json!({})));
        assert_eq!(out["verdict"]["verdict"], "escalate", "{out}");
        assert!(out["summary"]
            .as_str()
            .unwrap_or("")
            .contains("resolves to denied"));
    }

    #[test]
    fn a_window_with_no_figure_denies_and_the_page_is_told_which() {
        // The demo for BUGS.md #011: delete the spend line, watch it refuse.
        let out = call(&request(
            "1.000000",
            serde_json::json!({ "state": { "spent": {}, "payee_seen": true } }),
        ));
        assert_eq!(out["verdict"]["verdict"], "deny", "{out}");
        assert_eq!(out["windows_without_a_figure"][0], "24h");
    }

    #[test]
    fn a_payment_outside_the_delegated_payees_is_refused() {
        let out = call(&request(
            "1.000000",
            serde_json::json!({
                "authority": {
                    "max_amount": "50.000000",
                    "payees": ["someone.else"],
                    "not_after_ms": 4_000_000_000_000_i64,
                }
            }),
        ));
        assert_eq!(out["verdict"]["verdict"], "deny", "{out}");
    }

    #[test]
    fn dropping_a_payee_restriction_is_widening() {
        // The most interesting thing in the repo, as one request.
        let out = call(&serde_json::json!({
            "op": "attenuate",
            "currency": "USDC",
            "parent": {
                "max_amount": "50.000000",
                "payees": ["a.example", "b.example"],
                "not_after_ms": 4_000_000_000_000_i64,
            },
            "child": {
                "max_amount": "10.000000",
                "payees": null,
                "not_after_ms": 4_000_000_000_000_i64,
            },
        }));
        assert_eq!(out["within"], false, "{out}");
        assert!(
            out["widening"].as_str().unwrap_or("").contains("payee"),
            "{out}"
        );
    }

    #[test]
    fn a_genuinely_narrower_child_is_legal() {
        let out = call(&serde_json::json!({
            "op": "attenuate",
            "parent": {
                "max_amount": "50.000000",
                "payees": ["a.example", "b.example"],
                "not_after_ms": 4_000_000_000_000_i64,
            },
            "child": {
                "max_amount": "10.000000",
                "payees": ["a.example"],
                "not_after_ms": 3_000_000_000_000_i64,
            },
        }));
        assert_eq!(out["within"], true, "{out}");
    }

    #[test]
    fn a_broken_policy_file_is_a_sentence() {
        let out = call(&request(
            "1.000000",
            serde_json::json!({ "policy": "version = 99" }),
        ));
        assert!(
            out["error"].as_str().unwrap_or("").starts_with("policy:"),
            "{out}"
        );
    }

    #[test]
    fn a_float_amount_is_refused_rather_than_rounded() {
        let out = call(&request("1.0000005", serde_json::json!({})));
        assert!(out["error"].is_string(), "{out}");
    }
}
