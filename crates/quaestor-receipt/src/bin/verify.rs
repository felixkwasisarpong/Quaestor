//! `quaestor-verify-receipts` — check a receipt log offline.
//!
//! Deliberately tiny and deliberately standalone. Someone who does not trust
//! the system that produced these receipts, and does not want to install it,
//! should be able to build this one binary and check the record themselves.
//!
//! It opens no network connection. That is the entire point.

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]

use std::io::Read;

use quaestor_receipt::{verify_chain, Receipt};

const USAGE: &str = "\
quaestor-verify-receipts — verify a receipt log offline

USAGE:
    quaestor-verify-receipts --key <HEX> [FILE]

ARGS:
    <FILE>    JSON Lines, one receipt per line. Reads stdin if omitted.

OPTIONS:
    --key <HEX>    The 32-byte Ed25519 public key you expect, as hex.
    --partial      Treat the input as a slice of a longer chain, so the
                   first receipt need not be the start of history.
    -h, --help     Print this.

EXIT STATUS:
    0    every receipt verifies and the chain is intact
    1    verification failed
    2    the arguments or the input were unusable
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }

    let mut key_hex: Option<String> = None;
    let mut path: Option<String> = None;
    let mut partial = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key" => key_hex = it.next().cloned(),
            "--partial" => partial = true,
            other if other.starts_with('-') => fail(2, &format!("unknown option {other}")),
            other => path = Some(other.to_owned()),
        }
    }

    let Some(key_hex) = key_hex else {
        fail(2, "--key is required\n\n{USAGE}");
        return;
    };
    let key = match parse_key(&key_hex) {
        Ok(k) => k,
        Err(e) => {
            fail(2, &format!("bad --key: {e}"));
            return;
        }
    };

    let text = match read_input(path.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            fail(2, &format!("could not read input: {e}"));
            return;
        }
    };

    let mut receipts = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Receipt>(line) {
            Ok(r) => receipts.push(r),
            Err(e) => {
                fail(2, &format!("line {}: {e}", i.saturating_add(1)));
                return;
            }
        }
    }

    if receipts.is_empty() {
        fail(2, "no receipts found");
        return;
    }

    match verify_chain(&receipts, &key, !partial) {
        Ok(report) => {
            println!("OK  {} receipts verified", report.count);
            println!(
                "    {} allowed, {} denied, {} escalated",
                report.allowed, report.denied, report.escalated
            );
            println!("    head {}", hex(&report.head));
            println!();
            println!("Signatures check against the given key and the chain is unbroken.");
            println!("No receipt in this file was altered, removed or reordered.");
        }
        Err(e) => {
            eprintln!("FAILED  {e}");
            eprintln!();
            eprintln!("This log is not trustworthy. Do not rely on it.");
            std::process::exit(1);
        }
    }
}

fn read_input(path: Option<&str>) -> std::io::Result<String> {
    match path {
        Some(p) => std::fs::read_to_string(p),
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s)
        }
    }
}

fn parse_key(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim().trim_start_matches("0x");
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fail(code: i32, msg: &str) {
    eprintln!("{msg}");
    std::process::exit(code);
}
