//! The evaluator, in a browser.
//!
//! # Why only this layer
//!
//! [`quaestor_policy::evaluate()`] reads no clock, opens no socket and draws no
//! randomness. Those were not browser concessions — they are there so a
//! decision made today can be replayed next year and reach the same answer.
//! The side effect is that this is the one layer that runs unchanged in
//! WebAssembly.
//!
//! Everything below it needs something a browser does not have. The ledger
//! needs Postgres, the proxy needs sockets, the receipt log needs a
//! filesystem. None of that is missing from the playground; it was never
//! going to be there.
//!
//! So what you can try here is exactly the part that is pure, and the
//! demonstration is honest about it.
//!
//! # No unsafe, and no build tooling
//!
//! The usual way to move a string across the WebAssembly boundary is to
//! export an allocator, hand JavaScript a pointer, and reconstruct a slice
//! from it on the way back. That needs `unsafe`, and this workspace forbids
//! `unsafe` — a rule that would be worth very little if it were suspended
//! the first time it was inconvenient, in the one crate people actually
//! click on.
//!
//! There is one exception and it is narrower than it looks. `#[no_mangle]`
//! trips the `unsafe_code` lint, because the linker cannot promise two
//! libraries will not export the same symbol. That is a symbol-collision
//! concern, not a memory-safety one, and a WebAssembly export has to be
//! named. So the attribute is allowed on exactly the five exports below,
//! the lint stays `deny` everywhere else, and
//! `this_crate_contains_no_unsafe_block` checks the source for the thing the
//! lint is usually about.
//!
//! So bytes cross one at a time, through [`push`] and [`out`], into and out
//! of a `RefCell<Vec<u8>>`. For a two-kilobyte policy that is a few thousand
//! calls and well under a millisecond, which is nothing next to the human
//! typing the policy. It is the slowest sensible design and the only
//! completely safe one, and at this size the trade costs nothing.
//!
//! It also means the artifact is built by one command with no `wasm-pack`,
//! no `wasm-bindgen`, no npm, and nothing to install:
//!
//! ```bash
//! cargo build -p quaestor-playground --release --target wasm32-unknown-unknown
//! ```
//!
//! # The protocol
//!
//! ```text
//!   reset()                 empty the input buffer
//!   push(b) for each byte   UTF-8 JSON request
//!   run() -> len            evaluate; returns the response length
//!   out(i) -> byte          read the response back
//! ```
//!
//! A request that does not parse produces a response that says so. There is
//! no error channel and no panic path: this is a thing on the internet that
//! strangers will paste nonsense into, and the only acceptable answer to
//! nonsense is a sentence explaining it.

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
    )
)]

use std::cell::RefCell;

mod request;
mod respond;

thread_local! {
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Largest request we will accept, so a stuck loop on the page cannot grow
/// the heap without limit.
const MAX_INPUT: usize = 256 * 1024;

/// Empty the input buffer, ready for a new request.
#[allow(unsafe_code)] // see the module docs: a symbol name, not a pointer
#[no_mangle]
pub extern "C" fn reset() {
    INPUT.with(|b| b.borrow_mut().clear());
    OUTPUT.with(|b| b.borrow_mut().clear());
}

/// Append one byte of the UTF-8 JSON request. Only the low eight bits are
/// read, so a caller that passes a char code rather than a byte is truncated
/// rather than trusted.
#[allow(unsafe_code)] // see the module docs: a symbol name, not a pointer
#[no_mangle]
pub extern "C" fn push(byte: u32) {
    INPUT.with(|b| {
        let mut b = b.borrow_mut();
        if b.len() < MAX_INPUT {
            b.push((byte & 0xff) as u8);
        }
    });
}

/// Evaluate what has been pushed. Returns the response length in bytes.
#[allow(unsafe_code)] // see the module docs: a symbol name, not a pointer
#[no_mangle]
pub extern "C" fn run() -> u32 {
    let input = INPUT.with(|b| b.borrow().clone());
    let response = respond::answer(&input);
    let len = response.len();
    OUTPUT.with(|b| *b.borrow_mut() = response);
    u32::try_from(len).unwrap_or(0)
}

/// Read one byte of the response. Out of range reads return zero rather than
/// trapping, because a page with an off-by-one should show a mangled string,
/// not a dead WebAssembly instance.
#[allow(unsafe_code)] // see the module docs: a symbol name, not a pointer
#[no_mangle]
pub extern "C" fn out(index: u32) -> u32 {
    OUTPUT.with(|b| {
        let b = b.borrow();
        usize::try_from(index)
            .ok()
            .and_then(|i| b.get(i).copied())
            .map_or(0, u32::from)
    })
}

/// The protocol version, so a stale cached page can notice it is stale.
#[allow(unsafe_code)] // see the module docs: a symbol name, not a pointer
#[no_mangle]
pub extern "C" fn version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_crate_contains_no_unsafe_block() {
        // The lint had to be relaxed from `forbid` to `deny` so the exports
        // could be named. That is a narrow exception and this is the guard
        // that keeps it narrow: the attribute is permitted, an `unsafe`
        // block is not, and nobody gets to widen the first into the second
        // without this failing.
        // Only the shipped half of each file: the test modules below
        // necessarily contain the words being searched for, and a guard that
        // trips on its own assertion text guards nothing.
        let needle_block = concat!("unsafe", " {");
        let needle_fn = concat!("unsafe", " fn");
        for (name, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("request.rs", include_str!("request.rs")),
            ("respond.rs", include_str!("respond.rs")),
        ] {
            let shipped = source.split("#[cfg(test)]").next().unwrap_or(source);
            assert!(
                !shipped.contains(needle_block),
                "{name} contains an unsafe block"
            );
            assert!(
                !shipped.contains(needle_fn),
                "{name} declares an unsafe function"
            );
        }
    }

    /// Drive the export protocol exactly as the page does.
    fn call(request: &str) -> String {
        reset();
        for b in request.as_bytes() {
            push(u32::from(*b));
        }
        let len = run();
        let mut s = Vec::with_capacity(len as usize);
        for i in 0..len {
            s.push(out(i) as u8);
        }
        String::from_utf8(s).expect("responses are always valid UTF-8")
    }

    #[test]
    fn nonsense_gets_a_sentence_and_not_a_panic() {
        // Strangers will paste anything into this.
        for junk in ["", "{", "null", "[]", "{\"op\":\"nope\"}", "ðŸ”¥"] {
            let out = call(junk);
            assert!(out.contains("\"error\""), "{junk:?} produced {out}");
        }
    }

    #[test]
    fn a_reset_actually_resets() {
        call("{\"op\":\"nope\"}");
        reset();
        assert_eq!(run(), call("").len() as u32);
    }

    #[test]
    fn the_input_is_bounded() {
        reset();
        for _ in 0..(MAX_INPUT + 1_000) {
            push(u32::from(b'a'));
        }
        INPUT.with(|b| assert_eq!(b.borrow().len(), MAX_INPUT));
    }

    #[test]
    fn reading_past_the_end_is_zero_rather_than_a_trap() {
        let len = call("{}").len() as u32;
        assert_eq!(out(len), 0);
        assert_eq!(out(u32::MAX), 0);
    }

    #[test]
    fn only_the_low_byte_of_a_push_is_kept() {
        reset();
        push(0x4141);
        INPUT.with(|b| assert_eq!(b.borrow().as_slice(), b"A"));
    }
}
