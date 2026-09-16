// Execute the real WebAssembly artifact.
//
// The crate's own tests drive the same exports, but they run on x86_64
// against the rlib. This is the only place the thing that ships to a browser
// is actually executed, and the difference has bitten before: `getrandom`
// compiles happily for the host and not at all for wasm32.
//
//   node scripts/smoke-playground.mjs <path to .wasm>
import { readFileSync } from 'node:fs';
const bytes = readFileSync(process.argv[2]);
const { instance } = await WebAssembly.instantiate(bytes, {});
const x = instance.exports;

function call(obj) {
  const enc = new TextEncoder().encode(JSON.stringify(obj));
  x.reset();
  for (const b of enc) x.push(b);
  const len = x.run();
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = x.out(i);
  return JSON.parse(new TextDecoder().decode(out));
}

console.log('version export:', x.version());

const POLICY = `
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
`;

const base = (amount, payee) => ({
  op: 'evaluate', policy: POLICY,
  authority: { max_amount: '50.000000', payees: null, not_after_ms: 4000000000000 },
  payment: { amount, payee, rail: 'x402' },
  state: { spent: { '24h': '0.000000' }, payee_seen: true },
  now_ms: 1772000000000,
});

console.log('1 USDC to shop      ->', call(base('1.000000','shop.example')).verdict.verdict);
console.log('3 USDC (over limit) ->', call(base('3.000000','shop.example')).verdict.verdict);
console.log('1 USDC to blocked   ->', call(base('1.000000','blocked.example')).verdict.verdict);

const noState = base('1.000000','shop.example'); noState.state = { spent: {}, payee_seen: true };
const r = call(noState);
console.log('no spend figure     ->', r.verdict.verdict, '| missing:', r.windows_without_a_figure);

console.log('drop payee restr.   ->', call({
  op: 'attenuate',
  parent: { max_amount: '50.000000', payees: ['a.example'], not_after_ms: 4000000000000 },
  child:  { max_amount: '10.000000', payees: null,          not_after_ms: 4000000000000 },
}));

const garbage = call({ op: 'nope' });
console.log('garbage             ->', garbage.error ? 'refused with a sentence' : 'NOT REFUSED');

// Assert, rather than print and hope a human reads CI output.
const expect = (what, got, want) => {
  if (got !== want) { console.error(`FAIL ${what}: expected ${want}, got ${got}`); process.exitCode = 1; }
};
expect('small payment', call(base('1.000000','shop.example')).verdict.verdict, 'allow');
expect('over limit',    call(base('3.000000','shop.example')).verdict.verdict, 'escalate');
expect('blocked payee', call(base('1.000000','blocked.example')).verdict.verdict, 'deny');
expect('no figure',     call(noState).verdict.verdict, 'deny');
expect('widening',      call({
  op: 'attenuate',
  parent: { max_amount: '50.000000', payees: ['a.example'], not_after_ms: 4000000000000 },
  child:  { max_amount: '10.000000', payees: null,          not_after_ms: 4000000000000 },
}).within, false);
expect('garbage',       typeof garbage.error, 'string');
if (!process.exitCode) console.log('\nall playground assertions hold');
