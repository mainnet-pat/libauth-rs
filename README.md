# libauth (Rust port)

A Rust port of [`@bitauth/libauth`](https://github.com/bitauth/libauth)
v3.1.0-next.8 (commit `d28da7f5`).

## Layout

The crate mirrors libauth's `src/` tree file for file:

- `src/index.rs` is `src/index.ts`, and `src/lib/lib.rs` is `src/lib/lib.ts`.
  Every libauth source file `src/lib/**/X.ts` (or `X.js`/`X.d.ts`) has a Rust
  counterpart `src/lib/**/X.rs` with the same kebab-case name, mounted with
  `#[path]`; module identifiers replace `-` and `.` with `_` (so
  `vm/instruction-sets/bch/2023/bch-2023-tokens.ts` is
  `vm::instruction_sets::bch::bch_2023::bch_2023_tokens`).
- Barrels re-export exactly what libauth's `export *` statements re-export, in
  the same order. Directories without a barrel (e.g. `bin/sha256/`,
  `vmb-tests/sources/`) are inline modules of their parent. Everything is
  re-exported at the crate root, like libauth's package entry point.
- Specs: every `X.spec.ts` is a Cargo test target `X.spec.rs` beside it, every
  `X.spec.helper.ts` an `X.spec.helper.rs` (runnable helpers are Cargo
  examples), and every `X.bench.ts` a Cargo bench `X.bench.rs`
  (`harness = false`).
- Non-code files are copied verbatim: readmes, fixtures, JSON schemas, and
  BCHN result files. The generated VMB tests in
  `src/lib/vmb-tests/generated/` are not tracked, although libauth tracks most
  of them (see [Building and testing](#building-and-testing)).

Not mirrored:

- `src/runtime/` has no counterpart in libauth: it implements the JavaScript
  built-ins libauth relies on (`BigInt`, `JSON`, `RegExp`, `Number#toString`,
  `String#normalize`/`localeCompare`/`trim`, `Intl.Segmenter`,
  and `crypto.getRandomValues`). Their behavior follows Node.js
  22 (V8's `JSON.parse` error messages; Unicode 16.0 normalization data, as in
  ICU 77).
- `tests/fast-check.rs` is a minimal, deterministic stand-in for libauth's
  `fast-check` dev-dependency, used by the property-based specs.
- `tools/vm_bench.rs` (the `vm-bench` binary), `tools/bench-vm.mjs`, and
  `tests/fixtures/vm_benchmark_program.json` benchmark this port's VM against
  libauth's (see [VM benchmark](#vm-benchmark)).
- libauth's `src/lib/bin/` holds WebAssembly builds of its hash functions and
  of libsecp256k1, embedded as base64; this port implements them natively in
  `src/lib/crypto/` (see [Native cryptography](#constraints)), so only
  `bin.rs` and `hashes.rs` (the `HashFunction` type) remain.
- libauth's `src/types/*.d.ts` are ambient typings for JavaScript
  dev-dependencies (bitcore-lib-cash, chuhai, rollup plugins, the native
  `secp256k1` package); they have no Rust counterpart.

## API conventions

- Functions are snake_case (`deriveHdPath` → `derive_hd_path`); types keep
  their names. Exported data constants keep libauth's exact camelCase names as
  `const`s or `static`s (`bip32HmacSha512Key`, `walletTemplateP2pkh`,
  `ConsensusBch2025`, `cashAddressTypeToTypeBits`).
- String enums of error messages are unit structs with `&'static str`
  constants (`HdKeyDecodingError::invalidChecksum`); value-like string enums
  are Rust enums whose `as_str` returns libauth's value; numeric opcode enums
  are structs of `u8` constants (`OpcodesBch::OP_ADD`).
- Options objects become positional parameters in libauth's destructuring
  order, with `Option` for defaulted fields (`None` selects libauth's default).
  `crypto` options are tuples of implementations in alphabetical key order,
  e.g. `Option<(&Ripemd160, &Secp256k1, &Sha256, &Sha512)>`.
- `throwErrors` options are not ported: functions return libauth's
  non-throwing variant, usually `Result<T, String>`.
- TypeScript unions and anonymous object types are named Rust enums and
  structs (e.g. `HdNodeValid`, `DecodedHdKey<HdPrivateNodeValid>`,
  `GenerateHdPrivateNodeResult`).

## Constraints

- **Native cryptography.** libauth instantiates its hash functions and
  libsecp256k1 from embedded WebAssembly; this port implements them natively
  with RustCrypto crates, its only dependencies: `sha1`, `sha2`, and `ripemd`
  for hashing, and `k256` (with `hmac` for RFC6979 nonces) for secp256k1. The
  secp256k1 operations reproduce the libsecp256k1 version that libauth compiles
  (`bitauth/libauth-secp256k1` at `2b8e4e6`): its DER parser, its nonce
  function (which does not reduce the message hash modulo the order), hybrid
  public keys, unvalidated private keys in tweaks, and BCH Schnorr signatures,
  together with libauth's zero-padding of short inputs and `RangeError` for
  over-long ones.
- **Mandatory VMB suite.** All 88,007 of libauth's committed VMB vectors
  (176,014 standard/nonstandard verdicts) must match libauth's committed
  results, verified together with libauth's exact error messages.

## Building and testing

```sh
cargo build --offline --locked
cargo test --offline --locked              # all ported specs
cargo bench --offline --locked             # ported benchmarks
```

Verify every VMB vector (optionally only one test set prefix), or run a single
vector with its debug trace (`-v`) or a benchmark (`-b`). The generated VMB
tests are not tracked, so first copy libauth's committed set, or regenerate
them (about half an hour):

```sh
cp -r ../libauth/src/lib/vmb-tests/generated src/lib/vmb-tests/
cargo run --offline --release --example dev-vmb-tests  # or regenerate them

cargo run --offline --release --example run-bch-vmb-test -- --all
cargo run --offline --release --example run-bch-vmb-test -- --all bch_2025
cargo run --offline --release --example run-bch-vmb-test -- bch_2023_standard trxhzt -v
```

The `--all` mode is a port addition (libauth runs single vectors from this
helper), and it fails if it finds no VMB tests. Six of libauth's committed
results are stale: for `xxw95u`/`eadlnt` in `bch_2025_invalid` and
`bch_2026_invalid`, libauth's current VM (like this port) reports a stack-depth
error rather than the recorded clean-stack error. Verdicts match; only the
message differs. Regenerated tests record the current messages.

## VM benchmark

`tools/vm_bench.rs` builds a BCH 2026 authentication program that:
- uses 101 distinct opcode tokens (all but the disabled/undefined operations),
- fills 9,990 of the 10,000-byte locking-bytecode limit and 9,903 of the
  unlocking-bytecode limit,
- consumes 7,835,836 of the 7,955,200 operation-cost budget (98.5%),
- evaluates 4,645 instructions in one pass.

```sh
# Regenerate the shared fixture and inspect its VM metrics
cargo run --offline --release --bin vm-bench -- --write tests/fixtures/vm_benchmark_program.json

# Evaluate N times after warm-up (Rust)
cargo run --offline --release --bin vm-bench -- --iterations 500 --warmup 30

# Evaluate the same fixture with the reference TypeScript build
node tools/bench-vm.mjs tests/fixtures/vm_benchmark_program.json 500 30
```

Both harnesses print per-iteration mean, median, standard deviation, 95%
confidence interval, and p90/p99. Pass `--cpu` to measure CPU time instead of
wall time (Rust reports the evaluating thread; Node reports the process). See the
goal plan for measured results; timings depend on the host and load.

## Deviations

Where Rust cannot express libauth's JavaScript semantics directly, the port
makes these choices (each is noted at the affected code):

- `throwErrors` options are not ported (see API conventions). libauth's
  explicitly throwing variants (e.g. `decodeTransactionUnsafe`) panic, and so
  does `pbkdf2HmacSha*` for derived key lengths that exceed, but are not a
  multiple of, the HMAC length (libauth throws a `RangeError`). A panic carries
  the message of the error libauth throws; errors raised by the JavaScript
  engine itself are prefixed with their type (e.g. `RangeError: The number 1.5
  cannot be converted to a BigInt because it is not an integer`).
- Values that hold closures cannot be Rust `static`s, so `compilerOperationsCommon`
  and `compilerOperationsBch` are functions returning the operation sets.
- `AuthenticationVirtualMachine::debug` with libauth's `maskProgramState: true`
  is the separate method `debug_masked` (its return type differs), and a
  `MaskedProgramState` holds the masked `instruction` beside a full clone of the
  state (Rust cannot express `Omit<ProgramState, 'instructions' | 'program'>`
  generically). `stateOverride` options are closures that modify the initial
  state; `stateStepMutate` mutates in place without returning the state;
  `partiallyCloneProgramState` clones the whole state (libauth's key-list
  parameters rely on JavaScript reflection).
- JavaScript `number` parameters whose out-of-range values libauth defines
  (address indexes, the `numberToBin*` encoders, `regroupBits` input) accept
  JavaScript numbers or wider integers so that libauth's wrapping and clamping
  behavior is reproduced; other numeric parameters use fixed-width Rust
  integers for their valid domain.
- Wallet template, BCMR, and `CompilationData` fields that libauth types as
  `number` are `f64`, so imports accept every number libauth's schemas accept,
  and scenario generation converts them as libauth does (`BigInt(value)`, which
  rejects fractions, and the `ToUint32` wrapping of libauth's encoders). The
  transaction types keep fixed-width fields (`u32`, `u64`), so out-of-range
  scenario values are reduced to the value libauth encodes (negative token
  amounts to 0). Generated transactions therefore encode identically, except
  token amounts of 2^64 or more whose low 64 bits are below 2^32 (libauth
  encodes these with a 9-byte CompactUint), but VM introspection of such values
  (e.g. `OP_TXVERSION` for a version of `-1`) differs.
- libauth's WebAssembly-specific API is not ported: the `*Base64Bytes`
  payloads, `getEmbedded*Binary`, `instantiate*Bytes`, `instantiateRustWasm`,
  `instantiateSecp256k1Wasm(Bytes)`, `Secp256k1Wasm`, `ContextFlag`, and
  `CompressionFlag` (nor the specs of the embedded binaries). `instantiate*`
  returns the native implementations, whose incremental hashing state
  (`init`/`update`/`final`) is this port's own encoding. `instantiateSecp256k1`
  ignores its `randomSeed`, which libauth uses to blind libsecp256k1's
  computations without affecting their results.
- Mock crypto objects: a `HashFunction` is a struct of function pointers, so
  custom hash functions can be provided, but `Secp256k1` is the native
  implementation, so `crypto` options cannot take arbitrary secp256k1 objects.
- `stringify` and the other `format/log` helpers operate on `Json` values; libauth
  also accepts arbitrary JavaScript values (bigints, typed arrays, functions),
  which this port represents with libauth's string markers. Likewise, the
  pre-parsed objects accepted by `importWalletTemplate` and
  `importMetadataRegistry` are `Json` values, which cannot hold `undefined`,
  functions, or bigints.
- `RegExp`: the port has no regular expression engine. The CashAssembly
  parser's patterns are implemented by hand-written matchers, carried by
  `runtime::regexp::RegExp` together with the pattern text used in error
  messages. The parser matches libauth's `parseScript` exactly, including
  error positions and expectations.
- JSON schema validation: libauth's `validate-*.js` are AJV-compiled
  standalone validators; `schema/ajv/ajv-utils.rs` emulates AJV 8 over the same
  schemas, reproducing its results, `errors` arrays, and messages (including
  libauth's description of BCMR failures with the wallet template validator's
  errors). Rust strings are UTF-8, so JSON escapes of lone surrogates decode to
  U+FFFD, and V8's stack overflow `RangeError` for extremely deeply nested
  pre-parsed values is not reproduced.
- Specs that compare against JavaScript-only reference libraries (Node's
  `crypto`, `elliptic`, the native `secp256k1` package, `bitcore-lib-cash`,
  `bip39`) compare against vectors precomputed with those libraries instead.
  libauth tests that construct values Rust's types exclude (e.g. segments of
  unknown type, `null` from a byte generator) are ported as ignored tests with
  the intended code in a comment.
- `extractEvaluationSamples`: libauth's `internalStates` entries also carry
  an undeclared `iterations` property at runtime (they are slices of objects
  that have one); the port follows the declared type.
- `attemptBip39MnemonicErrorCorrection` returns libauth's own
  "not yet implemented" stub.
