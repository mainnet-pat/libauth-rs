# Benchmarks: libauth-rs vs libauth

> **For demonstration only.** These figures come from a single session on a
> shared machine that was busy with unrelated work (load average about 6 on 10
> cores, with other builds running). Rerun the benchmarks on a calm, idle
> machine before relying on them. Both implementations ran interleaved under
> the same load, so the ratios between them are more trustworthy than the
> absolute times.

Measured on 2026-10-28.

## Setup

- **libauth-rs:** this port with native cryptography: hashing via the RustCrypto
  `sha1`, `sha2`, and `ripemd` crates (`sha2`'s portable backend; its hardware
  SHA-2 backend on aarch64 requires the `asm` feature, which is not enabled),
  and secp256k1 via `k256`. Release build, Rust 1.90.0.
- **libauth:** v3.1.0-next.8, built in `/Code/libauth/build` and run on Node.js
  22.22.0. Its hash functions and libsecp256k1 are WebAssembly, compiled by V8.
- **Previous libauth-rs build:** the port before native cryptography (commit
  `2a44d3a`), which ran libauth's embedded WebAssembly in an interpreter (with
  native code substituted for libauth's four hash modules).
- **Machine:** a 10-core aarch64 Linux virtual machine.

## VM benchmark

`tools/vm_bench.rs` and `tools/bench-vm.mjs` evaluate the same BCH 2026
programs (see the README's VM benchmark section): the near-limit program in
`tests/fixtures/vm_benchmark_program.json`, and three variants that isolate its
parts. Each workload ran in 5 rounds, alternating which implementation went
first. Each round timed 150 evaluations (600 for the multiplication, 2,000 for
the opcode mix) after a warm-up. The table shows the median of the per-round
median wall-clock times.

| Workload | libauth-rs | libauth | libauth-rs speed | Previous build's speed |
|---|---|---|---|---|
| Full near-limit program | 4.5 ms | 10.1 ms | 2.2× faster | 0.95× |
| SHA-256 loop (1,380 × 520 B) | 3.6 ms | 7.2 ms | 2.0× faster | 0.90× |
| Big-number multiply (2,400 B × 2,400 B) | 0.60 ms | 1.57 ms | 2.6× faster | 3.3× faster |
| Opcode mix | 118 µs | 125 µs | 1.1× faster | 1.3× faster |

CPU time (`--cpu`) gave the same ratios within about 6%. The previous build
was measured earlier the same day, under a heavier load (about 10).

## Cryptography operations

`tools/crypto_bench.rs` and `tools/bench-crypto.mjs` time single operations on
fixed inputs: the median of five timed rounds after a warm-up. The table shows
the median of 3 runs, alternating the order of the implementations.

| Operation | libauth-rs | libauth | libauth-rs speed | Previous build | Speedup over previous |
|---|---|---|---|---|---|
| SHA-256, 520 B | 1.84 µs | 5.00 µs | 2.7× faster | 5.60 µs | 3× |
| SHA-256, 32 B | 0.28 µs | 1.14 µs | 4.1× faster | 2.82 µs | 10× |
| Derive public key | 61 µs | 43 µs | 0.7× | 2,290 µs | 38× |
| ECDSA sign (DER) | 82 µs | 89 µs | 1.1× faster | 4,654 µs | 57× |
| ECDSA verify (DER) | 176 µs | 138 µs | 0.8× | 6,575 µs | 37× |
| Schnorr sign | 134 µs | 98 µs | 0.7× | 5,451 µs | 41× |
| Schnorr verify | 170 µs | 103 µs | 0.6× | 4,793 µs | 28× |

## Observations

- With native cryptography, the port evaluates the near-limit program about
  twice as fast as libauth. Hashing dominates that program, and it was the one
  workload where libauth was faster before.
- secp256k1 operations are 28–57× faster than in the previous build, but
  libauth's libsecp256k1 (C compiled to WebAssembly, then optimized by V8) is
  still 1.25–1.7× faster than `k256` at most of them; ECDSA signing is about
  even. Scripts dominated by signature checks may therefore run faster in
  libauth. (The benchmark program contains a single signature check, which
  fails immediately.)
- Native cryptography also speeds up the port's tooling: verifying all 176,014
  VMB verdicts (`run-bch-vmb-test --all`) took 21 seconds (4 minutes 39 seconds
  before), and regenerating every VMB test (`dev-vmb-tests`) took 2 minutes 20
  seconds (27 minutes 53 seconds before).

## Rerunning

```sh
cargo build --offline --release --bin vm-bench --bin crypto-bench

# VM benchmark: the near-limit program (add --cpu to either for CPU time)
target/release/vm-bench --iterations 150 --warmup 30
node tools/bench-vm.mjs tests/fixtures/vm_benchmark_program.json 150 30

# Each variant (hash, mul, or ops), written as a fixture for Node.js
target/release/vm-bench --variant hash --write /tmp/vm-hash.json --iterations 150 --warmup 30
node tools/bench-vm.mjs /tmp/vm-hash.json 150 30

# Cryptography operations (the argument is seconds per operation)
target/release/crypto-bench 2
node tools/bench-crypto.mjs 2
```

The Node.js harnesses load libauth from `/Code/libauth/build`. Repeat each
measurement several times, alternating which implementation runs first.
