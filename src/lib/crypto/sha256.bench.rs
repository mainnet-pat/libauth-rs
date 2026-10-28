//! Port of `crypto/sha256.bench.ts`.
//!
//! Only libauth's side of each benchmark is timed (the JavaScript-only
//! libraries compared by libauth are dropped; see `hash.bench.helper.rs`).

#[path = "hash.bench.helper.rs"]
mod hash_bench_helper;

use hash_bench_helper::benchmark_hashing_function;
use libauth::instantiate_sha256;

fn main() {
    // benchmarkHashingFunction<Sha256>('sha256', instantiateSha256(), 'sha256');
    let hash_function = instantiate_sha256();
    benchmark_hashing_function("sha256", &hash_function, "sha256");
}
