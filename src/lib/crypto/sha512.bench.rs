//! Port of `crypto/sha512.bench.ts`.
//!
//! Only libauth's side of each benchmark is timed (the JavaScript-only
//! libraries compared by libauth are dropped; see `hash.bench.helper.rs`).

#[path = "hash.bench.helper.rs"]
mod hash_bench_helper;

use hash_bench_helper::benchmark_hashing_function;
use libauth::instantiate_sha512;

fn main() {
    // benchmarkHashingFunction<Sha512>('sha512', instantiateSha512(), 'sha512');
    let hash_function = instantiate_sha512().expect("the embedded binary instantiates");
    benchmark_hashing_function("sha512", &hash_function, "sha512");
}
