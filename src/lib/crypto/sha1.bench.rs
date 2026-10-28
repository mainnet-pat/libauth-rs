//! Port of `crypto/sha1.bench.ts`.
//!
//! Only libauth's side of each benchmark is timed (the JavaScript-only
//! libraries compared by libauth are dropped; see `hash.bench.helper.rs`).

#[path = "hash.bench.helper.rs"]
mod hash_bench_helper;

use hash_bench_helper::benchmark_hashing_function;
use libauth::instantiate_sha1;

fn main() {
    // benchmarkHashingFunction<Sha1>('sha1', instantiateSha1(), 'sha1');
    let hash_function = instantiate_sha1();
    benchmark_hashing_function("sha1", &hash_function, "sha1");
}
