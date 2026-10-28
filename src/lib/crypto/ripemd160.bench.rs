//! Port of `crypto/ripemd160.bench.ts`.
//!
//! Only libauth's side of each benchmark is timed (the JavaScript-only
//! libraries compared by libauth are dropped; see `hash.bench.helper.rs`).

#[path = "hash.bench.helper.rs"]
mod hash_bench_helper;

use hash_bench_helper::benchmark_hashing_function;
use libauth::instantiate_ripemd160;

fn main() {
    // benchmarkHashingFunction<Ripemd160>('ripemd160', instantiateRipemd160(), 'ripemd160');
    let hash_function = instantiate_ripemd160();
    benchmark_hashing_function("ripemd160", &hash_function, "ripemd160");
}
