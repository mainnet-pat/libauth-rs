//! Port of `crypto/hash.bench.helper.ts`.
//!
//! libauth's `benchmarkHashingFunction` uses `chuhai` to compare libauth with
//! `hash.js`, Node.js's native `crypto`, and `asmcrypto.js`. Those are
//! JavaScript-only libraries, so their benchmarks are dropped: this port times
//! only libauth's side of each benchmark (`std::time::Instant`), keeping each
//! benchmark's inputs, titles, and per-cycle result check.
//!
//! Each benchmark runs a few cycles; each cycle times the benchmarked call for
//! roughly [`CYCLE_DURATION`] (at least once) with fresh random inputs, then
//! checks the result, as libauth's `s.cycle` does.
#![allow(dead_code)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use libauth::runtime::crypto::get_random_values;
use libauth::HashFunction;

/// The minimum duration of one benchmark cycle.
pub const CYCLE_DURATION: Duration = Duration::from_millis(100);
/// The number of cycles run by each benchmark.
pub const CYCLES: usize = 2;

/// `randomBytes(length)` (from Node.js's `crypto` module), via the runtime's
/// `crypto.getRandomValues`.
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    get_random_values(&mut bytes).expect("random bytes");
    bytes
}

/// Time `function` for one cycle, returning the number of calls and the
/// elapsed time.
pub fn time_cycle(mut function: impl FnMut()) -> (u32, Duration) {
    let start = Instant::now();
    let mut calls = 0_u32;
    while calls == 0 || start.elapsed() < CYCLE_DURATION {
        function();
        calls += 1;
    }
    (calls, start.elapsed())
}

/// Print the result of a benchmark (`s.bench(name, ...)`).
pub fn report(title: &str, name: &str, calls: u32, elapsed: Duration) {
    println!(
        "{title}: {name}: {:.0} ops/sec ({calls} calls, {:?} per call)",
        f64::from(calls) / elapsed.as_secs_f64(),
        elapsed / calls
    );
}

/// `singlePassNodeBenchmark(inputLength)`
fn single_pass_node_benchmark(hash_function_name: &str, hash_function: &HashFunction, input_length: usize) {
    let title = format!("node: {hash_function_name}: hash a {input_length}-byte input");
    let mut message = random_bytes(input_length);
    for _ in 0..CYCLES {
        let mut hash = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            hash = hash_function.hash(black_box(&message));
        });
        report(&title, "libauth", calls, elapsed);
        // (hash.js, node.js native, and asmcrypto.js: JavaScript-only, dropped)
        // s.cycle
        assert_eq!(hash, hash_function.hash(&message));
        message = random_bytes(input_length);
    }
}

const MB: usize = 1_000_000;

/// `incrementalNodeBenchmark(totalInput, chunkSize)`
fn incremental_node_benchmark(
    hash_function_name: &str,
    hash_function: &HashFunction,
    total_input: usize,
    chunk_size: usize,
) {
    let title = format!(
        "node: {hash_function_name}: incrementally hash a {}MB input in {}MB chunks",
        total_input / MB,
        chunk_size / MB
    );
    for _ in 0..CYCLES {
        // nextCycle
        let message = random_bytes(total_input);
        let message_chunks: Vec<&[u8]> = message.chunks(chunk_size).collect();
        let mut hash = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            hash = hash_function.r#final(&mut message_chunks.iter().fold(hash_function.init(), |mut state, chunk| {
                hash_function.update(&mut state, black_box(chunk))
            }));
        });
        report(&title, "libauth", calls, elapsed);
        // (hash.js, node.js native, and asmcrypto.js: JavaScript-only, dropped)
        // s.cycle
        assert_eq!(hash, hash_function.hash(&message));
    }
}

/// `benchmarkHashingFunction(hashFunctionName, hashFunctionPromise, nodeJsAlgorithm)`
///
/// `node_js_algorithm` selected the JavaScript reference implementations; it
/// is unused here.
pub fn benchmark_hashing_function(hash_function_name: &str, hash_function: &HashFunction, node_js_algorithm: &str) {
    let _ = node_js_algorithm;
    single_pass_node_benchmark(hash_function_name, hash_function, 32);
    single_pass_node_benchmark(hash_function_name, hash_function, 100);
    single_pass_node_benchmark(hash_function_name, hash_function, 1_000);
    single_pass_node_benchmark(hash_function_name, hash_function, 10_000);

    incremental_node_benchmark(hash_function_name, hash_function, MB * 32, MB);
}
