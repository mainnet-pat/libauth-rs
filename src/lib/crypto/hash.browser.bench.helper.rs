//! Port of `crypto/hash.browser.bench.helper.ts`.
//!
//! In libauth, this module is bundled (with `chuhai` and `hash.js`) by
//! `hash.browser.bench.ts` and run in a headless Chromium page, comparing
//! libauth with `hash.js`, `crypto.subtle`, and `asmcrypto.js`. Those
//! comparisons are JavaScript/browser-only and are dropped: this port times
//! only libauth's side of each benchmark (`std::time::Instant`), natively –
//! there is no browser. `benchError` becomes a panic and `benchComplete` a
//! final message.
#![allow(dead_code)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use libauth::runtime::crypto::get_random_values;
use libauth::{instantiate_ripemd160, instantiate_sha1, instantiate_sha256, instantiate_sha512, HashFunction};

/// The minimum duration of one benchmark cycle.
const CYCLE_DURATION: Duration = Duration::from_millis(100);
/// The number of cycles run by each benchmark.
const CYCLES: usize = 2;

/// `benchError(error)`
fn bench_error(error: &str) -> ! {
    panic!("{error}");
}

/// `benchComplete()`
fn bench_complete() {
    println!("Browser benchmark complete.");
}

/// `compare(a, b)`
fn compare(a: &[u8], b: &[u8]) {
    if a != b {
        bench_error(&format!("\nInvalid result: {a:?} is not equal to {b:?}\n"));
    }
}

/// `randomBytes(bytes)` (`crypto.getRandomValues`)
fn random_bytes(bytes: usize) -> Vec<u8> {
    let mut array = vec![0; bytes];
    get_random_values(&mut array).expect("random bytes");
    array
}

/// Time `function` for one cycle, returning the number of calls and the
/// elapsed time.
fn time_cycle(mut function: impl FnMut()) -> (u32, Duration) {
    let start = Instant::now();
    let mut calls = 0_u32;
    while calls == 0 || start.elapsed() < CYCLE_DURATION {
        function();
        calls += 1;
    }
    (calls, start.elapsed())
}

fn report(title: &str, name: &str, calls: u32, elapsed: Duration) {
    println!(
        "{title}: {name}: {:.0} ops/sec ({calls} calls, {:?} per call)",
        f64::from(calls) / elapsed.as_secs_f64(),
        elapsed / calls
    );
}

/// `singlePassBrowserBenchmark({ hashFunction, hashFunctionName, inputLength, subtleCryptoAlgorithmName })`
///
/// (`subtleCryptoAlgorithmName` selected the `crypto.subtle` and
/// `asmcrypto.js` benchmarks; it is unused here.)
fn single_pass_browser_benchmark(
    hash_function: &HashFunction,
    hash_function_name: &str,
    input_length: usize,
    subtle_crypto_algorithm_name: Option<&str>,
) {
    let _ = subtle_crypto_algorithm_name;
    let title = format!("browser: {hash_function_name}: hash a {input_length}-byte input");
    let mut message = random_bytes(input_length);
    for _ in 0..CYCLES {
        let mut hash = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            hash = hash_function.hash(black_box(&message));
        });
        report(&title, "libauth", calls, elapsed);
        // (hash.js, crypto.subtle, and asmcrypto.js: JavaScript-only, dropped)
        // s.cycle
        compare(&hash, &hash_function.hash(&message));
        message = random_bytes(input_length);
    }
}

const MB: usize = 1_000_000;

/// `incrementalBrowserBenchmark({ chunkSize, hashFunction, hashFunctionName, totalInput })`
fn incremental_browser_benchmark(
    chunk_size: usize,
    hash_function: &HashFunction,
    hash_function_name: &str,
    total_input: usize,
) {
    let title = format!(
        "browser: {hash_function_name}: incrementally hash a {}MB input in {}MB chunks",
        total_input / MB,
        chunk_size / MB
    );
    for _ in 0..CYCLES {
        // nextCycle
        /*
         * We can't get this much entropy, so we just use 0s here.
         */
        let message = vec![0_u8; total_input];
        let message_chunks: Vec<&[u8]> = message.chunks(chunk_size).collect();
        let mut hash = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            hash = hash_function.r#final(&mut message_chunks.iter().fold(hash_function.init(), |mut state, chunk| {
                hash_function.update(&mut state, black_box(chunk))
            }));
        });
        report(&title, "libauth", calls, elapsed);
        // (hash.js and asmcrypto.js: JavaScript-only, dropped)
        // s.cycle
        compare(&hash, &hash_function.hash(&message));
    }
}

/// `browserBenchmarks({ hashFunction, hashFunctionName, subtleCryptoAlgorithmName })`
fn browser_benchmarks(
    hash_function: &HashFunction,
    hash_function_name: &str,
    subtle_crypto_algorithm_name: Option<&str>,
) {
    single_pass_browser_benchmark(hash_function, hash_function_name, 32, subtle_crypto_algorithm_name);
    single_pass_browser_benchmark(hash_function, hash_function_name, 100, subtle_crypto_algorithm_name);
    single_pass_browser_benchmark(hash_function, hash_function_name, 1_000, subtle_crypto_algorithm_name);
    single_pass_browser_benchmark(hash_function, hash_function_name, 10_000, subtle_crypto_algorithm_name);
    incremental_browser_benchmark(MB, hash_function, hash_function_name, MB * 32);
}

/// The module's top-level `(async () => { ... })()`: run every browser
/// benchmark, then `benchComplete()`.
pub fn run() {
    let sha1 = instantiate_sha1();
    let sha256 = instantiate_sha256();
    let sha512 = instantiate_sha512();
    let ripemd160 = instantiate_ripemd160();

    browser_benchmarks(&sha1, "sha1", Some("SHA-1"));
    browser_benchmarks(&sha256, "sha256", Some("SHA-256"));
    browser_benchmarks(&sha512, "sha512", Some("SHA-512"));
    browser_benchmarks(&ripemd160, "ripemd160", None);

    bench_complete();
}
