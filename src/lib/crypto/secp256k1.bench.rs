//! Port of `crypto/secp256k1.bench.ts`.
//!
//! libauth's benchmarks compare libauth with `elliptic` and `secp256k1-node`
//! using `chuhai`. Those are JavaScript-only libraries, so their benchmarks
//! are dropped: only libauth's side of each benchmark is timed
//! (`std::time::Instant`). Each benchmark runs a few cycles; each cycle times
//! the benchmarked call for roughly `CYCLE_DURATION` (at least once) with fresh
//! random inputs, then checks the result, as libauth's `s.cycle` does.

use std::hint::black_box;
use std::time::{Duration, Instant};

use libauth::runtime::crypto::get_random_values;
use libauth::{generate_private_key, instantiate_secp256k1, Secp256k1};

/// The minimum duration of one benchmark cycle.
const CYCLE_DURATION: Duration = Duration::from_millis(100);
/// The number of cycles run by each benchmark.
const CYCLES: usize = 2;

const PRIVATE_KEY_LENGTH: usize = 32;

/// `randomBytes(length)` (from Node.js's `crypto` module), via the runtime's
/// `crypto.getRandomValues`.
fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    get_random_values(&mut bytes).expect("random bytes");
    bytes
}

/// `const secureRandom = () => randomBytes(privateKeyLength);`
fn secure_random() -> Result<Vec<u8>, String> {
    Ok(random_bytes(PRIVATE_KEY_LENGTH))
}

/// `generatePrivateKey(secureRandom)`
fn private_key() -> Vec<u8> {
    generate_private_key(Some(&secure_random)).expect("a private key")
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

/// `test('bench: secp256k1: verify signature Low-S, uncompressed pubkey', ...)`
///
/// Note: elliptic doesn't document an equivalent to verifySignatureDERLowS,
/// so these benchmarks slightly overestimate elliptic's performance in
/// applications where Low-S verification is required (i.e. Bitcoin).
fn verify_signature_low_s_uncompressed_pubkey(secp256k1: &Secp256k1) {
    let title = "bench: secp256k1: verify signature Low-S, uncompressed pubkey";
    for _ in 0..CYCLES {
        // nextCycle
        let priv_key = private_key();
        let message_hash = random_bytes(PRIVATE_KEY_LENGTH);
        let pubkey_uncompressed = secp256k1.derive_public_key_uncompressed(&priv_key).expect("a public key");
        let sig_der = secp256k1.sign_message_hash_der(&priv_key, &message_hash).expect("a signature");
        let mut result = false;
        let (calls, elapsed) = time_cycle(|| {
            result = secp256k1.verify_signature_der_low_s(
                black_box(&sig_der),
                black_box(&pubkey_uncompressed),
                black_box(&message_hash),
            );
        });
        report(title, "libauth", calls, elapsed);
        // (elliptic and secp256k1-node: JavaScript-only, dropped)
        // s.cycle
        assert!(result);
    }
}

/// `test('bench: secp256k1: verify signature Low-S, compressed pubkey', ...)`
fn verify_signature_low_s_compressed_pubkey(secp256k1: &Secp256k1) {
    let title = "bench: secp256k1: verify signature Low-S, compressed pubkey";
    for _ in 0..CYCLES {
        // nextCycle
        let priv_key = private_key();
        let message_hash = random_bytes(PRIVATE_KEY_LENGTH);
        let pubkey_compressed = secp256k1.derive_public_key_compressed(&priv_key).expect("a public key");
        let sig_der = secp256k1.sign_message_hash_der(&priv_key, &message_hash).expect("a signature");
        let mut result = false;
        let (calls, elapsed) = time_cycle(|| {
            result = secp256k1.verify_signature_der_low_s(
                black_box(&sig_der),
                black_box(&pubkey_compressed),
                black_box(&message_hash),
            );
        });
        report(title, "libauth", calls, elapsed);
        // (elliptic and secp256k1-node: JavaScript-only, dropped)
        // s.cycle
        assert!(result);
    }
}

/// `test('bench: secp256k1: derive compressed pubkey', ...)`
fn derive_compressed_pubkey(secp256k1: &Secp256k1) {
    let title = "bench: secp256k1: derive compressed pubkey";
    for _ in 0..CYCLES {
        // nextCycle
        let priv_key = private_key();
        let pubkey_compressed_expected = secp256k1.derive_public_key_compressed(&priv_key).expect("a public key");
        let mut pubkey_compressed_benchmark = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            pubkey_compressed_benchmark = secp256k1
                .derive_public_key_compressed(black_box(&priv_key))
                .expect("a public key");
        });
        report(title, "libauth", calls, elapsed);
        // (elliptic and secp256k1-node: JavaScript-only, dropped)
        // s.cycle
        assert_eq!(pubkey_compressed_expected, pubkey_compressed_benchmark);
    }
}

/// `test('bench: secp256k1: create DER Low-S signature', ...)`
fn create_der_low_s_signature(secp256k1: &Secp256k1) {
    let title = "bench: secp256k1: create DER Low-S signature";
    for _ in 0..CYCLES {
        // nextCycle
        let priv_key = private_key();
        let message_hash = random_bytes(PRIVATE_KEY_LENGTH);
        let sig_der_expected = secp256k1.sign_message_hash_der(&priv_key, &message_hash).expect("a signature");
        let mut sig_der_benchmark = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            sig_der_benchmark = secp256k1
                .sign_message_hash_der(black_box(&priv_key), black_box(&message_hash))
                .expect("a signature");
        });
        report(title, "libauth", calls, elapsed);
        // (elliptic and secp256k1-node: JavaScript-only, dropped)
        // s.cycle
        assert_eq!(
            Ok(sig_der_expected),
            secp256k1.normalize_signature_der(&sig_der_benchmark)
        );
    }
}

/// `test('bench: secp256k1: sign: Schnorr vs. ECDSA', ...)`
fn sign_schnorr_vs_ecdsa(secp256k1: &Secp256k1) {
    let title = "bench: secp256k1: sign: Schnorr vs. ECDSA";
    for _ in 0..CYCLES {
        // nextCycle
        let priv_key = private_key();
        let message_hash = random_bytes(PRIVATE_KEY_LENGTH);
        let sig_der_expected = secp256k1.sign_message_hash_der(&priv_key, &message_hash).expect("a signature");
        let sig_schnorr_expected = secp256k1
            .sign_message_hash_schnorr(&priv_key, &message_hash)
            .expect("a signature");
        let mut sig_der_benchmark = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            sig_der_benchmark = secp256k1
                .sign_message_hash_der(black_box(&priv_key), black_box(&message_hash))
                .expect("a signature");
        });
        report(title, "secp256k1.signMessageHashDER", calls, elapsed);
        let mut sig_schnorr_benchmark = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            sig_schnorr_benchmark = secp256k1
                .sign_message_hash_schnorr(black_box(&priv_key), black_box(&message_hash))
                .expect("a signature");
        });
        report(title, "secp256k1.signMessageHashSchnorr", calls, elapsed);
        // s.cycle (run after each benchmark in libauth)
        assert_eq!(sig_der_expected, sig_der_benchmark);
        assert_eq!(sig_schnorr_expected, sig_schnorr_benchmark);
    }
}

/// `test('bench: secp256k1: verify: Schnorr vs. ECDSA', ...)`
fn verify_schnorr_vs_ecdsa(secp256k1: &Secp256k1) {
    let title = "bench: secp256k1: verify: Schnorr vs. ECDSA";
    for _ in 0..CYCLES {
        // nextCycle
        let priv_key = private_key();
        let message_hash = random_bytes(PRIVATE_KEY_LENGTH);
        let pubkey_compressed = secp256k1.derive_public_key_compressed(&priv_key).expect("a public key");
        let sig_der = secp256k1.sign_message_hash_der(&priv_key, &message_hash).expect("a signature");
        let sig_schnorr = secp256k1
            .sign_message_hash_schnorr(&priv_key, &message_hash)
            .expect("a signature");
        let mut result = false;
        let (calls, elapsed) = time_cycle(|| {
            result = secp256k1.verify_signature_der_low_s(
                black_box(&sig_der),
                black_box(&pubkey_compressed),
                black_box(&message_hash),
            );
        });
        report(
            title,
            "secp256k1.verifySignatureDERLowS (ECDSA, pubkey compressed)",
            calls,
            elapsed,
        );
        // s.cycle
        assert!(result);
        result = false;
        let (calls, elapsed) = time_cycle(|| {
            result = secp256k1.verify_signature_schnorr(
                black_box(&sig_schnorr),
                black_box(&pubkey_compressed),
                black_box(&message_hash),
            );
        });
        report(
            title,
            "secp256k1.verifySignatureSchnorr (Schnorr, pubkey compressed)",
            calls,
            elapsed,
        );
        // s.cycle
        assert!(result);
    }
}

fn main() {
    // const secp256k1Promise = instantiateSecp256k1();
    let secp256k1 = instantiate_secp256k1(None);
    verify_signature_low_s_uncompressed_pubkey(&secp256k1);
    verify_signature_low_s_compressed_pubkey(&secp256k1);
    derive_compressed_pubkey(&secp256k1);
    create_der_low_s_signature(&secp256k1);
    sign_schnorr_vs_ecdsa(&secp256k1);
    verify_schnorr_vs_ecdsa(&secp256k1);
}
