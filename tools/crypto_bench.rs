//! Cryptography micro-benchmark: times this port's hashing and secp256k1
//! operations on fixed inputs, for comparison with libauth's
//! (`tools/bench-crypto.mjs` uses the same inputs). This is a port-only tool;
//! libauth has no counterpart.
//!
//! `cargo run --offline --release --bin crypto-bench -- [seconds per operation]`

use std::hint::black_box;
use std::time::Instant;

use libauth::{hex_to_bin, secp256k1, sha256};

/// Print the median time per call of `operation` over five timed rounds,
/// after a short warm-up.
fn time_per_operation(label: &str, seconds: f64, mut operation: impl FnMut()) {
    for _ in 0..3 {
        operation();
    }
    let mut rounds = Vec::new();
    for _ in 0..5 {
        let (mut count, start) = (0_u64, Instant::now());
        while start.elapsed().as_secs_f64() < seconds / 5.0 {
            operation();
            count += 1;
        }
        rounds.push(start.elapsed().as_secs_f64() * 1e6 / count as f64);
    }
    rounds.sort_by(|a, b| a.total_cmp(b));
    println!("{label}\t{:.2}", rounds[2]);
}

fn main() {
    let seconds: f64 = std::env::args()
        .nth(1)
        .map_or(2.0, |value| value.parse().expect("seconds per operation"));
    let key = hex_to_bin("f85d4bd8a03ca106c9deb47b791803dac7f0333809e3f1dd04d182e0aba6e553");
    let message = hex_to_bin("da1e22c5f5f5f3f5d9a8b1c4e6f40f1b6c5b8a2f2a8c1e3d4b5a69788796a5b4");
    let public_key = secp256k1.derive_public_key_compressed(&key).expect("a valid key");
    let der = secp256k1.sign_message_hash_der(&key, &message).expect("a valid key");
    let schnorr = secp256k1.sign_message_hash_schnorr(&key, &message).expect("a valid key");
    let input_520 = vec![0xab_u8; 520];
    let input_32 = vec![0xab_u8; 32];
    println!("operation\tmedian µs");
    time_per_operation("sha256 (520 bytes)", seconds, || {
        black_box(sha256.hash(&input_520));
    });
    time_per_operation("sha256 (32 bytes)", seconds, || {
        black_box(sha256.hash(&input_32));
    });
    time_per_operation("derive public key", seconds, || {
        black_box(secp256k1.derive_public_key_compressed(&key).expect("a valid key"));
    });
    time_per_operation("ECDSA sign (DER)", seconds, || {
        black_box(secp256k1.sign_message_hash_der(&key, &message).expect("a valid key"));
    });
    time_per_operation("ECDSA verify (DER)", seconds, || {
        assert!(secp256k1.verify_signature_der_low_s(&der, &public_key, &message));
    });
    time_per_operation("Schnorr sign", seconds, || {
        black_box(secp256k1.sign_message_hash_schnorr(&key, &message).expect("a valid key"));
    });
    time_per_operation("Schnorr verify", seconds, || {
        assert!(secp256k1.verify_signature_schnorr(&schnorr, &public_key, &message));
    });
}
