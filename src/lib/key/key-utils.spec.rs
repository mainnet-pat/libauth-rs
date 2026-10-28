//! Port of `key/key-utils.spec.ts`.
//!
//! `randomBytes` (from Node.js's `crypto` module) is replaced by the runtime's
//! `crypto.getRandomValues` (`libauth::runtime::crypto::get_random_values`).

#[path = "../../../tests/fast-check.rs"]
mod fc;

use std::cell::Cell;

use libauth::runtime::crypto::get_random_values;
use libauth::{
    generate_deterministic_entropy, generate_hd_private_node, generate_private_key,
    generate_random_bytes, generate_random_bytes_unchecked, hex_to_bin,
    minimum_events_per_entropy_bits, secp256k1, sha256, shannon_entropy_per_event,
    validate_secp256k1_private_key, EntropyGenerationError,
};

const PRIVATE_KEY_LENGTH: usize = 32;
const MAXIMUM_UINT8_VALUE: u8 = 255;

/// `const secureRandom = () => randomBytes(privateKeyLength);`
fn secure_random() -> Result<Vec<u8>, String> {
    let mut bytes = vec![0; PRIVATE_KEY_LENGTH];
    get_random_values(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn validate_secp256k1_private_key_() {
    assert!(!validate_secp256k1_private_key(&hex_to_bin("")));
    assert!(!validate_secp256k1_private_key(&hex_to_bin("00")));
    assert!(!validate_secp256k1_private_key(&hex_to_bin(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )));
    assert!(validate_secp256k1_private_key(&hex_to_bin(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )));
    assert!(validate_secp256k1_private_key(&hex_to_bin(
        "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )));
    assert!(validate_secp256k1_private_key(&hex_to_bin(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f"
    )));
    assert!(validate_secp256k1_private_key(&hex_to_bin(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
    )));
    assert!(!validate_secp256k1_private_key(&hex_to_bin(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    )));
}

const SECP256K1_ORDER_N_FF_BYTES: usize = 15;

#[test]
fn fast_check_validate_secp256k1_private_key_secp256k1_validate_private_key() {
    let almost_invalid = vec![MAXIMUM_UINT8_VALUE; SECP256K1_ORDER_N_FF_BYTES];
    let the_rest = PRIVATE_KEY_LENGTH - almost_invalid.len();
    let arbitrary = {
        let random = fc::array(fc::integer(Some(0), Some(i64::from(MAXIMUM_UINT8_VALUE))), Some(the_rest), Some(the_rest));
        move |generator: &mut fc::Random| {
            let random = random(generator);
            [almost_invalid.clone(), random.iter().map(|value| *value as u8).collect()].concat()
        }
    };
    fc::test_prop(arbitrary, |input| {
        assert_eq!(validate_secp256k1_private_key(input), secp256k1.validate_private_key(input));
    });
}

#[test]
fn generate_random_bytes_unchecked_works() {
    // t.truthy(generateRandomBytesUnchecked(10));
    assert!(generate_random_bytes_unchecked(10, None).is_ok());
}

#[test]
fn generate_random_bytes_unchecked_accepts_crypto_object() {
    // t.truthy(generateRandomBytesUnchecked(10, crypto)); (the global `crypto`)
    assert!(generate_random_bytes_unchecked(10, Some(&get_random_values)).is_ok());
}

#[test]
fn generate_random_bytes_works() {
    // t.truthy(generateRandomBytes(10));
    assert!(generate_random_bytes(10, None).is_ok());
}

#[test]
fn generate_random_bytes_accepts_generation_function() {
    // t.truthy(generateRandomBytes(10, generateRandomBytesUnchecked));
    assert!(generate_random_bytes(10, Some(&|length| generate_random_bytes_unchecked(length, None))).is_ok());
}

#[test]
#[ignore = "MISSING-API: a Rust generation function cannot return null (libauth: generateRandomBytes(32, (_length) => null))"]
fn generate_random_bytes_throws_on_null_results() {
    // Intended:
    // const notRandom = (_length: number) => null as unknown as Uint8Array;
    // Closest compiling version (an empty result):
    let not_random = |_length: usize| Ok(vec![]);
    assert_eq!(
        generate_random_bytes(32, Some(&not_random)),
        Err(format!(
            "{} First result: [null]; second result: [null].",
            EntropyGenerationError::duplicateResults
        ))
    );
}

#[test]
#[ignore = "MISSING-API: a Rust generation function cannot return undefined (libauth: generateRandomBytes(32, (_length) => undefined))"]
fn generate_random_bytes_throws_on_undefined_results() {
    // Intended:
    // const notRandom = (_length: number) => undefined as unknown as Uint8Array;
    // Closest compiling version (an empty result):
    let not_random = |_length: usize| Ok(vec![]);
    assert_eq!(
        generate_random_bytes(32, Some(&not_random)),
        Err(format!(
            "{} First result: [undefined]; second result: [undefined].",
            EntropyGenerationError::duplicateResults
        ))
    );
}

#[test]
fn generate_random_bytes_throws_on_duplicate_uint8_array_results() {
    let not_random = |length: usize| Ok(vec![0; length]);
    assert_eq!(
        generate_random_bytes(32, Some(&not_random)),
        Err(format!(
            "{} First result: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]; second result: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].",
            EntropyGenerationError::duplicateResults
        ))
    );
}

#[test]
fn generate_random_bytes_throws_on_duplicate_uint8_array_results_filled() {
    let not_random = |length: usize| Ok(vec![0xff; length]);
    assert_eq!(
        generate_random_bytes(32, Some(&not_random)),
        Err(format!(
            "{} First result: [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255]; second result: [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255].",
            EntropyGenerationError::duplicateResults
        ))
    );
}

#[test]
fn generate_random_bytes_succeeds_on_unique_uint8_array_results() {
    let counter = Cell::new(0_u8);
    let not_random = |length: usize| {
        let fill = counter.get();
        counter.set(fill + 1);
        Ok(vec![fill; length])
    };
    assert_eq!(generate_random_bytes(32, Some(&not_random)), Ok(vec![0; 32]));
}

#[test]
fn generate_private_key_works() {
    let key = generate_private_key(Some(&secure_random)).expect("a private key");
    assert!(secp256k1.validate_private_key(&key));
}

#[test]
fn generate_private_key_works_with_default_entropy_source() {
    let key = generate_private_key(None).expect("a private key");
    assert!(validate_secp256k1_private_key(&key));
}

#[test]
fn generate_private_key_tries_until_success() {
    let calls = Cell::new(0);
    let entropy = [
        vec![MAXIMUM_UINT8_VALUE; PRIVATE_KEY_LENGTH],
        vec![1; PRIVATE_KEY_LENGTH],
    ];
    let mock_entropy = || {
        calls.set(calls.get() + 1);
        Ok(entropy[calls.get()].clone())
    };

    let key = generate_private_key(Some(&mock_entropy));
    assert_eq!(key, Ok(entropy[1].clone()));
    assert_eq!(calls.get(), 1);
}

#[test]
fn generate_hd_private_node_tries_until_success() {
    let calls = Cell::new(0);
    let entropy = [
        vec![MAXIMUM_UINT8_VALUE; PRIVATE_KEY_LENGTH],
        vec![1; PRIVATE_KEY_LENGTH],
    ];
    let mock_entropy = || {
        calls.set(calls.get() + 1);
        Ok(entropy[calls.get()].clone())
    };

    let key = generate_hd_private_node(Some(&mock_entropy)).expect("an HD private node");
    assert_eq!(key.seed, entropy[1]);
    assert_eq!(calls.get(), 1);
}

#[test]
fn shannon_entropy_per_event_() {
    assert_eq!(shannon_entropy_per_event(2), 2_f64.log2());
    assert_eq!(shannon_entropy_per_event(20), 20_f64.log2());
}

#[test]
fn minimum_events_per_entropy_bits_() {
    assert_eq!(minimum_events_per_entropy_bits(2, None), 128);
    assert_eq!(minimum_events_per_entropy_bits(6, None), 50);
    assert_eq!(minimum_events_per_entropy_bits(20, None), 30);
}

#[test]
fn generate_deterministic_entropy_() {
    assert_eq!(
        generate_deterministic_entropy(6, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0], None, Some(0)),
        Ok(hex_to_bin(
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
        ))
    );
    assert_eq!(
        generate_deterministic_entropy(12, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0], None, None),
        Err(format!(
            "{} With 12 possible results per event, a minimum of 36 events are required to obtain sufficient entropy. Events provided: 7.",
            EntropyGenerationError::insufficientEntropy
        ))
    );
    assert_eq!(
        generate_deterministic_entropy(1_048_576, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0], None, None),
        Ok(hex_to_bin(
            "8bb0cf6eb9b17d0f7d22b456f121257dc1254e1f01665370476383ea776df414"
        ))
    );
    assert_eq!(
        generate_deterministic_entropy(6, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0], None, None),
        Err(format!(
            "{} With 6 possible results per event, a minimum of 50 events are required to obtain sufficient entropy. Events provided: 6.",
            EntropyGenerationError::insufficientEntropy
        ))
    );
    assert_eq!(
        generate_deterministic_entropy(0, &[1.0], None, None),
        Err(format!(
            "{} With 0 possible results per event, a minimum of 0 events are required to obtain sufficient entropy. Events provided: 1.",
            EntropyGenerationError::insufficientEntropy
        ))
    );
    assert_eq!(
        generate_deterministic_entropy(20, &[13.0, 4.0, 10.0], Some(&*sha256), Some(12)),
        Ok(hex_to_bin(
            "6dd4f2758287be9f38e0e93c71146c76e90f83f0b8c9b49760fc0b594494607b"
        ))
    );
    assert_eq!(
        generate_deterministic_entropy(20, &[13.0, 4.0], None, Some(12)),
        Err(format!(
            "{} With 20 possible results per event, a minimum of 3 events are required to obtain sufficient entropy. Events provided: 2.",
            EntropyGenerationError::insufficientEntropy
        ))
    );
}
