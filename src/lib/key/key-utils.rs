//! Key generation utilities (port of `key/key-utils.ts`).

use crate::crypto::sha256;
use crate::format::{bins_are_equal, format_error};
use crate::runtime::number::number_to_string;
use crate::key::hd_key::{
    derive_hd_private_node_from_seed, validate_secp256k1_private_key, HdPrivateNode, HdPrivateNodeValid,
};

/// Errors produced during entropy generation (`EntropyGenerationError`).
pub struct EntropyGenerationError;

impl EntropyGenerationError {
    /// The random byte source returned duplicate results.
    pub const duplicateResults: &'static str = "Entropy generation error: the \"getRandomValues\" function provided by this JavaScript environment returned duplicate results across two evaluations; entropy generation was halted for safety.";
    /// The provided events do not contain the required entropy.
    pub const insufficientEntropy: &'static str = "Entropy generation error: the provided list of events contains insufficient entropy.";
}

const PRIVATE_KEY_LENGTH: usize = 32;
const UTF8_NUMBERS_OFFSET: u8 = 48;
/// The recommended minimum number of bits of entropy for private key generation.
const PRIVATE_KEY_REQUIRED_ENTROPY_BITS: usize = 128;

/// Generate a byte array of the specified length containing
/// cryptographically-random bytes using `crypto.getRandomValues`.
///
/// - `crypto_instance`: an optional implementation of `getRandomValues`
///   (defaults to the runtime's).
pub fn generate_random_bytes_unchecked(
    length: usize,
    crypto_instance: Option<&dyn Fn(&mut [u8]) -> Result<(), String>>,
) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0_u8; length];
    match crypto_instance {
        Some(get_random_values) => get_random_values(&mut bytes),
        None => crate::runtime::crypto::get_random_values(&mut bytes),
    }?;
    Ok(bytes)
}

/// Generate a byte array of the specified length containing
/// cryptographically-random bytes, verifying that the source does not return
/// duplicate results across two evaluations (which would indicate a
/// catastrophically broken random source).
///
/// - `generate`: an optional source of random bytes (defaults to
///   [`generate_random_bytes_unchecked`]).
pub fn generate_random_bytes(
    length: usize,
    generate: Option<&dyn Fn(usize) -> Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, String> {
    let generate = |length| match generate {
        Some(generate) => generate(length),
        None => generate_random_bytes_unchecked(length, None),
    };
    let first_run = generate(length)?;
    let second_run = generate(length)?;
    if bins_are_equal(&first_run, &second_run) {
        let join = |bin: &[u8]| bin.iter().map(u8::to_string).collect::<Vec<_>>().join(",");
        return Err(format_error(
            EntropyGenerationError::duplicateResults,
            Some(&format!(
                "First result: [{}]; second result: [{}].",
                join(&first_run),
                join(&second_run)
            )),
        ));
    }
    Ok(first_run)
}

/// Securely generate a 32-byte, cryptographically random seed (Uint8Array)
/// for use with BIP32 HD keys.
pub fn generate_random_seed() -> Result<Vec<u8>, String> {
    generate_random_bytes(PRIVATE_KEY_LENGTH, None)
}

/// Securely generate a valid Secp256k1 private key.
///
/// - `secure_random`: an optional source of random seeds (defaults to
///   [`generate_random_seed`]).
pub fn generate_private_key(
    secure_random: Option<&dyn Fn() -> Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, String> {
    loop {
        let maybe_key = match secure_random {
            Some(secure_random) => secure_random(),
            None => generate_random_seed(),
        }?;
        if validate_secp256k1_private_key(&maybe_key) {
            return Ok(maybe_key);
        }
    }
}

/// The result of [`generate_hd_private_node`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateHdPrivateNodeResult {
    /// The generated HD private node.
    pub hd_private_node: HdPrivateNodeValid,
    /// The seed from which `hd_private_node` was derived.
    pub seed: Vec<u8>,
}

/// Securely generate a new HD private node and the seed from which it was
/// derived.
///
/// - `secure_random`: an optional source of random seeds (defaults to
///   [`generate_random_seed`]).
pub fn generate_hd_private_node(
    secure_random: Option<&dyn Fn() -> Result<Vec<u8>, String>>,
) -> Result<GenerateHdPrivateNodeResult, String> {
    loop {
        let seed = match secure_random {
            Some(secure_random) => secure_random(),
            None => generate_random_seed(),
        }?;
        if let HdPrivateNode::Valid(hd_private_node) = derive_hd_private_node_from_seed(&seed, None, None, None) {
            return Ok(GenerateHdPrivateNodeResult { hd_private_node, seed });
        }
    }
}

/// Given the number of equally-likely results per event, return the Shannon
/// entropy of the event in bits.
pub fn shannon_entropy_per_event(possible_results: usize) -> f64 {
    (possible_results as f64).log2()
}

/// Given the number of equally-likely results per event, return the number of
/// events required to achieve `required_entropy_bits` of Shannon entropy.
///
/// `required_entropy_bits` defaults to `128`, the recommended value for all
/// private key generation.
pub fn minimum_events_per_entropy_bits(
    possible_results: usize,
    required_entropy_bits: Option<usize>,
) -> usize {
    let required_entropy_bits = required_entropy_bits.unwrap_or(PRIVATE_KEY_REQUIRED_ENTROPY_BITS);
    (required_entropy_bits as f64 / shannon_entropy_per_event(possible_results)).ceil() as usize
}

/// Generate deterministic entropy by hashing a list of random events with
/// SHA-256.
///
/// For coin flips, use `0` ("heads") and `1` ("tails"); for dice, use the
/// visible number.
///
/// `crypto` (an implementation of sha256) defaults to the internal instance,
/// and `required_entropy_bits` to `128`, the recommended value for all private
/// key generation.
pub fn generate_deterministic_entropy(
    possible_results: usize,
    events: &[f64],
    crypto: Option<&crate::crypto::Sha256>,
    required_entropy_bits: Option<usize>,
) -> Result<Vec<u8>, String> {
    let minimum_event_count =
        minimum_events_per_entropy_bits(possible_results, required_entropy_bits);
    if possible_results == 0 || events.len() < minimum_event_count {
        return Err(format!(
            "{} With {possible_results} possible results per event, a minimum of {minimum_event_count} events are required to obtain sufficient entropy. Events provided: {}.",
            EntropyGenerationError::insufficientEntropy,
            events.len()
        ));
    }
    // `[...events.join('')].map((digit) => Number(digit) + 48)`: each digit
    // becomes its UTF-8 byte; any other character is `NaN`, stored as `0`.
    let concatenated_digits: String = events.iter().map(|event| number_to_string(*event)).collect();
    let source: Vec<u8> = concatenated_digits
        .chars()
        .map(|digit| digit.to_digit(10).map_or(0, |value| value as u8 + UTF8_NUMBERS_OFFSET))
        .collect();
    Ok(crypto.unwrap_or(&sha256).hash(&source))
}
