//! BIP39 mnemonic phrases (port of `key/bip39.ts`).
//!
//! Word lists for all ten standard BIP39 languages are available in
//! [`crate::key::word_lists`].

use crate::runtime::string::normalize_nfkd;
use crate::crypto::{pbkdf2_hmac_sha512, sha256, Pbkdf2Parameters, Sha512};
use crate::key::hd_key::{derive_hd_private_node_from_seed, HdPrivateNode};
use crate::format::{bin_string_to_bin, bin_to_bin_string};
use crate::key::key_utils::generate_random_bytes as internal_generate_random_bytes;

/// Errors produced by BIP39 helpers (`Bip39Error`).
pub struct Bip39Error;

impl Bip39Error {
    /// The entropy length is not one of 16, 20, 24, 28, or 32 bytes.
    pub const invalidEntropyLength: &'static str = "BIP39 Error: invalid entropy length. Entropy length must be 16, 20, 24, 28, or 32 bytes.";
    /// The mnemonic does not contain 12, 15, 18, 21, or 24 words.
    pub const invalidMnemonicLength: &'static str = "BIP39 Error: invalid mnemonic length. Word count must be 12, 15, 18, 21, or 24.";
    /// The word list does not contain exactly 2048 words.
    pub const invalidWordListLength: &'static str = "BIP39 Error: invalid word list length. BIP39 word lists must contain exactly 2048 words.";
    /// The mnemonic checksum is invalid.
    pub const invalidChecksum: &'static str = "BIP39 Error: invalid checksum for the given mnemonic phrase.";
    /// The mnemonic contains words not present in the word list.
    pub const unknownWord: &'static str = "BIP39 Error: unknown word(s). The mnemonic phrase contains one or more words that do not exist in the word list.";
}

/// The number of words in a valid BIP39 word list.
const BIP39_VALID_WORD_LIST_LENGTH: usize = 2048;

const BITS_PER_BYTE: usize = 8;
const BITS_PER_WORD: usize = 11;
const MIN_WORD_COUNT: usize = 12;
const MAX_WORD_COUNT: usize = 24;
const WORD_COUNT_STEP_SIZE: usize = 3;
const ENTROPY_LENGTH_STEP_SIZE: usize = 4;
const MIN_ENTROPY_BYTES: usize = 16;
const MAX_ENTROPY_BYTES: usize = 32;
const CHECKSUM_RATIO: usize = 32;
const DERIVED_KEY_LENGTH: usize = 64;
const PBKDF2_ITERATIONS: u32 = 2048;

/// Verify that the provided BIP39 word list contains exactly 2048 words.
pub fn is_valid_bip39_word_list(word_list: &[&str]) -> bool {
    word_list.len() == BIP39_VALID_WORD_LIST_LENGTH
}

/// Verify that the length of the provided entropy is valid for BIP39 (16, 20,
/// 24, 28, or 32 bytes).
pub fn is_valid_bip39_entropy_length(entropy: &[u8]) -> bool {
    (MIN_ENTROPY_BYTES..=MAX_ENTROPY_BYTES).contains(&entropy.len())
        && entropy.len() % ENTROPY_LENGTH_STEP_SIZE == 0
}

/// Derive the BIP39 checksum bits for the given entropy.
pub fn derive_bip39_checksum_bits(entropy: &[u8]) -> String {
    let entropy_bits = entropy.len() * BITS_PER_BYTE;
    let checksum_bits = entropy_bits / CHECKSUM_RATIO;
    bin_to_bin_string(&sha256.hash(entropy))[..checksum_bits].to_string()
}

/// Decode a BIP39 mnemonic phrase using the provided word list.
pub fn decode_bip39_mnemonic_non_standard(
    mnemonic: &str,
    word_list: &[&str],
) -> Result<Vec<u8>, String> {
    if !is_valid_bip39_word_list(word_list) {
        return Err(format!(
            "{} Word list length: {}.",
            Bip39Error::invalidWordListLength,
            word_list.len()
        ));
    }
    let normalized = normalize_nfkd(mnemonic);
    let words: Vec<&str> = normalized.split(' ').collect();
    if words.len() % WORD_COUNT_STEP_SIZE != 0
        || words.len() < MIN_WORD_COUNT
        || words.len() > MAX_WORD_COUNT
    {
        return Err(format!(
            "{} Word count: {}.",
            Bip39Error::invalidMnemonicLength,
            words.len()
        ));
    }
    let unknown_words: Vec<&str> = words
        .iter()
        .copied()
        .filter(|word| !word_list.contains(word))
        .collect();
    if !unknown_words.is_empty() {
        return Err(format!(
            "{} Unknown word(s): {}.",
            Bip39Error::unknownWord,
            unknown_words.join(", ")
        ));
    }
    let mut bin_string = String::with_capacity(words.len() * BITS_PER_WORD);
    for word in &words {
        let index = word_list
            .iter()
            .position(|candidate| candidate == word)
            .expect("known word");
        bin_string.push_str(&format!("{index:011b}"));
    }
    let split_index = (words.len() / WORD_COUNT_STEP_SIZE) * CHECKSUM_RATIO;
    let entropy_bits = &bin_string[..split_index];
    let checksum_bits = &bin_string[split_index..];
    let entropy = bin_string_to_bin(entropy_bits);
    let new_checksum = derive_bip39_checksum_bits(&entropy);
    if new_checksum != checksum_bits {
        return Err(format!(
            "{} Encoded: {}; computed: {}.",
            Bip39Error::invalidChecksum,
            checksum_bits,
            new_checksum
        ));
    }
    Ok(entropy)
}

/// Decode a BIP39 mnemonic phrase using the English word list.
pub fn decode_bip39_mnemonic(mnemonic: &str) -> Result<Vec<u8>, String> {
    decode_bip39_mnemonic_non_standard(mnemonic, &bip39WordListEnglish)
}

/// Encode the provided entropy in a BIP39 mnemonic phrase using a custom word
/// list.
pub fn encode_bip39_mnemonic_non_standard(
    entropy: &[u8],
    word_list: &[&str],
) -> Result<Bip39MnemonicResult, String> {
    if !is_valid_bip39_entropy_length(entropy) {
        return Err(format!(
            "{} Entropy length: {}.",
            Bip39Error::invalidEntropyLength,
            entropy.len()
        ));
    }
    if !is_valid_bip39_word_list(word_list) {
        return Err(format!(
            "{} Word list length: {}.",
            Bip39Error::invalidWordListLength,
            word_list.len()
        ));
    }
    let entropy_bits = bin_to_bin_string(entropy);
    let checksum_bits = derive_bip39_checksum_bits(entropy);
    let bits = format!("{entropy_bits}{checksum_bits}");
    let words: Vec<&str> = bits
        .as_bytes()
        .chunks(BITS_PER_WORD)
        .map(|chunk| {
            let index = chunk.iter().fold(0_usize, |value, digit| {
                (value << 1) | usize::from(*digit == b'1')
            });
            word_list[index]
        })
        .collect();
    let separator = if word_list[0] == "\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}" {
        '\u{3000}'
    } else {
        ' '
    };
    Ok(Bip39MnemonicResult {
        phrase: words.join(&separator.to_string()),
    })
}

/// Encode the provided entropy in an English BIP39 mnemonic phrase.
pub fn encode_bip39_mnemonic(entropy: &[u8]) -> Result<Bip39MnemonicResult, String> {
    encode_bip39_mnemonic_non_standard(entropy, &bip39WordListEnglish)
}

/// Derive a seed from the provided BIP39 mnemonic phrase.
///
/// Note that by design, BIP39 seeds are formally defined for any string;
/// mnemonic phrases are not required to be valid. Use
/// [`decode_bip39_mnemonic`] to validate the phrase first.
///
/// - `crypto`: an optional implementation of `pbkdf2HmacSha512`.
/// - `passphrase`: an optional BIP39 passphrase (defaults to `''`).
pub fn derive_seed_from_bip39_mnemonic(
    mnemonic: &str,
    crypto: Option<&dyn Fn(&Pbkdf2Parameters) -> Result<Vec<u8>, String>>,
    passphrase: Option<&str>,
) -> Vec<u8> {
    let mnemonic_normalized = normalize_nfkd(mnemonic);
    let salt = format!("mnemonic{}", passphrase.unwrap_or(""));
    let salt_normalized = normalize_nfkd(&salt);
    let parameters = Pbkdf2Parameters {
        derived_key_length: DERIVED_KEY_LENGTH,
        iterations: PBKDF2_ITERATIONS,
        password: mnemonic_normalized.into_bytes(),
        salt: salt_normalized.into_bytes(),
    };
    match crypto {
        Some(pbkdf2_hmac_sha512) => pbkdf2_hmac_sha512(&parameters),
        None => pbkdf2_hmac_sha512(&parameters, None),
    }
    .expect("valid BIP39 PBKDF2 parameters")
}

/// Derive an [`HdPrivateNode`] from the provided BIP39 mnemonic phrase
/// following the BIP32 and BIP39 specifications.
///
/// - `crypto`: optional implementations of `pbkdf2HmacSha512` and sha512.
/// - `hmac_sha512_key`: the HMAC SHA-512 key to use (defaults to
///   [`crate::key::bip32HmacSha512Key`]).
/// - `passphrase`: an optional BIP39 passphrase (defaults to `''`).
pub fn derive_hd_private_node_from_bip39_mnemonic(
    mnemonic: &str,
    crypto: Option<(&dyn Fn(&Pbkdf2Parameters) -> Result<Vec<u8>, String>, &Sha512)>,
    hmac_sha512_key: Option<&[u8]>,
    passphrase: Option<&str>,
) -> HdPrivateNode {
    derive_hd_private_node_from_seed(
        &derive_seed_from_bip39_mnemonic(mnemonic, crypto.map(|(pbkdf2, _)| pbkdf2), passphrase),
        None,
        crypto.map(|(_, sha512)| sha512),
        hmac_sha512_key,
    )
}

/// Generate a new, cryptographically secure, BIP39 mnemonic phrase using a
/// localized or custom word list.
///
/// See [`generate_bip39_mnemonic`] to generate a standard, 12-word English
/// BIP39 mnemonic phrase.
///
/// - `entropy_length`: the number of bytes of entropy to use (defaults to
///   `16`, a 12-word phrase).
/// - `generate_random_bytes`: an optional source of random bytes (defaults to
///   [`crate::key::generate_random_bytes`]).
pub fn generate_bip39_mnemonic_non_standard(
    word_list: &[&str],
    entropy_length: Option<usize>,
    generate_random_bytes: Option<&dyn Fn(usize) -> Result<Vec<u8>, String>>,
) -> Result<Bip39MnemonicResult, String> {
    if !is_valid_bip39_word_list(word_list) {
        return Err(format!(
            "{} Word list length: {}.",
            Bip39Error::invalidWordListLength,
            word_list.len()
        ));
    }
    let entropy_length = entropy_length.unwrap_or(MIN_ENTROPY_BYTES);
    let entropy = match generate_random_bytes {
        Some(generate_random_bytes) => generate_random_bytes(entropy_length),
        None => internal_generate_random_bytes(entropy_length, None),
    }?;
    if !is_valid_bip39_entropy_length(&entropy) {
        return Err(format!(
            "{} Entropy length: {}.",
            Bip39Error::invalidEntropyLength,
            entropy.len()
        ));
    }
    encode_bip39_mnemonic_non_standard(&entropy, word_list)
}

/// Generate a new, cryptographically secure, 12-word English BIP39 mnemonic
/// phrase.
pub fn generate_bip39_mnemonic() -> Result<String, String> {
    Ok(generate_bip39_mnemonic_non_standard(&bip39WordListEnglish, Some(MIN_ENTROPY_BYTES), None)?.phrase)
}

/// Attempt to correct an invalid BIP39 mnemonic
/// (`attemptBip39MnemonicErrorCorrection`).
///
/// libauth v3.1.0-next.8 exposes this function but has not implemented it yet;
/// it always returns the message below. This port preserves that behavior.
pub fn attempt_bip39_mnemonic_error_correction(
    _mnemonic: &str,
    _possible_word_lists: &[&[&str]],
) -> String {
    "TODO: not yet implemented".to_string()
}

/// libauth's `Bip39MnemonicResult`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip39MnemonicResult {
    pub phrase: String,
}

/// libauth's `Bip39MnemonicCorrection`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip39MnemonicCorrection {
    pub phrase: String,
    pub corrections: Vec<Bip39MnemonicCorrectionRange>,
    pub description: String,
}

/// libauth's `Bip39ValidEntropyLength` (16, 20, 24, 28, or 32 bytes).
pub type Bip39ValidEntropyLength = usize;

pub use super::word_lists::bip39_chinese_simplified::bip39WordListChineseSimplified;
pub use super::word_lists::bip39_chinese_traditional::bip39WordListChineseTraditional;
pub use super::word_lists::bip39_czech::bip39WordListCzech;
pub use super::word_lists::bip39_english::bip39WordListEnglish;
pub use super::word_lists::bip39_french::bip39WordListFrench;
pub use super::word_lists::bip39_italian::bip39WordListItalian;
pub use super::word_lists::bip39_japanese::bip39WordListJapanese;
pub use super::word_lists::bip39_korean::bip39WordListKorean;
pub use super::word_lists::bip39_portuguese::bip39WordListPortuguese;
pub use super::word_lists::bip39_spanish::bip39WordListSpanish;

/// A correction range within a BIP39 mnemonic phrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bip39MnemonicCorrectionRange {
    pub start: usize,
    pub end: usize,
}
