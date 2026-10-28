//! Bech32 character-set encoding, decoding, and bit regrouping.
//!
//! CashAddress uses the original Bech32 character set with a 40-bit checksum;
//! the Bech32m constant is not used by this crate.

use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The 32 symbols used in Bech32 encoding.
pub const bech32CharacterSet: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The index of each character in the Bech32 character set.
pub static bech32CharacterSetIndex: LazyLock<BTreeMap<char, u8>> =
    LazyLock::new(|| bech32CharacterSet.chars().zip(0..).collect());

/// Errors returned while regrouping bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitRegroupingError {
    IntegerOutOfRange,
    HasDisallowedPadding,
    RequiresDisallowedPadding,
}

impl BitRegroupingError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntegerOutOfRange => {
                "An integer provided in the source array is out of the range of the specified source word length."
            }
            Self::HasDisallowedPadding => "Encountered padding when padding was disallowed.",
            Self::RequiresDisallowedPadding => {
                "Encoding requires padding while padding is disallowed."
            }
        }
    }
}

impl core::fmt::Display for BitRegroupingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Regroup bits from `source_word_length` to `result_word_length`.
///
/// Each item in `bin` must fit in `source_word_length` bits (libauth accepts
/// any `number[]`, so `bin` may hold any integer type). Result word lengths up
/// to 8 bits are supported (all Bech32 and CashAddress uses).
pub fn regroup_bits<T: Copy + Into<i64>>(
    bin: &[T],
    source_word_length: u32,
    result_word_length: u32,
    allow_padding: Option<bool>,
) -> Result<Vec<u8>, String> {
    let allow_padding = allow_padding.unwrap_or(true);
    if result_word_length == 0 || result_word_length > 8 || source_word_length >= 64 {
        return Err(BitRegroupingError::IntegerOutOfRange.as_str().to_string());
    }
    let max_result_int: u64 = (1_u64 << result_word_length) - 1;
    let mut accumulator: u64 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    for &value in bin {
        let value: i64 = value.into();
        if value < 0 || (value >> source_word_length) != 0 {
            return Err(BitRegroupingError::IntegerOutOfRange.as_str().to_string());
        }
        accumulator = (accumulator << source_word_length) | value as u64;
        bits += source_word_length;
        while bits >= result_word_length {
            bits -= result_word_length;
            result.push(((accumulator >> bits) & max_result_int) as u8);
        }
        accumulator &= if bits == 0 { 0 } else { (1_u64 << bits) - 1 };
    }

    if allow_padding {
        if bits > 0 {
            result.push(((accumulator << (result_word_length - bits)) & max_result_int) as u8);
        }
    } else if bits >= source_word_length {
        return Err(BitRegroupingError::HasDisallowedPadding
            .as_str()
            .to_string());
    } else if ((accumulator << (result_word_length - bits)) & max_result_int) > 0 {
        return Err(BitRegroupingError::RequiresDisallowedPadding
            .as_str()
            .to_string());
    }
    Ok(result)
}

/// Encode an array of 5-bit integers as a base32 string using the Bech32 character set.
///
/// As in libauth, values outside of `0..32` are not validated; such indices
/// encode as the text `undefined`.
pub fn encode_bech32(base32_integer_array: &[u8]) -> String {
    let characters = bech32CharacterSet.as_bytes();
    let mut result = String::with_capacity(base32_integer_array.len());
    for &value in base32_integer_array {
        match characters.get(value as usize) {
            Some(character) => result.push(char::from(*character)),
            None => result.push_str("undefined"),
        }
    }
    result
}

/// Errors returned while decoding Bech32 strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bech32DecodingError {
    NotBech32CharacterSet,
}

impl Bech32DecodingError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotBech32CharacterSet => {
                "Bech32 decoding error: input contains characters outside of the Bech32 character set."
            }
        }
    }
}

impl core::fmt::Display for Bech32DecodingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Decode a Bech32-encoded string into an array of 5-bit integers.
///
/// The string must use only characters from the Bech32 character set (see
/// [`is_bech32_character_set`]); libauth leaves any other character's index
/// `undefined`, which subsequent bitwise operations treat as `0`, so such
/// characters decode as `0`.
pub fn decode_bech32(valid_bech32: &str) -> Vec<u8> {
    valid_bech32
        .chars()
        .map(|character| bech32CharacterSetIndex.get(&character).copied().unwrap_or(0))
        .collect()
}

/// Validate that a string uses only characters from the Bech32 character set.
pub fn is_bech32_character_set(maybe_bech32: &str) -> bool {
    maybe_bech32
        .chars()
        .all(|character| bech32CharacterSet.contains(character))
}

/// Return the non-Bech32 characters in the provided string, in order of first appearance.
pub fn extract_non_bech32_characters(maybe_bech32: &str) -> Vec<char> {
    let mut result = Vec::new();
    for character in maybe_bech32.chars() {
        if !bech32CharacterSet.contains(character) && !result.contains(&character) {
            result.push(character);
        }
    }
    result
}

/// Convert a padded Bech32-encoded string (without checksum) to bytes, removing padding.
pub fn bech32_padded_to_bin(bech32_padded: &str) -> Result<Vec<u8>, String> {
    if !is_bech32_character_set(bech32_padded) {
        return Err(Bech32DecodingError::NotBech32CharacterSet
            .as_str()
            .to_string());
    }
    let decoded = decode_bech32(bech32_padded);
    regroup_bits(&decoded, 5, 8, Some(false))
}

/// Convert bytes to a padded Bech32-encoded string (without a checksum).
pub fn bin_to_bech32_padded(bytes: &[u8]) -> String {
    let regrouped = regroup_bits(bytes, 8, 5, Some(true)).expect("padding regroup of bytes cannot fail");
    encode_bech32(&regrouped)
}
