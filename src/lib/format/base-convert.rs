use super::error::format_error;

/// Errors produced by {@link createBaseConverter}.
pub struct BaseConverterCreationError;

impl BaseConverterCreationError {
    pub const tooLong: &'static str =
        "Base converter creation error: an alphabet may be no longer than 254 characters.";
    pub const ambiguousCharacter: &'static str =
        "Base converter creation error: a character code may only appear once in a single alphabet.";
}

/// Errors produced by a {@link BaseConverter}.
pub struct BaseConversionError;

impl BaseConversionError {
    pub const unknownCharacter: &'static str =
        "Base conversion error: encountered an unknown character for this alphabet.";
}

const UNDEFINED_VALUE: u8 = 255;
const UINT8_ARRAY_BASE: usize = 256;

/// A converter between a byte array and an alphabet-encoded string, as
/// produced by {@link createBaseConverter}.
#[derive(Clone, Debug)]
pub struct BaseConverter {
    alphabet: Vec<u16>,
    alphabet_map: [u8; UINT8_ARRAY_BASE],
    factor: f64,
    inverse_factor: f64,
}

impl BaseConverter {
    /// Decode an alphabet-encoded string, or return an error.
    pub fn decode(&self, input: &str) -> Result<Vec<u8>, String> {
        let input: Vec<u16> = input.encode_utf16().collect();
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let base = self.alphabet.len();
        let padding_character = self.alphabet.first().copied();
        let Some(first_non_zero_index) = input
            .iter()
            .position(|character| Some(*character) != padding_character)
        else {
            return Ok(vec![0; input.len()]);
        };
        let required_length =
            ((input.len() - first_non_zero_index) as f64 * self.factor + 1.0).floor() as usize;
        let mut decoded = vec![0_u8; required_length];
        let mut remaining_bytes = 0_usize;
        for &character in &input[first_non_zero_index..] {
            let mut carry = self.character_value(character);
            if carry == UNDEFINED_VALUE as usize {
                return Err(format_error(
                    BaseConversionError::unknownCharacter,
                    Some(&format!(
                        "Unknown character: \"{}\".",
                        String::from_utf16_lossy(&[character])
                    )),
                ));
            }
            let mut digit = 0_usize;
            let mut steps = required_length as isize - 1;
            while (carry != 0 || digit < remaining_bytes) && steps != -1 {
                carry += base * decoded[steps as usize] as usize;
                decoded[steps as usize] = (carry % UINT8_ARRAY_BASE) as u8;
                carry /= UINT8_ARRAY_BASE;
                steps -= 1;
                digit += 1;
            }
            remaining_bytes = digit;
        }
        let first_non_zero_result_digit = decoded.iter().position(|value| *value != 0).unwrap_or(0);
        let mut bin = vec![0_u8; first_non_zero_index];
        bin.extend_from_slice(&decoded[first_non_zero_result_digit..]);
        Ok(bin)
    }

    /// Encode bytes using this converter's alphabet.
    pub fn encode(&self, input: &[u8]) -> String {
        if input.is_empty() {
            return String::new();
        }
        let base = self.alphabet.len();
        let padding = self.alphabet.first().copied().unwrap_or(0);
        let Some(first_non_zero_index) = input.iter().position(|byte| *byte != 0) else {
            return String::from_utf16_lossy(&vec![padding; input.len()]);
        };
        let required_length =
            ((input.len() - first_non_zero_index) as f64 * self.inverse_factor + 1.0).floor() as usize;
        let mut encoded = vec![0_u8; required_length];
        let mut remaining_bytes = 0_usize;
        for &byte in &input[first_non_zero_index..] {
            let mut carry = byte as usize;
            let mut digit = 0_usize;
            let mut steps = required_length as isize - 1;
            while (carry != 0 || digit < remaining_bytes) && steps != -1 {
                carry += UINT8_ARRAY_BASE * encoded[steps as usize] as usize;
                encoded[steps as usize] = (carry % base) as u8;
                carry /= base;
                steps -= 1;
                digit += 1;
            }
            remaining_bytes = digit;
        }
        let first_non_zero_result_digit = encoded.iter().position(|value| *value != 0).unwrap_or(0);
        let mut result = vec![padding; first_non_zero_index];
        result.extend(
            encoded[first_non_zero_result_digit..]
                .iter()
                .map(|digit| self.alphabet[*digit as usize]),
        );
        String::from_utf16_lossy(&result)
    }

    fn character_value(&self, character: u16) -> usize {
        // libauth indexes a 256-entry table by character code; codes beyond the
        // table read `undefined`, which never matches an alphabet character.
        self.alphabet_map
            .get(character as usize)
            .map_or(UNDEFINED_VALUE as usize, |value| *value as usize)
    }
}

/// Create a {@link BaseConverter}, which exposes methods for encoding and
/// decoding `Uint8Array`s using bitcoin-style padding: each leading zero in the
/// input is replaced with the zero-index character of the `alphabet`, then the
/// remainder of the input is encoded as a large number in the specified
/// alphabet.
///
/// For example, using the alphabet `01`, the input `[0, 15]` is encoded `01111`
/// – a single `0` represents the leading padding, followed by the base2
/// encoded `0x1111` (15). With the same alphabet, the input `[0, 0, 255]` is
/// encoded `0011111111` - only two `0` characters are required to represent
/// both leading zeros, followed by the base2 encoded `0x11111111` (255).
///
/// **This is not compatible with `RFC 3548`'s `Base16`, `Base32`, or `Base64`.**
///
/// If the alphabet is malformed, this method returns the error as a `string`.
pub fn create_base_converter(alphabet: &str) -> Result<BaseConverter, String> {
    let characters: Vec<u16> = alphabet.encode_utf16().collect();
    if characters.len() >= UNDEFINED_VALUE as usize {
        return Err(format_error(
            BaseConverterCreationError::tooLong,
            Some(&format!("Alphabet length: {}", characters.len())),
        ));
    }
    let mut alphabet_map = [UNDEFINED_VALUE; UINT8_ARRAY_BASE];
    for (index, character) in characters.iter().enumerate() {
        // Character codes beyond the 256-entry table read `undefined` in
        // libauth, which is reported as an ambiguous character.
        let Some(slot) = alphabet_map.get_mut(*character as usize) else {
            return Err(format_error(
                BaseConverterCreationError::ambiguousCharacter,
                Some("Ambiguous character: undefined"),
            ));
        };
        if *slot != UNDEFINED_VALUE {
            return Err(format_error(
                BaseConverterCreationError::ambiguousCharacter,
                Some(&format!("Ambiguous character: {slot}")),
            ));
        }
        *slot = index as u8;
    }
    let base = characters.len() as f64;
    let factor = base.ln() / (UINT8_ARRAY_BASE as f64).ln();
    let inverse_factor = (UINT8_ARRAY_BASE as f64).ln() / base.ln();
    Ok(BaseConverter {
        alphabet: characters,
        alphabet_map,
        factor,
        inverse_factor,
    })
}

/// The bitcoin base58 alphabet.
pub const bitcoinBase58Alphabet: &str =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58() -> &'static BaseConverter {
    static BASE58: std::sync::OnceLock<BaseConverter> = std::sync::OnceLock::new();
    BASE58.get_or_init(|| {
        create_base_converter(bitcoinBase58Alphabet).expect("the base58 alphabet is valid")
    })
}

/// Convert a bitcoin-style base58-encoded string to a Uint8Array.
///
/// See {@link createBaseConverter} for format details.
pub fn base58_to_bin(input: &str) -> Result<Vec<u8>, String> {
    base58().decode(input)
}

/// Convert a Uint8Array to a bitcoin-style base58-encoded string.
///
/// See {@link createBaseConverter} for format details.
pub fn bin_to_base58(input: &[u8]) -> String {
    base58().encode(input)
}
