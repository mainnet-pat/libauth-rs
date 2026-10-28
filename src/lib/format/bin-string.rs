use super::hex::split_every;

const BINARY_BYTE_WIDTH: usize = 8;
const BINARY: u32 = 2;

/// Decode a binary-encoded string into a Uint8Array.
///
/// E.g.: `binStringToBin('0010101001100100')` → `new Uint8Array([42, 100])`
///
/// Note, this method always completes. If `binaryDigits` is not divisible by 8,
/// the final byte will be parsed as if it were prepended with `0`s (e.g. `1` is
/// interpreted as `00000001`). If `binaryDigits` is potentially malformed,
/// check it with {@link isBinString} before calling this method.
pub fn bin_string_to_bin(binary_digits: &str) -> Vec<u8> {
    split_every(binary_digits, BINARY_BYTE_WIDTH)
        .iter()
        .map(|byte_string| {
            let mut value = 0_u32;
            for character in byte_string.chars() {
                match character.to_digit(BINARY) {
                    Some(digit) => value = value * BINARY + digit,
                    None => break,
                }
            }
            value as u8
        })
        .collect()
}

/// Encode a Uint8Array into a binary-encoded string.
///
/// E.g.: `binToBinString(Uint8Array.from([42, 100]))` → `'0010101001100100'`
pub fn bin_to_bin_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:08b}")).collect()
}

/// For use before {@link binStringToBin}. Returns true if the provided string is
/// a valid binary string (length is divisible by 8 and only uses the characters
/// `0` and `1`).
pub fn is_bin_string(maybe_bin_string: &str) -> bool {
    maybe_bin_string.len() % BINARY_BYTE_WIDTH == 0
        && maybe_bin_string.bytes().all(|byte| byte == b'0' || byte == b'1')
}
