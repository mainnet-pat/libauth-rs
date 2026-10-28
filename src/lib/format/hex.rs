/// Returns an array of incrementing values starting at `begin` and incrementing
/// by one for `length`.
///
/// E.g.: `range(3, None)` → `[0, 1, 2]` and `range(3, Some(1))` → `[1, 2, 3]`
pub fn range(length: usize, begin: Option<usize>) -> Vec<usize> {
    let begin = begin.unwrap_or(0);
    (0..length).map(|index| begin + index).collect()
}

/// Split a string into an array of `chunkLength` strings. The final string may
/// have a length between 1 and `chunkLength`.
///
/// E.g.: `splitEvery('abcde', 2)` → `['ab', 'cd', 'e']`
pub fn split_every(input: &str, chunk_length: usize) -> Vec<&str> {
    let bytes = input.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let end = core::cmp::min(index + chunk_length, bytes.len());
        // Only split on char boundaries (hex input is ASCII, but UTF-8 input must not panic).
        let mut safe_end = end;
        while safe_end < bytes.len() && !input.is_char_boundary(safe_end) {
            safe_end += 1;
        }
        let mut safe_start = index;
        while safe_start < bytes.len() && !input.is_char_boundary(safe_start) {
            safe_start += 1;
        }
        if safe_start < safe_end {
            result.push(&input[safe_start..safe_end]);
        }
        index = safe_end.max(index + 1);
    }
    result
}

const HEX_BYTE_WIDTH: usize = 2;
const HEXADECIMAL: u32 = 16;

/// Decode a hexadecimal-encoded string into a Uint8Array.
///
/// E.g.: `hexToBin('2a64ff')` → `new Uint8Array([42, 100, 255])`
///
/// Note, this method always completes. If `validHex` is not divisible by 2,
/// the final byte will be parsed as if it were prepended with a `0` (e.g. `aaa`
/// is interpreted as `aa0a`). If `validHex` is potentially malformed, check it
/// with {@link isHex} before calling this method.
pub fn hex_to_bin(valid_hex: &str) -> Vec<u8> {
    split_every(valid_hex, HEX_BYTE_WIDTH)
        .iter()
        .map(|byte| parse_int_prefix(byte, HEXADECIMAL))
        .collect()
}

/// `parseInt(text, radix)` for a byte-sized chunk: parse the leading digits
/// and yield `0` when there are none (`Uint8Array.from([NaN])` is `[0]`).
fn parse_int_prefix(text: &str, radix: u32) -> u8 {
    let mut value = 0_u32;
    for character in text.chars() {
        match character.to_digit(radix) {
            Some(digit) => value = value * radix + digit,
            None => break,
        }
    }
    value as u8
}

/// For use before {@link hexToBin}. Returns true if the provided string is
/// valid hexadecimal (length is divisible by 2, only uses hexadecimal
/// characters).
pub fn is_hex(maybe_hex: &str) -> bool {
    maybe_hex.len() % HEX_BYTE_WIDTH == 0 && maybe_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Encode a Uint8Array into a hexadecimal-encoded string.
///
/// E.g.: `binToHex(new Uint8Array([42, 100, 255]))` → `'2a64ff'`
pub fn bin_to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * HEX_BYTE_WIDTH);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

/// Decode a hexadecimal-encoded string into bytes, reverse it, then re-encode it
/// as hexadecimal. This is useful for switching from big endian to little
/// endian (and vice versa).
pub fn swap_endianness(valid_hex: &str) -> String {
    let mut bytes = hex_to_bin(valid_hex);
    bytes.reverse();
    bin_to_hex(&bytes)
}

/// Reduce an array of `Uint8Array`s into a single `Uint8Array`.
pub fn flatten_bin_array(array: &[Vec<u8>]) -> Vec<u8> {
    let total_length = array.iter().map(Vec::len).sum();
    let mut flattened = Vec::with_capacity(total_length);
    for bin in array {
        flattened.extend_from_slice(bin);
    }
    flattened
}

/// Exhaustively compare the contents of two `Uint8Array`s for equality.
/// Returns `true` if the arrays are equal.
pub fn bins_are_equal(a: &[u8], b: &[u8]) -> bool {
    a == b
}
