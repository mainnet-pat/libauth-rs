// base64 encode/decode derived from: https://github.com/niklasvh/base64-arraybuffer

const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64_GROUP_LENGTH: usize = 4;

/// For use before {@link base64ToBin}. Returns true if the provided string is
/// valid base64 (length is divisible by 4, only uses base64 characters).
pub fn is_base64(maybe_base64: &str) -> bool {
    maybe_base64.len() % BASE64_GROUP_LENGTH == 0
        && maybe_base64
            .bytes()
            .all(|byte| CHARS.contains(&byte) || byte == b'=')
}

fn lookup(character: Option<&u8>) -> u8 {
    character
        .and_then(|character| CHARS.iter().position(|item| item == character))
        .unwrap_or(0) as u8
}

/// Convert a valid base64 string to a Uint8Array. If `validBase64` is not
/// valid base64, an incorrect result will be returned.
pub fn base64_to_bin(valid_base64: &str) -> Vec<u8> {
    let bytes = valid_base64.as_bytes();
    let buffer_length_estimate = bytes.len() * 3 / 4;
    let buffer_length = match (bytes.last(), bytes.len().checked_sub(2).map(|index| bytes[index])) {
        (Some(b'='), Some(b'=')) => buffer_length_estimate.saturating_sub(2),
        (Some(b'='), _) => buffer_length_estimate.saturating_sub(1),
        _ => buffer_length_estimate,
    };
    let mut result = Vec::with_capacity(buffer_length + 2);
    for group in bytes.chunks(BASE64_GROUP_LENGTH) {
        let encoded1 = lookup(group.first());
        let encoded2 = lookup(group.get(1));
        let encoded3 = lookup(group.get(2));
        let encoded4 = lookup(group.get(3));
        result.push((encoded1 << 2) | (encoded2 >> 4));
        result.push(((encoded2 & 15) << 4) | (encoded3 >> 2));
        result.push(((encoded3 & 3) << 6) | (encoded4 & 63));
    }
    result.truncate(buffer_length);
    result
}

/// Convert a Uint8Array to a base64 string.
pub fn bin_to_base64(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * BASE64_GROUP_LENGTH);
    for group in bytes.chunks(3) {
        let byte0 = group[0] as usize;
        let byte1 = *group.get(1).unwrap_or(&0) as usize;
        let byte2 = *group.get(2).unwrap_or(&0) as usize;
        result.push(CHARS[byte0 >> 2] as char);
        result.push(CHARS[((byte0 & 3) << 4) | (byte1 >> 4)] as char);
        result.push(CHARS[((byte1 & 15) << 2) | (byte2 >> 6)] as char);
        result.push(CHARS[byte2 & 63] as char);
    }
    match bytes.len() % 3 {
        2 => {
            result.pop();
            result.push('=');
        }
        1 => {
            result.truncate(result.len() - 2);
            result.push_str("==");
        }
        _ => {}
    }
    result
}
