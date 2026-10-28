use crate::runtime::bigint::BigInt;

use super::error::format_error;
use super::read::{MaybeReadResult, ReadPosition, ReadResult};

/// Encode a positive integer as a little-endian Uint8Array. For values
/// exceeding `Number.MAX_SAFE_INTEGER` (`9007199254740991`), use
/// {@link bigIntToBinUintLE}. Negative values will return the same result as
/// `0`.
pub fn number_to_bin_uint_le(value: impl Into<i64>) -> Vec<u8> {
    const BASE_UINT8_ARRAY: i64 = 256;
    let mut result = Vec::new();
    let mut remaining: i64 = value.into();
    while remaining >= BASE_UINT8_ARRAY {
        result.push((remaining % BASE_UINT8_ARRAY) as u8);
        remaining /= BASE_UINT8_ARRAY;
    }
    if remaining > 0 {
        result.push(remaining as u8);
    }
    result
}

/// Fill a new Uint8Array of a specific byte-length with the contents of a
/// smaller Uint8Array, padding the remaining bytes with `0`. If the provided
/// Uint8Array is larger than the requested length, the result will be filled
/// with `0xff` (the maximum value).
pub fn bin_to_fixed_length(bin: &[u8], bytes: usize) -> Vec<u8> {
    const MAX_VALUE: u8 = 255;
    if bin.len() > bytes {
        return vec![MAX_VALUE; bytes];
    }
    let mut fixed_bytes = vec![0_u8; bytes];
    fixed_bytes[..bin.len()].copy_from_slice(bin);
    fixed_bytes
}

/// Encode a positive integer as a 2-byte Uint16LE Uint8Array, clamping the
/// results – values exceeding `0xffff` (`65535`) return the same result as
/// `0xffff`, negative values will return the same result as `0`.
pub fn number_to_bin_uint16_le_clamped(value: impl Into<i64>) -> Vec<u8> {
    const UINT16: usize = 2;
    bin_to_fixed_length(&number_to_bin_uint_le(value), UINT16)
}

/// Encode a positive integer as a 4-byte Uint32LE Uint8Array, clamping the
/// results – values exceeding `0xffffffff` (`4294967295`) return the same
/// result as `0xffffffff`, negative values will return the same result as `0`.
pub fn number_to_bin_uint32_le_clamped(value: impl Into<i64>) -> Vec<u8> {
    const UINT32: usize = 4;
    bin_to_fixed_length(&number_to_bin_uint_le(value), UINT32)
}

/// Encode a positive integer as a 2-byte Uint16LE Uint8Array.
///
/// This method will return an incorrect result for values outside of the range
/// `0` to `0xffff` (`65535`). If applicable, applications should handle such
/// cases prior to calling this method.
pub fn number_to_bin_uint16_le(value: impl Into<i64>) -> Vec<u8> {
    // `DataView#setUint16` reduces the value modulo 2^16.
    (value.into() as u16).to_le_bytes().to_vec()
}

/// Encode an integer as a 2-byte Int16LE Uint8Array.
///
/// This method will return an incorrect result for values outside of the range
/// `0x0000` to `0xffff` (`65535`). If applicable, applications should handle
/// such cases prior to calling this method.
pub fn number_to_bin_int16_le(value: i16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Encode an integer as a 4-byte Uint32LE Uint8Array.
///
/// This method will return an incorrect result for values outside of the range
/// `0x00000000` to `0xffffffff` (`4294967295`). If applicable, applications
/// should handle such cases prior to calling this method.
pub fn number_to_bin_int32_le(value: i32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Decode a 2-byte Int16LE Uint8Array into a number.
///
/// Throws if `bin` is shorter than 2 bytes.
pub fn bin_to_number_int16_le(bin: &[u8]) -> i16 {
    i16::from_le_bytes([bin[0], bin[1]])
}

/// Decode a 4-byte Int32LE Uint8Array into a number.
///
/// Throws if `bin` is shorter than 4 bytes.
pub fn bin_to_number_int32_le(bin: &[u8]) -> i32 {
    i32::from_le_bytes([bin[0], bin[1], bin[2], bin[3]])
}

/// Encode a positive integer as a 2-byte Uint16LE Uint8Array.
///
/// This method will return an incorrect result for values outside of the range
/// `0` to `0xffff` (`65535`). If applicable, applications should handle such
/// cases prior to calling this method.
pub fn number_to_bin_uint16_be(value: impl Into<i64>) -> Vec<u8> {
    // `DataView#setUint16` reduces the value modulo 2^16.
    (value.into() as u16).to_be_bytes().to_vec()
}

/// Encode a positive number as a 4-byte Uint32LE Uint8Array.
///
/// This method will return an incorrect result for values outside of the range
/// `0` to `0xffffffff` (`4294967295`). If applicable, applications should
/// handle such cases prior to calling this method.
pub fn number_to_bin_uint32_le(value: impl Into<i64>) -> Vec<u8> {
    // `DataView#setUint32` reduces the value modulo 2^32.
    (value.into() as u32).to_le_bytes().to_vec()
}

/// Encode a positive number as a 4-byte Uint32BE Uint8Array.
///
/// This method will return an incorrect result for values outside of the range
/// `0` to `0xffffffff` (`4294967295`). If applicable, applications should
/// handle such cases prior to calling this method.
pub fn number_to_bin_uint32_be(value: impl Into<i64>) -> Vec<u8> {
    // `DataView#setUint32` reduces the value modulo 2^32.
    (value.into() as u32).to_be_bytes().to_vec()
}

/// Encode a positive BigInt as little-endian Uint8Array. Negative values will
/// return the same result as `0`.
pub fn big_int_to_bin_uint_le(value: &BigInt) -> Vec<u8> {
    let base = BigInt::from_u64(256);
    let mut result = Vec::new();
    let mut remaining = value.clone();
    while remaining.cmp(&base).is_ge() {
        let (quotient, remainder) = remaining.div_mod(&base);
        result.push(remainder.to_u64().unwrap_or(0) as u8);
        remaining = quotient;
    }
    if remaining.cmp(&BigInt::zero()).is_gt() {
        result.push(remaining.to_u64().unwrap_or(0) as u8);
    }
    if result.is_empty() {
        result.push(0);
    }
    result
}

/// Encode a positive BigInt as an 8-byte Uint64LE Uint8Array, clamping the
/// results – values exceeding `0xffff_ffff_ffff_ffff` (`18446744073709551615`)
/// return the same result as `0xffff_ffff_ffff_ffff`, negative values return
/// the same result as `0`.
pub fn big_int_to_bin_uint64_le_clamped(value: &BigInt) -> Vec<u8> {
    const UINT64: usize = 8;
    bin_to_fixed_length(&big_int_to_bin_uint_le(value), UINT64)
}

/// Encode a positive BigInt as an 8-byte Uint64LE Uint8Array (reduced modulo
/// 2^64, `BigInt.asUintN(64, value)`).
pub fn big_int_to_bin_uint64_le(value: impl Into<i128>) -> Vec<u8> {
    (value.into() as u64).to_le_bytes().to_vec()
}

/// Encode an integer as a 4-byte, little-endian Uint8Array using the number's
/// two's compliment representation (the format used by JavaScript's bitwise
/// operators).
///
/// @remarks
/// The C++ bitcoin implementations sometimes represent short vectors using
/// signed 32-bit integers (e.g. `sighashType`). This method can be used to test
/// compatibility with those implementations.
pub fn number_to_bin_int32_twos_compliment(value: i64) -> Vec<u8> {
    (value as u32).to_le_bytes().to_vec()
}

/// Decode a little-endian Uint8Array of any length into a number. For numbers
/// larger than `Number.MAX_SAFE_INTEGER` (`9007199254740991`), use
/// `binToBigIntUintLE`.
///
/// The `bytes` parameter can be set to constrain the expected length (default:
/// `bin.length`). This method throws if `bin.length` is not equal to `bytes`.
pub fn bin_to_number_uint_le(bin: &[u8], bytes: Option<usize>) -> u64 {
    const BITS_IN_A_BYTE: u32 = 8;
    let bytes = bytes.unwrap_or(bin.len());
    if bin.len() != bytes {
        panic!("Bin length must be {bytes}.");
    }
    bin.iter().enumerate().fold(0_u64, |accumulated, (index, byte)| {
        accumulated.wrapping_add((*byte as u64).wrapping_shl(BITS_IN_A_BYTE * index as u32))
    })
}

/// Decode a 2-byte Uint16LE Uint8Array into a number.
///
/// Throws if `bin` is shorter than 2 bytes.
pub fn bin_to_number_uint16_le(bin: &[u8]) -> u16 {
    u16::from_le_bytes([bin[0], bin[1]])
}

/// Decode a 4-byte Uint32LE Uint8Array into a number.
///
/// Throws if `bin` is shorter than 4 bytes.
pub fn bin_to_number_uint32_le(bin: &[u8]) -> u32 {
    u32::from_le_bytes([bin[0], bin[1], bin[2], bin[3]])
}

/// Decode a big-endian Uint8Array of any length into a BigInt. If starting from
/// a hex value, consider using the BigInt constructor instead:
/// ```js
/// BigInt(`0x${hex}`)
/// ```
///
/// The `bytes` parameter can be set to constrain the expected length (default:
/// `bin.length`). This method throws if `bin.length` is not equal to `bytes`.
pub fn bin_to_big_int_uint_be(bin: &[u8], bytes: Option<usize>) -> BigInt {
    const BITS_IN_A_BYTE: u64 = 8;
    let bytes = bytes.unwrap_or(bin.len());
    if bin.len() != bytes {
        panic!("Bin length must be {bytes}.");
    }
    bin.iter().fold(BigInt::zero(), |accumulated, byte| {
        accumulated.shl(BITS_IN_A_BYTE).add(&BigInt::from_u64(*byte as u64))
    })
}

/// Encode a positive BigInt into an unsigned 32-byte big-endian Uint8Array. This
/// can be used to encode numbers for cryptographic primitives like private keys,
/// public keys, curve parameters, and signature points.
///
/// Negative values will return the same result as `0`.
pub fn big_int_to_bin_uint_be(value: &BigInt) -> Vec<u8> {
    let mut result = big_int_to_bin_uint_le(value);
    result.reverse();
    result
}

/// Decode an unsigned, 32-byte big-endian Uint8Array into a BigInt. This can be
/// used to decode Uint8Array-encoded cryptographic primitives like private keys,
/// public keys, curve parameters, and signature points.
///
/// If starting from a hex value, consider using the BigInt constructor instead:
/// ```js
/// BigInt(`0x${hex}`)
/// ```
pub fn bin_to_big_int_uint256_be(bin: &[u8]) -> BigInt {
    const UINT256_BYTES: usize = 32;
    bin_to_big_int_uint_be(bin, Some(UINT256_BYTES))
}

/// Encode a positive BigInt into an unsigned 32-byte big-endian Uint8Array. This
/// can be used to encoded numbers for cryptographic primitives like private
/// keys, public keys, curve parameters, and signature points.
///
/// Negative values will return the same result as `0`, values higher than
/// 2^256-1 will return the maximum expressible unsigned 256-bit value
/// (`0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`).
pub fn big_int_to_bin_uint256_be_clamped(value: &BigInt) -> Vec<u8> {
    const UINT256_BYTES: usize = 32;
    let mut result = bin_to_fixed_length(&big_int_to_bin_uint_le(value), UINT256_BYTES);
    result.reverse();
    result
}

/// Decode a little-endian Uint8Array of any length into a BigInt.
///
/// The `bytes` parameter can be set to constrain the expected length (default:
/// `bin.length`). This method throws if `bin.length` is not equal to `bytes`.
pub fn bin_to_big_int_uint_le(bin: &[u8], bytes: Option<usize>) -> BigInt {
    const BITS_IN_A_BYTE: u64 = 8;
    let bytes = bytes.unwrap_or(bin.len());
    if bin.len() != bytes {
        panic!("Bin length must be {bytes}.");
    }
    bin.iter().rev().fold(BigInt::zero(), |accumulated, byte| {
        accumulated.shl(BITS_IN_A_BYTE).add(&BigInt::from_u64(*byte as u64))
    })
}

/// Decode an 8-byte Uint64LE Uint8Array into a BigInt.
///
/// Throws if `bin` is shorter than 8 bytes.
pub fn bin_to_big_int_uint64_le(bin: &[u8]) -> u64 {
    const UINT64_LENGTH_IN_BYTES: usize = 8;
    let truncated_bin = &bin[..bin.len().min(UINT64_LENGTH_IN_BYTES)];
    if truncated_bin.len() != UINT64_LENGTH_IN_BYTES {
        panic!("Bin length must be {UINT64_LENGTH_IN_BYTES}.");
    }
    u64::from_le_bytes(truncated_bin.try_into().expect("8 bytes"))
}

/// Decode a {@link Output.valueSatoshis} into a `BigInt`. This is an alias for
/// {@link binToBigIntUint64LE}.
///
/// Throws if the provided value is shorter than 8 bytes.
pub fn bin_to_value_satoshis(bin: &[u8]) -> u64 {
    bin_to_big_int_uint64_le(bin)
}

/// Encode a satoshi value ({@link Output.valueSatoshis}) into a `Uint8Array`.
/// This is an alias for {@link bigIntToBinUint64LE}.
pub fn value_satoshis_to_bin(value: u64) -> Vec<u8> {
    big_int_to_bin_uint64_le(value)
}

// `CompactUint` (A.K.A. "VarInt" or "CompactSize") constants.
const COMPACT_UINT_UINT8_MAX_VALUE: u64 = 0xfc;
const COMPACT_UINT_UINT16_PREFIX: u8 = 0xfd;
const COMPACT_UINT_UINT16_MAX_VALUE: u64 = 0xffff;
const COMPACT_UINT_UINT32_PREFIX: u8 = 0xfe;
const COMPACT_UINT_UINT32_MAX_VALUE: u64 = 0xffff_ffff;
const COMPACT_UINT_UINT64_PREFIX: u8 = 0xff;
const COMPACT_UINT_UINT8: usize = 1;
const COMPACT_UINT_UINT16: usize = 2;
const COMPACT_UINT_UINT32: usize = 4;
const COMPACT_UINT_UINT64: usize = 8;

/// Get the expected byte length of a CompactUint given a first byte.
pub fn compact_uint_prefix_to_length(first_byte: u8) -> usize {
    match first_byte {
        COMPACT_UINT_UINT16_PREFIX => COMPACT_UINT_UINT16 + 1,
        COMPACT_UINT_UINT32_PREFIX => COMPACT_UINT_UINT32 + 1,
        COMPACT_UINT_UINT64_PREFIX => COMPACT_UINT_UINT64 + 1,
        _ => COMPACT_UINT_UINT8,
    }
}

/// Errors produced while reading or decoding a CompactUint.
pub struct CompactUintError;

impl CompactUintError {
    pub const noPrefix: &'static str = "Error reading CompactUint: requires at least one byte.";
    pub const insufficientBytes: &'static str = "Error reading CompactUint: insufficient bytes.";
    pub const nonMinimal: &'static str =
        "Error reading CompactUint: CompactUint is not minimally encoded.";
    pub const excessiveBytes: &'static str =
        "Error decoding CompactUint: unexpected bytes after CompactUint.";
}

/// Read a non-minimally-encoded `CompactUint` (see {@link bigIntToCompactUint})
/// from the provided {@link ReadPosition}, returning either an error message (as
/// a string) or an object containing the value and the next
/// {@link ReadPosition}.
///
/// Rather than this function, most applications should
/// use {@link readCompactUintMinimal}.
pub fn read_compact_uint(position: ReadPosition<'_>) -> MaybeReadResult<'_, u64> {
    let ReadPosition { bin, index } = position;
    let Some(&prefix) = bin.get(index) else {
        return Err(format_error(CompactUintError::noPrefix, None));
    };
    let bytes = compact_uint_prefix_to_length(prefix);
    if bin.len() - index < bytes {
        return Err(format_error(
            CompactUintError::insufficientBytes,
            Some(&format!(
                "CompactUint prefix {prefix} requires at least {bytes} bytes. Remaining bytes: {}",
                bin.len() - index
            )),
        ));
    }
    let has_prefix = bytes != 1;
    let contents = if has_prefix {
        &bin[index + 1..index + bytes]
    } else {
        &bin[index..index + bytes]
    };
    let result = contents
        .iter()
        .rev()
        .fold(0_u64, |accumulated, byte| (accumulated << 8) | *byte as u64);
    Ok(ReadResult {
        position: ReadPosition {
            bin,
            index: index + bytes,
        },
        result,
    })
}

/// Encode a positive BigInt as bitcoin's `CompactUint` format.
///
/// For example, `253` is encoded as `0xfdfd00`, `0xffff` is encoded as
/// `0xfdffff`, and `0x10000` is encoded as `0xfe00000100`.
pub fn big_int_to_compact_uint(value: impl Into<i128>) -> Vec<u8> {
    let value: i128 = value.into();
    if value <= i128::from(COMPACT_UINT_UINT8_MAX_VALUE) {
        // `Uint8Array.of(Number(value))` reduces the value modulo 2^8.
        vec![value as u8]
    } else if value <= i128::from(COMPACT_UINT_UINT16_MAX_VALUE) {
        let mut result = vec![COMPACT_UINT_UINT16_PREFIX];
        result.extend(number_to_bin_uint16_le(value as u16));
        result
    } else if value <= i128::from(COMPACT_UINT_UINT32_MAX_VALUE) {
        let mut result = vec![COMPACT_UINT_UINT32_PREFIX];
        result.extend(number_to_bin_uint32_le(value as u32));
        result
    } else {
        let mut result = vec![COMPACT_UINT_UINT64_PREFIX];
        result.extend(big_int_to_bin_uint64_le(value));
        result
    }
}

/// Read a minimally-encoded `CompactUint` from the provided
/// {@link ReadPosition}, returning either an error message (as a string) or an
/// object containing the value and the next {@link ReadPosition}.
pub fn read_compact_uint_minimal(position: ReadPosition<'_>) -> MaybeReadResult<'_, u64> {
    let read = read_compact_uint(position)?;
    let read_length = read.position.index - position.index;
    let canonical_encoding = big_int_to_compact_uint(read.result);
    if read_length != canonical_encoding.len() {
        return Err(format_error(
            CompactUintError::nonMinimal,
            Some(&format!(
                "Value: {}, encoded length: {read_length}, canonical length: {}",
                read.result,
                canonical_encoding.len()
            )),
        ));
    }
    Ok(read)
}

/// Decode a minimally-encoded `CompactUint` (see {@link bigIntToCompactUint})
/// from a Uint8Array, returning either an error message (as a string) or the
/// decoded value.
pub fn compact_uint_to_big_int(bin: &[u8]) -> Result<u64, String> {
    let read = read_compact_uint_minimal(ReadPosition { bin, index: 0 })?;
    if read.position.index != bin.len() {
        return Err(format_error(
            CompactUintError::excessiveBytes,
            Some(&format!(
                "CompactUint ends at index {}, but input includes {} bytes.",
                read.position.index,
                bin.len()
            )),
        ));
    }
    Ok(read.result)
}

/// Convert from a JavaScript `number` to a signed 32-bit integer to its
/// unsigned 32-bit integer representation.
pub fn int32_signed_to_unsigned(int32: i32) -> u32 {
    int32 as u32
}

/// Convert from an unsigned 32-bit integer to its signed 32-bit integer
/// representation.
pub fn int32_unsigned_to_signed(int32: u32) -> i32 {
    int32 as i32
}
