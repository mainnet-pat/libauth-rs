use crate::format::{
    bin_to_big_int_uint64_le, bin_to_number_uint32_le, format_error, read_compact_uint_minimal,
    MaybeReadResult, ReadPosition, ReadResult,
};

const BYTES_PER_UINT32: usize = 4;
const BYTES_PER_UINT64: usize = 8;

/// Errors produced by {@link readBytes}.
pub struct ReadBytesError;

impl ReadBytesError {
    pub const insufficientLength: &'static str = "Error reading bytes: insufficient length.";
}

/// Returns a function that reads the requested number of bytes from a
/// {@link ReadPosition}, returning either an error message (as a string) or an
/// object containing the `Uint8Array` and the next {@link ReadPosition}.
///
/// @param length - the number of bytes to read
pub fn read_bytes(length: usize) -> impl for<'a> Fn(ReadPosition<'a>) -> MaybeReadResult<'a, Vec<u8>> {
    move |position: ReadPosition<'_>| {
        let next_position = ReadPosition {
            bin: position.bin,
            index: position.index + length,
        };
        let start = position.index.min(position.bin.len());
        let result = position.bin[start..next_position.index.min(position.bin.len())].to_vec();
        if result.len() != length {
            return Err(format_error(
                ReadBytesError::insufficientLength,
                Some(&format!("Bytes requested: {length}; remaining bytes: {}", result.len())),
            ));
        }
        Ok(ReadResult {
            position: next_position,
            result,
        })
    }
}

/// Errors produced by {@link readUint32LE}.
pub struct ReadUint32LEError;

impl ReadUint32LEError {
    pub const insufficientBytes: &'static str = "Error reading Uint32LE: requires 4 bytes.";
}

/// Read a Uint32LE number from a {@link ReadPosition}, returning either an
/// error message (as a string) or an object containing the number and the
/// next {@link ReadPosition}.
pub fn read_uint32_le(position: ReadPosition<'_>) -> MaybeReadResult<'_, u32> {
    let next_position = ReadPosition {
        bin: position.bin,
        index: position.index + BYTES_PER_UINT32,
    };
    let start = position.index.min(position.bin.len());
    let uint32_le_bin = &position.bin[start..next_position.index.min(position.bin.len())];
    if uint32_le_bin.len() != BYTES_PER_UINT32 {
        return Err(format_error(
            ReadUint32LEError::insufficientBytes,
            Some(&format!("Remaining bytes: {}", uint32_le_bin.len())),
        ));
    }
    Ok(ReadResult {
        position: next_position,
        result: bin_to_number_uint32_le(uint32_le_bin),
    })
}

/// Errors produced by {@link readUint64LE}.
pub struct ReadUint64LEError;

impl ReadUint64LEError {
    pub const insufficientBytes: &'static str = "Error reading Uint64LE: requires 8 bytes.";
}

/// Read a Uint64LE number from a {@link ReadPosition}, returning either an
/// error message (as a string) or an object containing the number and the
/// next {@link ReadPosition}.
pub fn read_uint64_le(position: ReadPosition<'_>) -> MaybeReadResult<'_, u64> {
    let next_position = ReadPosition {
        bin: position.bin,
        index: position.index + BYTES_PER_UINT64,
    };
    let start = position.index.min(position.bin.len());
    let uint64_le_bin = &position.bin[start..next_position.index.min(position.bin.len())];
    if uint64_le_bin.len() != BYTES_PER_UINT64 {
        return Err(format_error(
            ReadUint64LEError::insufficientBytes,
            Some(&format!("Remaining bytes: {}", uint64_le_bin.len())),
        ));
    }
    Ok(ReadResult {
        position: next_position,
        result: bin_to_big_int_uint64_le(uint64_le_bin),
    })
}

/// Errors produced by {@link readCompactUintPrefixedBin}.
pub struct CompactUintPrefixedBinError;

impl CompactUintPrefixedBinError {
    pub const invalidCompactUint: &'static str =
        "Error reading CompactUint-prefixed bin: invalid CompactUint.";
    pub const insufficientBytes: &'static str =
        "Error reading CompactUint-prefixed bin: insufficient bytes.";
}

/// Read a bitcoin `CompactUint`-prefixed `Uint8Array` from the provided
/// {@link ReadPosition}, returning either an error message (as a string) or an
/// object containing the `Uint8Array` and the next {@link ReadPosition}.
pub fn read_compact_uint_prefixed_bin(position: ReadPosition<'_>) -> MaybeReadResult<'_, Vec<u8>> {
    let read = read_compact_uint_minimal(position)
        .map_err(|error| format_error(CompactUintPrefixedBinError::invalidCompactUint, Some(&error)))?;
    let ReadResult {
        result,
        position: p2,
    } = read;
    let length = result as usize;
    let next_index = p2.index.saturating_add(length);
    let next_position = ReadPosition {
        bin: position.bin,
        index: next_index,
    };
    let start = p2.index.min(position.bin.len());
    let contents = position.bin[start..next_index.min(position.bin.len())].to_vec();
    if contents.len() != length {
        return Err(format_error(
            CompactUintPrefixedBinError::insufficientBytes,
            Some(&format!(
                "Required bytes: {length}, remaining bytes: {}",
                contents.len()
            )),
        ));
    }
    Ok(ReadResult {
        position: next_position,
        result: contents,
    })
}

/// Read the remaining bytes from the provided {@link ReadPosition}, returning
/// an object containing the `Uint8Array` and the next {@link ReadPosition}
/// (with `index === bin.length`).
pub fn read_remaining_bytes(position: ReadPosition<'_>) -> ReadResult<'_, Vec<u8>> {
    let next_position = ReadPosition {
        bin: position.bin,
        index: position.bin.len(),
    };
    let start = position.index.min(position.bin.len());
    ReadResult {
        position: next_position,
        result: position.bin[start..].to_vec(),
    }
}
