//! Port of `message/read-components.spec.ts`.

use libauth::{
    big_int_to_bin_uint64_le, hex_to_bin, number_to_bin_uint32_le, read_bytes, read_uint32_le,
    read_uint64_le, ReadBytesError, ReadPosition, ReadResult, ReadUint32LEError,
    ReadUint64LEError,
};

#[test]
fn read_bytes_() {
    let bin = hex_to_bin("00010203");
    assert_eq!(
        read_bytes(1)(ReadPosition { bin: &bin, index: 4 }),
        Err(format!(
            "{} Bytes requested: 1; remaining bytes: 0",
            ReadBytesError::insufficientLength
        ))
    );
    let not_mutated = ReadPosition { bin: &bin, index: 0 };
    let result = read_bytes(1)(not_mutated);
    assert_eq!(
        result,
        Ok(ReadResult {
            position: ReadPosition { bin: &bin, index: 1 },
            result: hex_to_bin("00"),
        })
    );
    assert_eq!(not_mutated, ReadPosition { bin: &bin, index: 0 });
    // The read bytes are a copy: filling them leaves `bin` untouched.
    let mut new_bin = result.unwrap().result;
    new_bin.fill(0xff);
    assert_eq!(new_bin, hex_to_bin("ff"));
    assert_eq!(not_mutated.bin, bin.as_slice());
    assert_eq!(
        read_bytes(3)(ReadPosition { bin: &bin, index: 1 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &bin, index: 4 },
            result: hex_to_bin("010203"),
        })
    );
}

#[test]
fn read_uint32_le_() {
    let mut bin = hex_to_bin("00010203");
    let num: u32 = 0x0302_0100;
    {
        let result = ReadResult {
            position: ReadPosition { bin: &bin, index: 4 },
            result: num,
        };
        assert_eq!(read_uint32_le(ReadPosition { bin: &bin, index: 0 }), Ok(result));
    }
    assert_eq!(bin, number_to_bin_uint32_le(num));
    // libauth fills `result.position.bin` (the expected value's reference to
    // `bin` itself) to show that the position shares the original
    // `Uint8Array`. A Rust `ReadPosition` only holds a shared borrow, so the
    // port fills `bin` directly once that borrow has ended.
    bin.fill(0xff);
    let mutates = hex_to_bin("ffffffff");
    assert_eq!(bin, mutates);
    assert_eq!(
        read_uint32_le(ReadPosition {
            bin: &hex_to_bin("0001"),
            index: 0
        }),
        Err(format!(
            "{} Remaining bytes: 2",
            ReadUint32LEError::insufficientBytes
        ))
    );
}

#[test]
fn read_uint64_le_() {
    let mut bin = hex_to_bin("00010203ffffffff");
    let num: u64 = 0xffff_ffff_0302_0100;
    {
        let result = ReadResult {
            position: ReadPosition { bin: &bin, index: 8 },
            result: num,
        };
        assert_eq!(read_uint64_le(ReadPosition { bin: &bin, index: 0 }), Ok(result));
    }
    assert_eq!(bin, big_int_to_bin_uint64_le(num));
    // See `read_uint32_le_`: libauth fills `bin` through the expected value's
    // `position.bin` reference.
    bin.fill(0xff);
    let mutates = hex_to_bin("ffffffffffffffff");
    assert_eq!(bin, mutates);
    assert_eq!(
        read_uint64_le(ReadPosition {
            bin: &hex_to_bin("00010203"),
            index: 0
        }),
        Err(format!(
            "{} Remaining bytes: 4",
            ReadUint64LEError::insufficientBytes
        ))
    );
}

#[test]
#[ignore = "test.todo: readCompactUintPrefixedBin"]
fn read_compact_uint_prefixed_bin() {}

#[test]
#[ignore = "test.todo: readRemainingBytes"]
fn read_remaining_bytes() {}
