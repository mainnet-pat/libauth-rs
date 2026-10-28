//! Port of `format/number.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use std::panic::{catch_unwind, UnwindSafe};

use libauth::runtime::bigint::BigInt;
use libauth::{
    big_int_to_bin_uint256_be_clamped, big_int_to_bin_uint64_le, big_int_to_bin_uint64_le_clamped,
    big_int_to_bin_uint_be, big_int_to_bin_uint_le, big_int_to_compact_uint, bin_to_big_int_uint256_be,
    bin_to_big_int_uint64_le, bin_to_big_int_uint_be, bin_to_big_int_uint_le, bin_to_hex,
    bin_to_number_int16_le, bin_to_number_int32_le, bin_to_number_uint16_le, bin_to_number_uint32_le,
    bin_to_number_uint_le, bin_to_value_satoshis, compact_uint_prefix_to_length, compact_uint_to_big_int,
    hex_to_bin, int32_signed_to_unsigned, int32_unsigned_to_signed, number_to_bin_int16_le,
    number_to_bin_int32_le, number_to_bin_int32_twos_compliment, number_to_bin_uint16_be,
    number_to_bin_uint16_le, number_to_bin_uint16_le_clamped, number_to_bin_uint32_be,
    number_to_bin_uint32_le, number_to_bin_uint32_le_clamped, number_to_bin_uint_le, read_compact_uint,
    read_compact_uint_minimal, value_satoshis_to_bin, CompactUintError, ReadPosition, ReadResult,
};

/// `Number.MAX_SAFE_INTEGER`
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// `t.throws(fn)`: whether `function` panics.
fn throws(function: impl FnOnce() + UnwindSafe) -> bool {
    catch_unwind(function).is_err()
}

/// A `bigint` literal.
fn big(text: &str) -> BigInt {
    BigInt::parse(text).expect("a valid bigint literal")
}

#[test]
fn number_to_bin_uint16_le_() {
    assert_eq!(number_to_bin_uint16_le(0), vec![0, 0]);
    assert_eq!(number_to_bin_uint16_le(1), vec![1, 0]);
    assert_eq!(number_to_bin_uint16_le(0x1234), vec![0x34, 0x12]);
}

#[test]
fn number_to_bin_uint16_be_() {
    assert_eq!(number_to_bin_uint16_be(0), vec![0, 0]);
    assert_eq!(number_to_bin_uint16_be(1), vec![0, 1]);
    assert_eq!(number_to_bin_uint16_be(0x1234), vec![0x12, 0x34]);
}

#[test]
fn number_to_bin_uint16_le_vs_number_to_bin_uint16_le_clamped_behavior_on_overflow() {
    assert_eq!(number_to_bin_uint16_le(0x01_0000), number_to_bin_uint16_le(0x01_0000 % (0xffff + 1)));
    assert_eq!(number_to_bin_uint16_le_clamped(0x01_0000), vec![0xff, 0xff]);
}

#[test]
fn number_to_bin_uint16_le_vs_number_to_bin_uint16_le_clamped_behavior_on_negative_numbers() {
    assert_eq!(number_to_bin_uint16_le(-2), number_to_bin_uint16_le(0xffff - 1));
    assert_eq!(number_to_bin_uint16_le_clamped(-2), vec![0, 0]);
}

#[test]
fn number_to_bin_uint32_le_() {
    assert_eq!(number_to_bin_uint32_le(0), vec![0, 0, 0, 0]);
    assert_eq!(number_to_bin_uint32_le(1), vec![1, 0, 0, 0]);
    assert_eq!(number_to_bin_uint32_le(0x1234), vec![0x34, 0x12, 0, 0]);
    assert_eq!(number_to_bin_uint32_le(0x12345678), vec![0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn number_to_bin_uint32_be_() {
    assert_eq!(number_to_bin_uint32_be(0), vec![0, 0, 0, 0]);
    assert_eq!(number_to_bin_uint32_be(1), vec![0, 0, 0, 1]);
    assert_eq!(number_to_bin_uint32_be(0x1234), vec![0, 0, 0x12, 0x34]);
    assert_eq!(number_to_bin_uint32_be(0x12345678), vec![0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn number_to_bin_uint32_le_vs_number_to_bin_uint32_le_clamped_behavior_on_overflow() {
    assert_eq!(
        number_to_bin_uint32_le(0x01_0000_0000_i64),
        number_to_bin_uint32_le(0x01_0000_0000_i64 % (0xffff_ffff + 1))
    );
    assert_eq!(number_to_bin_uint32_le_clamped(0x01_0000_0000_i64), vec![0xff, 0xff, 0xff, 0xff]);
}

#[test]
fn number_to_bin_uint32_le_behavior_on_negative_numbers() {
    assert_eq!(number_to_bin_uint32_le(-2), number_to_bin_uint32_le(0xffff_ffff_i64 - 1));
    assert_eq!(number_to_bin_uint32_le_clamped(-2), vec![0, 0, 0, 0]);
}

#[test]
fn number_to_bin_uint_le_() {
    assert_eq!(number_to_bin_uint_le(MAX_SAFE_INTEGER as i64), vec![255, 255, 255, 255, 255, 255, 31]);
}

#[test]
fn number_to_bin_int16_le_() {
    assert_eq!(number_to_bin_int16_le(0), vec![0, 0]);
    assert_eq!(number_to_bin_int16_le(1), vec![1, 0]);
    assert_eq!(number_to_bin_int16_le(0x1234), vec![0x34, 0x12]);
    assert_eq!(number_to_bin_int16_le(-0x1234), vec![0xcc, 0xed]);
}

#[test]
fn number_to_bin_int32_le_() {
    assert_eq!(number_to_bin_int32_le(0), vec![0, 0, 0, 0]);
    assert_eq!(number_to_bin_int32_le(1), vec![1, 0, 0, 0]);
    assert_eq!(number_to_bin_int32_le(0x1234), vec![0x34, 0x12, 0, 0]);
    assert_eq!(number_to_bin_int32_le(-0x1234), vec![0xcc, 0xed, 0xff, 0xff]);
    assert_eq!(number_to_bin_uint32_le(0x12345678), vec![0x78, 0x56, 0x34, 0x12]);
    assert_eq!(number_to_bin_int32_le(-0x12345678), vec![0x88, 0xa9, 0xcb, 0xed]);
}

#[test]
fn number_to_bin_int32_twos_compliment_() {
    assert_eq!(number_to_bin_int32_twos_compliment(0), vec![0, 0, 0, 0]);
    assert_eq!(number_to_bin_int32_twos_compliment(1), vec![1, 0, 0, 0]);
    assert_eq!(number_to_bin_int32_twos_compliment(-0xffffffff), vec![1, 0, 0, 0]);
    assert_eq!(number_to_bin_int32_twos_compliment(0xffffffff), vec![255, 255, 255, 255]);
    assert_eq!(number_to_bin_int32_twos_compliment(-1), vec![255, 255, 255, 255]);
    assert_eq!(number_to_bin_int32_twos_compliment(0xffff), vec![255, 255, 0, 0]);
    assert_eq!(number_to_bin_int32_twos_compliment(-0xffff), vec![1, 0, 255, 255]);
    assert_eq!(number_to_bin_int32_twos_compliment(1234567890), vec![210, 2, 150, 73]);
    assert_eq!(number_to_bin_int32_twos_compliment(-1234567890), vec![46, 253, 105, 182]);
}

#[test]
fn big_int_to_bin_uint64_le_() {
    assert_eq!(big_int_to_bin_uint64_le(0), vec![0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(big_int_to_bin_uint64_le(0x01), vec![0x01, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(big_int_to_bin_uint64_le(0x12345678), vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
    assert_eq!(
        big_int_to_bin_uint64_le(MAX_SAFE_INTEGER),
        vec![255, 255, 255, 255, 255, 255, 31, 0]
    );
    assert_eq!(
        big_int_to_bin_uint64_le(0xffffffffffffffff_u64),
        vec![255, 255, 255, 255, 255, 255, 255, 255]
    );
}

#[test]
fn value_satoshis_to_bin_() {
    assert_eq!(value_satoshis_to_bin(0), vec![0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(value_satoshis_to_bin(0x01), vec![0x01, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(value_satoshis_to_bin(0x12345678), vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
    assert_eq!(
        value_satoshis_to_bin(MAX_SAFE_INTEGER),
        vec![255, 255, 255, 255, 255, 255, 31, 0]
    );
    assert_eq!(
        value_satoshis_to_bin(0xffffffffffffffff),
        vec![255, 255, 255, 255, 255, 255, 255, 255]
    );
}

#[test]
fn big_int_to_bin_uint64_le_vs_big_int_to_bin_uint64_le_clamped_behavior_on_overflow() {
    assert_eq!(
        big_int_to_bin_uint64_le(0x01_0000_0000_0000_0000_i128),
        big_int_to_bin_uint64_le(0x01_0000_0000_0000_0000_i128 % (0xffff_ffff_ffff_ffff_i128 + 1))
    );
    assert_eq!(
        big_int_to_bin_uint64_le_clamped(&big("0x010000000000000000")),
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn big_int_to_bin_uint64_le_vs_big_int_to_bin_uint64_le_clamped_behavior_on_negative_numbers() {
    assert_eq!(big_int_to_bin_uint64_le(-1), vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(big_int_to_bin_uint64_le_clamped(&big("-1")), vec![0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn big_int_to_compact_uint_larger_values_return_modulo_result_after_opcode() {
    assert_eq!(
        big_int_to_compact_uint(0x01_0000_0000_0000_0001_i128),
        vec![0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}

#[test]
fn bin_to_number_uint_le_() {
    assert_eq!(bin_to_number_uint_le(&[0x12], None), 0x12);
    assert_eq!(bin_to_number_uint_le(&[0x34, 0x12], None), 0x1234);
    assert_eq!(bin_to_number_uint_le(&[0x78, 0x56, 0x34, 0x12], None), 0x12345678);
    assert_eq!(bin_to_number_uint_le(&[0x90, 0x78, 0x56, 0x34, 0x12], None), 0x1234567890);
    assert_eq!(
        bin_to_number_uint_le(&[255, 255, 255, 255, 255, 255, 31], None),
        MAX_SAFE_INTEGER
    );
    assert_eq!(bin_to_number_uint_le(&[0x56, 0x34, 0x12], None), 0x123456);
    let data = [0x90, 0x78, 0x56, 0x34, 0x12];
    let view = &data[2..];
    assert_eq!(bin_to_number_uint_le(view, None), 0x123456);
    assert!(throws(|| {
        bin_to_number_uint_le(&[0x12], Some(2));
    }));
}

#[test]
fn fast_check_number_to_bin_uint_le_bin_to_number_uint_le() {
    fc::test_prop(fc::integer(Some(0), Some(MAX_SAFE_INTEGER as i64)), |max_safe_int| {
        let max_safe_int = *max_safe_int as u64;
        assert_eq!(bin_to_number_uint_le(&number_to_bin_uint_le(max_safe_int as i64), None), max_safe_int);
    });
}

#[test]
fn bin_to_number_uint16_le_() {
    assert_eq!(bin_to_number_uint16_le(&[0x34, 0x12]), 0x1234);
    let data = [0x90, 0x78, 0x56, 0x34, 0x12, 0x00];
    let view = &data[2..4];
    assert_eq!(bin_to_number_uint16_le(view), 0x3456);
}

#[test]
fn bin_to_number_int16_le_() {
    assert_eq!(bin_to_number_int16_le(&[0x34, 0x12]), 0x1234);
    assert_eq!(bin_to_number_int16_le(&[0xcc, 0xed]), -0x1234);
}

#[test]
fn bin_to_number_int32_le_() {
    assert_eq!(bin_to_number_int32_le(&[0x78, 0x56, 0x34, 0x12]), 0x12345678);

    assert_eq!(bin_to_number_int32_le(&[0x88, 0xa9, 0xcb, 0xed]), -0x12345678);
}

#[test]
fn bin_to_number_uint16_le_ignores_bytes_after_the_2nd() {
    assert_eq!(bin_to_number_uint16_le(&[0x78, 0x56, 0x34, 0x12, 0xff]), 0x5678);
}

#[test]
fn bin_to_number_uint32_le_() {
    assert_eq!(bin_to_number_uint32_le(&[0x78, 0x56, 0x34, 0x12]), 0x12345678);
    let data = [0x90, 0x78, 0x56, 0x34, 0x12, 0x00];
    let view = &data[2..];
    assert_eq!(bin_to_number_uint32_le(view), 0x123456);
}

#[test]
fn bin_to_number_uint32_le_ignores_bytes_after_the_4th() {
    assert_eq!(bin_to_number_uint32_le(&[0x78, 0x56, 0x34, 0x12, 0xff]), 0x12345678);
}

#[test]
fn bin_to_big_int_uint_be_() {
    assert_eq!(bin_to_big_int_uint_be(&[0x12], None), big("0x12"));
    assert_eq!(bin_to_big_int_uint_be(&[0x12, 0x34], None), big("0x1234"));
    assert_eq!(bin_to_big_int_uint_be(&[0x12, 0x34, 0x56], None), big("0x123456"));
    assert_eq!(bin_to_big_int_uint_be(&[0x12, 0x34, 0x56, 0x78], None), big("0x12345678"));
    assert_eq!(
        bin_to_big_int_uint_be(&[0x12, 0x34, 0x56, 0x78, 0x90], None),
        big("0x1234567890")
    );
    assert_eq!(
        bin_to_big_int_uint_be(&[0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef], None),
        big("0x1234567890abcdef")
    );
    assert_eq!(
        bin_to_big_int_uint_be(&[0x56, 0x78, 0x90, 0xab, 0xcd, 0xef], None),
        big("0x567890abcdef")
    );
    let d = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
    let view = &d[2..];
    assert_eq!(bin_to_big_int_uint_be(view, None), big("0x567890abcdef"));
    assert!(throws(|| {
        bin_to_big_int_uint_be(&[0x12], Some(2));
    }));
}

#[test]
fn big_int_to_bin_uint_be_() {
    assert_eq!(big_int_to_bin_uint_be(&big("-1")), vec![0]);
    assert_eq!(big_int_to_bin_uint_be(&big("0")), vec![0]);
    assert_eq!(big_int_to_bin_uint_be(&big("0x12")), vec![0x12]);
    assert_eq!(big_int_to_bin_uint_be(&big("0x1234")), vec![0x12, 0x34]);
    assert_eq!(big_int_to_bin_uint_be(&big("0x123456")), vec![0x12, 0x34, 0x56]);
    assert_eq!(big_int_to_bin_uint_be(&big("0x12345678")), vec![0x12, 0x34, 0x56, 0x78]);
    assert_eq!(
        big_int_to_bin_uint_be(&big("0x1234567890")),
        vec![0x12, 0x34, 0x56, 0x78, 0x90]
    );
    assert_eq!(
        big_int_to_bin_uint_be(&big("0x1234567890abcdef")),
        vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
    );
    assert_eq!(
        big_int_to_bin_uint_be(&big("0x567890abcdef")),
        vec![0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
    );
}

#[test]
fn bin_to_big_int_uint256_be_and_big_int_to_bin_uint256_be_clamped() {
    assert_eq!(bin_to_big_int_uint256_be(&[0; 32]), big("0"));
    assert_eq!(big_int_to_bin_uint256_be_clamped(&big("0")), vec![0; 32]);
    assert_eq!(big_int_to_bin_uint256_be_clamped(&big("-1")), vec![0; 32]);
    let secp256k1_order_n_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    let secp256k1_order_n_bin = hex_to_bin(secp256k1_order_n_hex);
    let secp256k1_order_n = big(&format!("0x{secp256k1_order_n_hex}"));
    assert_eq!(bin_to_big_int_uint256_be(&secp256k1_order_n_bin), secp256k1_order_n);
    assert_eq!(big_int_to_bin_uint256_be_clamped(&secp256k1_order_n), secp256k1_order_n_bin);
    let max = vec![255; 32];
    let mut over_max = vec![0; 33];

    over_max[0] = 255;
    assert_eq!(
        big_int_to_bin_uint256_be_clamped(&big(&format!("0x{}", bin_to_hex(&over_max)))),
        max
    );
}

#[test]
fn fast_check_bin_to_big_int_uint256_be_big_int_to_bin_uint256_be_clamped() {
    fc::test_prop(fc::big_uint_n(256), |uint256| {
        assert_eq!(
            bin_to_big_int_uint256_be(&big_int_to_bin_uint256_be_clamped(uint256)),
            *uint256
        );
    });
}

#[test]
fn bin_to_big_int_uint_le_() {
    assert_eq!(bin_to_big_int_uint_le(&[0x12], None), big("0x12"));
    assert_eq!(bin_to_big_int_uint_le(&[0x34, 0x12], None), big("0x1234"));
    assert_eq!(bin_to_big_int_uint_le(&[0x56, 0x34, 0x12], None), big("0x123456"));
    assert_eq!(bin_to_big_int_uint_le(&[0x78, 0x56, 0x34, 0x12], None), big("0x12345678"));
    assert_eq!(
        bin_to_big_int_uint_le(&[0x90, 0x78, 0x56, 0x34, 0x12], None),
        big("0x1234567890")
    );
    assert_eq!(
        bin_to_big_int_uint_le(&[0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12], None),
        big("0x1234567890abcdef")
    );
    assert_eq!(
        bin_to_big_int_uint_le(&[0xab, 0x90, 0x78, 0x56, 0x34, 0x12], None),
        big("0x1234567890ab")
    );
    let d = [0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12];
    let view = &d[2..];
    assert_eq!(bin_to_big_int_uint_le(view, None), big("0x1234567890ab"));
    assert!(throws(|| {
        bin_to_big_int_uint_le(&[0x12], Some(2));
    }));
}

#[test]
fn fast_check_big_int_to_bin_uint_le_bin_to_big_int_uint_be_reverse() {
    fc::test_prop(fc::big_uint_n(256), |uint256| {
        let bin = big_int_to_bin_uint_le(uint256);
        let mut bin_reverse = bin.clone();
        bin_reverse.reverse();
        assert_eq!(
            bin_to_big_int_uint_be(&bin_reverse, None),
            bin_to_big_int_uint_le(&bin, None)
        );
    });
}

#[test]
fn fast_check_big_int_to_bin_uint_le_bin_to_big_int_uint_le() {
    fc::test_prop(fc::big_uint_n(65), |uint65| {
        assert_eq!(bin_to_big_int_uint_le(&big_int_to_bin_uint_le(uint65), None), *uint65);
    });
}

#[test]
fn bin_to_big_int_uint64_le_() {
    assert_eq!(bin_to_big_int_uint64_le(&[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]), 0x12345678);
    assert_eq!(
        bin_to_big_int_uint64_le(&[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]),
        0x0123456789abcdef
    );
    assert_eq!(
        bin_to_big_int_uint64_le(&[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00]),
        0x0123456789abcdef
    );
    let data = [0x90, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0];
    let view = &data[2..];
    assert_eq!(bin_to_big_int_uint64_le(view), 0x123456);
    assert!(throws(|| {
        bin_to_big_int_uint64_le(&[0x78, 0x56, 0x34, 0x12]);
    }));
}

#[test]
fn bin_to_value_satoshis_() {
    assert_eq!(bin_to_value_satoshis(&[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]), 0x12345678);
    assert_eq!(
        bin_to_value_satoshis(&[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]),
        0x0123456789abcdef
    );
    assert_eq!(
        bin_to_value_satoshis(&[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00]),
        0x0123456789abcdef
    );
    let data = [0x90, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0];
    let view = &data[2..];
    assert_eq!(bin_to_value_satoshis(view), 0x123456);
    assert!(throws(|| {
        bin_to_value_satoshis(&[0x78, 0x56, 0x34, 0x12]);
    }));
}

#[test]
fn compact_uint_prefix_to_length_() {
    assert_eq!(compact_uint_prefix_to_length(0), 1);
    assert_eq!(compact_uint_prefix_to_length(252), 1);
    assert_eq!(compact_uint_prefix_to_length(253), 3);
    assert_eq!(compact_uint_prefix_to_length(254), 5);
    assert_eq!(compact_uint_prefix_to_length(255), 9);
}

#[test]
fn read_compact_uint_() {
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &[252], index: 0 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &[252], index: 1 },
            result: 252,
        })
    );
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &[0], index: 0 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &[0], index: 1 },
            result: 0,
        })
    );
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &[253, 0, 0], index: 0 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &[253, 0, 0], index: 3 },
            result: 0,
        })
    );
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &[254, 0, 0, 0, 0], index: 0 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &[254, 0, 0, 0, 0], index: 5 },
            result: 0,
        })
    );
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &[255, 0, 0, 0, 0, 0, 0, 0, 0], index: 0 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &[255, 0, 0, 0, 0, 0, 0, 0, 0], index: 9 },
            result: 0,
        })
    );
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &[253, 253, 0], index: 0 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &[253, 253, 0], index: 3 },
            result: 253,
        })
    );
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &[], index: 0 }),
        Err(CompactUintError::noPrefix.to_string())
    );
}

#[test]
fn read_compact_uint_minimal_() {
    assert_eq!(
        read_compact_uint_minimal(ReadPosition { bin: &[1], index: 0 }),
        Ok(ReadResult {
            position: ReadPosition { bin: &[1], index: 1 },
            result: 1,
        })
    );
    assert_eq!(
        read_compact_uint_minimal(ReadPosition { bin: &[253, 1, 0], index: 0 }),
        Err(format!(
            "{} Value: 1, encoded length: 3, canonical length: 1",
            CompactUintError::nonMinimal
        ))
    );
}

#[test]
fn compact_uint_to_big_int_() {
    assert_eq!(compact_uint_to_big_int(&[252]), Ok(252));
    assert_eq!(compact_uint_to_big_int(&[253, 253, 0]), Ok(253));
    assert_eq!(
        compact_uint_to_big_int(&[253]),
        Err("Error reading CompactUint: insufficient bytes. CompactUint prefix 253 requires at least 3 bytes. Remaining bytes: 1".to_string())
    );
    assert_eq!(
        compact_uint_to_big_int(&[253, 0, 254, 0]),
        Err("Error decoding CompactUint: unexpected bytes after CompactUint. CompactUint ends at index 3, but input includes 4 bytes.".to_string())
    );
}

/// The `compactUintVector` macro.
fn compact_uint_vector(hex: &str, value: u64, next_index: usize, start: Option<usize>, expected: Option<&str>) {
    let start = start.unwrap_or(0);
    let expected = expected.unwrap_or(hex);
    assert_eq!(
        read_compact_uint(ReadPosition { bin: &hex_to_bin(hex), index: start }),
        Ok(ReadResult {
            position: ReadPosition { bin: &hex_to_bin(hex), index: next_index },
            result: value,
        })
    );
    assert_eq!(big_int_to_compact_uint(value), hex_to_bin(expected));
}

/* spell-checker: disable */
#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_00() {
    compact_uint_vector("00", 0x0, 1, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_01() {
    compact_uint_vector("01", 0x1, 1, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_12() {
    compact_uint_vector("12", 0x12, 1, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_6a() {
    compact_uint_vector("6a", 0x6a, 1, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_00006a() {
    compact_uint_vector("00006a", 0x6a, 3, Some(2), Some("6a"));
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fc() {
    compact_uint_vector("fc", 0xfc, 1, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fdfd00() {
    compact_uint_vector("fdfd00", 0xfd, 3, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_000000fdfd00() {
    compact_uint_vector("000000fdfd00", 0xfd, 6, Some(3), Some("fdfd00"));
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fdfe00() {
    compact_uint_vector("fdfe00", 0xfe, 3, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fdff00() {
    compact_uint_vector("fdff00", 0xff, 3, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fd1111() {
    compact_uint_vector("fd1111", 0x1111, 3, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fd1234() {
    compact_uint_vector("fd1234", 0x3412, 3, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fdfeff() {
    compact_uint_vector("fdfeff", 0xfffe, 3, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fdffff() {
    compact_uint_vector("fdffff", 0xffff, 3, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fe00000100() {
    compact_uint_vector("fe00000100", 0x10000, 5, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_00fe00000100() {
    compact_uint_vector("00fe00000100", 0x10000, 6, Some(1), Some("fe00000100"));
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fe01000100() {
    compact_uint_vector("fe01000100", 0x10001, 5, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fe11111111() {
    compact_uint_vector("fe11111111", 0x11111111, 5, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_fe12345678() {
    compact_uint_vector("fe12345678", 0x78563412, 5, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_feffffffff() {
    compact_uint_vector("feffffffff", 0xffffffff, 5, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_ff0000000001000000() {
    compact_uint_vector("ff0000000001000000", 0x100000000, 9, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_0000ff0000000001000000() {
    compact_uint_vector("0000ff0000000001000000", 0x100000000, 11, Some(2), Some("ff0000000001000000"));
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_ff0100000001000000() {
    compact_uint_vector("ff0100000001000000", 0x100000001, 9, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_ff1111111111111111() {
    compact_uint_vector("ff1111111111111111", 0x1111111111111111, 9, None, None);
}

#[test]
fn compact_uint_to_big_int_big_int_to_compact_uint_ff1234567890abcdef() {
    compact_uint_vector("ff1234567890abcdef", 0xefcdab9078563412, 9, None, None);
}
/* spell-checker: enable */

#[test]
fn fast_check_big_int_to_compact_uint_compact_uint_to_big_int() {
    fc::test_prop(fc::big_uint_n(64), |uint64| {
        let uint64 = uint64.to_u64().expect("a 64-bit value");
        let compact_uint = big_int_to_compact_uint(uint64);
        let result = compact_uint_to_big_int(&compact_uint);
        assert_eq!(result, Ok(uint64));
    });
}

#[test]
fn int32_signed_to_unsigned_int32_unsigned_to_signed() {
    assert_eq!(int32_signed_to_unsigned(1), 1);
    assert_eq!(int32_signed_to_unsigned(-1), 4294967295);
    assert_eq!(int32_signed_to_unsigned(-2), 4294967294);
    assert_eq!(int32_unsigned_to_signed(4294967294), -2);
    assert_eq!(int32_unsigned_to_signed(4294967295), -1);
    assert_eq!(int32_unsigned_to_signed(1), 1);
}

#[test]
fn fast_check_int32_unsigned_to_signed_int32_signed_to_unsigned() {
    fc::test_prop(fc::integer(Some(0), Some(2_i64.pow(32) - 1)), |uint32| {
        let uint32 = *uint32 as u32;
        let signed = int32_unsigned_to_signed(uint32);
        let unsigned = int32_signed_to_unsigned(signed);
        assert_eq!(unsigned, uint32);
    });
}
