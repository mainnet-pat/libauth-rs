//! Port of `format/bin-string.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use libauth::{bin_string_to_bin, bin_to_bin_string, is_bin_string};

#[test]
fn is_bin_string_() {
    assert!(!is_bin_string("0"));
    assert!(!is_bin_string("01"));
    assert!(is_bin_string("00000000"));
    assert!(!is_bin_string("0000000 "));
    assert!(is_bin_string("00000001"));
    assert!(!is_bin_string("00000002"));
    assert!(is_bin_string("0000000100000001"));
    assert!(is_bin_string("000000010000000100000001"));
}

#[test]
fn bin_string_to_bin_() {
    assert_eq!(bin_string_to_bin("0010101001100100"), vec![42, 100]);
}

#[test]
fn bin_to_bin_string_() {
    assert_eq!(bin_to_bin_string(&[42, 100]), "0010101001100100");
}

#[test]
fn fast_check_bin_string_to_bin_bin_to_bin_string() {
    fc::test_prop(fc::uint8_array(Some(0), Some(100)), |input| {
        assert_eq!(
            bin_to_bin_string(&bin_string_to_bin(&bin_to_bin_string(input))),
            bin_to_bin_string(input)
        );
    });
}
