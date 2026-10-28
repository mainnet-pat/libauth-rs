//! Port of `format/hex.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use libauth::{bin_to_hex, hex_to_bin, is_hex, range, split_every, swap_endianness};

#[test]
fn range_() {
    assert_eq!(range(3, None), vec![0, 1, 2]);
    assert_eq!(range(3, Some(1)), vec![1, 2, 3]);
}

#[test]
fn split_every_() {
    assert_eq!(split_every("abcd", 2), vec!["ab", "cd"]);
    assert_eq!(split_every("abcde", 2), vec!["ab", "cd", "e"]);
}

#[test]
fn is_hex_() {
    assert!(is_hex("0001022a646566ff"));
    assert!(is_hex("0001022A646566Ff"));
    assert!(is_hex("0001022A646566FF"));
    assert!(!is_hex("0001022A646566F"));
    assert!(!is_hex("0001022A646566FG"));
}

#[test]
fn hex_to_bin_() {
    assert_eq!(hex_to_bin("0001022a646566ff"), vec![0, 1, 2, 42, 100, 101, 102, 255]);
    assert_eq!(hex_to_bin("0001022A646566FF"), vec![0, 1, 2, 42, 100, 101, 102, 255]);
}

#[test]
fn bin_to_hex_() {
    assert_eq!(bin_to_hex(&[0, 1, 2, 42, 100, 101, 102, 255]), "0001022a646566ff");
}

#[test]
fn fast_check_hex_to_bin_bin_to_hex() {
    fc::test_prop(fc::uint8_array(Some(0), Some(100)), |input| {
        assert_eq!(bin_to_hex(&hex_to_bin(&bin_to_hex(input))), bin_to_hex(input));
    });
}

#[test]
fn swap_endianness_() {
    assert_eq!(swap_endianness("0001022a646566ff"), "ff6665642a020100");
}
