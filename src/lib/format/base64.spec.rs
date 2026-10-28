//! Port of `format/base64.spec.ts`.

use libauth::{base64_to_bin, bin_to_base64, is_base64};

#[test]
fn is_base64_() {
    assert!(is_base64("YWJj"));
    assert!(is_base64("YWJjZA=="));
    assert!(!is_base64("YWJ&"));
    assert!(!is_base64("YWJ"));
    assert!(!is_base64("YW"));
    assert!(!is_base64("Y"));
}

#[test]
fn base64_to_bin_works_as_expected() {
    let abc = vec![97, 98, 99];
    let abcd = vec![97, 98, 99, 100];
    let abcde = vec![97, 98, 99, 100, 101];
    assert_eq!(base64_to_bin("YWJj"), abc);
    assert_eq!(base64_to_bin("YWJjZA=="), abcd);
    assert_eq!(base64_to_bin("YWJjZGU="), abcde);
}

#[test]
fn bin_to_base64_works_as_expected() {
    let abc = "YWJj";
    let abcd = "YWJjZA==";
    let abcde = "YWJjZGU=";
    assert_eq!(bin_to_base64(&[97, 98, 99]), abc);
    assert_eq!(bin_to_base64(&[97, 98, 99, 100]), abcd);
    assert_eq!(bin_to_base64(&[97, 98, 99, 100, 101]), abcde);
}
