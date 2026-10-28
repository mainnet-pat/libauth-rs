//! Port of `crypto/combinations.spec.ts`.

use libauth::{hash160, hash256, hex_to_bin, utf8_to_bin};

#[test]
fn hash160_() {
    assert_eq!(
        hash160(&hex_to_bin(""), None),
        hex_to_bin("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
    );
    assert_eq!(
        hash160(&utf8_to_bin("abc"), None),
        hex_to_bin("bb1be98c142444d7a56aa3981c3942a978e4dc33")
    );
}

#[test]
fn hash256_() {
    assert_eq!(
        hash256(&hex_to_bin(""), None),
        hex_to_bin("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
    );
    assert_eq!(
        hash256(&utf8_to_bin("abc"), None),
        hex_to_bin("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
    );
}
