//! Port of `vmb-tests/sources/core.bigint.not.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_mixins_bigint::notTests;
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, VmbTestDefinitionGroup, map_test_cases, set_expected_results,
};

/// Build a `setExpectedResults` result dictionary (test description → test
/// set override labels).
fn results(entries: &[(&str, &[&str])]) -> ExpectedResultsDictionary {
    entries
        .iter()
        .map(|(description, labels)| {
            (description.to_string(), labels.iter().map(|label| label.to_string()).collect())
        })
        .collect()
}

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "BigInt".to_string(),
            set_expected_results(map_test_cases(["<$1>", "<$0> OP_NOT OP_EQUAL", "OP_NOT $0"], &notTests, None, Some(true), None), &results(&[
                ("OP_NOT 1-byte number (all bits set)", &[]),
                ("OP_NOT 1-byte number (alternating bits set)", &[]),
                ("OP_NOT 1-byte number (highest-bit set)", &[]),
                ("OP_NOT 1-byte number (one bit set per byte)", &["skip"]),
                ("OP_NOT 4096-byte number (all bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_NOT 4096-byte number (alternating bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_NOT 4096-byte number (highest-bit set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_NOT 4096-byte number (one bit set per byte)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_NOT 512-byte number (all bits set)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_NOT 512-byte number (alternating bits set)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_NOT 512-byte number (highest-bit set)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_NOT 512-byte number (one bit set per byte)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_NOT 64-byte number (all bits set)", &["2023_invalid"]),
                ("OP_NOT 64-byte number (alternating bits set)", &["2023_invalid"]),
                ("OP_NOT 64-byte number (highest-bit set)", &["2023_invalid"]),
                ("OP_NOT 64-byte number (one bit set per byte)", &["2023_invalid"]),
                ("OP_NOT 8-byte number (all bits set)", &[]),
                ("OP_NOT 8-byte number (alternating bits set)", &[]),
                ("OP_NOT 8-byte number (highest-bit set)", &[]),
                ("OP_NOT 8-byte number (one bit set per byte)", &[]),
                ("OP_NOT 8192-byte number (all bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_NOT 8192-byte number (alternating bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_NOT 8192-byte number (highest-bit set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_NOT 8192-byte number (one bit set per byte)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
            ]), None).expect("setExpectedResults"),
        ),
    ]
});
