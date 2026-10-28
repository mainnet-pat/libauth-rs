//! Port of `vmb-tests/sources/core.bigint.0notequal.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_mixins_bigint::zeroNotEqualTests;
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
            set_expected_results(map_test_cases(["<$1>", "<$0> OP_0NOTEQUAL OP_EQUAL", "OP_0NOTEQUAL $0"], &zeroNotEqualTests, None, Some(true), None), &results(&[
                ("OP_0NOTEQUAL 1-byte number (all bits set)", &[]),
                ("OP_0NOTEQUAL 1-byte number (alternating bits set)", &[]),
                ("OP_0NOTEQUAL 1-byte number (highest-bit set)", &[]),
                ("OP_0NOTEQUAL 1-byte number (one bit set per byte)", &["skip"]),
                ("OP_0NOTEQUAL 4096-byte number (all bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_0NOTEQUAL 4096-byte number (alternating bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_0NOTEQUAL 4096-byte number (highest-bit set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_0NOTEQUAL 4096-byte number (one bit set per byte)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_0NOTEQUAL 512-byte number (all bits set)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_0NOTEQUAL 512-byte number (alternating bits set)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_0NOTEQUAL 512-byte number (highest-bit set)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_0NOTEQUAL 512-byte number (one bit set per byte)", &["p2s_nonstandard", "2023_invalid"]),
                ("OP_0NOTEQUAL 64-byte number (all bits set)", &["2023_invalid"]),
                ("OP_0NOTEQUAL 64-byte number (alternating bits set)", &["2023_invalid"]),
                ("OP_0NOTEQUAL 64-byte number (highest-bit set)", &["2023_invalid"]),
                ("OP_0NOTEQUAL 64-byte number (one bit set per byte)", &["2023_invalid"]),
                ("OP_0NOTEQUAL 8-byte number (all bits set)", &[]),
                ("OP_0NOTEQUAL 8-byte number (alternating bits set)", &[]),
                ("OP_0NOTEQUAL 8-byte number (highest-bit set)", &[]),
                ("OP_0NOTEQUAL 8-byte number (one bit set per byte)", &[]),
                ("OP_0NOTEQUAL 8192-byte number (all bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_0NOTEQUAL 8192-byte number (alternating bits set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_0NOTEQUAL 8192-byte number (highest-bit set)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
                ("OP_0NOTEQUAL 8192-byte number (one bit set per byte)", &["p2s_nonstandard", "2023_invalid", "2025_p2sh_nonstandard"]),
            ]), None).expect("setExpectedResults"),
        ),
    ]
});
