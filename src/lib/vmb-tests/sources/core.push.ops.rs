//! Port of `vmb-tests/sources/core.push.ops.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, VmbTestDefinitionGroup, generate_test_cases, set_expected_results,
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
            "Operations which push to the stack".to_string(),
            set_expected_results(
                generate_test_cases(
                    ["<0> <$0>", "OP_NUM2BIN OP_TOALTSTACK OP_FROMALTSTACK OP_SIZE <$0> OP_EQUAL OP_NIP", "OP_TOALTSTACK/OP_FROMALTSTACK $0"],
                    &[
                        vec![
                            ("520 bytes".to_string(), "520".to_string()),
                            ("521 bytes".to_string(), "521".to_string()),
                            ("10,000 bytes".to_string(), "10_000".to_string()),
                            ("10,001 bytes".to_string(), "10_001".to_string()),
                        ],
                    ],
                    None,
                    None,
                ),
                &results(&[
                    ("OP_TOALTSTACK/OP_FROMALTSTACK 10,000 bytes", &["2023_invalid"]),
                    ("OP_TOALTSTACK/OP_FROMALTSTACK 10,001 bytes", &["invalid"]),
                    ("OP_TOALTSTACK/OP_FROMALTSTACK 520 bytes", &[]),
                    ("OP_TOALTSTACK/OP_FROMALTSTACK 521 bytes", &["2023_invalid"]),
                ]),
                None,
            ).expect("setExpectedResults"),
        ),
    ]
});
