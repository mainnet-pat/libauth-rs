//! Port of `vmb-tests/sources/core.bigint-limits.ternary.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_mixins::repeat;
use crate::vmb_tests::bch_vmb_test_mixins_bigint::ternaryOpcodes;
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
            "BigInt ternary operation limits".to_string(),
            set_expected_results(
                generate_test_cases(
                    [&format!("<{}>", repeat("$1", 625)), &format!("{} $2 $0", repeat("OP_DUP OP_CAT", 4)), "$2 $0, 10,000 bytes of $1"],
                    &[
                        ternaryOpcodes.clone(),
                        vec![
                            ("0x00".to_string(), "0x00".to_string()),
                            ("0x7f".to_string(), "0x7f".to_string()),
                            ("0x80".to_string(), "0x80".to_string()),
                            ("0xff".to_string(), "0xff".to_string()),
                        ],
                        vec![
                            ("OP_BIN2NUM OP_DUP OP_DUP".to_string(), "OP_BIN2NUM OP_DUP OP_DUP".to_string()),
                            ("OP_BIN2NUM OP_DUP OP_DUP OP_NEGATE".to_string(), "OP_BIN2NUM OP_DUP OP_DUP OP_NEGATE".to_string()),
                            ("OP_BIN2NUM OP_DUP OP_DUP OP_ABS".to_string(), "OP_BIN2NUM OP_DUP OP_DUP OP_ABS".to_string()),
                            ("OP_BIN2NUM OP_DUP OP_DUP OP_1ADD".to_string(), "OP_BIN2NUM OP_DUP OP_DUP OP_1ADD".to_string()),
                            ("OP_BIN2NUM OP_DUP OP_DUP OP_1SUB".to_string(), "OP_BIN2NUM OP_DUP OP_DUP OP_1SUB".to_string()),
                            ("OP_BIN2NUM OP_DUP <0>".to_string(), "OP_BIN2NUM OP_DUP <0>".to_string()),
                            ("OP_BIN2NUM OP_DUP <1>".to_string(), "OP_BIN2NUM OP_DUP <1>".to_string()),
                        ],
                    ],
                    None,
                    None,
                ),
                &results(&[
                    ("OP_BIN2NUM OP_DUP <0> OP_WITHIN, 10,000 bytes of 0x00", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP <0> OP_WITHIN, 10,000 bytes of 0x7f", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP <0> OP_WITHIN, 10,000 bytes of 0x80", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP <0> OP_WITHIN, 10,000 bytes of 0xff", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP <1> OP_WITHIN, 10,000 bytes of 0x00", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP <1> OP_WITHIN, 10,000 bytes of 0x7f", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP <1> OP_WITHIN, 10,000 bytes of 0x80", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP <1> OP_WITHIN, 10,000 bytes of 0xff", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1ADD OP_WITHIN, 10,000 bytes of 0x00", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1ADD OP_WITHIN, 10,000 bytes of 0x7f", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1ADD OP_WITHIN, 10,000 bytes of 0x80", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1ADD OP_WITHIN, 10,000 bytes of 0xff", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1SUB OP_WITHIN, 10,000 bytes of 0x00", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1SUB OP_WITHIN, 10,000 bytes of 0x7f", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1SUB OP_WITHIN, 10,000 bytes of 0x80", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_1SUB OP_WITHIN, 10,000 bytes of 0xff", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_ABS OP_WITHIN, 10,000 bytes of 0x00", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_ABS OP_WITHIN, 10,000 bytes of 0x7f", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_ABS OP_WITHIN, 10,000 bytes of 0x80", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_ABS OP_WITHIN, 10,000 bytes of 0xff", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_NEGATE OP_WITHIN, 10,000 bytes of 0x00", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_NEGATE OP_WITHIN, 10,000 bytes of 0x7f", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_NEGATE OP_WITHIN, 10,000 bytes of 0x80", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_NEGATE OP_WITHIN, 10,000 bytes of 0xff", &["2023_invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_WITHIN, 10,000 bytes of 0x00", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_WITHIN, 10,000 bytes of 0x7f", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_WITHIN, 10,000 bytes of 0x80", &["invalid"]),
                    ("OP_BIN2NUM OP_DUP OP_DUP OP_WITHIN, 10,000 bytes of 0xff", &["invalid"]),
                ]),
                None,
            ).expect("setExpectedResults"),
        ),
    ]
});
