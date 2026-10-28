//! Port of `vmb-tests/sources/core.bigint-limits.unary.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::repeat;
use crate::vmb_tests::bch_vmb_test_mixins_bigint::unaryOpcodes;
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, VmbTestDefinition, VmbTestDefinitionGroup, generate_test_cases,
    set_expected_results,
};

/// Build a [`VmbTestDefinition`] from the elements of libauth's
/// `VmbTestDefinition` tuple: `[unlockingScript, redeemOrLockingScript,
/// testDescription, testSetOverrideLabels?, scenario?, additionalScripts?]`.
fn definition(
    unlocking_script: &str,
    redeem_or_locking_script: &str,
    test_description: &str,
    test_set_override_labels: &[&str],
    scenario: Option<WalletTemplateScenario>,
    additional_scripts: Option<BTreeMap<String, WalletTemplateScriptDefinition>>,
) -> VmbTestDefinition {
    VmbTestDefinition {
        unlocking_script: unlocking_script.to_string(),
        redeem_or_locking_script: redeem_or_locking_script.to_string(),
        test_description: test_description.to_string(),
        test_set_override_labels: test_set_override_labels.iter().map(|label| label.to_string()).collect(),
        scenario,
        additional_scripts,
    }
}

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
            "BigInt unary operation limits".to_string(),
            [
                vec![
                    definition("<$(<0xff> <11> LIB_REPEAT)>", "<0> <9988> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT", "Maximum VM number (max op cost density)", &["2023_invalid", "p2s_ignore"], None, None),
                    definition("<$(<0xff> <35> LIB_REPEAT)>", "<0> <9964> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT OP_1SUB", "Subtract one from maximum VM number", &["2023_invalid", "p2s_ignore"], None, None),
                    definition("<$(<0xff> <35> LIB_REPEAT)>", "<0> <9964> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT OP_ABS", "OP_ABS maximum VM number", &["2023_invalid", "p2s_ignore"], None, None),
                    definition("<$(<0xff> <35> LIB_REPEAT)>", "<0> <9964> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT OP_1ADD", "Add one to maximum VM number", &["invalid", "p2s_ignore"], None, None),
                    definition("<$(<0xff> <35> LIB_REPEAT)>", "<0> <9964> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT OP_NEGATE", "Negate maximum VM number", &["2023_invalid", "p2s_ignore"], None, None),
                    definition("<$(<0xff> <59> LIB_REPEAT)>", "<0> <9940> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT OP_NEGATE OP_1ADD", "Add one to minimum VM number", &["2023_invalid", "p2s_ignore"], None, None),
                    definition("<$(<0xff> <59> LIB_REPEAT)>", "<0> <9940> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT OP_NEGATE OP_ABS", "OP_ABS minimum VM number", &["2023_invalid", "p2s_ignore"], None, None),
                    definition("<$(<0xff> <59> LIB_REPEAT)>", "<0> <9940> OP_NUM2BIN <0x8000> OP_CAT OP_1SUB OP_CAT OP_NEGATE OP_1SUB", "Subtract one from minimum VM number", &["invalid", "p2s_ignore"], None, None),
                ],
                set_expected_results(
                    generate_test_cases(
                        [&format!("<{}>", repeat("$1", 625)), &format!("{} $2$0", repeat("OP_DUP OP_CAT", 4)), "$2$0, 10,000 bytes of $1"],
                        &[
                            unaryOpcodes.clone(),
                            vec![
                                ("0x00".to_string(), "0x00".to_string()),
                                ("0x7f".to_string(), "0x7f".to_string()),
                                ("0x80".to_string(), "0x80".to_string()),
                                ("0xff".to_string(), "0xff".to_string()),
                            ],
                            vec![
                                ("".to_string(), "".to_string()),
                                ("OP_BIN2NUM ".to_string(), "OP_BIN2NUM ".to_string()),
                            ],
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("OP_0NOTEQUAL, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_0NOTEQUAL, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_0NOTEQUAL, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_0NOTEQUAL, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_1ADD, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_1ADD, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_1ADD, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_1ADD, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_1SUB, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_1SUB, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_1SUB, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_1SUB, 10,000 bytes of 0xff", &["invalid"]),
                        ("OP_ABS, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_ABS, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_ABS, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_ABS, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_0NOTEQUAL, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_BIN2NUM OP_0NOTEQUAL, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_0NOTEQUAL, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_0NOTEQUAL, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1ADD, 10,000 bytes of 0x00", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1ADD, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1ADD, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1ADD, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1SUB, 10,000 bytes of 0x00", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1SUB, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1SUB, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_1SUB, 10,000 bytes of 0xff", &["invalid"]),
                        ("OP_BIN2NUM OP_ABS, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_BIN2NUM OP_ABS, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_ABS, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_ABS, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_BIN2NUM, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_BIN2NUM OP_BIN2NUM, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_BIN2NUM, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_BIN2NUM, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_INVERT, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_BIN2NUM OP_INVERT, 10,000 bytes of 0x7f", &["2025_invalid"]),
                        ("OP_BIN2NUM OP_INVERT, 10,000 bytes of 0x80", &["2025_invalid"]),
                        ("OP_BIN2NUM OP_INVERT, 10,000 bytes of 0xff", &["invalid"]),
                        ("OP_BIN2NUM OP_NEGATE, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_BIN2NUM OP_NEGATE, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_NEGATE, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_NEGATE, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_NOT, 10,000 bytes of 0x00", &["2023_invalid"]),
                        ("OP_BIN2NUM OP_NOT, 10,000 bytes of 0x7f", &["invalid"]),
                        ("OP_BIN2NUM OP_NOT, 10,000 bytes of 0x80", &["invalid"]),
                        ("OP_BIN2NUM OP_NOT, 10,000 bytes of 0xff", &["invalid"]),
                        ("OP_BIN2NUM, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_BIN2NUM, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_BIN2NUM, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_BIN2NUM, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_INVERT, 10,000 bytes of 0x00", &["2025_invalid"]),
                        ("OP_INVERT, 10,000 bytes of 0x7f", &["2025_invalid"]),
                        ("OP_INVERT, 10,000 bytes of 0x80", &["2025_invalid"]),
                        ("OP_INVERT, 10,000 bytes of 0xff", &["invalid"]),
                        ("OP_NEGATE, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_NEGATE, 10,000 bytes of 0x7f", &["2023_invalid"]),
                        ("OP_NEGATE, 10,000 bytes of 0x80", &["2023_invalid"]),
                        ("OP_NEGATE, 10,000 bytes of 0xff", &["2023_invalid"]),
                        ("OP_NOT, 10,000 bytes of 0x00", &["invalid"]),
                        ("OP_NOT, 10,000 bytes of 0x7f", &["invalid"]),
                        ("OP_NOT, 10,000 bytes of 0x80", &["invalid"]),
                        ("OP_NOT, 10,000 bytes of 0xff", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
            ]
            .concat(),
        ),
    ]
});
