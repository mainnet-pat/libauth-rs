//! Port of `vmb-tests/sources/core.push.data.limits.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
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
            "PUSHDATA limits".to_string(),
            [
                set_expected_results(
                    generate_test_cases(
                        ["OP_PUSHDATA_2 $0 $(<0> <$0> OP_NUM2BIN)", "OP_SIZE <$0> OP_EQUAL OP_NIP", "OP_PUSHDATA_2 $0"],
                        &[
                            vec![
                                ("520 bytes".to_string(), "520".to_string()),
                                ("521 bytes".to_string(), "521".to_string()),
                                ("1,640 bytes".to_string(), "1_640".to_string()),
                                ("1,641 bytes".to_string(), "1_641".to_string()),
                                ("9,990 bytes".to_string(), "9_990".to_string()),
                                ("9,991 bytes".to_string(), "9_991".to_string()),
                                ("9,997 bytes".to_string(), "9_997".to_string()),
                                ("9,998 bytes".to_string(), "9_998".to_string()),
                                ("10,000 bytes".to_string(), "10_000".to_string()),
                            ],
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("OP_PUSHDATA_2 1,640 bytes", &["2023_invalid"]),
                        ("OP_PUSHDATA_2 1,641 bytes", &["2023_invalid", "2025_p2sh_nonstandard"]),
                        ("OP_PUSHDATA_2 10,000 bytes", &["invalid"]),
                        ("OP_PUSHDATA_2 520 bytes", &[]),
                        ("OP_PUSHDATA_2 521 bytes", &["2023_invalid"]),
                        ("OP_PUSHDATA_2 9,990 bytes", &["2023_invalid", "2025_p2sh_nonstandard"]),
                        ("OP_PUSHDATA_2 9,991 bytes", &["p2sh_invalid", "2023_invalid"]),
                        ("OP_PUSHDATA_2 9,997 bytes", &["p2sh_invalid", "2023_invalid"]),
                        ("OP_PUSHDATA_2 9,998 bytes", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
                vec![
                    definition("OP_PUSHDATA_2 0xffff $(<0> <65535> OP_NUM2BIN)", "OP_SIZE <65535> OP_EQUAL OP_NIP", "Max OP_PUSHDATA_2 in unlocking bytecode", &["invalid", "spec_standard"], None, None),
                    definition("OP_PUSHDATA_4 0x00000100 $(<0> <65536> OP_NUM2BIN)", "OP_SIZE <65536> OP_EQUAL OP_NIP", "Min OP_PUSHDATA_4 in unlocking bytecode", &["invalid", "spec_standard"], None, None),
                ],
            ]
            .concat(),
        ),
    ]
});
