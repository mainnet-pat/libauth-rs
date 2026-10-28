//! Port of `vmb-tests/sources/core.push.numbers.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::format::range;
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, PossibleTestValue, VmbTestDefinition, VmbTestDefinitionGroup,
    generate_test_cases, set_expected_results,
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
            "Push number operations (OP_1NEGATE-OP_16)".to_string(),
            [
                vec![
                    definition("OP_1NEGATE", "<-1 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL", "Unlocking bytecode OP_1NEGATE pushes 0x81", &[], None, None),
                    definition("OP_0", "<0x00> OP_CAT <0x00> OP_EQUAL", "Unlocking bytecode OP_0 pushes an empty stack item", &[], None, None),
                ],
                set_expected_results(generate_test_cases(["OP_$0", "<$0 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL", "Unlocking bytecode OP_$0 pushes $0"], &[range(16, Some(1)).into_iter().map(|i| (format!("{}", i), format!("{}", i))).collect::<Vec<PossibleTestValue>>()], None, None), &results(&[
                    ("Unlocking bytecode OP_1 pushes 1", &[]),
                    ("Unlocking bytecode OP_10 pushes 10", &[]),
                    ("Unlocking bytecode OP_11 pushes 11", &[]),
                    ("Unlocking bytecode OP_12 pushes 12", &[]),
                    ("Unlocking bytecode OP_13 pushes 13", &[]),
                    ("Unlocking bytecode OP_14 pushes 14", &[]),
                    ("Unlocking bytecode OP_15 pushes 15", &[]),
                    ("Unlocking bytecode OP_16 pushes 16", &[]),
                    ("Unlocking bytecode OP_2 pushes 2", &[]),
                    ("Unlocking bytecode OP_3 pushes 3", &[]),
                    ("Unlocking bytecode OP_4 pushes 4", &[]),
                    ("Unlocking bytecode OP_5 pushes 5", &[]),
                    ("Unlocking bytecode OP_6 pushes 6", &[]),
                    ("Unlocking bytecode OP_7 pushes 7", &[]),
                    ("Unlocking bytecode OP_8 pushes 8", &[]),
                    ("Unlocking bytecode OP_9 pushes 9", &[]),
                ]), None).expect("setExpectedResults"),
                vec![
                    definition("", "OP_1NEGATE <-1 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL", "Locking bytecode OP_1NEGATE pushes 0x81", &[], None, None),
                    definition("", "OP_0 <0x00> OP_CAT <0x00> OP_EQUAL", "Locking bytecode OP_0 pushes an empty stack item", &[], None, None),
                ],
                set_expected_results(generate_test_cases(["", "OP_$0 <$0 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL", "Locking bytecode OP_$0 pushes $0"], &[range(16, Some(1)).into_iter().map(|i| (format!("{}", i), format!("{}", i))).collect::<Vec<PossibleTestValue>>()], None, None), &results(&[
                    ("Locking bytecode OP_1 pushes 1", &[]),
                    ("Locking bytecode OP_10 pushes 10", &[]),
                    ("Locking bytecode OP_11 pushes 11", &[]),
                    ("Locking bytecode OP_12 pushes 12", &[]),
                    ("Locking bytecode OP_13 pushes 13", &[]),
                    ("Locking bytecode OP_14 pushes 14", &[]),
                    ("Locking bytecode OP_15 pushes 15", &[]),
                    ("Locking bytecode OP_16 pushes 16", &[]),
                    ("Locking bytecode OP_2 pushes 2", &[]),
                    ("Locking bytecode OP_3 pushes 3", &[]),
                    ("Locking bytecode OP_4 pushes 4", &[]),
                    ("Locking bytecode OP_5 pushes 5", &[]),
                    ("Locking bytecode OP_6 pushes 6", &[]),
                    ("Locking bytecode OP_7 pushes 7", &[]),
                    ("Locking bytecode OP_8 pushes 8", &[]),
                    ("Locking bytecode OP_9 pushes 9", &[]),
                ]), None).expect("setExpectedResults"),
                vec![
                    definition("<0> OP_IF OP_1NEGATE OP_ENDIF", "", "<0> OP_IF OP_1NEGATE OP_ENDIF in unlocking bytecode", &["invalid"], None, None),
                    definition("<1> OP_IF OP_1NEGATE OP_ENDIF", "", "<1> OP_IF OP_1NEGATE OP_ENDIF in unlocking bytecode", &["invalid"], None, None),
                    definition("<0> OP_IF OP_0 OP_ENDIF OP_NOT", "", "<0> OP_IF OP_1NEGATE OP_ENDIF OP_NOT in unlocking bytecode", &["invalid"], None, None),
                    definition("<1> OP_IF OP_0 OP_ENDIF OP_NOT", "", "<1> OP_IF OP_1NEGATE OP_ENDIF OP_NOT in unlocking bytecode", &["invalid"], None, None),
                    definition("", "<0> OP_IF OP_1NEGATE OP_ENDIF", "<0> OP_IF OP_1NEGATE OP_ENDIF in locking bytecode", &["invalid"], None, None),
                    definition("", "<1> OP_IF OP_1NEGATE OP_ENDIF", "<1> OP_IF OP_1NEGATE OP_ENDIF in locking bytecode", &[], None, None),
                    definition("", "<0> OP_IF OP_0 OP_ENDIF OP_NOT", "<0> OP_IF OP_1NEGATE OP_ENDIF OP_NOT in locking bytecode", &["invalid"], None, None),
                    definition("", "<1> OP_IF OP_0 OP_ENDIF OP_NOT", "<1> OP_IF OP_1NEGATE OP_ENDIF OP_NOT in locking bytecode", &[], None, None),
                ],
                set_expected_results(
                    generate_test_cases(
                        ["<$1> OP_IF OP_$0 OP_ENDIF", "", "<$1> OP_IF OP_$0 OP_ENDIF in unlocking bytecode"],
                        &[
                            range(16, Some(1)).into_iter().map(|i| (format!("{}", i), format!("{}", i))).collect::<Vec<PossibleTestValue>>(),
                            vec![
                                ("0".to_string(), "0".to_string()),
                                ("1".to_string(), "1".to_string()),
                            ],
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("<0> OP_IF OP_1 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_10 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_11 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_12 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_13 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_14 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_15 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_16 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_2 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_3 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_4 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_5 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_6 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_7 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_8 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_9 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_1 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_10 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_11 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_12 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_13 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_14 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_15 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_16 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_2 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_3 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_4 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_5 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_6 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_7 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_8 OP_ENDIF in unlocking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_9 OP_ENDIF in unlocking bytecode", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
                set_expected_results(
                    generate_test_cases(
                        ["", "<$1> OP_IF OP_$0 OP_ENDIF", "<$1> OP_IF OP_$0 OP_ENDIF in locking bytecode"],
                        &[
                            range(16, Some(1)).into_iter().map(|i| (format!("{}", i), format!("{}", i))).collect::<Vec<PossibleTestValue>>(),
                            vec![
                                ("0".to_string(), "0".to_string()),
                                ("1".to_string(), "1".to_string()),
                            ],
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("<0> OP_IF OP_1 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_10 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_11 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_12 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_13 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_14 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_15 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_16 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_2 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_3 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_4 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_5 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_6 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_7 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_8 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<0> OP_IF OP_9 OP_ENDIF in locking bytecode", &["invalid"]),
                        ("<1> OP_IF OP_1 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_10 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_11 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_12 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_13 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_14 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_15 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_16 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_2 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_3 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_4 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_5 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_6 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_7 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_8 OP_ENDIF in locking bytecode", &[]),
                        ("<1> OP_IF OP_9 OP_ENDIF in locking bytecode", &[]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
            ]
            .concat(),
        ),
    ]
});
