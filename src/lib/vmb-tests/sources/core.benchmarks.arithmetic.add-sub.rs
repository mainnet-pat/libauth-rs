//! Port of `vmb-tests/sources/core.benchmarks.arithmetic.add-sub.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::{
    minimalScenarioNonStandard, minimalScenarioStandard, repeat,
};
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, TestValues, VmbTestDefinition, VmbTestDefinitionGroup,
    map_test_cases, set_expected_results,
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

static addAndSub: LazyLock<Vec<TestValues>> = LazyLock::new(|| ["OP_ADD", "OP_SUB"].into_iter().map(|value| vec![(value.to_string(), value.to_string())]).collect::<Vec<TestValues>>());

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            [
                set_expected_results(map_test_cases(["<0xffffffffff7f>", &format!("OP_DUP OP_2DUP {} {}", repeat("OP_3DUP", 49), repeat("$0 $0 $0", 50)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize $0"], &addAndSub, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_ADD", &["p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_SUB", &["p2s_ignore"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(map_test_cases(["<0xffffffffff7f>", &format!("OP_DUP OP_2DUP {} {}", repeat("OP_3DUP", 49), repeat("$0 $0 $0", 50)), "Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize $0"], &addAndSub, None, None, Some(&minimalScenarioNonStandard)), &results(&[
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize OP_ADD", &["nonstandard", "p2sh_ignore"]),
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize OP_SUB", &["nonstandard", "p2sh_ignore"]),
                ]), None).expect("setExpectedResults"),
                vec![
                    definition("<0xffffffffffffff7f> <0xffffffffffff7f>", &format!("OP_2DUP {} {}", repeat("OP_3DUP", 49), repeat("OP_SUB", 150)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_SUB (minimize 0 results)", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0x3fffffffffffffffffffffffffffff>", "<10000> OP_NUM2BIN OP_REVERSEBYTES OP_DUP OP_ADD", "Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_ADD operand bytes", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffffffffffffffffffffffffff>", "<9999> OP_NUM2BIN OP_REVERSEBYTES OP_DUP OP_ADD", "Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_SUB operand bytes", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP OP_ADD", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize (OP_DUP OP_CAT) OP_ADD operand bytes", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP OP_SUB OP_NOT", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize (OP_DUP OP_CAT) OP_SUB operand bytes (OP_DUP OP_SUB OP_NOT)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} <1> OP_SUB", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize (OP_DUP OP_CAT) OP_SUB operand bytes (<1> OP_SUB)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP OP_2DUP {} {}", repeat("OP_DUP OP_CAT", 7), repeat("OP_3DUP", 24), repeat("OP_ADD", 75)), "Within BCH_2025_05 P2SH20/standard, single-input limits, balance (OP_DUP OP_CAT) OP_ADD density and operand bytes", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                ],
            ]
            .concat(),
        ),
    ]
});
