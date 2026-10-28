//! Port of `vmb-tests/sources/core.benchmarks.bitwise.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::{
    minimalScenarioStandard, minimal_scenario_standard_plus_bytes, repeat,
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

static bitwiseOps: LazyLock<Vec<TestValues>> = LazyLock::new(|| ["OP_AND", "OP_OR", "OP_XOR"].into_iter().map(|value| vec![(value.to_string(), value.to_string())]).collect::<Vec<TestValues>>());

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            [
                set_expected_results(map_test_cases(["<1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} OP_2DUP $0 $0 $0 $0 $0", repeat("OP_3DUP $0 $0 $0", 48)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize $0"], &bitwiseOps, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_AND", &["p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_OR", &["p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_XOR", &["invalid"]),
                ]), None).expect("setExpectedResults"),
                vec![definition("<1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} OP_2DUP OP_XOR OP_XOR OP_XOR OP_XOR OP_DROP", repeat("OP_3DUP OP_XOR OP_XOR OP_XOR", 48)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_XOR (trailing OP_DROP)", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None)],
                set_expected_results(map_test_cases(["<1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} OP_2DUP $0 $0 $0 $0 $0", repeat("OP_3DUP $0 $0 $0", 48)), "Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize $0"], &bitwiseOps, None, None, Some(&minimal_scenario_standard_plus_bytes(2))), &results(&[
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize OP_AND", &["invalid", "2023_nonstandard", "p2sh_ignore"]),
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize OP_OR", &["invalid", "2023_nonstandard", "p2sh_ignore"]),
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize OP_XOR", &["invalid"]),
                ]), None).expect("setExpectedResults"),
                vec![definition("<1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} OP_2DUP OP_XOR OP_XOR OP_XOR OP_XOR OP_DROP", repeat("OP_3DUP OP_XOR OP_XOR OP_XOR", 48)), "Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize OP_XOR (trailing OP_DROP)", &["invalid", "2023_nonstandard", "p2sh_ignore"], Some(minimal_scenario_standard_plus_bytes(2)), None)],
                set_expected_results(map_test_cases(["<1> <10_000>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} $0 $0 $0", repeat("OP_3DUP $0 $0 $0", 409)), "Beyond single-input limits, maximize $0 (otherwise-standard P2SH)"], &bitwiseOps, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Beyond single-input limits, maximize OP_AND (otherwise-standard P2SH)", &["invalid", "p2s_ignore"]),
                    ("Beyond single-input limits, maximize OP_OR (otherwise-standard P2SH)", &["invalid", "p2s_ignore"]),
                    ("Beyond single-input limits, maximize OP_XOR (otherwise-standard P2SH)", &["invalid"]),
                ]), None).expect("setExpectedResults"),
                vec![definition("<1> <10_000>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} OP_XOR OP_XOR OP_DROP", repeat("OP_3DUP OP_XOR OP_XOR OP_XOR", 409)), "Beyond single-input limits, maximize OP_XOR (otherwise-standard P2SH, trailing OP_DROP)", &["invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None)],
                set_expected_results(map_test_cases(["<1> <10_000>", "OP_NUM2BIN OP_DUP $0", "Within BCH_2025_05 P2SH/standard, single-input limits, maximize $0"], &bitwiseOps, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_AND", &["2023_invalid", "p2s_ignore"]),
                    ("Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_OR", &["2023_invalid", "p2s_ignore"]),
                    ("Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_XOR", &["invalid"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(map_test_cases(["<1> <479>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} {} {} {}", repeat("OP_3DUP", 332), repeat("$0", 994), repeat("OP_3DUP", 77), repeat("$0", 236)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize $0 density, then operand bytes, then stack usage"], &bitwiseOps, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_AND density, then operand bytes, then stack usage", &["2023_invalid", "p2s_ignore"]),
                    ("Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_OR density, then operand bytes, then stack usage", &["2023_invalid", "p2s_ignore"]),
                    ("Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_XOR density, then operand bytes, then stack usage", &["2023_invalid", "p2s_ignore"]),
                ]), None).expect("setExpectedResults"),
                vec![
                    definition("<1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} OP_EQUALVERIFY OP_EQUAL", repeat("OP_3DUP OP_3DUP OP_EQUALVERIFY OP_EQUALVERIFY OP_EQUALVERIFY", 39)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_EQUAL", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} OP_EQUALVERIFY OP_EQUAL", repeat("OP_3DUP OP_3DUP OP_EQUALVERIFY OP_EQUALVERIFY OP_EQUALVERIFY", 39)), "Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize OP_EQUAL", &["invalid", "2023_nonstandard", "p2sh_ignore"], Some(minimal_scenario_standard_plus_bytes(2)), None),
                ],
            ]
            .concat(),
        ),
    ]
});
