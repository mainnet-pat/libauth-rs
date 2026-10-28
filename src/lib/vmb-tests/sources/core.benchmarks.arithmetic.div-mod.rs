//! Port of `vmb-tests/sources/core.benchmarks.arithmetic.div-mod.ts`.

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

static divAndMod: LazyLock<Vec<TestValues>> = LazyLock::new(|| ["OP_DIV", "OP_MOD"].into_iter().map(|value| vec![(value.to_string(), value.to_string())]).collect::<Vec<TestValues>>());

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            [
                set_expected_results(map_test_cases(["<0xffffffffff7f> <0x00ffffff7e>", &format!("OP_2DUP {} {} $0 $0 $0 $0 OP_SUB $0 OP_0NOTEQUAL", repeat("OP_3DUP", 49), repeat("$0 $0 $0 $0 OP_SUB $0 $0 $0 OP_SUB", 16)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize $0"], &divAndMod, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_DIV", &["p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_MOD", &["p2s_ignore"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(map_test_cases(["<0xffffffffff7f> <0x00ffffff7e>", &format!("OP_2DUP {} {} $0 $0 $0 $0 OP_SUB $0 OP_0NOTEQUAL", repeat("OP_3DUP", 49), repeat("$0 $0 $0 $0 OP_SUB $0 $0 $0 OP_SUB", 16)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize $0"], &divAndMod, None, None, Some(&minimalScenarioNonStandard)), &results(&[
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_DIV", &["nonstandard", "p2sh_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_MOD", &["nonstandard", "p2sh_ignore"]),
                ]), None).expect("setExpectedResults"),
                vec![
                    definition("<0xffffffff>", &format!("{} <0xff> OP_DIV", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 1-by-8192 byte OP_DIV (all bits set, long bottom operand)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} <0xff> OP_SWAP OP_DIV OP_NOT", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 1-by-8192 byte OP_DIV (all bits set, long top operand)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("OP_DUP OP_DUP {} OP_ROT OP_ROT OP_CAT OP_DIV", repeat("OP_DUP OP_CAT", 10)), "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize 4096-by-8 byte OP_DIV (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_DIV OP_NOT", repeat("OP_DUP OP_CAT", 2), repeat("OP_DUP OP_CAT", 7)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 16-by-2048 byte OP_DIV (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_DIV OP_NOT", repeat("OP_DUP OP_CAT", 3), repeat("OP_DUP OP_CAT", 5)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 32-by-1024 byte OP_DIV (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_DIV OP_NOT", repeat("OP_DUP OP_CAT", 4), repeat("OP_DUP OP_CAT", 3)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 64-by-512 byte OP_DIV (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_DIV OP_NOT", repeat("OP_DUP OP_CAT", 5), repeat("OP_DUP OP_CAT", 1)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 128-by-256 byte OP_DIV (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_DUP OP_ROT OP_CAT OP_DUP OP_CAT OP_DIV OP_NOT", repeat("OP_DUP OP_CAT", 3), repeat("OP_DUP OP_CAT", 2)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 128-by-320 byte OP_DIV (all bits set)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xff>", "<195> OP_NUM2BIN OP_REVERSEBYTES OP_DUP OP_DIV", "Within BCH_2025_05 P2SH/standard, single-input limits, maximize square OP_DIV (195-by-195 byte) (highest byte set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xff> <8033>", "OP_NUM2BIN OP_REVERSEBYTES <0xff> OP_DIV", "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize 1-byte OP_DIV (1-by-8033 byte) (highest byte set)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xff> <8028>", "OP_NUM2BIN OP_REVERSEBYTES <0xff> OP_DIV", "Within BCH_2025_05 P2SH32/standard, single-input limits, maximize 1-byte OP_DIV (1-by-8028 byte) (highest byte set)", &["2023_invalid", "p2s_ignore", "p2sh20_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} <0xff> OP_MOD", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 1-by-8192 byte OP_MOD (all bits set, long bottom operand)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} <0xff> OP_SWAP OP_MOD", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 1-by-8192 byte OP_MOD (all bits set, long top operand)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("OP_DUP OP_DUP {} OP_ROT OP_ROT OP_CAT OP_MOD", repeat("OP_DUP OP_CAT", 10)), "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize 4096-by-8 byte OP_MOD (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MOD", repeat("OP_DUP OP_CAT", 2), repeat("OP_DUP OP_CAT", 7)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 16-by-2048 byte OP_MOD (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MOD", repeat("OP_DUP OP_CAT", 3), repeat("OP_DUP OP_CAT", 5)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 32-by-1024 byte OP_MOD (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MOD", repeat("OP_DUP OP_CAT", 4), repeat("OP_DUP OP_CAT", 3)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 64-by-512 byte OP_MOD (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MOD", repeat("OP_DUP OP_CAT", 5), repeat("OP_DUP OP_CAT", 1)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 128-by-256 byte OP_MOD (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xffffffff>", &format!("{} OP_DUP {} OP_DUP OP_ROT OP_CAT OP_DUP OP_CAT OP_MOD", repeat("OP_DUP OP_CAT", 3), repeat("OP_DUP OP_CAT", 2)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 128-by-320 byte OP_MOD (all bits set)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xff> <198>", "OP_NUM2BIN OP_REVERSEBYTES OP_DUP OP_MOD OP_NOT", "Within BCH_2025_05 P2SH/standard, single-input limits, maximize square OP_MOD (198-by-198 byte) (highest byte set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                    definition("<0xff> <10000>", "OP_NUM2BIN OP_REVERSEBYTES <0xffff> OP_MOD", "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 1-byte OP_MOD (1-by-10000 byte) (highest byte set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                ],
            ]
            .concat(),
        ),
    ]
});
