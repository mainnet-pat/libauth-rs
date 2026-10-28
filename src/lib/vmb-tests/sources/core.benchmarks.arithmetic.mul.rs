//! Port of `vmb-tests/sources/core.benchmarks.arithmetic.mul.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::{
    minimalScenarioStandard, minimal_scenario_standard_plus_bytes, repeat,
};
use crate::vmb_tests::bch_vmb_test_utils::{VmbTestDefinition, VmbTestDefinitionGroup};

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

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            vec![
                definition("<-2>", &format!("OP_DUP OP_2DUP {} OP_DUP {} <0xffffff7f> {}", repeat("OP_3DUP", 47), repeat(&format!("<0xffffffff7f> {} OP_DROP", repeat("OP_MUL", 24)), 5), repeat("OP_MUL", 26)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_MUL", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<-2>", &format!("OP_DUP OP_2DUP {} OP_DUP {} <0xffffff7f> {}", repeat("OP_3DUP", 47), repeat(&format!("<0xffffffff7f> {} OP_DROP", repeat("OP_MUL", 24)), 5), repeat("OP_MUL", 26)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize OP_MUL", &["nonstandard", "p2sh_ignore"], Some(minimal_scenario_standard_plus_bytes(1)), None),
                definition("<0xffffffff>", &format!("{} <0xff> OP_MUL", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 1-by-8192 byte OP_MUL (all bits set, long bottom operand)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xffffffff>", &format!("{} <0xff> OP_SWAP OP_MUL", repeat("OP_DUP OP_CAT", 11)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 1-by-8192 byte OP_MUL (all bits set, long top operand)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xffffffff>", &format!("OP_DUP OP_DUP {} OP_ROT OP_ROT OP_CAT OP_MUL", repeat("OP_DUP OP_CAT", 10)), "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize 4096-by-8 byte OP_MUL (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MUL", repeat("OP_DUP OP_CAT", 2), repeat("OP_DUP OP_CAT", 7)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 16-by-2048 byte OP_MUL (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MUL", repeat("OP_DUP OP_CAT", 3), repeat("OP_DUP OP_CAT", 5)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 32-by-1024 byte OP_MUL (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MUL", repeat("OP_DUP OP_CAT", 4), repeat("OP_DUP OP_CAT", 3)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 64-by-512 byte OP_MUL (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xffffffff>", &format!("{} OP_DUP {} OP_MUL", repeat("OP_DUP OP_CAT", 5), repeat("OP_DUP OP_CAT", 1)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 128-by-256 byte OP_MUL (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xffffffff>", &format!("{} OP_DUP {} OP_DUP OP_ROT OP_CAT OP_DUP OP_CAT OP_MUL", repeat("OP_DUP OP_CAT", 3), repeat("OP_DUP OP_CAT", 2)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize 128-by-320 byte OP_MUL (all bits set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xff> <194>", "OP_NUM2BIN OP_REVERSEBYTES OP_DUP OP_MUL", "Within BCH_2025_05 P2SH/standard, single-input limits, maximize square OP_MUL (194-by-194 byte) (highest byte set)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xff> <7873>", "OP_NUM2BIN OP_REVERSEBYTES OP_16 OP_MUL", "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize top-operand OP_MUL (1-by-7873 byte) (highest byte set)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xff> <7868>", "OP_NUM2BIN OP_REVERSEBYTES OP_16 OP_MUL", "Within BCH_2025_05 P2SH32/standard, single-input limits, maximize top-operand OP_MUL (1-by-7868 byte) (highest byte set)", &["2023_invalid", "p2s_ignore", "p2sh20_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xff> <8032>", "OP_NUM2BIN OP_REVERSEBYTES <0xff> OP_MUL", "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize 1-byte OP_MUL (1-by-8032 byte) (highest byte set)", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xff> <8028>", "OP_NUM2BIN OP_REVERSEBYTES <0xff> OP_MUL", "Within BCH_2025_05 P2SH32/standard, single-input limits, maximize 1-byte OP_MUL (1-by-8028 byte) (highest byte set)", &["2023_invalid", "p2s_ignore", "p2sh20_ignore"], Some(minimalScenarioStandard.clone()), None),
            ],
        ),
    ]
});
