//! Port of `vmb-tests/sources/core.benchmarks.stack.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::{
    minimalScenarioNonStandard, minimalScenarioStandard, minimal_scenario_standard_plus_bytes,
    repeat,
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
                definition("<1> <1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} {}", repeat("OP_3DUP", 78), repeat("OP_2DROP", 119)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes pushed to the stack", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("", &format!("<1> <1> <520> OP_NUM2BIN OP_DUP OP_2DUP {} {}", repeat("OP_3DUP", 78), repeat("OP_2DROP", 119)), "Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize bytes pushed to the stack", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"], Some(minimal_scenario_standard_plus_bytes(3)), None),
                definition("<1> <$(<1> <397> OP_NUM2BIN)> <$(<1> <520> OP_NUM2BIN)> <$(<2> <520> OP_NUM2BIN)>", &format!("OP_2DUP {} {}", repeat("OP_3DUP", 79), repeat("OP_2DROP", 121)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize stack usage", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<1> <$(<1> <397> OP_NUM2BIN)> <$(<1> <520> OP_NUM2BIN)> <$(<2> <520> OP_NUM2BIN)>", &format!("OP_2DUP {} {}", repeat("OP_3DUP", 79), repeat("OP_2DROP", 121)), "Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize stack usage", &["p2s_nonstandard", "p2sh_ignore"], Some(minimalScenarioNonStandard.clone()), None),
                definition("<0xff> <10000>", "OP_NUM2BIN OP_DUP OP_2DUP OP_2DROP OP_DROP", "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize stack usage", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xff> <10000>", "OP_NUM2BIN OP_DUP OP_2DUP OP_2DROP OP_DROP", "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize stack usage", &["2023_invalid", "p2s_ignore", "p2sh20_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0xf77f>", &format!("{} OP_DUP {} OP_2DUP OP_CAT OP_DROP OP_CAT", repeat("OP_DUP OP_CAT", 9), repeat("OP_DUP OP_CAT", 3)), "Within BCH_2025_05 P2SH20/standard, single-input limits, maximize OP_DUP OP_CAT", &["2023_invalid", "p2s_ignore", "p2sh32_ignore"], Some(minimalScenarioStandard.clone()), None),
                // ['<0xf77f>', `${repeat('OP_DUP OP_CAT', 4)} OP_DUP ${repeat('OP_DUP OP_CAT', 8)} ${repeat('OP_2DUP OP_CAT OP_DROP', 2)} OP_DROP`, 'Within BCH_2025_05 P2SH32/standard, single-input limits, maximize OP_DUP OP_CAT', ['2023_invalid', 'p2s_ignore', 'p2sh20_ignore'], minimalScenarioStandard],
                definition("<0>", &format!("OP_DUP OP_2DUP {} {} OP_DROP {} <7> OP_CHECKMULTISIG", repeat("OP_3DUP", 332), repeat("OP_1ADD", 1174), repeat("<20> OP_CHECKMULTISIGVERIFY", 45)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize stack usage checking (OP_1ADD)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<$(<0> <2500> OP_NUM2BIN)>", &format!("OP_BIN2NUM OP_DUP OP_2DUP {} {} OP_DROP {} <7> OP_CHECKMULTISIG", repeat("OP_3DUP", 332), repeat("OP_1ADD", 9527), repeat("<20> OP_CHECKMULTISIGVERIFY", 45)), "Within BCH_2025_05 P2S/nonstandard, single-input limits, maximize stack usage checking (OP_1ADD)", &["p2s_nonstandard", "2023_invalid", "p2sh_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0>", &format!("OP_DUP OP_2DUP {} {} {} OP_0NOTEQUAL", repeat("OP_3DUP", 332), repeat("OP_TOALTSTACK", 999), repeat("OP_1ADD", 312)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize alternate stack usage checking (OP_1ADD)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<$(<0> <1251> OP_NUM2BIN)>", &format!("OP_BIN2NUM OP_DUP OP_2DUP {} {} {} OP_0NOTEQUAL", repeat("OP_3DUP", 332), repeat("OP_TOALTSTACK", 999), repeat("OP_1ADD", 8665)), "Within BCH_2025_05 P2S/nonstandard, single-input limits, maximize alternate stack usage checking (OP_1ADD)", &["p2s_nonstandard", "2023_invalid", "p2sh_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition(
                    "<0>",
                    &format!("OP_DUP OP_2DUP {} {} OP_NOTIF OP_DUP {} {} OP_DROP {} <7> OP_CHECKMULTISIG", repeat("OP_3DUP", 332), repeat("OP_NOTIF OP_NOTIF OP_NOTIF OP_3DUP", 33), repeat("OP_1ADD", 940), repeat("OP_ENDIF", 100), repeat("<20> OP_CHECKMULTISIGVERIFY", 45)),
                    "Within BCH_2025_05 P2SH/standard, single-input limits, maximize control stack and stack usage checking (OP_NOTIF, OP_1ADD)",
                    &["2023_invalid", "p2s_ignore"],
                    Some(minimalScenarioStandard.clone()),
                    None,
                ),
                definition(
                    "<$(<0> <1249> OP_NUM2BIN)>",
                    &format!("OP_BIN2NUM OP_DUP OP_2DUP {} {} OP_NOTIF OP_DUP {} {} OP_DROP {} <7> OP_CHECKMULTISIG", repeat("OP_3DUP", 332), repeat("OP_NOTIF OP_NOTIF OP_NOTIF OP_3DUP", 33), repeat("OP_1ADD", 9293), repeat("OP_ENDIF", 100), repeat("<20> OP_CHECKMULTISIGVERIFY", 45)),
                    "Within BCH_2025_05 P2S/nonstandard, single-input limits, maximize control stack and stack usage checking (OP_NOTIF, OP_1ADD)",
                    &["p2s_nonstandard", "2023_invalid", "p2sh_ignore"],
                    Some(minimalScenarioStandard.clone()),
                    None,
                ),
                definition("<1>", &format!("OP_DUP OP_2DUP {} {} {} {}", repeat("OP_3DUP", 234), repeat("OP_IF", 100), repeat("OP_ENDIF OP_IF", 605), repeat("OP_ENDIF", 100)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize control stack usage checking (OP_IF)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<1>", &format!("OP_DUP OP_2DUP {} {} {} {} <1>", repeat("OP_3DUP", 32), repeat("OP_IF", 100), repeat("OP_ELSE", 1411), repeat("OP_ENDIF", 100)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize control stack usage checking (OP_ELSE)", &["2023_invalid", "p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
            ],
        ),
    ]
});
