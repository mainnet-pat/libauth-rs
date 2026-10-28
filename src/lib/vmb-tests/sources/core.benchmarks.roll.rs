//! Port of `vmb-tests/sources/core.benchmarks.roll.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::{minimalScenarioStandard, repeat};
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
                definition("<1> <1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} {} {}", repeat("OP_3DUP", 76), repeat(&format!("<{}> OP_ROLL", 4 + 76 * 3), 6), repeat("OP_2DROP", 116)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes pushed to the stack, inner OP_ROLLs (6)", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<1> <1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} {} {}", repeat("OP_3DUP", 70), repeat(&format!("<{}> OP_ROLL", 4 + 70 * 3), 21), repeat("OP_2DROP", 107)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes pushed to the stack, inner OP_ROLLs (21)", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<1> <1> <520>", &format!("OP_NUM2BIN OP_DUP OP_2DUP {} {} {}", repeat("OP_3DUP", 50), repeat(&format!("<{}> OP_ROLL", 4 + 50 * 3), 71), repeat("OP_2DROP", 77)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes pushed to the stack, inner OP_ROLLs (71)", &["p2s_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition(&repeat("<1>", 999), &repeat("<998> OP_ROLL", 201), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize abusive OP_ROLL (ends with non-clean stack)", &["invalid"], Some(minimalScenarioStandard.clone()), None),
                definition("<0> <0> <0> <0>", &format!("{} OP_2DUP {} {} <7> OP_CHECKMULTISIG", repeat("OP_3DUP", 331), repeat("<998> OP_ROLL", 293), repeat("<20> OP_CHECKMULTISIGVERIFY", 45)), "Within BCH_2025_05 P2SH/standard, single-input limits, maximize OP_ROLL", &["p2s_invalid", "2023_invalid"], Some(minimalScenarioStandard.clone()), None),
            ],
        ),
    ]
});
