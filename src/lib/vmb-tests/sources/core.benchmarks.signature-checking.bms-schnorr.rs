//! Port of `vmb-tests/sources/core.benchmarks.signature-checking.bms-schnorr.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::{minimalScenarioStandard, packed_transaction_scenario};
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
                definition("<0b001> <key1.schnorr_signature.default>", "<1> <key1.public_key> <key2.public_key> <key3.public_key> OP_3 OP_CHECKMULTISIG", "Within BCH_2023_05 standard limits, 1-of-3 bare multisig input, 1 output (Schnorr signature)", &["p2s_standard", "p2sh_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<0b001> <key1.schnorr_signature.default>", "<1> <key1.public_key> <key2.public_key> <key3.public_key> OP_3 OP_CHECKMULTISIG", "Within BCH_2023_05 standard limits, packed 1-of-3 bare multisig inputs, 1 output (all Schnorr signatures)", &["p2s_standard", "p2sh_ignore"], Some(packed_transaction_scenario("p2s", 924)), None),
            ],
        ),
    ]
});
