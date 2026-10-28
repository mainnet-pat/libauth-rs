//! Port of `vmb-tests/sources/core.benchmarks.signature-checking.p2pkh.ts`.

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
                definition("<key1.schnorr_signature.all_outputs> <key1.public_key>", "OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG", "Within BCH_2023_05 standard limits, P2PKH input, 1 output (Schnorr signature)", &["p2s_standard", "p2sh_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<key1.schnorr_signature.all_outputs> <key1.public_key>", "OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG", "Within BCH_2023_05 standard limits, packed P2PKH inputs, 1 output (all Schnorr signatures)", &["p2s_standard", "p2sh_ignore"], Some(packed_transaction_scenario("p2s", 708)), None),
                definition("<key1.ecdsa_signature.all_outputs> <key1.public_key>", "OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG", "Within BCH_2023_05 standard limits, P2PKH input, 1 output (ECDSA signature)", &["p2s_standard", "p2sh_ignore"], Some(minimalScenarioStandard.clone()), None),
                definition("<key1.ecdsa_signature.all_outputs> <key1.public_key>", "OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG", "Within BCH_2023_05 standard limits, packed P2PKH inputs, 1 output (all ECDSA signatures)", &["p2s_standard", "p2sh_ignore"], Some(packed_transaction_scenario("p2s", 676)), None),
            ],
        ),
    ]
});
