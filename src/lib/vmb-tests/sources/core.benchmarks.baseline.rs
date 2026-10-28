//! Port of `vmb-tests/sources/core.benchmarks.baseline.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{
    WalletTemplateScenario, WalletTemplateScenarioBytecode,
    WalletTemplateScenarioBytecodeDefinition, WalletTemplateScenarioBytecodeScript,
    WalletTemplateScenarioInput, WalletTemplateScenarioOutput,
    WalletTemplateScenarioOutputLockingBytecode, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioUnlockingBytecode, WalletTemplateScenarioValueSatoshis,
    WalletTemplateScriptDefinition,
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
                definition(
                    "<key1.schnorr_signature.all_outputs> <key1.public_key>",
                    "OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG",
                    "[baseline] 2 P2PKH inputs, 2 P2PKH outputs (one Schnorr signature, one ECDSA signature)",
                    &["p2s_standard", "spec_standard", "p2sh_ignore"],
                    Some(WalletTemplateScenario {
                        source_outputs: Some(vec![
                            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(100_000.0)), token: None },
                            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(100_000.0)), token: None },
                        ]),
                        transaction: Some(WalletTemplateScenarioTransaction {
                            inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("unlockP2pkhStandardEcdsa".to_string())), overrides: None }))), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }, WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]),
                            outputs: Some(vec![
                                WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(100_000.0)), token: None },
                                WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(99_634.0)), token: None },
                            ]),
                            locktime: None,
                            version: None,
                        }),
                        data: None,
                        description: None,
                        extends: None,
                        name: None,
                    }),
                    None,
                ),
            ],
        ),
    ]
});
