//! Port of `vmb-tests/sources/chip.p2s.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::crypto::secp256k1;
use crate::engine::{
    WalletTemplateScenario, WalletTemplateScenarioBytecode,
    WalletTemplateScenarioBytecodeDefinition, WalletTemplateScenarioBytecodeScript,
    WalletTemplateScenarioInput, WalletTemplateScenarioNft, WalletTemplateScenarioOutput,
    WalletTemplateScenarioOutputLockingBytecode, WalletTemplateScenarioToken,
    WalletTemplateScenarioTokenAmount, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioUnlockingBytecode, WalletTemplateScenarioValueSatoshis,
    WalletTemplateScriptDefinition,
};
use crate::format::{assert_success, bin_to_hex, hex_to_bin};
use crate::message::NonFungibleTokenCapability;
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

static key1Compressed: LazyLock<Vec<u8>> = LazyLock::new(|| hex_to_bin("03a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e785"));

static key1Uncompressed: LazyLock<Vec<u8>> = LazyLock::new(|| assert_success(secp256k1.uncompress_public_key(&key1Compressed), None));

static key2Compressed: LazyLock<Vec<u8>> = LazyLock::new(|| hex_to_bin("03c23083dccdc50247ebc5725c88d6d550cc49c9cb94e4bd4c485a1c6715a5dbfd"));

static key2Uncompressed: LazyLock<Vec<u8>> = LazyLock::new(|| assert_success(secp256k1.uncompress_public_key(&key2Compressed), None));

static key3Compressed: LazyLock<Vec<u8>> = LazyLock::new(|| hex_to_bin("0369fb8ddd38ab04cfb912a76c1bde5c7d0c1415ff4caf199461878d5fb03dc3f8"));

static key3Uncompressed: LazyLock<Vec<u8>> = LazyLock::new(|| assert_success(secp256k1.uncompress_public_key(&key3Compressed), None));

static longestTokenPrefix: LazyLock<WalletTemplateScenarioToken> = LazyLock::new(|| WalletTemplateScenarioToken { amount: Some(WalletTemplateScenarioTokenAmount::Decimal("9223372036854775807".to_string())), category: Some("0102030400000000000000000000000000000000000000000000000001020304".to_string()), nft: Some(WalletTemplateScenarioNft { capability: Some(NonFungibleTokenCapability::Minting), commitment: Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string()) }) });

static oneBeyondLongestTokenCommitment2025: LazyLock<WalletTemplateScenarioToken> = LazyLock::new(|| WalletTemplateScenarioToken { amount: Some(WalletTemplateScenarioTokenAmount::Decimal("9223372036854775807".to_string())), category: Some("0102030400000000000000000000000000000000000000000000000001020304".to_string()), nft: Some(WalletTemplateScenarioNft { capability: Some(NonFungibleTokenCapability::Minting), commitment: Some("ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdd".to_string()) }) });

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Pay to Script".to_string(),
            vec![
                definition(
                    "<0> <key1.ecdsa_signature.default> <key2.ecdsa_signature.default> <key3.ecdsa_signature.default>",
                    &format!("<3> <0x{}> <0x{}> <0x{}> OP_3 OP_CHECKMULTISIG", bin_to_hex(&key1Uncompressed), bin_to_hex(&key2Uncompressed), bin_to_hex(&key3Uncompressed)),
                    "Maximum length BCH_2025_05 standard UTXO and output (3-of-3 bare multisig, uncompressed keys), ECDSA signatures",
                    &["p2s_standard", "p2sh_ignore"],
                    Some(WalletTemplateScenario {
                        source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), token: Some(longestTokenPrefix.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_898.0)) }]),
                        transaction: Some(WalletTemplateScenarioTransaction {
                            inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]),
                            outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Copy), overrides: None }))), token: Some(longestTokenPrefix.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_332.0)) }]),
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
                definition(
                    "<0b111> <key1.schnorr_signature.default> <key2.schnorr_signature.default> <key3.schnorr_signature.default>",
                    &format!("<3> <0x{}> <0x{}> <0x{}> OP_3 OP_CHECKMULTISIG", bin_to_hex(&key1Uncompressed), bin_to_hex(&key2Uncompressed), bin_to_hex(&key3Uncompressed)),
                    "Maximum length BCH_2025_05 standard UTXO and output (3-of-3 bare multisig, uncompressed keys), Schnorr signatures",
                    &["p2s_standard", "p2sh_ignore"],
                    Some(WalletTemplateScenario {
                        source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), token: Some(longestTokenPrefix.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_898.0)) }]),
                        transaction: Some(WalletTemplateScenarioTransaction {
                            inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]),
                            outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Copy), overrides: None }))), token: Some(longestTokenPrefix.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_332.0)) }]),
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
                definition(
                    "<0> <key1.ecdsa_signature.default> <key2.ecdsa_signature.default> <key3.ecdsa_signature.default>",
                    &format!("<3> <0x{}> <0x{}> <0x{}> OP_3 OP_CHECKMULTISIG", bin_to_hex(&key1Uncompressed), bin_to_hex(&key2Uncompressed), bin_to_hex(&key3Uncompressed)),
                    "Maximum length BCH_2025_05 standard UTXO and output (3-of-3 bare multisig, uncompressed keys), ECDSA signatures, 41-byte commitment",
                    &["chip_p2s", "p2sh_ignore"],
                    Some(WalletTemplateScenario {
                        source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), token: Some(oneBeyondLongestTokenCommitment2025.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_902.0)) }]),
                        transaction: Some(WalletTemplateScenarioTransaction {
                            inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]),
                            outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Copy), overrides: None }))), token: Some(oneBeyondLongestTokenCommitment2025.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_335.0)) }]),
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
                definition(
                    "<0b111> <key1.schnorr_signature.default> <key2.schnorr_signature.default> <key3.schnorr_signature.default>",
                    &format!("<3> <0x{}> <0x{}> <0x{}> OP_3 OP_CHECKMULTISIG", bin_to_hex(&key1Uncompressed), bin_to_hex(&key2Uncompressed), bin_to_hex(&key3Uncompressed)),
                    "Maximum length BCH_2025_05 standard UTXO and output (3-of-3 bare multisig, uncompressed keys), Schnorr signatures, 41-byte commitment",
                    &["chip_p2s", "p2sh_ignore"],
                    Some(WalletTemplateScenario {
                        source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), token: Some(oneBeyondLongestTokenCommitment2025.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_902.0)) }]),
                        transaction: Some(WalletTemplateScenarioTransaction {
                            inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]),
                            outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Copy), overrides: None }))), token: Some(oneBeyondLongestTokenCommitment2025.clone()), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_335.0)) }]),
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
