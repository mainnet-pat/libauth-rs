//! Port of `vmb-tests/sources/core.signing-serialization.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{
    WalletTemplateScenario, WalletTemplateScenarioBytecode,
    WalletTemplateScenarioBytecodeDefinition, WalletTemplateScenarioBytecodeScript,
    WalletTemplateScenarioInput, WalletTemplateScenarioNft, WalletTemplateScenarioOutput,
    WalletTemplateScenarioOutputLockingBytecode, WalletTemplateScenarioToken,
    WalletTemplateScenarioTokenAmount, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioUnlockingBytecode, WalletTemplateScenarioValueSatoshis,
    WalletTemplateScriptDefinition,
};
use crate::message::NonFungibleTokenCapability;
use crate::vmb_tests::bch_vmb_test_mixins::{
    emptyP2sh20Input, emptyP2sh20Output, simpleP2pkhInput, simpleP2pkhOutput,
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

const algorithms: [&str; 12] = [
    "all_outputs_all_utxos",
    "all_outputs_single_input_INVALID_all_utxos",
    "all_outputs_single_input",
    "all_outputs",
    "corresponding_output_all_utxos",
    "corresponding_output_single_input_INVALID_all_utxos",
    "corresponding_output_single_input",
    "corresponding_output",
    "no_outputs_all_utxos",
    "no_outputs_single_input_INVALID_all_utxos",
    "no_outputs_single_input",
    "no_outputs",
];

const signatureTypes: [(&str, &str); 2] = [
    ("schnorr signature", "schnorr_signature"),
    ("ECDSA signature", "ecdsa_signature"),
];

const opcodePatterns: [(&str, &str); 8] = [
    ("single ECDSA signature", "OP_2DUP OP_CHECKSIG OP_VERIFY OP_2DUP OP_CHECKSIGVERIFY"),
    ("single schnorr signature", "OP_2DUP OP_CHECKSIG OP_VERIFY OP_2DUP OP_CHECKSIGVERIFY"),
    ("1-of-1 multisig ECDSA signature", "OP_2DUP OP_0 OP_ROT OP_ROT OP_1 OP_SWAP OP_1 OP_CHECKMULTISIG OP_VERIFY OP_2DUP OP_0 OP_ROT OP_ROT OP_1 OP_SWAP OP_1 OP_CHECKMULTISIGVERIFY"),
    ("1-of-2 multisig ECDSA signature (second key)", "OP_2DUP <0> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <2> OP_CHECKMULTISIG OP_VERIFY OP_2DUP <0> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <2> OP_CHECKMULTISIGVERIFY"),
    ("1-of-3 multisig ECDSA signature (middle key)", "OP_2DUP <0> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <key3.public_key> <3> OP_CHECKMULTISIG OP_VERIFY OP_2DUP <0> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <key3.public_key> <3> OP_CHECKMULTISIGVERIFY"),
    ("1-of-1 multisig schnorr signature", "OP_2DUP <0b1> OP_ROT OP_ROT OP_1 OP_SWAP OP_1 OP_CHECKMULTISIG OP_VERIFY OP_2DUP <0b1> OP_ROT OP_ROT OP_1 OP_SWAP OP_1 OP_CHECKMULTISIGVERIFY"),
    ("1-of-2 multisig schnorr signature (second key)", "OP_2DUP <0b10> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <2> OP_CHECKMULTISIG OP_VERIFY OP_2DUP <0b10> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <2> OP_CHECKMULTISIGVERIFY"),
    ("1-of-3 multisig schnorr signature (middle key)", "OP_2DUP <0b10> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <key3.public_key> <3> OP_CHECKMULTISIG OP_VERIFY OP_2DUP <0b10> OP_ROT OP_ROT <1> OP_SWAP <key2.public_key> OP_SWAP <key3.public_key> <3> OP_CHECKMULTISIGVERIFY"),
];

static akaMap: LazyLock<BTreeMap<&str, &str>> = LazyLock::new(|| {
    BTreeMap::from([
        ("all_outputs", "SIGHASH_ALL|SIGHASH_FORKID"),
        ("all_outputs_all_utxos", "SIGHASH_ALL|SIGHASH_UTXOS|SIGHASH_FORKID"),
        ("all_outputs_single_input", "SIGHASH_ALL|SIGHASH_FORKID|ANYONECANPAY"),
        ("all_outputs_single_input_INVALID_all_utxos", "SIGHASH_ALL|SIGHASH_UTXOS|SIGHASH_FORKID|ANYONECANPAY"),
        ("corresponding_output", "SIGHASH_SINGLE|SIGHASH_FORKID"),
        ("corresponding_output_all_utxos", "SIGHASH_SINGLE|SIGHASH_UTXOS|SIGHASH_FORKID"),
        ("corresponding_output_single_input", "SIGHASH_SINGLE|SIGHASH_FORKID|ANYONECANPAY"),
        ("corresponding_output_single_input_INVALID_all_utxos", "SIGHASH_SINGLE|SIGHASH_UTXOS|SIGHASH_FORKID|ANYONECANPAY"),
        ("no_outputs", "SIGHASH_NONE|SIGHASH_FORKID"),
        ("no_outputs_all_utxos", "SIGHASH_NONE|SIGHASH_UTXOS|SIGHASH_FORKID"),
        ("no_outputs_single_input", "SIGHASH_NONE|SIGHASH_FORKID|ANYONECANPAY"),
        ("no_outputs_single_input_INVALID_all_utxos", "SIGHASH_NONE|SIGHASH_UTXOS|SIGHASH_FORKID|ANYONECANPAY"),
    ])
});

static combinatorial: LazyLock<Vec<(&str, (&str, &str), (&str, &str), bool)>> = LazyLock::new(|| {
    algorithms
        .into_iter()
        .flat_map(|algorithm| {
            signatureTypes.into_iter().flat_map(move |signature_type| {
                opcodePatterns
                    .into_iter()
                    .flat_map(move |pattern| [true, false].map(|valid| (algorithm, signature_type, pattern, valid)))
            })
        })
        .filter(|(_, signature_type, pattern, _)| pattern.0.contains(signature_type.0))
        .collect()
});

static verifyAlgorithm: LazyLock<Vec<VmbTestDefinition>> = LazyLock::new(|| {
    combinatorial
        .iter()
        .map(|&(algorithm, signature_type, pattern, valid)| {
            definition(
                &format!("<signing_serialization.full_{}> <{}.{}.{}>", algorithm, if valid { "key1" } else { "key2" }, signature_type.1, algorithm),
                &format!("<key1.public_key> {} OP_SWAP OP_SIZE <1> OP_SUB OP_SPLIT OP_DROP OP_ROT OP_SHA256 OP_ROT OP_3DUP OP_CHECKDATASIGVERIFY OP_CHECKDATASIG", pattern.1),
                &format!("verify algorithm - {} ({}), {}, {}, {}", algorithm, akaMap[algorithm], signature_type.0, pattern.0, if valid { "valid" } else { "check failure" }),
                if !valid || algorithm.contains("INVALID") { &["invalid"] } else { &[] },
                Some(WalletTemplateScenario { source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(10_000.0)), token: None }]), transaction: Some(WalletTemplateScenarioTransaction { inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]), outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("vmbTestNullData".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(0.0)), token: None }]), locktime: None, version: None }), data: None, description: None, extends: None, name: None }),
                None,
            )
        })
        .collect()
});

/// `changeScenario`: copy `test_definitions`, appending `append_description` to
/// each description and replacing each scenario with `new_scenario`
/// (`label_changer` defaults to leaving the labels unchanged).
fn change_scenario(
    test_definitions: &[VmbTestDefinition],
    append_description: &str,
    new_scenario: WalletTemplateScenario,
    label_changer: Option<&dyn Fn(&[String]) -> Vec<String>>,
) -> Vec<VmbTestDefinition> {
    let label_changer = label_changer.unwrap_or(&|labels| labels.to_vec());
    test_definitions
        .iter()
        .map(|test_definition| VmbTestDefinition {
            unlocking_script: test_definition.unlocking_script.clone(),
            redeem_or_locking_script: test_definition.redeem_or_locking_script.clone(),
            test_description: format!("{}{}", test_definition.test_description, append_description),
            test_set_override_labels: label_changer(&test_definition.test_set_override_labels),
            scenario: Some(new_scenario.clone()),
            additional_scripts: None,
        })
        .collect()
}

static verifyAlgorithmWithP2pkhInput: LazyLock<Vec<VmbTestDefinition>> = LazyLock::new(|| change_scenario(&verifyAlgorithm, " (with P2PKH input)", WalletTemplateScenario { source_outputs: Some(vec![simpleP2pkhOutput.clone(), WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(10_000.0)), token: None }]), transaction: Some(WalletTemplateScenarioTransaction { inputs: Some(vec![simpleP2pkhInput.clone(), WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]), outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("vmbTestNullData".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(0.0)), token: None }]), locktime: None, version: None }), data: None, description: None, extends: None, name: None }, None));

static verifyAlgorithmWithP2pkhInputAndOutput: LazyLock<Vec<VmbTestDefinition>> = LazyLock::new(|| change_scenario(&verifyAlgorithm, " (with P2PKH input, P2PKH output)", WalletTemplateScenario { source_outputs: Some(vec![simpleP2pkhOutput.clone(), WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(10_000.0)), token: None }]), transaction: Some(WalletTemplateScenarioTransaction { inputs: Some(vec![simpleP2pkhInput.clone(), WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]), outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None }]), locktime: None, version: None }), data: None, description: None, extends: None, name: None }, None));

static verifyAlgorithmWithP2pkhInputAndTwoOutputs: LazyLock<Vec<VmbTestDefinition>> = LazyLock::new(|| change_scenario(&verifyAlgorithm, " (with P2PKH input, 2 P2PKH outputs)", WalletTemplateScenario {
    source_outputs: Some(vec![simpleP2pkhOutput.clone(), WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(10_000.0)), token: None }]),
    transaction: Some(WalletTemplateScenarioTransaction {
        inputs: Some(vec![simpleP2pkhInput.clone(), WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]),
        outputs: Some(vec![
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
        ]),
        locktime: None,
        version: None,
    }),
    data: None,
    description: None,
    extends: None,
    name: None,
}, None));

static verifyAlgorithmWithMultipleInputsAndOutputs: LazyLock<Vec<VmbTestDefinition>> = LazyLock::new(|| change_scenario(&verifyAlgorithm, " (with multiple inputs and outputs)", WalletTemplateScenario {
    source_outputs: Some(vec![simpleP2pkhOutput.clone(), WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(10_000.0)), token: None }, simpleP2pkhOutput.clone(), emptyP2sh20Output.clone(), emptyP2sh20Output.clone()]),
    transaction: Some(WalletTemplateScenarioTransaction {
        inputs: Some(vec![simpleP2pkhInput.clone(), WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }, simpleP2pkhInput.clone(), emptyP2sh20Input.clone(), emptyP2sh20Input.clone()]),
        outputs: Some(vec![
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
        ]),
        locktime: None,
        version: None,
    }),
    data: None,
    description: None,
    extends: None,
    name: None,
}, None));

static verifyAlgorithmWithTokensInMultipleInputsAndOutputs: LazyLock<Vec<VmbTestDefinition>> = LazyLock::new(|| change_scenario(&verifyAlgorithm, " (with all token types in multiple inputs and outputs)", WalletTemplateScenario {
    source_outputs: Some(vec![
        WalletTemplateScenarioOutput { token: Some(WalletTemplateScenarioToken { category: Some("0000000000000000000000000000000000000000000000000000000000000003".to_string()), nft: Some(WalletTemplateScenarioNft { capability: Some(NonFungibleTokenCapability::Minting), commitment: None }), amount: None }), ..simpleP2pkhOutput.clone() },
        WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), token: Some(WalletTemplateScenarioToken { amount: Some(WalletTemplateScenarioTokenAmount::Number(100.0)), nft: Some(WalletTemplateScenarioNft { capability: Some(NonFungibleTokenCapability::Mutable), commitment: Some("ff".to_string()) }), category: None }), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(10_000.0)) },
        WalletTemplateScenarioOutput { token: Some(WalletTemplateScenarioToken { nft: Some(WalletTemplateScenarioNft { commitment: Some("010203".to_string()), capability: None }), amount: None, category: None }), ..simpleP2pkhOutput.clone() },
        WalletTemplateScenarioOutput { token: Some(WalletTemplateScenarioToken { amount: Some(WalletTemplateScenarioTokenAmount::Number(1_000_000.0)), category: None, nft: None }), ..emptyP2sh20Output.clone() },
        emptyP2sh20Output.clone(),
    ]),
    transaction: Some(WalletTemplateScenarioTransaction {
        inputs: Some(vec![simpleP2pkhInput.clone(), WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }, simpleP2pkhInput.clone(), emptyP2sh20Input.clone(), emptyP2sh20Input.clone()]),
        outputs: Some(vec![
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), token: Some(WalletTemplateScenarioToken { category: Some("0000000000000000000000000000000000000000000000000000000000000003".to_string()), nft: Some(WalletTemplateScenarioNft { capability: Some(NonFungibleTokenCapability::Minting), commitment: Some("abcdef".to_string()) }), amount: None }), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)) },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), token: Some(WalletTemplateScenarioToken { category: Some("0000000000000000000000000000000000000000000000000000000000000003".to_string()), nft: Some(WalletTemplateScenarioNft { capability: Some(NonFungibleTokenCapability::Minting), commitment: Some("0102030405".to_string()) }), amount: None }), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)) },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), token: Some(WalletTemplateScenarioToken { amount: Some(WalletTemplateScenarioTokenAmount::Number(1_000_100.0)), nft: Some(WalletTemplateScenarioNft { commitment: Some("010203".to_string()), capability: None }), category: None }), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)) },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), token: Some(WalletTemplateScenarioToken { nft: Some(WalletTemplateScenarioNft { capability: Some(NonFungibleTokenCapability::Mutable), commitment: Some("ffffff".to_string()) }), amount: None, category: None }), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)) },
            WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("lockP2pkh".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1_000.0)), token: None },
        ]),
        locktime: None,
        version: None,
    }),
    data: None,
    description: None,
    extends: None,
    name: None,
}, None));

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Signing serializations".to_string(),
            [
                verifyAlgorithm.clone(),
                vec![
                    definition(
                        "<signing_serialization.full_default> <key1.schnorr_signature.default>",
                        "<key1.public_key> OP_2DUP OP_CHECKSIGVERIFY OP_SWAP OP_SIZE <1> OP_SUB OP_SPLIT OP_DROP OP_ROT OP_SHA256 OP_ROT OP_CHECKDATASIG",
                        "verify algorithm - default (A.K.A. all_outputs_all_utxos, SIGHASH_ALL|SIGHASH_UTXOS|SIGHASH_FORKID)",
                        &[],
                        Some(WalletTemplateScenario { source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(11_000.0)), token: None }]), transaction: Some(WalletTemplateScenarioTransaction { inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]), outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("vmbTestNullData".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(0.0)), token: None }]), locktime: None, version: None }), data: None, description: None, extends: None, name: None }),
                        None,
                    ),
                    definition(
                        "<signing_serialization.full_default> <0x199d5a593615f64e79b912f310984280dd90482b97d257230bc9d3ce36c09c70d6d47b35a6a3e71471d8cffb705c97208d8cd49621142e696532a6c9cf37ca9061>",
                        "<key1.public_key> OP_2DUP OP_CHECKSIGVERIFY OP_SWAP OP_SIZE <1> OP_SUB OP_SPLIT OP_DROP OP_ROT OP_SHA256 OP_ROT OP_CHECKDATASIG",
                        "verify algorithm - all_outputs_all_utxos test with SIGHASH_FORKID (A.K.A. SIGHASH_ALL|SIGHASH_UTXOS|SIGHASH_FORKID)",
                        &["p2sh_ignore"],
                        Some(WalletTemplateScenario { source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(12_000.0)), token: None }]), transaction: Some(WalletTemplateScenarioTransaction { inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]), outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("vmbTestNullData".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(0.0)), token: None }]), locktime: None, version: None }), data: None, description: None, extends: None, name: None }),
                        None,
                    ),
                    definition(
                        "<signing_serialization.full_default> <0x199d5a593615f64e79b912f310984280dd90482b97d257230bc9d3ce36c09c70d6d47b35a6a3e71471d8cffb705c97208d8cd49621142e696532a6c9cf37ca9021>",
                        "<key1.public_key> OP_2DUP OP_CHECKSIGVERIFY OP_SWAP OP_SIZE <1> OP_SUB OP_SPLIT OP_DROP OP_ROT OP_SHA256 OP_ROT OP_CHECKDATASIG",
                        "verify algorithm - all_outputs_all_utxos test without SIGHASH_FORKID (invalid) (A.K.A. SIGHASH_ALL|SIGHASH_UTXOS)",
                        &["invalid", "p2sh_ignore"],
                        Some(WalletTemplateScenario { source_outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(12_000.0)), token: None }]), transaction: Some(WalletTemplateScenarioTransaction { inputs: Some(vec![WalletTemplateScenarioInput { unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot), outpoint_index: None, outpoint_transaction_hash: None, sequence_number: None }]), outputs: Some(vec![WalletTemplateScenarioOutput { locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script: Some(WalletTemplateScenarioBytecodeScript::Id("vmbTestNullData".to_string())), overrides: None }))), value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(0.0)), token: None }]), locktime: None, version: None }), data: None, description: None, extends: None, name: None }),
                        None,
                    ),
                ],
                verifyAlgorithmWithP2pkhInput.clone(),
                verifyAlgorithmWithP2pkhInputAndOutput.clone(),
                verifyAlgorithmWithP2pkhInputAndTwoOutputs.clone(),
                verifyAlgorithmWithMultipleInputsAndOutputs.clone(),
                verifyAlgorithmWithTokensInMultipleInputsAndOutputs.clone(),
            ]
            .concat(),
        ),
    ]
});
