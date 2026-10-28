//! Port of `transaction/transaction-e2e.p2pkh.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    decode_transaction_common, generate_transaction, hex_to_bin, import_wallet_template,
    locking_bytecode_to_cash_address, wallet_template_to_compiler_bch, BytecodeGenerationResult,
    CashAddressNetworkPrefix, CashAddressResult, CompilationData, CompilationDataHdKeys, CompilationDirectiveUnlocking,
    InputTemplate, InputUnlockingBytecode, OutputLockingBytecode, OutputTemplate, TransactionGenerationAttempt,
    TransactionGenerationSuccess, TransactionTemplateFixed,
};

use transaction_e2e_spec_helper::{hdPrivateKey, hdPublicKey, p2pkhJson};

#[test]
fn transaction_e2e_tests_p2pkh_wallet_template_p2pkh_hd() {
    let template = match import_wallet_template(&p2pkhJson) {
        Err(error) => panic!("{error}"),
        Ok(template) => template,
    };

    let locking_script = "lock";

    // Available to observer
    let locking_data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            address_index: Some(0.0),
            hd_public_keys: Some(BTreeMap::from([("owner".to_string(), hdPublicKey.to_string())])),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Only available to owner
    let unlocking_data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            address_index: Some(0.0),
            hd_private_keys: Some(BTreeMap::from([("owner".to_string(), hdPrivateKey.to_string())])),
            ..Default::default()
        }),
        ..Default::default()
    };

    let compiler = wallet_template_to_compiler_bch(&template, None);
    let locking_bytecode = match compiler.generate_bytecode(&locking_data, locking_script) {
        BytecodeGenerationResult::Error(error) => panic!("lockingBytecode: {error:?}"),
        BytecodeGenerationResult::Success { bytecode } => bytecode,
    };

    assert_eq!(
        locking_bytecode_to_cash_address(
            Some(CashAddressNetworkPrefix::Testnet.as_str()),
            &locking_bytecode,
            None
        ),
        Ok(CashAddressResult {
            address: "bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x".to_string(),
        })
    );

    let utxo_outpoint_transaction_hash = hex_to_bin("68127de83d2ab77d7f5fd8d2ac6181d94473c0cbb2d0776084bf28884f6ecd77");

    let satoshis = 1000000;
    let result = generate_transaction(&TransactionTemplateFixed {
        inputs: vec![InputTemplate {
            outpoint_index: 1,
            outpoint_transaction_hash: utxo_outpoint_transaction_hash,
            sequence_number: 0,
            unlocking_bytecode: InputUnlockingBytecode::Compilation(CompilationDirectiveUnlocking {
                compiler,
                data: Some(unlocking_data),
                script: "unlock".to_string(),
                token: None,
                value_satoshis: satoshis,
            }),
        }],
        locktime: 0,
        outputs: vec![OutputTemplate {
            locking_bytecode: OutputLockingBytecode::Bytecode(hex_to_bin("6a0b68656c6c6f20776f726c64")),
            token: None,
            value_satoshis: 0,
        }],
        version: 2,
    });

    if let TransactionGenerationAttempt::Error(error) = &result {
        panic!("result: {error:?}");
    }

    assert_eq!(
        format!("{result:?}"),
        format!(
            "{:?}",
            TransactionGenerationAttempt::Success(TransactionGenerationSuccess {
                transaction: decode_transaction_common(&hex_to_bin(
                    "020000000177cd6e4f8828bf846077d0b2cbc07344d98161acd2d85f7f7db72a3de87d1268010000006441f87a1dc0fb4a30443fdfcc678e713d99cffb963bd52b497377e81abe2cc2b5ac6e9837fab0a23f4d05fd06b80e7673a68bfa8d2f66b7ec5537e88696d7bae1b841210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5000000000100000000000000000d6a0b68656c6c6f20776f726c6400000000"
                ))
                .unwrap(),
            })
        )
    );
}
