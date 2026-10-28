//! Port of `transaction/transaction-e2e.2-of-3.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    create_virtual_machine_bch, decode_transaction_common, encode_transaction_common, extract_missing_variables,
    extract_resolved_variables, generate_transaction, hex_to_bin, import_wallet_template,
    locking_bytecode_to_cash_address, safely_extend_compilation_data, wallet_template_to_compiler_bch,
    AuthenticationVirtualMachineBch, BytecodeGenerationCompletion, BytecodeGenerationResult, CashAddressNetworkPrefix,
    CashAddressResult, CompilationData, CompilationDataHdKeys, CompilationDirectiveUnlocking, InputTemplate,
    InputUnlockingBytecode, Output, OutputLockingBytecode, OutputTemplate, ResolvedTransactionCommon,
    TransactionGenerationAttempt, TransactionGenerationSuccess, TransactionTemplateFixed,
};

use transaction_e2e_spec_helper::{
    hdPrivateKey0H, hdPrivateKey2H, hdPublicKey0H, hdPublicKey1H, hdPublicKey2H, twoOfThreeJson,
};

thread_local! {
    static vm: AuthenticationVirtualMachineBch = create_virtual_machine_bch(None);
}

#[test]
fn transaction_e2e_tests_2_of_3_multisig() {
    let template = match import_wallet_template(&twoOfThreeJson) {
        Err(error) => panic!("{error}"),
        Ok(template) => template,
    };

    // The HD public keys shared between the entities at wallet creation time
    let hd_public_keys = BTreeMap::from([
        ("signer_1".to_string(), hdPublicKey0H.to_string()),
        ("signer_2".to_string(), hdPublicKey1H.to_string()),
        ("signer_3".to_string(), hdPublicKey2H.to_string()),
    ]);

    let locking_data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            address_index: Some(0.0),
            hd_public_keys: Some(hd_public_keys.clone()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let locking_script = "lock";
    let compiler = wallet_template_to_compiler_bch(&template, None);
    let locking_bytecode = match compiler.generate_bytecode(&locking_data, locking_script) {
        BytecodeGenerationResult::Error(error) => panic!("lockingBytecode: {error:?}"),
        BytecodeGenerationResult::Success { bytecode } => bytecode,
    };

    let address = locking_bytecode_to_cash_address(
        Some(CashAddressNetworkPrefix::Testnet.as_str()),
        &locking_bytecode,
        None,
    );

    assert_eq!(
        address,
        Ok(CashAddressResult {
            address: "bchtest:pplldqjpjaj0058xma6csnpgxd9ew2vxgv26n639yk".to_string(),
        })
    );

    let value_satoshis = 10000;
    let utxo_output = Output {
        locking_bytecode: locking_bytecode.clone(),
        token: None,
        value_satoshis,
    };

    // `{ ...input1, unlockingBytecode: { ...input1.unlockingBytecode, data } }`
    let input1 = |data: CompilationData| InputTemplate {
        outpoint_index: 1,
        outpoint_transaction_hash: hex_to_bin("3423be78a1976b4ae3516cda594577df004663ff24f1beb9d5bb63056b1b0a60"),
        sequence_number: 0,
        unlocking_bytecode: InputUnlockingBytecode::Compilation(CompilationDirectiveUnlocking {
            compiler: compiler.clone(),
            data: Some(data),
            script: "1_and_3".to_string(),
            token: None,
            value_satoshis: utxo_output.value_satoshis,
        }),
    };

    // `{ ...transactionProposal, inputs }`
    let transaction_proposal = |inputs: Vec<InputTemplate>| TransactionTemplateFixed {
        inputs,
        locktime: 0,
        outputs: vec![OutputTemplate {
            locking_bytecode: OutputLockingBytecode::Bytecode(hex_to_bin("6a0b68656c6c6f20776f726c64")),
            token: None,
            value_satoshis: 0,
        }],
        version: 2,
    };

    let signer1_unlocking_data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            hd_private_keys: Some(BTreeMap::from([("signer_1".to_string(), hdPrivateKey0H.to_string())])),
            ..locking_data.hd_keys.clone().unwrap()
        }),
        ..locking_data.clone()
    };

    let signer1_attempt = generate_transaction(&transaction_proposal(vec![input1(signer1_unlocking_data)]));

    let signer1_attempt = match signer1_attempt {
        TransactionGenerationAttempt::Success(success) => panic!("signer1Attempt: {success:?}"),
        TransactionGenerationAttempt::Error(error) => error,
    };

    let signer1_missing_variables = extract_missing_variables(&signer1_attempt);

    assert_eq!(
        signer1_missing_variables,
        Some(BTreeMap::from([(
            "key3.ecdsa_signature.all_outputs".to_string(),
            "signer_3".to_string()
        )]))
    );

    assert_eq!(
        format!("{:?}", signer1_attempt.completions),
        format!("{:?}", Vec::<BytecodeGenerationCompletion>::new())
    );

    let signer1_resolved_variables = extract_resolved_variables(&signer1_attempt);

    let expected_signer1_signature = hex_to_bin(
        "304402205e7d56c4e7854f9c672977d6606dd2f0af5494b8e61108e2a92fc920bf8049fc022065262675b0e1a3850d88bd3c56e0eb5fb463d9cdbe49f2f625da5c0f82c7653041",
    );

    assert_eq!(
        signer1_resolved_variables,
        BTreeMap::from([(
            "key1.ecdsa_signature.all_outputs".to_string(),
            expected_signer1_signature.clone()
        )]),
        "{signer1_resolved_variables:?}"
    );

    let signer3_unlocking_data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            address_index: Some(0.0),
            hd_private_keys: Some(BTreeMap::from([("signer_3".to_string(), hdPrivateKey2H.to_string())])),
            hd_public_keys: Some(hd_public_keys),
        }),
        ..Default::default()
    };

    let signer3_attempt = generate_transaction(&transaction_proposal(vec![input1(signer3_unlocking_data.clone())]));

    let signer3_attempt = match signer3_attempt {
        TransactionGenerationAttempt::Success(success) => panic!("signer3Attempt: {success:?}"),
        TransactionGenerationAttempt::Error(error) => error,
    };

    let signer3_unlocking_data_with_missing_variables = safely_extend_compilation_data(
        &signer3_attempt,
        &signer3_unlocking_data,
        &BTreeMap::from([("signer_1".to_string(), signer1_resolved_variables)]),
    )
    .expect("CompilationData");

    assert_eq!(
        signer3_unlocking_data_with_missing_variables,
        CompilationData {
            bytecode: Some(BTreeMap::from([(
                "key1.ecdsa_signature.all_outputs".to_string(),
                expected_signer1_signature,
            )])),
            ..signer3_unlocking_data
        },
        "{signer3_unlocking_data_with_missing_variables:?}"
    );

    let successful_compilation = generate_transaction(&transaction_proposal(vec![input1(
        signer3_unlocking_data_with_missing_variables,
    )]));

    let transaction = match &successful_compilation {
        TransactionGenerationAttempt::Error(error) => panic!("successfulCompilation: {error:?}"),
        TransactionGenerationAttempt::Success(success) => success.transaction.clone(),
    };

    let result = vm.with(|virtual_machine| {
        virtual_machine.verify(&ResolvedTransactionCommon {
            source_outputs: vec![utxo_output],
            transaction: transaction.clone(),
        })
    });
    assert!(result.is_ok(), "{result:?}");

    assert_eq!(
        format!("{successful_compilation:?}"),
        format!(
            "{:?}",
            TransactionGenerationAttempt::Success(TransactionGenerationSuccess {
                transaction: decode_transaction_common(
                    // tx: c903aba46b4069e485b51292fd68eefdc95110fb95461b118c650fb454c34a9c
                    &hex_to_bin(
                        "0200000001600a1b6b0563bbd5b9bef124ff634600df774559da6c51e34a6b97a178be233401000000fc0047304402205e7d56c4e7854f9c672977d6606dd2f0af5494b8e61108e2a92fc920bf8049fc022065262675b0e1a3850d88bd3c56e0eb5fb463d9cdbe49f2f625da5c0f82c765304147304402200d167d5ed77fa169346d295f6fb742e80ae391f0ae086d42b99152bdb23edf4102202c8b85c2583b07b66485b88cacdd14f680bd3aa3f3f12e9f63bc02b4d1cc6d15414c6952210349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e465882102a438b1662aec9c35f85794600e1d2d3683a43cbb66307cf825fc4486b84695452103d9fffac162e9e15aecbe4f937b951815ccb4f940c850fff9ee52fa70805ae7de53ae000000000100000000000000000d6a0b68656c6c6f20776f726c6400000000"
                    )
                )
                .unwrap(),
            })
        ),
        "{successful_compilation:?} - {:?}",
        encode_transaction_common(&transaction)
    );
}
