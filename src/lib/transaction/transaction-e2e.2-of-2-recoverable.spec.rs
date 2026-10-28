//! Port of `transaction/transaction-e2e.2-of-2-recoverable.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    compile_cash_assembly, create_virtual_machine_bch, date_to_locktime, decode_transaction_common,
    encode_transaction_common, extract_missing_variables, generate_transaction, hex_to_bin, import_wallet_template,
    locking_bytecode_to_cash_address, wallet_template_to_compiler_bch, AuthenticationVirtualMachineBch,
    BytecodeGenerationCompletion, BytecodeGenerationCompletionInput, BytecodeGenerationResult,
    CashAddressNetworkPrefix, CashAddressResult, CompilationData, CompilationDataHdKeys, CompilationDirectiveUnlocking,
    Input, InputTemplate, InputUnlockingBytecode, Output, OutputLockingBytecode, OutputTemplate,
    ResolvedTransactionCommon, TransactionGenerationAttempt, TransactionGenerationSuccess, TransactionTemplateFixed,
};

use transaction_e2e_spec_helper::{
    hdPrivateKey0H, hdPrivateKey1H, hdPrivateKey2H, hdPublicKey0H, hdPublicKey1H, hdPublicKey2H,
    twoOfTwoRecoverableJson,
};

thread_local! {
    static vm: AuthenticationVirtualMachineBch = create_virtual_machine_bch(None);
}

/// `{ ...data, bytecode: { ...data.bytecode, [identifier]: value } }`
fn with_bytecode(data: &CompilationData, identifier: &str, value: &[u8]) -> CompilationData {
    let mut bytecode = data.bytecode.clone().unwrap_or_default();
    bytecode.insert(identifier.to_string(), value.to_vec());
    CompilationData {
        bytecode: Some(bytecode),
        ..data.clone()
    }
}

#[test]
fn transaction_e2e_tests_2_of_2_recoverable_vault() {
    let template = match import_wallet_template(&twoOfTwoRecoverableJson) {
        Err(error) => panic!("{error}"),
        Ok(template) => template,
    };

    // The HD public keys shared between the entities at wallet creation time
    let hd_public_keys = BTreeMap::from([
        ("signer_1".to_string(), hdPublicKey0H.to_string()),
        ("signer_2".to_string(), hdPublicKey1H.to_string()),
        ("trusted_party".to_string(), hdPublicKey2H.to_string()),
    ]);

    // `dateToLocktime(new Date('2020-01-01T00:00:00.000Z')) as number`
    let creation_date = date_to_locktime(1577836800000).unwrap();

    let three_months = 60 * 60 * 24 * 90;
    // `dateToLocktime(new Date('2020-04-01T00:00:00.000Z')) as number`
    let locktime_four_months_later = date_to_locktime(1585699200000).unwrap();

    let locking_data = CompilationData {
        bytecode: Some(BTreeMap::from([(
            "delay_seconds".to_string(),
            compile_cash_assembly(&format!("{three_months}")).unwrap(),
        )])),
        current_block_time: Some(f64::from(creation_date)),
        hd_keys: Some(CompilationDataHdKeys {
            address_index: Some(0.0),
            hd_public_keys: Some(hd_public_keys),
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
            address: "bchtest:pz8p649zg3a492hxy86sh0ccvc7sptrlx5cp3eapah".to_string(),
        })
    );

    let value_satoshis = 10000;
    let utxo_output1 = Output {
        locking_bytecode: locking_bytecode.clone(),
        token: None,
        value_satoshis,
    };

    let utxo_output2 = Output {
        locking_bytecode: locking_bytecode.clone(),
        token: None,
        value_satoshis,
    };

    // Test standard spend:
    let input1_outpoint_transaction_hash =
        hex_to_bin("6168cbf5d24784df4fef46e1e5cfacaee14cda4c29dd8114b9cfc44972aea46a");
    // `{ ...input1, unlockingBytecode: { ...input1.unlockingBytecode, data } }`
    let input1 = |data: CompilationData| InputTemplate {
        outpoint_index: 0,
        outpoint_transaction_hash: input1_outpoint_transaction_hash.clone(),
        sequence_number: 0,
        unlocking_bytecode: InputUnlockingBytecode::Compilation(CompilationDirectiveUnlocking {
            compiler: compiler.clone(),
            data: Some(data),
            script: "spend".to_string(),
            token: None,
            value_satoshis: utxo_output1.value_satoshis,
        }),
    };

    // Test delayed recovery (in the same TX to make a useful reference TX):
    let input2 = |data: CompilationData| InputTemplate {
        outpoint_index: 1,
        outpoint_transaction_hash: hex_to_bin("0ce50e17e71dadd8ba59e89a291cf3082862b32b229c5fbfc8dee3288165d97c"),
        sequence_number: 0,
        unlocking_bytecode: InputUnlockingBytecode::Compilation(CompilationDirectiveUnlocking {
            compiler: compiler.clone(),
            data: Some(data),
            script: "recover_1".to_string(),
            token: None,
            value_satoshis: utxo_output2.value_satoshis,
        }),
    };

    // `{ ...transactionProposal, inputs }`
    let transaction_proposal = |inputs: Vec<InputTemplate>| TransactionTemplateFixed {
        inputs,
        locktime: locktime_four_months_later,
        outputs: vec![OutputTemplate {
            locking_bytecode: OutputLockingBytecode::Bytecode(hex_to_bin("6a0b68656c6c6f20776f726c64")),
            token: None,
            value_satoshis: 0,
        }],
        version: 2,
    };

    let with_hd_private_keys = |entity_id: &str, hd_private_key: &str| CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            hd_private_keys: Some(BTreeMap::from([(entity_id.to_string(), hd_private_key.to_string())])),
            ..locking_data.hd_keys.clone().unwrap()
        }),
        ..locking_data.clone()
    };

    let signer1_unlocking_data = with_hd_private_keys("signer_1", hdPrivateKey0H);

    let signer1_attempt = generate_transaction(&transaction_proposal(vec![
        input1(signer1_unlocking_data.clone()),
        input2(signer1_unlocking_data),
    ]));

    let signer1_attempt = match signer1_attempt {
        TransactionGenerationAttempt::Success(success) => panic!("signer1Attempt: {success:?}"),
        TransactionGenerationAttempt::Error(error) => error,
    };

    let signer1_missing_variables = extract_missing_variables(&signer1_attempt);

    assert_eq!(
        signer1_missing_variables,
        Some(BTreeMap::from([
            ("second.ecdsa_signature.all_outputs".to_string(), "signer_2".to_string()),
            (
                "trusted.ecdsa_signature.all_outputs".to_string(),
                "trusted_party".to_string()
            ),
        ]))
    );

    assert_eq!(
        format!("{:?}", signer1_attempt.completions),
        format!("{:?}", Vec::<BytecodeGenerationCompletion>::new())
    );

    let expected_signer1_signature_input1 = hex_to_bin(
        "304402200a34f3387a8aa3d7ed55506fbddb6957e27cc42063410306ac82e7a77f4d7030022065b08d5a07fac82d1cd6c90ff126f1af965e541525676538eab088b99daa897b41",
    );
    let expected_signer1_signature_input2 = hex_to_bin(
        "3044022028141930f622819de84cf1a1b42fc2ea15c56bafd45e768c72fd84b4d0fe5b7e022066f659c79e6d8b6c53561be0b472bbeb355ffa443828fd8fb083148ffd26e8c841",
    );

    // Signer 2 adds their signature, pulling in missing variables from signer 1

    let signer2_unlocking_data = with_hd_private_keys("signer_2", hdPrivateKey1H);

    let signer2_attempt = generate_transaction(&transaction_proposal(vec![
        input1(signer2_unlocking_data.clone()),
        input2(signer2_unlocking_data.clone()),
    ]));

    if let TransactionGenerationAttempt::Success(success) = &signer2_attempt {
        panic!("signer2Attempt: {success:?}");
    }

    let signer2_attempt2 = generate_transaction(&transaction_proposal(vec![
        input1(with_bytecode(
            &signer2_unlocking_data,
            "first.ecdsa_signature.all_outputs",
            &expected_signer1_signature_input1,
        )),
        input2(with_bytecode(
            &signer2_unlocking_data,
            "first.ecdsa_signature.all_outputs",
            &expected_signer1_signature_input2,
        )),
    ]));

    let signer2_attempt2 = match signer2_attempt2 {
        TransactionGenerationAttempt::Success(success) => panic!("signer2Attempt2: {success:?}"),
        TransactionGenerationAttempt::Error(error) => error,
    };

    let signer2_attempt2_missing_variables = extract_missing_variables(&signer2_attempt2);

    assert_eq!(
        signer2_attempt2_missing_variables,
        Some(BTreeMap::from([(
            "trusted.ecdsa_signature.all_outputs".to_string(),
            "trusted_party".to_string()
        )]))
    );

    assert_eq!(
        format!("{:?}", signer2_attempt2.completions),
        format!(
            "{:?}",
            vec![BytecodeGenerationCompletion::Input(BytecodeGenerationCompletionInput {
                index: 0,
                // `{ ...input1, unlockingBytecode: hexToBin('...') }`
                input: Input {
                    outpoint_index: 0,
                    outpoint_transaction_hash: input1_outpoint_transaction_hash.clone(),
                    sequence_number: 0,
                    unlocking_bytecode: hex_to_bin(
                        "0047304402200a34f3387a8aa3d7ed55506fbddb6957e27cc42063410306ac82e7a77f4d7030022065b08d5a07fac82d1cd6c90ff126f1af965e541525676538eab088b99daa897b4147304402207d987a4d736fb6abb5f90109da05411e515c212c3b2c8527d15e8d863fe83957022004ad83f50e7b1ae87665c211717caca4b9e9714cd2d27bc4759cf6482394c9f641004c7563040088825eb1752103d9fffac162e9e15aecbe4f937b951815ccb4f940c850fff9ee52fa70805ae7dead51675268210349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e465882102a438b1662aec9c35f85794600e1d2d3683a43cbb66307cf825fc4486b846954552ae"
                    ),
                },
            })]
        ),
        "{:?}",
        signer2_attempt2.completions
    );

    let BytecodeGenerationCompletion::Input(BytecodeGenerationCompletionInput {
        input: completed_input1,
        ..
    }) = signer2_attempt2.completions[0].clone()
    else {
        panic!("the first completion is an input");
    };
    // `completedInput1` (an `Input`) used as an input template
    let completed_input1 = InputTemplate {
        outpoint_index: completed_input1.outpoint_index,
        outpoint_transaction_hash: completed_input1.outpoint_transaction_hash,
        sequence_number: completed_input1.sequence_number,
        unlocking_bytecode: InputUnlockingBytecode::Bytecode(completed_input1.unlocking_bytecode),
    };

    // Signer 3 adds their signature, pulling in the completed first input

    let signer3_unlocking_data = with_hd_private_keys("trusted_party", hdPrivateKey2H);

    let signer3_attempt = generate_transaction(&transaction_proposal(vec![
        completed_input1.clone(),
        input2(signer3_unlocking_data.clone()),
    ]));

    if let TransactionGenerationAttempt::Success(success) = &signer3_attempt {
        panic!("signer3Attempt: {success:?}");
    }

    let successful_compilation = generate_transaction(&transaction_proposal(vec![
        completed_input1,
        input2(with_bytecode(
            &signer3_unlocking_data,
            "first.ecdsa_signature.all_outputs",
            &expected_signer1_signature_input2,
        )),
    ]));

    let transaction = match &successful_compilation {
        TransactionGenerationAttempt::Error(error) => panic!("successfulCompilation: {error:?}"),
        TransactionGenerationAttempt::Success(success) => success.transaction.clone(),
    };

    let result = vm.with(|virtual_machine| {
        virtual_machine.verify(&ResolvedTransactionCommon {
            source_outputs: vec![utxo_output1, utxo_output2],
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
                    // tx: e6c808adcb3cfc06461e962373659554bf6c447ea7b25ac503ff429e21050755
                    &hex_to_bin(
                        "02000000026aa4ae7249c4cfb91481dd294cda4ce1aeaccfe5e146ef4fdf8447d2f5cb686100000000fd09010047304402200a34f3387a8aa3d7ed55506fbddb6957e27cc42063410306ac82e7a77f4d7030022065b08d5a07fac82d1cd6c90ff126f1af965e541525676538eab088b99daa897b4147304402207d987a4d736fb6abb5f90109da05411e515c212c3b2c8527d15e8d863fe83957022004ad83f50e7b1ae87665c211717caca4b9e9714cd2d27bc4759cf6482394c9f641004c7563040088825eb1752103d9fffac162e9e15aecbe4f937b951815ccb4f940c850fff9ee52fa70805ae7dead51675268210349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e465882102a438b1662aec9c35f85794600e1d2d3683a43cbb66307cf825fc4486b846954552ae000000007cd9658128e3dec8bf5f9c222bb3622808f31c299ae859bad8ad1de7170ee50c01000000fd0a0100473044022028141930f622819de84cf1a1b42fc2ea15c56bafd45e768c72fd84b4d0fe5b7e022066f659c79e6d8b6c53561be0b472bbeb355ffa443828fd8fb083148ffd26e8c841483045022100d62f54380b58b99677467a4016fceffd1cd85adabe6d2ffffab61a7e599dc5d302207a43e7809e5afae5069cef08d5f4960adcb9d245d295bbdf6bb8ab9a9056d11441514c7563040088825eb1752103d9fffac162e9e15aecbe4f937b951815ccb4f940c850fff9ee52fa70805ae7dead51675268210349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e465882102a438b1662aec9c35f85794600e1d2d3683a43cbb66307cf825fc4486b846954552ae000000000100000000000000000d6a0b68656c6c6f20776f726c6480d9835e"
                    )
                )
                .unwrap(),
            })
        ),
        "{successful_compilation:?} - {:?}",
        encode_transaction_common(&transaction)
    );
}
