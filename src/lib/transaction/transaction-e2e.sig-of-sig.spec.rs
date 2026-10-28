//! Port of `transaction/transaction-e2e.sig-of-sig.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    create_virtual_machine_bch, decode_transaction_common, encode_transaction_common, extract_missing_variables,
    extract_resolved_variables, generate_transaction, hex_to_bin, import_wallet_template,
    locking_bytecode_to_cash_address, wallet_template_to_compiler_bch, AuthenticationVirtualMachineBch,
    BytecodeGenerationCompletion, BytecodeGenerationResult, CashAddressNetworkPrefix, CashAddressResult,
    CompilationData, CompilationDataHdKeys, CompilationDirectiveUnlocking, InputTemplate, InputUnlockingBytecode,
    Output, OutputLockingBytecode, OutputTemplate, ResolvedTransactionCommon, TransactionGenerationAttempt,
    TransactionGenerationSuccess, TransactionTemplateFixed,
};

use transaction_e2e_spec_helper::{
    hdPrivateKey0H, hdPrivateKey1H, hdPublicKey0H, hdPublicKey1H, sigOfSigJson,
};

thread_local! {
    static vm: AuthenticationVirtualMachineBch = create_virtual_machine_bch(None);
}

#[test]
fn transaction_e2e_tests_sig_of_sig_example() {
    let template = match import_wallet_template(&sigOfSigJson) {
        Err(error) => panic!("{error:?}"),
        Ok(template) => template,
    };

    // The HD public keys shared between the entities at wallet creation time
    let hd_public_keys = BTreeMap::from([
        ("signer_1".to_string(), hdPublicKey0H.to_string()),
        ("signer_2".to_string(), hdPublicKey1H.to_string()),
    ]);

    let locking_data = CompilationData {
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
            address: "bchtest:ppcvyjuqwhuz06np4us443l26dzck305psl0dw6as9".to_string(),
        })
    );

    let value_satoshis = 10000;
    let utxo_output = Output {
        locking_bytecode: locking_bytecode.clone(),
        token: None,
        value_satoshis,
    };

    // `{ ...input, unlockingBytecode: { ...input.unlockingBytecode, data } }`
    let input = |data: CompilationData| InputTemplate {
        outpoint_index: 1,
        outpoint_transaction_hash: hex_to_bin("1a3c3f950738c23de2461f04b2acd4dfb6b6eb80daeb457f24a6084c45c7da01"),
        sequence_number: 0,
        unlocking_bytecode: InputUnlockingBytecode::Compilation(CompilationDirectiveUnlocking {
            compiler: compiler.clone(),
            data: Some(data),
            script: "spend".to_string(),
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

    let signer1_attempt = generate_transaction(&transaction_proposal(vec![input(signer1_unlocking_data)]));

    let signer1_attempt = match signer1_attempt {
        TransactionGenerationAttempt::Success(success) => panic!("signer1Attempt: {success:?}"),
        TransactionGenerationAttempt::Error(error) => error,
    };

    assert_eq!(
        format!("{:?}", signer1_attempt.completions),
        format!("{:?}", Vec::<BytecodeGenerationCompletion>::new())
    );

    let signer1_missing_variables = extract_missing_variables(&signer1_attempt);

    assert_eq!(
        signer1_missing_variables,
        Some(BTreeMap::from([(
            "second.ecdsa_data_signature.first_signature".to_string(),
            "signer_2".to_string(),
        )])),
        "{signer1_missing_variables:?}"
    );

    let signer1_resolved_variables = extract_resolved_variables(&signer1_attempt);

    let expected_signer1_signature = hex_to_bin(
        "30440220097cf5732181c1b398909993b4e7794d6f1dc2d40fa803e4e92665e929ce75d40220208df3ba16d67f20f3063bde3234a131845f21a724ef29dad5086d75d76385ec41",
    );

    assert_eq!(
        signer1_resolved_variables,
        BTreeMap::from([
            (
                "first.ecdsa_signature.all_outputs".to_string(),
                expected_signer1_signature.clone()
            ),
            (
                "first.public_key".to_string(),
                hex_to_bin("0349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e46588"),
            ),
        ]),
        "{signer1_resolved_variables:?}"
    );

    // Signer 2 tries to sign (but needs Signer 1's signature)

    let signer2_unlocking_data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            hd_private_keys: Some(BTreeMap::from([("signer_2".to_string(), hdPrivateKey1H.to_string())])),
            ..locking_data.hd_keys.clone().unwrap()
        }),
        ..locking_data.clone()
    };

    let signer2_attempt = generate_transaction(&transaction_proposal(vec![input(signer2_unlocking_data.clone())]));

    if let TransactionGenerationAttempt::Success(success) = &signer2_attempt {
        panic!("signer2Attempt: {success:?}");
    }

    let successful_compilation = generate_transaction(&transaction_proposal(vec![input(CompilationData {
        bytecode: Some(
            signer2_unlocking_data
                .bytecode
                .clone()
                .unwrap_or_default()
                .into_iter()
                .chain([(
                    "first.ecdsa_signature.all_outputs".to_string(),
                    expected_signer1_signature,
                )])
                .collect(),
        ),
        ..signer2_unlocking_data
    })]));

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
                // tx: 47623fba38548005eb8e5773a288d3fa5898b80178e94296f7b9f82ee053560c
                transaction: decode_transaction_common(&hex_to_bin(
                    "020000000101dac7454c08a6247f45ebda80ebb6b6dfd4acb2041f46e23dc23807953f3c1a01000000f04730440220097cf5732181c1b398909993b4e7794d6f1dc2d40fa803e4e92665e929ce75d40220208df3ba16d67f20f3063bde3234a131845f21a724ef29dad5086d75d76385ec41210349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e4658846304402201673c0f6e8741bf2fd259411c212a2d7e326fe4c238118c0dbcab662ef439de10220259d9cf3414f662b83f5d7210e5b5890cdb64ee7e36f2187e6377c9e88a484613e52792102a438b1662aec9c35f85794600e1d2d3683a43cbb66307cf825fc4486b8469545bb76a91433c4f1d1e60cbe8eda7cf976752bbb313780c7db88ac000000000100000000000000000d6a0b68656c6c6f20776f726c6400000000"
                ))
                .unwrap(),
            })
        ),
        "{successful_compilation:?} - {:?}",
        encode_transaction_common(&transaction)
    );
}
