//! Port of `compiler/compiler-bch/compiler-bch.e2e.signing-serialization-algorithms.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;
use std::rc::Rc;

use libauth::{
    compiler_configuration_to_compiler_bch, compiler_operations_bch, create_authentication_program_evaluation_common,
    create_compilation_context_common_testing, create_virtual_machine_bch, generate_bytecode_map, hex_to_bin,
    ripemd160, secp256k1, sha256, sha512, AuthenticationVirtualMachineBch, BytecodeGenerationResult, CompilationData,
    CompilationDataHdKeys, CompilationDataKeys, CompilationError, CompilationErrorType, CompilationResultError,
    CompilerConfiguration, OpcodesBch, Range, WalletTemplateHdKey, WalletTemplateKey, WalletTemplateVariable,
    WalletTemplateVariableType,
};

use compiler_bch_e2e_spec_helper::{hdPrivateKey, privateKeyM0};

thread_local! {
    static vm: AuthenticationVirtualMachineBch = create_virtual_machine_bch(None);
}

/// The `testSigningSerializationAlgorithms` macro (`test.macro`).
fn test_signing_serialization_algorithms(unlock_script: &str, bytecode_hex: &str) {
    let compiler = compiler_configuration_to_compiler_bch(CompilerConfiguration {
        create_authentication_program: Some(Rc::new(create_authentication_program_evaluation_common)),
        entity_ownership: Some(BTreeMap::from([("b".to_string(), "entity".to_string())])),
        opcodes: Some(generate_bytecode_map(OpcodesBch::MEMBERS)),
        operations: Some(compiler_operations_bch()),
        ripemd160: Some(ripemd160.clone()),
        scripts: BTreeMap::from([
            (
                "lock".to_string(),
                "OP_DUP OP_HASH160 <$(<a.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG".to_string(),
            ),
            (
                "lockHd".to_string(),
                "OP_DUP OP_HASH160 <$(<b.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG".to_string(),
            ),
            ("unlock".to_string(), unlock_script.to_string()),
            // `unlockScript.replace(/a\./gu, 'b.')`
            ("unlockHd".to_string(), unlock_script.replace("a.", "b.")),
        ]),
        secp256k1: Some(secp256k1.clone()),
        sha256: Some(sha256.clone()),
        sha512: Some(sha512.clone()),
        unlocking_scripts: Some(BTreeMap::from([
            ("unlock".to_string(), "lock".to_string()),
            ("unlockHd".to_string(), "lockHd".to_string()),
        ])),
        variables: Some(BTreeMap::from([
            (
                "a".to_string(),
                WalletTemplateVariable::Key(WalletTemplateKey {
                    description: None,
                    name: None,
                    never_sign_twice: None,
                    r#type: WalletTemplateVariableType::Key,
                }),
            ),
            (
                "b".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/i".to_string()),
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            ),
        ])),
        vm: Some(vm.with(Clone::clone)),
        ..Default::default()
    });

    let result_unlock = compiler.generate_bytecode(
        &CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(None, None, None, None, None)),
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("a".to_string(), privateKeyM0.clone())])),
            }),
            ..Default::default()
        },
        "unlock",
    );
    let expected = BytecodeGenerationResult::Success {
        bytecode: hex_to_bin(bytecode_hex),
    };
    assert_eq!(
        format!("{result_unlock:?}"),
        format!("{expected:?}"),
        "Expected bytecode:\n {bytecode_hex:?} \n\nResult: {result_unlock:?}"
    );
    let result_unlock_hd = compiler.generate_bytecode(
        &CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(None, None, None, None, None)),
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("entity".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..Default::default()
        },
        "unlockHd",
    );
    assert_eq!(
        format!("{result_unlock_hd:?}"),
        format!("{expected:?}"),
        "Expected bytecode:\n {bytecode_hex:?} \n\nResult: {result_unlock_hd:?}"
    );
}

// [BCH compiler] signing serialization algorithms - ECDSA all_outputs
#[test]
fn bch_compiler_signing_serialization_algorithms_ecdsa_all_outputs() {
    test_signing_serialization_algorithms(
        "<a.ecdsa_signature.all_outputs> <a.public_key>",
        "483045022100f129fea5cb875fe5f35e3b2cf919aaf2211340cb49de5253db1d0726cf5f3b7c0220747c59400a81473510883199f59a3f957adf0418dff9d1549ed985bf0b66c4af41210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - ECDSA all_outputs_single_input
#[test]
fn bch_compiler_signing_serialization_algorithms_ecdsa_all_outputs_single_input() {
    test_signing_serialization_algorithms(
        "<a.ecdsa_signature.all_outputs_single_input> <a.public_key>",
        "47304402200bae7a74222909fd730299721e1b9b845ddff659416d21ef3b49ec3e2f6085a7022000d7de7820222acac078a757f80bc0849de0bfd33f99578735066853a20a9b62c1210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - ECDSA corresponding_output
#[test]
fn bch_compiler_signing_serialization_algorithms_ecdsa_corresponding_output() {
    test_signing_serialization_algorithms(
        "<a.ecdsa_signature.corresponding_output> <a.public_key>",
        "47304402204d4861ddd785319eeed198dfe58b39504a72669f9790d2e5d73b24c38cd3710d02200217272f27334ccf5526d51a599c55577dd7b7d2195f1fcf6766bf04d55d9b1643210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - ECDSA corresponding_output_single_input
#[test]
fn bch_compiler_signing_serialization_algorithms_ecdsa_corresponding_output_single_input() {
    test_signing_serialization_algorithms(
        "<a.ecdsa_signature.corresponding_output_single_input> <a.public_key>",
        "483045022100ee40b9616c0b7a9fca7456581f52c5e8ece708b4192cc4631193accc66b5874402200c2b86872c9aaba0363e5cc224e8e18d989cb7b0cb2d13700d730126de6eb842c3210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - ECDSA no_outputs
#[test]
fn bch_compiler_signing_serialization_algorithms_ecdsa_no_outputs() {
    test_signing_serialization_algorithms(
        "<a.ecdsa_signature.no_outputs> <a.public_key>",
        "47304402207402dd45907e09b8691ff1deac8699e1fa7c1a7d186021fab7867b1356f35ecc022012db0b990cce2bfc9a9ce12e5dc5d176ec118254d23169c5f7fcd49431e8cfc342210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - ECDSA no_outputs_single_input
#[test]
fn bch_compiler_signing_serialization_algorithms_ecdsa_no_outputs_single_input() {
    test_signing_serialization_algorithms(
        "<a.ecdsa_signature.no_outputs_single_input> <a.public_key>",
        "4730440220046fb453891c53a4d0a6a1df4f04a93977c214af364dc1de5eb6d681d054f11b02207cdef4f66779d5569ec3afceeca2b4cc6eb1f76eaea29034f0b301688f83021bc2210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - Schnorr all_outputs
#[test]
fn bch_compiler_signing_serialization_algorithms_schnorr_all_outputs() {
    test_signing_serialization_algorithms(
        "<a.schnorr_signature.all_outputs> <a.public_key>",
        "412000c439d7eb94cb7b501560a2e96fe9eb7d9a4083f0ab84408fb0fab97e51f6ed4d8a4d7aae3bc805afe3aa8b75f6bf74fa102529349c9d0d112d2c34ec9b2b41210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - Schnorr all_outputs_single_input
#[test]
fn bch_compiler_signing_serialization_algorithms_schnorr_all_outputs_single_input() {
    test_signing_serialization_algorithms(
        "<a.schnorr_signature.all_outputs_single_input> <a.public_key>",
        "417c0b312ffcc4be4d725e4badfef5735cf77027962ab0ac40d1327299d421299be9b04679a86ad296c4ca6cf7797d3ece597ba99ccab9792f8dabafb6cae66dc3c1210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - Schnorr corresponding_output
#[test]
fn bch_compiler_signing_serialization_algorithms_schnorr_corresponding_output() {
    test_signing_serialization_algorithms(
        "<a.schnorr_signature.corresponding_output> <a.public_key>",
        "410e510e6138c0f865555b103bee209d38d688c7cf7530f05d1ecdfb4bc8e0dcddf64d8b996c8d4b1f60e362e3c49686a6fd69d871774aa147e790b86470389f8c43210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - Schnorr corresponding_output_single_input
#[test]
fn bch_compiler_signing_serialization_algorithms_schnorr_corresponding_output_single_input() {
    test_signing_serialization_algorithms(
        "<a.schnorr_signature.corresponding_output_single_input> <a.public_key>",
        "4177d54e3b26ea81f0dfe49f9eb244af888abc9a7efc36da3087f3c014f0105bbd62a45831b3c786df4aa33593b3d325847cd2c0bbefc2e795cd6bd6f6c04949cfc3210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - Schnorr no_outputs
#[test]
fn bch_compiler_signing_serialization_algorithms_schnorr_no_outputs() {
    test_signing_serialization_algorithms(
        "<a.schnorr_signature.no_outputs> <a.public_key>",
        "4174f12e5c9bf9bb1e6c81e7d59b049392e39ddb9f4da5b411e3e6e6d0947ac18cf4a83d99014f297637472d1195a95eb06c3afa2ea70da1c7ff4b6c09bdae270042210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - Schnorr no_outputs_single_input
#[test]
fn bch_compiler_signing_serialization_algorithms_schnorr_no_outputs_single_input() {
    test_signing_serialization_algorithms(
        "<a.schnorr_signature.no_outputs_single_input> <a.public_key>",
        "41813954aa765ca52b752f65870f4b6026ebdbfb3a49054f42811b6abd2255262ea925d70168a776c04c2993bbaa894391f2acc05e23112853aa74633868bd28f4c2210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
    );
}

// [BCH compiler] signing serialization algorithms - no signing serialization data
#[test]
fn bch_compiler_signing_serialization_algorithms_no_signing_serialization_data() {
    let compiler = compiler_configuration_to_compiler_bch(CompilerConfiguration {
        create_authentication_program: Some(Rc::new(create_authentication_program_evaluation_common)),
        opcodes: Some(generate_bytecode_map(OpcodesBch::MEMBERS)),
        operations: Some(compiler_operations_bch()),
        scripts: BTreeMap::from([
            (
                "lock".to_string(),
                "OP_DUP OP_HASH160 <$(<a.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG".to_string(),
            ),
            (
                "unlock".to_string(),
                "<a.schnorr_signature.all_outputs> <a.public_key>".to_string(),
            ),
        ]),
        secp256k1: Some(secp256k1.clone()),
        sha256: Some(sha256.clone()),
        unlocking_scripts: Some(BTreeMap::from([("unlock".to_string(), "lock".to_string())])),
        variables: Some(BTreeMap::from([(
            "a".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        vm: Some(vm.with(Clone::clone)),
        ..Default::default()
    });

    let result_unlock = compiler.generate_bytecode(
        &CompilationData {
            compilation_context: None,
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("a".to_string(), privateKeyM0.clone())])),
            }),
            ..Default::default()
        },
        "unlock",
    );
    assert_eq!(
        format!("{result_unlock:?}"),
        format!(
            "{:?}",
            BytecodeGenerationResult::Error(CompilationResultError {
                error_type: CompilationErrorType::Resolve,
                errors: vec![CompilationError {
                    error: "Cannot resolve \"a.schnorr_signature.all_outputs\" - the \"compilationContext\" property was not provided in the compilation data.".to_string(),  
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 33,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                }],
                parse: None,
                reduce: None,
                resolve: None,
            })
        )
    );
}
