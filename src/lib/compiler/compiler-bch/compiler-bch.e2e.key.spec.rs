//! Port of `compiler/compiler-bch/compiler-bch.e2e.key.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    hex_to_bin, BytecodeGenerationResult, CompilationData, CompilationDataKeys, CompilationError, CompilationErrorType,
    CompilationResultError, CompilerConfiguration, Range, WalletTemplateKey, WalletTemplateVariable,
    WalletTemplateVariableType,
};

use compiler_bch_e2e_spec_helper::{expect_compilation_result, privateKeyM0};

// [BCH compiler] Key - errors on deprecated "signature" operation
#[test]
fn bch_compiler_key_errors_on_deprecated_signature_operation() {
    expect_compilation_result(
        "<owner.signature.anything>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"signature\" compiler operation was renamed to \"ecdsa_signature\". Consider fixing this error by changing \"owner.signature.anything\" to \"owner.schnorr_signature.anything\" (schnorr signatures reduce transaction sizes and enable multi-party signature aggregation).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 26,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - ECDSA: use a private key (".ecdsa_signature")
#[test]
fn bch_compiler_key_ecdsa_use_a_private_key_ecdsa_signature() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "473044022023aafaded9a737022375e895d752466760c98fdd40841dc0b1c9dff6eb884469022035672abd7d7402d9b9791805d78581fa1e23cea7f1887ee80ea346ca75ee3f1f41",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - schnorr: use a private key
#[test]
fn bch_compiler_key_schnorr_use_a_private_key() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "41dc748427ac03d7436efeed4a8a2deef63522dd60f2b401302e7120b6117b440e858571c17d5a4b66646c52093100f9242569767cc1a510c522ccfc36019eea8641",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - derive a public key from a private key
#[test]
fn bch_compiler_key_derive_a_public_key_from_a_private_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5"),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - derive a public key: no secp256k1
#[test]
fn bch_compiler_key_derive_a_public_key_no_secp256k1() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.public_key\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] Key - use a provided public key (without secp256k1)
#[test]
fn bch_compiler_key_use_a_provided_public_key_without_secp256k1() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.public_key".to_string(),
                hex_to_bin("0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5"),
            )])),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "Could not validate compilation data: the public key provided for \"owner.public_key\" could not be validated because the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 0,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] Key - public_key: no matching public or private keys
#[test]
fn bch_compiler_key_public_key_no_matching_public_or_private_keys() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::new()),
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::new()),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.public_key\" refers to a public key, but no public or private keys for \"owner\" were provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.public_key".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - public_key: invalid private key (insufficient length)
#[test]
fn bch_compiler_key_public_key_invalid_private_key_insufficient_length() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::new()),
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), vec![1, 2, 3])])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "Invalid compilation data detected: the private key provided for the \"owner\" variable is not a valid Secp256k1 private key.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 0,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - public_key: invalid private key (exceeds maximum)
#[test]
fn bch_compiler_key_public_key_invalid_private_key_exceeds_maximum() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::new()),
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([(
                    "owner".to_string(),
                    hex_to_bin("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
                )])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "Invalid compilation data detected: the private key provided for the \"owner\" variable is not a valid Secp256k1 private key.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 0,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - ECDSA: use a provided signature (without secp256k1)
#[test]
fn bch_compiler_key_ecdsa_use_a_provided_signature_without_secp256k1() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.ecdsa_signature.all_outputs".to_string(),
                hex_to_bin(
                    "3044022059e9ad8fabd511fa2ef6935dae6395d5d3ce93b929436c835c9c8372b353bd3d0220527c17e2e4ec12f7b8969a9bb80e58ab1a24e44c2e5512916d1bcb3fc4dc2f2241",
                ),
            )])),
            keys: Some(CompilationDataKeys { private_keys: None }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "473044022059e9ad8fabd511fa2ef6935dae6395d5d3ce93b929436c835c9c8372b353bd3d0220527c17e2e4ec12f7b8969a9bb80e58ab1a24e44c2e5512916d1bcb3fc4dc2f2241",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] Key - schnorr: use a provided signature
#[test]
fn bch_compiler_key_schnorr_use_a_provided_signature() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.schnorr_signature.all_outputs".to_string(),
                hex_to_bin(
                    "313d8a853bd82f5fe251d6b04581333800001ee7680c5e4775db3afabf4873360b3481802d8d656cc608e4625d6568bf1a8801bb1efff19a8306267681177aed41",
                ),
            )])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "41313d8a853bd82f5fe251d6b04581333800001ee7680c5e4775db3afabf4873360b3481802d8d656cc608e4625d6568bf1a8801bb1efff19a8306267681177aed41",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - malformed identifier
#[test]
fn bch_compiler_key_malformed_identifier() {
    expect_compilation_result(
        "<owner.ecdsa_signature>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Invalid signature identifier. Signatures must be of the form: \"[variable_id].ecdsa_signature.[signing_serialization_type]\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 23,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - ECDSA: wrong private key
#[test]
fn bch_compiler_key_ecdsa_wrong_private_key() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("wrong".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.ecdsa_signature.all_outputs\" refers to a Key, but a private key for \"owner\" (or an existing signature) was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.ecdsa_signature.all_outputs".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - schnorr: wrong private key
#[test]
fn bch_compiler_key_schnorr_wrong_private_key() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("wrong".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.schnorr_signature.all_outputs\" refers to a Key, but a private key for \"owner\" (or an existing signature) was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.schnorr_signature.all_outputs".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - signature with no "privateKeys"
#[test]
fn bch_compiler_key_signature_with_no_private_keys() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys { private_keys: None }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.schnorr_signature.all_outputs\" refers to a Key, but a private key for \"owner\" (or an existing signature) was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.schnorr_signature.all_outputs".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - ECDSA: unknown signing serialization algorithm
#[test]
fn bch_compiler_key_ecdsa_unknown_signing_serialization_algorithm() {
    expect_compilation_result(
        "<owner.ecdsa_signature.another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown signing serialization algorithm, \"another\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 31,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - schnorr: unknown signing serialization algorithm
#[test]
fn bch_compiler_key_schnorr_unknown_signing_serialization_algorithm() {
    expect_compilation_result(
        "<owner.schnorr_signature.another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown signing serialization algorithm, \"another\".".to_string(),
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
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - unrecognized identifier fragment
#[test]
fn bch_compiler_key_unrecognized_identifier_fragment() {
    expect_compilation_result(
        "<owner.ecdsa_signature.some.future_operation.with_more_levels>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown component in \"owner.ecdsa_signature.some.future_operation.with_more_levels\" - the fragment \"future_operation\" is not recognized.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 62,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        None,
    );
}

// [BCH compiler] Key - ECDSA: no secp256k1
#[test]
fn bch_compiler_key_ecdsa_no_secp256k1() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_signature.all_outputs\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] Key - schnorr: no secp256k1
#[test]
fn bch_compiler_key_schnorr_no_secp256k1() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.schnorr_signature.all_outputs\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] Key - ECDSA: no sha256
#[test]
fn bch_compiler_key_ecdsa_no_sha256() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_signature.all_outputs\" - the \"sha256\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            sha256: None,
            ..configuration
        }),
    );
}

// [BCH compiler] Key - schnorr: no sha256
#[test]
fn bch_compiler_key_schnorr_no_sha256() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.schnorr_signature.all_outputs\" - the \"sha256\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            sha256: None,
            ..configuration
        }),
    );
}

// [BCH compiler] Key - error in coveredBytecode compilation
#[test]
fn bch_compiler_key_error_in_covered_bytecode_compilation() {
    expect_compilation_result(
        "",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Compilation error in resolved script \"lock\": [1, 1] Unknown identifier \"invalid\"."
                    .to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            scripts: BTreeMap::from([
                ("lock".to_string(), "invalid".to_string()),
                ("test".to_string(), "<owner.ecdsa_signature.all_outputs>".to_string()),
            ]),
            ..configuration
        }),
    );
}
