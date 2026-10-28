//! Port of `compiler/compiler-bch/compiler-bch.e2e.data-signatures.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    hex_to_bin, BytecodeGenerationResult, CompilationData, CompilationDataHdKeys, CompilationDataKeys,
    CompilationError, CompilationErrorType, CompilationResultError, CompilerConfiguration, Range, WalletTemplateHdKey,
    WalletTemplateKey, WalletTemplateVariable, WalletTemplateVariableType,
};

use compiler_bch_e2e_spec_helper::{expect_compilation_result, hdPrivateKey, privateKeyM0};

// [BCH compiler] data signatures - use a private key
#[test]
fn bch_compiler_data_signatures_use_a_private_key() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.another> <another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "463044022100de1a02c286421ca34e854b9a01449ff8f19c46dfa4397de563d5f694db9d3855021f55b7bf7cd14189f6e1dca08d9a7cdf9b5c38a5bddbd0168aa33d34666950a003abcdef",
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

// [BCH compiler] data signatures - keys error on deprecated "data_signature" operation
#[test]
fn bch_compiler_data_signatures_keys_error_on_deprecated_data_signature_operation() {
    expect_compilation_result(
        "<owner.data_signature.another> <another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"data_signature\" compiler operation was renamed to \"ecdsa_data_signature\". Consider fixing this error by changing \"owner.data_signature.another\" to \"owner.schnorr_data_signature.another\" (schnorr signatures reduce transaction sizes and enable multi-party signature aggregation).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 30,
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

// [BCH compiler] data signatures - use a provided signature
#[test]
fn bch_compiler_data_signatures_use_a_provided_signature() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.another> <another>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.ecdsa_data_signature.another".to_string(),
                hex_to_bin(
                    "3044022100de1a02c286421ca34e854b9a01449ff8f19c46dfa4397de563d5f694db9d3855021f55b7bf7cd14189f6e1dca08d9a7cdf9b5c38a5bddbd0168aa33d34666950a0",
                ),
            )])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "463044022100de1a02c286421ca34e854b9a01449ff8f19c46dfa4397de563d5f694db9d3855021f55b7bf7cd14189f6e1dca08d9a7cdf9b5c38a5bddbd0168aa33d34666950a003abcdef",
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

// [BCH compiler] data signatures - require a script ID
#[test]
fn bch_compiler_data_signatures_require_a_script_id() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Invalid data signature identifier. Data signatures must be of the form: \"[variable_id].ecdsa_data_signature.[target_script_id]\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 28,
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

// [BCH compiler] data signatures - error on unknown script ID
#[test]
fn bch_compiler_data_signatures_error_on_unknown_script_id() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.wrong>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Data signature tried to sign an unknown target script, \"wrong\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 34,
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

// [BCH compiler] data signatures - error on script ID of broken script
#[test]
fn bch_compiler_data_signatures_error_on_script_id_of_broken_script() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.broken>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Compilation error in resolved script \"broken\": [1, 1] Unknown identifier \"does_not_exist\"."
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
        None,
    );
}

// [BCH compiler] data signatures - no private keys
#[test]
fn bch_compiler_data_signatures_no_private_keys() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.another> <another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys { private_keys: None }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.ecdsa_data_signature.another\" refers to a Key, but a private key for \"owner\" (or an existing signature) was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.ecdsa_data_signature.another".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 36,
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

// [BCH compiler] data signatures - necessary private key not provided
#[test]
fn bch_compiler_data_signatures_necessary_private_key_not_provided() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.another> <another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("wrong".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_data_signature.another\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 36,
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

// [BCH compiler] data signatures - no secp256k1
#[test]
fn bch_compiler_data_signatures_no_secp256k1() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.another> <another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_data_signature.another\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 36,
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

// [BCH compiler] data signatures - no sha256
#[test]
fn bch_compiler_data_signatures_no_sha256() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.another> <another>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_data_signature.another\" - the \"sha256\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 36,
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

// [BCH compiler] data signatures - unrecognized identifier fragment
#[test]
fn bch_compiler_data_signatures_unrecognized_identifier_fragment() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.some.future_operation.with_more_levels>",
        |data| CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown component in \"owner.ecdsa_data_signature.some.future_operation.with_more_levels\" - the fragment \"future_operation\" is not recognized.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 67,
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

// [BCH compiler] data signatures - use an HD private key
#[test]
fn bch_compiler_data_signatures_use_an_hd_private_key() {
    expect_compilation_result(
        "<owner.ecdsa_data_signature.another> <another>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "463044022100de1a02c286421ca34e854b9a01449ff8f19c46dfa4397de563d5f694db9d3855021f55b7bf7cd14189f6e1dca08d9a7cdf9b5c38a5bddbd0168aa33d34666950a003abcdef",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] data signatures - HD keys error on deprecated "data_signature" operation
#[test]
fn bch_compiler_data_signatures_hd_keys_error_on_deprecated_data_signature_operation() {
    expect_compilation_result(
        "<owner.data_signature.another> <another>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"data_signature\" compiler operation was renamed to \"ecdsa_data_signature\". Consider fixing this error by changing \"owner.data_signature.another\" to \"owner.schnorr_data_signature.another\" (schnorr signatures reduce transaction sizes and enable multi-party signature aggregation).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 30,
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
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}
