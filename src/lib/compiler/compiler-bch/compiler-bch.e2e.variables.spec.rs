//! Port of `compiler/compiler-bch/compiler-bch.e2e.variables.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    hex_to_bin, BytecodeGenerationResult, CompilationData, CompilationError, CompilationErrorType,
    CompilationResultError, CompilerConfiguration, Range, WalletTemplateAddressData, WalletTemplateHdKey,
    WalletTemplateKey, WalletTemplateVariable, WalletTemplateVariableType, WalletTemplateWalletData,
};

use compiler_bch_e2e_spec_helper::expect_compilation_result;

// [BCH compiler] variables - AddressData
#[test]
fn bch_compiler_variables_address_data() {
    expect_compilation_result(
        "<data>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([("data".to_string(), vec![0xab, 0xcd])])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("02abcd"),
        },
        Some(BTreeMap::from([(
            "data".to_string(),
            WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                description: Some("the description".to_string()),
                name: Some("Data".to_string()),
                r#type: WalletTemplateVariableType::AddressData,
            }),
        )])),
        None,
    );
}

// [BCH compiler] variables - multiple AddressData
#[test]
fn bch_compiler_variables_multiple_address_data() {
    expect_compilation_result(
        "<one> <two>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([
                ("one".to_string(), vec![0xab, 0xcd]),
                ("two".to_string(), vec![0xef, 0xab]),
            ])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("02abcd02efab"),
        },
        Some(BTreeMap::from([
            (
                "one".to_string(),
                WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                    description: Some("no name".to_string()),
                    name: None,
                    r#type: WalletTemplateVariableType::AddressData,
                }),
            ),
            (
                "two".to_string(),
                WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                    description: None,
                    name: Some("no description".to_string()),
                    r#type: WalletTemplateVariableType::AddressData,
                }),
            ),
        ])),
        None,
    );
}

// [BCH compiler] variables - missing AddressData
#[test]
fn bch_compiler_variables_missing_address_data() {
    expect_compilation_result(
        "<one> <two>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![
                CompilationError {
                    error:
                        "Cannot resolve \"one\" - the \"bytecode\" property was not provided in the compilation data."
                            .to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                },
                CompilationError {
                    error:
                        "Cannot resolve \"two\" - the \"bytecode\" property was not provided in the compilation data."
                            .to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 11,
                        end_line_number: 1,
                        start_column: 8,
                        start_line_number: 1,
                    },
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([
            (
                "one".to_string(),
                WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::AddressData,
                }),
            ),
            (
                "two".to_string(),
                WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::AddressData,
                }),
            ),
        ])),
        None,
    );
}

// [BCH compiler] variables - incomplete bytecode
#[test]
fn bch_compiler_variables_incomplete_bytecode() {
    expect_compilation_result(
        "<one> <two>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::new()),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![
                CompilationError {
                    error: "Identifier \"one\" refers to an AddressData, but \"one\" was not provided in the CompilationData \"bytecode\".".to_string(),
                    missing_identifier: Some("one".to_string()),
                    owning_entity: Some("ownerEntityOne".to_string()),
                    range: Range {
                        end_column: 5,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                },
                CompilationError {
                    error: "Identifier \"two\" refers to an AddressData, but \"two\" was not provided in the CompilationData \"bytecode\".".to_string(),
                    missing_identifier: Some("two".to_string()),
                    owning_entity: Some("ownerEntityTwo".to_string()),
                    range: Range {
                        end_column: 11,
                        end_line_number: 1,
                        start_column: 8,
                        start_line_number: 1,
                    },
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([
            (
                "one".to_string(),
                WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::AddressData,
                }),
            ),
            (
                "two".to_string(),
                WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::AddressData,
                }),
            ),
        ])),
        None,
    );
}

// [BCH compiler] variables - WalletData
#[test]
fn bch_compiler_variables_wallet_data() {
    expect_compilation_result(
        "<data>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([("data".to_string(), vec![0xab, 0xcd])])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("02abcd"),
        },
        Some(BTreeMap::from([(
            "data".to_string(),
            WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                description: Some("the description".to_string()),
                name: Some("Data".to_string()),
                r#type: WalletTemplateVariableType::WalletData,
            }),
        )])),
        None,
    );
}

// [BCH compiler] variables - multiple WalletData
#[test]
fn bch_compiler_variables_multiple_wallet_data() {
    expect_compilation_result(
        "<one> <two>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([
                ("one".to_string(), vec![0xab, 0xcd]),
                ("two".to_string(), vec![0xef, 0xab]),
            ])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("02abcd02efab"),
        },
        Some(BTreeMap::from([
            (
                "one".to_string(),
                WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                    description: Some("no name".to_string()),
                    name: None,
                    r#type: WalletTemplateVariableType::WalletData,
                }),
            ),
            (
                "two".to_string(),
                WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                    description: None,
                    name: Some("no description".to_string()),
                    r#type: WalletTemplateVariableType::WalletData,
                }),
            ),
        ])),
        None,
    );
}

// [BCH compiler] variables - missing WalletData
#[test]
fn bch_compiler_variables_missing_wallet_data() {
    expect_compilation_result(
        "<one> <two>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![
                CompilationError {
                    error:
                        "Cannot resolve \"one\" - the \"bytecode\" property was not provided in the compilation data."
                            .to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                },
                CompilationError {
                    error:
                        "Cannot resolve \"two\" - the \"bytecode\" property was not provided in the compilation data."
                            .to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 11,
                        end_line_number: 1,
                        start_column: 8,
                        start_line_number: 1,
                    },
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([
            (
                "one".to_string(),
                WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::WalletData,
                }),
            ),
            (
                "two".to_string(),
                WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::WalletData,
                }),
            ),
        ])),
        None,
    );
}

// [BCH compiler] variables - incomplete WalletData
#[test]
fn bch_compiler_variables_incomplete_wallet_data() {
    expect_compilation_result(
        "<one> <two>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::new()),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![
                CompilationError {
                    error: "Identifier \"one\" refers to a WalletData, but \"one\" was not provided in the CompilationData \"bytecode\".".to_string(),
                    missing_identifier: Some("one".to_string()),
                    owning_entity: Some("ownerEntityOne".to_string()),
                    range: Range {
                        end_column: 5,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                },
                CompilationError {
                    error: "Identifier \"two\" refers to a WalletData, but \"two\" was not provided in the CompilationData \"bytecode\".".to_string(),
                    missing_identifier: Some("two".to_string()),
                    owning_entity: Some("ownerEntityTwo".to_string()),
                    range: Range {
                        end_column: 11,
                        end_line_number: 1,
                        start_column: 8,
                        start_line_number: 1,
                    },
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([
            (
                "one".to_string(),
                WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::WalletData,
                }),
            ),
            (
                "two".to_string(),
                WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                    description: None,
                    name: None,
                    r#type: WalletTemplateVariableType::WalletData,
                }),
            ),
        ])),
        None,
    );
}

// [BCH compiler] variables - missing operation: currentBlockHeight
#[test]
fn bch_compiler_variables_missing_operation_current_block_height() {
    expect_compilation_result(
        "<current_block_height>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"current_block_height\" variable type can not be resolved because the \"currentBlockHeight\" operation has not been included in this compiler's configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 22,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            operations: None,
            ..configuration
        }),
    );
}

// [BCH compiler] variables - missing operation: currentBlockTime
#[test]
fn bch_compiler_variables_missing_operation_current_block_time() {
    expect_compilation_result(
        "<current_block_time>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"current_block_time\" variable type can not be resolved because the \"currentBlockTime\" operation has not been included in this compiler's configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 20,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            operations: None,
            ..configuration
        }),
    );
}

// [BCH compiler] variables - missing operation: signingSerialization
#[test]
fn bch_compiler_variables_missing_operation_signing_serialization() {
    expect_compilation_result(
        "<signing_serialization.version>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"signing_serialization\" variable type can not be resolved because the \"signingSerialization\" operation has not been included in this compiler's configuration.".to_string(),
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
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            operations: None,
            ..configuration
        }),
    );
}

// [BCH compiler] variables - missing operation: addressData
#[test]
fn bch_compiler_variables_missing_operation_address_data() {
    expect_compilation_result(
        "<a>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"a\" variable type can not be resolved because the \"addressData\" operation has not been included in this compiler's configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 3,
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
            "a".to_string(),
            WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                description: None,
                name: None,
                r#type: WalletTemplateVariableType::AddressData,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            operations: None,
            ..configuration
        }),
    );
}

// [BCH compiler] variables - missing operation: hdKey
#[test]
fn bch_compiler_variables_missing_operation_hd_key() {
    expect_compilation_result(
        "<a>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"a\" variable type can not be resolved because the \"hdKey\" operation has not been included in this compiler's configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 3,
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
            "a".to_string(),
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
        Some(|configuration| CompilerConfiguration {
            operations: None,
            ..configuration
        }),
    );
}

// [BCH compiler] variables - missing operation: key
#[test]
fn bch_compiler_variables_missing_operation_key() {
    expect_compilation_result(
        "<a>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"a\" variable type can not be resolved because the \"key\" operation has not been included in this compiler's configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 3,
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
            "a".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            operations: None,
            ..configuration
        }),
    );
}

// [BCH compiler] variables - missing operation: walletData
#[test]
fn bch_compiler_variables_missing_operation_wallet_data() {
    expect_compilation_result(
        "<a>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"a\" variable type can not be resolved because the \"walletData\" operation has not been included in this compiler's configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 3,
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
            "a".to_string(),
            WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                description: None,
                name: None,
                r#type: WalletTemplateVariableType::WalletData,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            operations: None,
            ..configuration
        }),
    );
}
