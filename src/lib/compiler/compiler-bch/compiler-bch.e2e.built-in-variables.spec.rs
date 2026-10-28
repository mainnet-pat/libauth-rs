//! Port of `compiler/compiler-bch/compiler-bch.e2e.built-in-variables.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;
use std::rc::Rc;

use libauth::{
    compiler_configuration_to_compiler_bch, compiler_operations_bch, create_authentication_program_evaluation_common,
    create_compilation_context_common_testing, create_virtual_machine_bch, date_to_locktime, generate_bytecode_map,
    hex_to_bin, sha256, BytecodeGenerationResult, CompilationContextBch, CompilationData, CompilationDataKeys,
    CompilationError, CompilationErrorType, CompilationResultError, CompilerConfiguration, Input, Nft,
    NonFungibleTokenCapability, OpcodesBch, Output, Range, Token, WalletTemplateKey, WalletTemplateTimeLockType,
    WalletTemplateVariable, WalletTemplateVariableType,
};

use compiler_bch_e2e_spec_helper::{expect_compilation_result, privateKeyM0};

// [BCH compiler] built-in variables - current_block_time - error
#[test]
fn bch_compiler_built_in_variables_current_block_time_error() {
    expect_compilation_result(
        "<current_block_time>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"current_block_time\" - the \"currentBlockTime\" property was not provided in the compilation data.".to_string(),
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
        None,
        None,
    );
}

// [BCH compiler] built-in variables - current_block_time
#[test]
fn bch_compiler_built_in_variables_current_block_time() {
    expect_compilation_result(
        "<current_block_time>",
        |data| CompilationData {
            current_block_time: Some(f64::from(
                date_to_locktime(1570924800000 /* new Date("2019-10-13T00:00:00.000Z") */).unwrap(),
            )),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("040069a25d"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - current_block_height - error
#[test]
fn bch_compiler_built_in_variables_current_block_height_error() {
    expect_compilation_result(
        "<current_block_height>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"current_block_height\" - the \"currentBlockHeight\" property was not provided in the compilation data.".to_string(),
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
        None,
        None,
    );
}

// [BCH compiler] built-in variables - current_block_height
#[test]
fn bch_compiler_built_in_variables_current_block_height() {
    expect_compilation_result(
        "<current_block_height>",
        |data| CompilationData {
            current_block_height: Some(1.0),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("51"),
        },
        None,
        None,
    );
}

// [BCH compiler] timeLockType - requires a height-based locktime
#[test]
fn bch_compiler_time_lock_type_requires_a_height_based_locktime() {
    expect_compilation_result(
        "",
        |data| CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(None, None, Some(500000000), None, None)),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "The script \"test\" requires a height-based locktime (less than 500,000,000), but this transaction uses a timestamp-based locktime (\"500000000\").".to_string(),
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
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            unlocking_script_time_lock_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateTimeLockType::Height,
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] timeLockType - requires a timestamp-based locktime
#[test]
fn bch_compiler_time_lock_type_requires_a_timestamp_based_locktime() {
    expect_compilation_result(
        "",
        |data| CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(None, None, Some(0), None, None)),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "The script \"test\" requires a timestamp-based locktime (greater than or equal to 500,000,000), but this transaction uses a height-based locktime (\"0\").".to_string(),
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
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            unlocking_script_time_lock_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateTimeLockType::Timestamp,
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] timeLockType - locktime disabled by sequenceNumber
#[test]
fn bch_compiler_time_lock_type_locktime_disabled_by_sequence_number() {
    expect_compilation_result(
        "",
        |data| CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(
                None,
                Some(vec![Input {
                    outpoint_index: 0,
                    outpoint_transaction_hash: vec![0],
                    sequence_number: 0xffffffff,
                    unlocking_bytecode: None,
                }]),
                None,
                None,
                None,
            )),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "The script \"test\" requires a locktime, but this input's sequence number is set to disable transaction locktime (0xffffffff). This will cause the OP_CHECKLOCKTIMEVERIFY operation to error when the transaction is verified. To be valid, this input must use a sequence number that does not disable locktime.".to_string(),
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
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            unlocking_script_time_lock_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateTimeLockType::Height,
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] built-in variables - signing_serialization.full_all_outputs - error
#[test]
fn bch_compiler_built_in_variables_signing_serialization_full_all_outputs_error() {
    expect_compilation_result(
        "<signing_serialization.full_all_outputs>",
        |data| CompilationData {
            compilation_context: None,
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"signing_serialization.full_all_outputs\" - the \"compilationContext\" property was not provided in the compilation data.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 40,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization - no component or algorithm
#[test]
fn bch_compiler_built_in_variables_signing_serialization_no_component_or_algorithm() {
    expect_compilation_result(
        "<signing_serialization>",
        |data| CompilationData {
            compilation_context: None,
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "This \"signing_serialization\" variable could not be resolved because this compiler's \"signingSerialization\" operations require an operation identifier, e.g. 'signing_serialization.version'.".to_string(),
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
        None,
        None,
    );
}

// While this can't work in a locking or unlocking script (a transaction may
// have only one locktime value, and OP_CHECKLOCKTIMEVERIFY must test against
// the same type), this must still be supported by the compiler for use cases
// such as attestation (for data signatures).
// [BCH compiler] built-in variables - current_block_height and current_block_time
#[test]
fn bch_compiler_built_in_variables_current_block_height_and_current_block_time() {
    expect_compilation_result(
        "<current_block_height> <current_block_time>",
        |data| CompilationData {
            current_block_height: Some(1.0),
            current_block_time: Some(f64::from(
                date_to_locktime(1570924800000 /* new Date("2019-10-13T00:00:00.000Z") */).unwrap(),
            )),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("51040069a25d"),
        },
        None,
        None,
    );
}

// [BCH compiler] errors - multiple reduction errors
#[test]
fn bch_compiler_errors_multiple_reduction_errors() {
    expect_compilation_result(
        "<current_block_height> <current_block_time>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![
                CompilationError {
                    error: "Cannot resolve \"current_block_height\" - the \"currentBlockHeight\" property was not provided in the compilation data.".to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 22,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                },
                CompilationError {
                    error: "Cannot resolve \"current_block_time\" - the \"currentBlockTime\" property was not provided in the compilation data.".to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 43,
                        end_line_number: 1,
                        start_column: 25,
                        start_line_number: 1,
                    },
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization - error
#[test]
fn bch_compiler_built_in_variables_signing_serialization_error() {
    expect_compilation_result(
        "<signing_serialization>",
        |data| CompilationData {
            compilation_context: None,
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "This \"signing_serialization\" variable could not be resolved because this compiler's \"signingSerialization\" operations require an operation identifier, e.g. 'signing_serialization.version'.".to_string(),
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
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.full_all_outputs
#[test]
fn bch_compiler_built_in_variables_signing_serialization_full_all_outputs() {
    expect_compilation_result(
        "<signing_serialization.full_all_outputs>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "4c9d000000002d6c6135bed260db00d1b9ad203fbd17ee6c8b009850fc407bfec29fc45e3d4d8cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb901010101010101010101010101010101010101010101010101010101010101010000000000ffffffffffffffff00000000dd2aed19e2aa2ddc93b21ca9e9bb5e89016be12113ea1746ebb4e1d0417eca550000000041000000",
            ),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.full_all_outputs_single_input
#[test]
fn bch_compiler_built_in_variables_signing_serialization_full_all_outputs_single_input() {
    expect_compilation_result(
        "<signing_serialization.full_all_outputs_single_input>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "4c9d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010000000000ffffffffffffffff00000000dd2aed19e2aa2ddc93b21ca9e9bb5e89016be12113ea1746ebb4e1d0417eca5500000000c1000000",
            ),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.full_corresponding_output
#[test]
fn bch_compiler_built_in_variables_signing_serialization_full_corresponding_output() {
    expect_compilation_result(
        "<signing_serialization.full_corresponding_output>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "4c9d000000002d6c6135bed260db00d1b9ad203fbd17ee6c8b009850fc407bfec29fc45e3d4d000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010000000000ffffffffffffffff00000000dd2aed19e2aa2ddc93b21ca9e9bb5e89016be12113ea1746ebb4e1d0417eca550000000043000000",
            ),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.full_corresponding_output_single_input
#[test]
fn bch_compiler_built_in_variables_signing_serialization_full_corresponding_output_single_input() {
    expect_compilation_result(
        "<signing_serialization.full_corresponding_output_single_input>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "4c9d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010000000000ffffffffffffffff00000000dd2aed19e2aa2ddc93b21ca9e9bb5e89016be12113ea1746ebb4e1d0417eca5500000000c3000000",
            ),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.full_no_outputs
#[test]
fn bch_compiler_built_in_variables_signing_serialization_full_no_outputs() {
    expect_compilation_result(
        "<signing_serialization.full_no_outputs>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "4c9d000000002d6c6135bed260db00d1b9ad203fbd17ee6c8b009850fc407bfec29fc45e3d4d000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010000000000ffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000042000000",
            ),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.full_no_outputs_single_input
#[test]
fn bch_compiler_built_in_variables_signing_serialization_full_no_outputs_single_input() {
    expect_compilation_result(
        "<signing_serialization.full_no_outputs_single_input>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "4c9d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010000000000ffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000c2000000",
            ),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.corresponding_output
#[test]
fn bch_compiler_built_in_variables_signing_serialization_corresponding_output() {
    expect_compilation_result(
        "<signing_serialization.corresponding_output>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("09ffffffffffffffff00"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.corresponding_output_hash
#[test]
fn bch_compiler_built_in_variables_signing_serialization_corresponding_output_hash() {
    expect_compilation_result(
        "<signing_serialization.corresponding_output_hash>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("20dd2aed19e2aa2ddc93b21ca9e9bb5e89016be12113ea1746ebb4e1d0417eca55"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.covered_bytecode_length
#[test]
fn bch_compiler_built_in_variables_signing_serialization_covered_bytecode_length() {
    expect_compilation_result(
        "<signing_serialization.covered_bytecode_length>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("0100"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.covered_bytecode
#[test]
fn bch_compiler_built_in_variables_signing_serialization_covered_bytecode() {
    expect_compilation_result(
        "<signing_serialization.covered_bytecode>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("00"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.locktime
#[test]
fn bch_compiler_built_in_variables_signing_serialization_locktime() {
    expect_compilation_result(
        "<signing_serialization.locktime>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("0400000000"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.outpoint_index
#[test]
fn bch_compiler_built_in_variables_signing_serialization_outpoint_index() {
    expect_compilation_result(
        "<signing_serialization.outpoint_index>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("0400000000"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.outpoint_transaction_hash
#[test]
fn bch_compiler_built_in_variables_signing_serialization_outpoint_transaction_hash() {
    expect_compilation_result(
        "<signing_serialization.outpoint_transaction_hash>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("200101010101010101010101010101010101010101010101010101010101010101"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.output_value
#[test]
fn bch_compiler_built_in_variables_signing_serialization_output_value() {
    expect_compilation_result(
        "<signing_serialization.output_value>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("08ffffffffffffffff"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.sequence_number
#[test]
fn bch_compiler_built_in_variables_signing_serialization_sequence_number() {
    expect_compilation_result(
        "<signing_serialization.sequence_number>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("0400000000"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.transaction_outpoints
#[test]
fn bch_compiler_built_in_variables_signing_serialization_transaction_outpoints() {
    expect_compilation_result(
        "<signing_serialization.transaction_outpoints>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("24010101010101010101010101010101010101010101010101010101010101010100000000"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.transaction_outpoints_hash
#[test]
fn bch_compiler_built_in_variables_signing_serialization_transaction_outpoints_hash() {
    expect_compilation_result(
        "<signing_serialization.transaction_outpoints_hash>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("202d6c6135bed260db00d1b9ad203fbd17ee6c8b009850fc407bfec29fc45e3d4d"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.transaction_outputs
#[test]
fn bch_compiler_built_in_variables_signing_serialization_transaction_outputs() {
    expect_compilation_result(
        "<signing_serialization.transaction_outputs>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("09ffffffffffffffff00"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.transaction_outputs_hash
#[test]
fn bch_compiler_built_in_variables_signing_serialization_transaction_outputs_hash() {
    expect_compilation_result(
        "<signing_serialization.transaction_outputs_hash>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("20dd2aed19e2aa2ddc93b21ca9e9bb5e89016be12113ea1746ebb4e1d0417eca55"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.transaction_sequence_numbers
#[test]
fn bch_compiler_built_in_variables_signing_serialization_transaction_sequence_numbers() {
    expect_compilation_result(
        "<signing_serialization.transaction_sequence_numbers>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("0400000000"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.transaction_sequence_numbers_hash
#[test]
fn bch_compiler_built_in_variables_signing_serialization_transaction_sequence_numbers_hash() {
    expect_compilation_result(
        "<signing_serialization.transaction_sequence_numbers_hash>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("208cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb9"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.version
#[test]
fn bch_compiler_built_in_variables_signing_serialization_version() {
    expect_compilation_result(
        "<signing_serialization.version>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("0400000000"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.token_prefix - no token
#[test]
fn bch_compiler_built_in_variables_signing_serialization_token_prefix_no_token() {
    expect_compilation_result(
        "<signing_serialization.token_prefix>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("00"),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.token_prefix - complex token prefix
#[test]
fn bch_compiler_built_in_variables_signing_serialization_token_prefix_complex_token_prefix() {
    expect_compilation_result(
        "<signing_serialization.token_prefix>",
        |data| CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(
                Some(vec![Output {
                    locking_bytecode: vec![],
                    token: Some(Token {
                        amount: 9223372036854775807,
                        category: hex_to_bin("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                        nft: Some(Nft {
                            capability: NonFungibleTokenCapability::Minting,
                            commitment: hex_to_bin(
                                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                            ),
                        }),
                    }),
                    value_satoshis: 0xffffffffffffffff,
                }]),
                None,
                None,
                None,
                None,
            )),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "4c54efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7228ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccffffffffffffffff7f",
            ),
        },
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization.covered_bytecode - unlocking script not in unlockingScripts
#[test]
fn bch_compiler_built_in_variables_signing_serialization_covered_bytecode_unlocking_script_not_in_unlocking_scripts() {
    expect_compilation_result(
        "<signing_serialization.covered_bytecode>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"signing_serialization.covered_bytecode\" requires a signing serialization, but \"coveredBytecode\" cannot be determined because \"test\" is not present in the compiler configuration's \"unlockingScripts\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 40,
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
            unlocking_scripts: Some(BTreeMap::new()),
            ..configuration
        }),
    );
}

// [BCH compiler] built-in variables - signing_serialization.covered_bytecode - unknown covered script
#[test]
fn bch_compiler_built_in_variables_signing_serialization_covered_bytecode_unknown_covered_script() {
    expect_compilation_result(
        "<signing_serialization.covered_bytecode>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"signing_serialization.covered_bytecode\" requires a signing serialization that covers an unknown locking script, \"some_unknown_script\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 40,
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
            unlocking_scripts: Some(BTreeMap::from([("test".to_string(), "some_unknown_script".to_string())])),
            ..configuration
        }),
    );
}

// [BCH compiler] built-in variables - signing_serialization.covered_bytecode - error in coveredBytecode compilation
#[test]
fn bch_compiler_built_in_variables_signing_serialization_covered_bytecode_error_in_covered_bytecode_compilation() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Compilation error in resolved script \"lock\": [1, 1] Unknown identifier \"invalid\"."
                    .to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 40,
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
            scripts: BTreeMap::from([
                ("lock".to_string(), "invalid".to_string()),
                (
                    "test".to_string(),
                    "<signing_serialization.full_all_outputs>".to_string(),
                ),
            ]),
            ..configuration
        }),
    );
}

// [BCH compiler] built-in variables - signing_serialization.unknown
#[test]
fn bch_compiler_built_in_variables_signing_serialization_unknown() {
    expect_compilation_result(
        "<signing_serialization.unknown>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The identifier \"signing_serialization.unknown\" could not be resolved because the \"signing_serialization.unknown\" operation is not available to this compiler.".to_string(),
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
        None,
        None,
    );
}

// [BCH compiler] built-in variables - signing_serialization: unrecognized identifier fragment
#[test]
fn bch_compiler_built_in_variables_signing_serialization_unrecognized_identifier_fragment() {
    expect_compilation_result(
        "<signing_serialization.full_all_outputs.future_operation.with_more_levels>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown component in \"signing_serialization.full_all_outputs.future_operation.with_more_levels\" - the fragment \"future_operation\" is not recognized.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 74,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        None,
        None,
    );
}

// [BCH compiler] signing_serialization.corresponding_output and signing_serialization.corresponding_output_hash - returns empty bytecode if no corresponding output
// TS: `test.failing` (expected to fail).
#[should_panic]
#[test]
fn bch_compiler_signing_serialization_corresponding_output_and_signing_serialization_corresponding_output_hash_returns_empty_bytecode_if_no_corresponding_output(
) {
    let compiler = compiler_configuration_to_compiler_bch(CompilerConfiguration {
        create_authentication_program: Some(Rc::new(create_authentication_program_evaluation_common)),
        opcodes: Some(generate_bytecode_map(OpcodesBch::MEMBERS)),
        operations: Some(compiler_operations_bch()),
        scripts: BTreeMap::from([
            (
                "corresponding_output".to_string(),
                "<1> <signing_serialization.corresponding_output> <2>".to_string(),
            ),
            (
                "corresponding_output_hash".to_string(),
                "<1> <signing_serialization.corresponding_output_hash> <2>".to_string(),
            ),
        ]),
        sha256: Some(sha256.clone()),
        variables: Some(BTreeMap::from([(
            "a".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        vm: Some(create_virtual_machine_bch(None)),
        ..Default::default()
    });

    let data = CompilationData {
        compilation_context: Some(CompilationContextBch {
            input_index: 1,
            ..create_compilation_context_common_testing(None, None, None, None, None)
        }),
        keys: Some(CompilationDataKeys {
            private_keys: Some(BTreeMap::from([("a".to_string(), privateKeyM0.clone())])),
        }),
        ..Default::default()
    };

    assert_eq!(
        format!("{:?}", compiler.generate_bytecode(&data, "corresponding_output")),
        format!(
            "{:?}",
            BytecodeGenerationResult::Success {
                bytecode: hex_to_bin("510052")
            }
        )
    );

    assert_eq!(
        format!("{:?}", compiler.generate_bytecode(&data, "corresponding_output_hash")),
        format!(
            "{:?}",
            BytecodeGenerationResult::Success {
                bytecode: hex_to_bin("510052")
            }
        )
    );
}
