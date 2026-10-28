//! Port of `compiler/compiler-bch/compiler-bch.e2e.evaluations.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    BytecodeGenerationResult, CompilationError, CompilationErrorType, CompilationResultError, CompilerConfiguration,
    Range,
};

use compiler_bch_e2e_spec_helper::expect_compilation_result;

// [BCH compiler] evaluations - simple evaluation
#[test]
fn bch_compiler_evaluations_simple_evaluation() {
    expect_compilation_result(
        "$(<1> <2> OP_ADD)",
        |data| data,
        BytecodeGenerationResult::Success { bytecode: vec![0x03] },
        None,
        None,
    );
}

// [BCH compiler] evaluations - nested evaluations
// TS: `test.only` (in AVA, the other tests of this file are skipped).
#[test]
fn bch_compiler_evaluations_nested_evaluations() {
    expect_compilation_result(
        "$( $(<1> <2> OP_ADD) 0xaabbcc )",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: vec![0xaa, 0xbb, 0xcc],
        },
        None,
        None,
    );
}

// [BCH compiler] evaluations - empty results are erased
#[test]
fn bch_compiler_evaluations_empty_results_are_erased() {
    expect_compilation_result(
        "$( OP_0 )",
        |data| data,
        BytecodeGenerationResult::Success { bytecode: vec![] },
        None,
        None,
    );
}

// [BCH compiler] evaluations - error if evaluation completes with more than one stack item
#[ignore = "UPSTREAM-STALE: never runs upstream (this file has a `test.only`), and the expected error is outdated: libauth v3.1.0-next.8 itself returns \"Failed to reduce evaluation: Non-P2SH locking bytecode completed evaluation with an unexpected number of items on the stack (must be exactly 1). Remaining stack depth: 2.\" (Rust returns the same)"]
#[test]
fn bch_compiler_evaluations_error_if_evaluation_completes_with_more_than_one_stack_item() {
    expect_compilation_result(
        "$( OP_1 OP_2 )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program completed with an unexpected number of items on the stack (must be exactly 1).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 15,
                    end_line_number: 1,
                    start_column: 1,
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

// [BCH compiler] evaluations - requires vm
#[test]
fn bch_compiler_evaluations_requires_vm() {
    expect_compilation_result(
        "$( OP_1 OP_2 )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Both a VM and a createAuthenticationProgram method are required to reduce evaluations."
                    .to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 15,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            vm: None,
            ..configuration
        }),
    );
}

// [BCH compiler] evaluations - requires createAuthenticationProgram
#[test]
fn bch_compiler_evaluations_requires_create_authentication_program() {
    expect_compilation_result(
        "$( OP_1 OP_2 )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Both a VM and a createAuthenticationProgram method are required to reduce evaluations."
                    .to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 15,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            create_authentication_program: None,
            ..configuration
        }),
    );
}

// [BCH compiler] evaluations - error if evaluation completes with no stack items
#[ignore = "UPSTREAM-STALE: never runs upstream (this file has a `test.only`), and the expected error is outdated: libauth v3.1.0-next.8 itself returns \"Failed to reduce evaluation: Non-P2SH locking bytecode completed evaluation with an unexpected number of items on the stack (must be exactly 1). Remaining stack depth: 0.\" (Rust returns the same)"]
#[test]
fn bch_compiler_evaluations_error_if_evaluation_completes_with_no_stack_items() {
    expect_compilation_result(
        "$( OP_1 OP_2 OP_2DROP )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program completed with an unexpected number of items on the stack (must be exactly 1).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 24,
                    end_line_number: 1,
                    start_column: 1,
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

// [BCH compiler] evaluations - error if evaluation ends with an error
#[test]
fn bch_compiler_evaluations_error_if_evaluation_ends_with_an_error() {
    expect_compilation_result(
        "$( OP_1 OP_RETURN )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program called an OP_RETURN operation.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 20,
                    end_line_number: 1,
                    start_column: 1,
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

// [BCH compiler] evaluations - error if nested evaluation begins with an error
#[test]
fn bch_compiler_evaluations_error_if_nested_evaluation_begins_with_an_error() {
    expect_compilation_result(
        "$( $( OP_RETURN ) )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program called an OP_RETURN operation.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 4,
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

// [BCH compiler] evaluations - nested error within first sample
#[test]
fn bch_compiler_evaluations_nested_error_within_first_sample() {
    expect_compilation_result(
        "$( $( 0x6a0000 ) )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program called an OP_RETURN operation.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 17,
                    end_line_number: 1,
                    start_column: 4,
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

// [BCH compiler] evaluations - malformed first sample
#[ignore = "UPSTREAM-STALE: never runs upstream (this file has a `test.only`), and the expected error is outdated: libauth v3.1.0-next.8 itself returns \"Failed to reduce evaluation: The provided locking bytecode is malformed. Malformed instruction: OP_PUSHBYTES_1 [missing 1 byte].\" (Rust returns the same)"]
#[test]
fn bch_compiler_evaluations_malformed_first_sample() {
    expect_compilation_result(
        "$( $( 0x01 ) )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: The provided locking bytecode is malformed.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 13,
                    end_line_number: 1,
                    start_column: 4,
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

// [BCH compiler] evaluations - malformed later sample
#[ignore = "UPSTREAM-STALE: never runs upstream (this file has a `test.only`), and the expected error is outdated: libauth v3.1.0-next.8 itself returns \"Failed to reduce evaluation: The provided locking bytecode is malformed. Malformed instruction: OP_PUSHBYTES_1 [missing 1 byte].\" (Rust returns the same)"]
#[test]
fn bch_compiler_evaluations_malformed_later_sample() {
    expect_compilation_result(
        "$( $( OP_1 0x01 ) )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: The provided locking bytecode is malformed.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 4,
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

// [BCH compiler] evaluations - nested erasure
#[test]
fn bch_compiler_evaluations_nested_erasure() {
    expect_compilation_result(
        "$( < $( \"\" <\"\"> ) $(OP_0) > )",
        |data| data,
        BytecodeGenerationResult::Success { bytecode: vec![] },
        None,
        None,
    );
}

// [BCH compiler] evaluations - ignore empty instruction aggregations
#[test]
fn bch_compiler_evaluations_ignore_empty_instruction_aggregations() {
    expect_compilation_result(
        "$( \"\" \"\"  OP_1 OP_2 \"\" OP_ADD )",
        |data| data,
        BytecodeGenerationResult::Success { bytecode: vec![0x03] },
        None,
        None,
    );
}

// [BCH compiler] evaluations - error in the middle of an evaluation
#[test]
fn bch_compiler_evaluations_error_in_the_middle_of_an_evaluation() {
    expect_compilation_result(
        "$( OP_1 OP_2 OP_ADD OP_DUP OP_RETURN OP_DROP )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program called an OP_RETURN operation.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 47,
                    end_line_number: 1,
                    start_column: 1,
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

// [BCH compiler] evaluations - evaluation with non-empty execution stack
#[ignore = "UPSTREAM-STALE: never runs upstream (this file has a `test.only`), and the expected error is outdated: libauth v3.1.0-next.8 itself returns \"Failed to reduce evaluation: The locking bytecode completed with a non-empty control stack. Remaining control stack depth: 1.\" (Rust returns the same)"]
#[test]
fn bch_compiler_evaluations_evaluation_with_non_empty_execution_stack() {
    expect_compilation_result(
        "$( OP_1 OP_IF <\"abc\"> )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program completed with a non-empty execution stack (missing `OP_ENDIF`).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 24,
                    end_line_number: 1,
                    start_column: 1,
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

// [BCH compiler] evaluations - multiple evaluation errors
#[test]
fn bch_compiler_evaluations_multiple_evaluation_errors() {
    expect_compilation_result(
        "$( $( OP_RETURN ) $( OP_RETURN ) OP_1 )",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![
                CompilationError {
                    error: "Failed to reduce evaluation: Program called an OP_RETURN operation.".to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 18,
                        end_line_number: 1,
                        start_column: 4,
                        start_line_number: 1,
                    },
                },
                CompilationError {
                    error: "Failed to reduce evaluation: Program called an OP_RETURN operation.".to_string(),
                    missing_identifier: None,
                    owning_entity: None,
                    range: Range {
                        end_column: 33,
                        end_line_number: 1,
                        start_column: 19,
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

// [BCH compiler] evaluations - push an evaluation with an error
#[ignore = "UPSTREAM-STALE: never runs upstream (this file has a `test.only`), and the expected error is outdated: libauth v3.1.0-next.8 itself returns \"Failed to reduce evaluation: Non-P2SH locking bytecode completed evaluation with an unexpected number of items on the stack (must be exactly 1). Remaining stack depth: 0.\" (Rust returns the same)"]
#[test]
fn bch_compiler_evaluations_push_an_evaluation_with_an_error() {
    expect_compilation_result(
        "<$()>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Failed to reduce evaluation: Program completed with an unexpected number of items on the stack (must be exactly 1).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 5,
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
