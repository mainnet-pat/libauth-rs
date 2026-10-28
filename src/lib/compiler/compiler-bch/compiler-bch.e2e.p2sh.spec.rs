//! Port of `compiler/compiler-bch/compiler-bch.e2e.p2sh.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    hex_to_bin, BytecodeGenerationResult, CompilationError, CompilationErrorType, CompilationResultError,
    CompilerConfiguration, Range, WalletTemplateLockingType,
};

use compiler_bch_e2e_spec_helper::expect_compilation_result;

// [BCH compiler] transformation - unlocking script - standard locking type
#[test]
fn bch_compiler_transformation_unlocking_script_standard_locking_type() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("51"),
        },
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            locking_script_types: Some(BTreeMap::from([(
                "lock".to_string(),
                WalletTemplateLockingType::Standard,
            )])),
            scripts: BTreeMap::from([
                ("lock".to_string(), "OP_DROP OP_1".to_string()),
                ("test".to_string(), "OP_1".to_string()),
            ]),
            unlocking_scripts: Some(BTreeMap::from([("test".to_string(), "lock".to_string())])),
            ..configuration
        }),
    );
}

// [BCH compiler] transformation - unlocking script - p2sh20 locking type
#[test]
fn bch_compiler_transformation_unlocking_script_p2sh20_locking_type() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("51027551"),
        },
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            locking_script_types: Some(BTreeMap::from([(
                "lock".to_string(),
                WalletTemplateLockingType::P2sh20,
            )])),
            scripts: BTreeMap::from([
                ("lock".to_string(), "OP_DROP OP_1".to_string()),
                ("test".to_string(), "OP_1".to_string()),
            ]),
            unlocking_scripts: Some(BTreeMap::from([("test".to_string(), "lock".to_string())])),
            ..configuration
        }),
    );
}

// [BCH compiler] transformation - locking script - standard locking type
#[test]
fn bch_compiler_transformation_locking_script_standard_locking_type() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("7551"),
        },
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            locking_script_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateLockingType::Standard,
            )])),
            scripts: BTreeMap::from([
                ("test".to_string(), "OP_DROP OP_1".to_string()),
                ("unlock".to_string(), "OP_1".to_string()),
            ]),
            unlocking_scripts: Some(BTreeMap::from([("unlock".to_string(), "test".to_string())])),
            ..configuration
        }),
    );
}

// [BCH compiler] transformation - locking script - p2sh20 locking type
#[test]
fn bch_compiler_transformation_locking_script_p2sh20_locking_type() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("a914ca2bb4a2729927a38a0f266dc890d2bb5990769e87"),
        },
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            locking_script_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateLockingType::P2sh20,
            )])),
            scripts: BTreeMap::from([
                ("test".to_string(), "OP_DROP OP_1".to_string()),
                ("unlock".to_string(), "OP_1".to_string()),
            ]),
            unlocking_scripts: Some(BTreeMap::from([("unlock".to_string(), "test".to_string())])),
            ..configuration
        }),
    );
}

// [BCH compiler] transformation - locking script - p2sh32 locking type
#[test]
fn bch_compiler_transformation_locking_script_p2sh32_locking_type() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("aa20cc2cfe8f87c6f8dc5a518c06c7c939a2f91d0294a59cd8d0b97a3d68700b95b287"),
        },
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            locking_script_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateLockingType::P2sh32,
            )])),
            scripts: BTreeMap::from([
                ("test".to_string(), "OP_DROP OP_1".to_string()),
                ("unlock".to_string(), "OP_1".to_string()),
            ]),
            unlocking_scripts: Some(BTreeMap::from([("unlock".to_string(), "test".to_string())])),
            ..configuration
        }),
    );
}

// [BCH compiler] transformation - unlocking script - p2sh20 locking type - failed locking bytecode compilation
#[test]
fn bch_compiler_transformation_unlocking_script_p2sh20_locking_type_failed_locking_bytecode_compilation() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown identifier \"unknown\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 21,
                    end_line_number: 1,
                    start_column: 14,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            locking_script_types: Some(BTreeMap::from([(
                "lock".to_string(),
                WalletTemplateLockingType::P2sh20,
            )])),
            scripts: BTreeMap::from([
                ("lock".to_string(), "OP_DROP OP_1 unknown".to_string()),
                ("test".to_string(), "OP_1".to_string()),
            ]),
            unlocking_scripts: Some(BTreeMap::from([("test".to_string(), "lock".to_string())])),
            ..configuration
        }),
    );
}

// [BCH compiler] transformation - locking script - p2sh20 locking type - failed raw compilation
#[test]
fn bch_compiler_transformation_locking_script_p2sh20_locking_type_failed_raw_compilation() {
    expect_compilation_result(
        "unknown",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown identifier \"unknown\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 8,
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
            locking_script_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateLockingType::P2sh20,
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] transformation - locking script - p2sh20 locking type - failed hash160 (bad vm)
#[test]
fn bch_compiler_transformation_locking_script_p2sh20_locking_type_failed_hash160_bad_vm() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors: vec![CompilationError {
                error: "Both a VM and a createAuthenticationProgram method are required to reduce evaluations."
                    .to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 44,
                    end_line_number: 1,
                    start_column: 13,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            locking_script_types: Some(BTreeMap::from([(
                "test".to_string(),
                WalletTemplateLockingType::P2sh20,
            )])),
            scripts: BTreeMap::from([
                ("test".to_string(), "OP_DROP OP_1".to_string()),
                ("unlock".to_string(), "OP_1".to_string()),
            ]),
            unlocking_scripts: Some(BTreeMap::from([("unlock".to_string(), "test".to_string())])),
            vm: None,
            ..configuration
        }),
    );
}
