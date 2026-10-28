//! Port of `compiler/compiler-bch/compiler-bch-operations.spec.ts`.

use std::collections::BTreeMap;

use libauth::{
    compiler_operation_signing_serialization_full_bch, sha256, CompilationContextBch, CompilationData,
    CompilerConfiguration, CompilerOperationError, CompilerOperationResult, TransactionBch,
};

/// libauth's `{} as CompilationContextBch` (an empty compilation context).
fn empty_compilation_context() -> CompilationContextBch {
    CompilationContextBch {
        input_index: 0,
        source_outputs: vec![],
        transaction: TransactionBch {
            inputs: vec![],
            locktime: 0,
            outputs: vec![],
            version: 0,
        },
    }
}

/// libauth's configuration for these tests mocks `sha256` with
/// `{ hash: () => Uint8Array.of() }`; the Rust `Sha256` is a concrete type, so
/// the default `sha256` instance is used instead (neither test reaches a hash).
fn configuration() -> CompilerConfiguration {
    CompilerConfiguration {
        scripts: BTreeMap::from([("lock".to_string(), String::new())]),
        sha256: Some(sha256.clone()),
        source_script_ids: Some(vec!["test".to_string()]),
        unlocking_scripts: Some(BTreeMap::from([("test".to_string(), "lock".to_string())])),
        ..Default::default()
    }
}

#[test]
fn compiler_operation_signing_serialization_full_bch_requires_an_algorithm() {
    assert_eq!(
        compiler_operation_signing_serialization_full_bch(
            "",
            &CompilationData {
                compilation_context: Some(empty_compilation_context()),
                ..Default::default()
            },
            &configuration(),
        ),
        CompilerOperationResult::Error(CompilerOperationError {
            debug: None,
            error: "Invalid signing serialization operation. Include the desired component or algorithm, e.g. \"signing_serialization.version\".".to_string(),
            recoverable: false,
        })
    );
}

#[test]
fn compiler_operation_signing_serialization_full_bch_error_on_unknown_algorithms() {
    assert_eq!(
        compiler_operation_signing_serialization_full_bch(
            "signing_serialization.full_unknown_serialization",
            &CompilationData {
                compilation_context: Some(empty_compilation_context()),
                ..Default::default()
            },
            &configuration(),
        ),
        CompilerOperationResult::Error(CompilerOperationError {
            debug: None,
            error: "Unknown signing serialization algorithm, \"full_unknown_serialization\".".to_string(),
            recoverable: false,
        })
    );
}
