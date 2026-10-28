//! Port of `compiler/compiler-operation-helpers.spec.ts`.

use std::collections::BTreeMap;

use libauth::{
    compiler_operation_helper_generate_covered_bytecode, compiler_operation_requires, CompilationData,
    CompilerConfiguration, CompilerOperationError, CompilerOperationResult, CompilerOperationSkip,
};

#[test]
fn attempt_compiler_operations_can_skip_configuration_property_check() {
    assert_eq!(
        compiler_operation_requires(true, &[], &["entityOwnership"], |_, _, _| {
            CompilerOperationResult::Error(CompilerOperationError {
                debug: None,
                error: "test failed".to_string(),
                recoverable: false,
            })
        })("", &CompilationData::default(), &CompilerConfiguration::default()),
        CompilerOperationResult::Skip(CompilerOperationSkip)
    );
}

#[test]
fn compiler_operation_helper_generate_covered_bytecode_empty_source_script_ids() {
    let result = compiler_operation_helper_generate_covered_bytecode(
        &CompilationData::default(),
        &CompilerConfiguration::default(),
        "test",
        &[],
        &BTreeMap::new(),
    );
    assert_eq!(
        result,
        Err(CompilerOperationError {
            debug: None,
            error: "Identifier \"test\" requires a signing serialization, but \"coveredBytecode\" cannot be determined because the compiler configuration's \"sourceScriptIds\" is empty.".to_string(),
            recoverable: false,
        })
    );
}
