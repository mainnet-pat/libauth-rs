use std::collections::BTreeMap;

use crate::compiler::{CompilationData, CompilerConfiguration};
use crate::engine::{
    WalletTemplateAddressData, WalletTemplateLockingType as LockingScriptType,
    WalletTemplateTimeLockType as TimeLockType, WalletTemplateVariable, WalletTemplateVariableType,
};

use super::resolve::compile_script_raw;
use super::language_types::{
    CompilationError, CompilationErrorType, CompilationResult, CompilationResultError, Transform,
};
use super::resolve::create_empty_range;

/// Parse, resolve, and reduce the selected script using the provided data and
/// configuration.
///
/// Note, locktime validation only occurs if `compilationContext` is provided in
/// the configuration.
pub fn compile_script(
    script_id: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilationResult {
    const LOCKTIME_DISABLING_SEQUENCE_NUMBER: u32 = 0xffff_ffff;
    const LOCK_TIME_TYPE_BECOMES_TIMESTAMP: u32 = 500_000_000;
    if let Some(compilation_context) = &data.compilation_context {
        let time_lock_type = configuration
            .unlocking_script_time_lock_types
            .as_ref()
            .and_then(|types| types.get(script_id))
            .copied();
        if time_lock_type == Some(TimeLockType::Height)
            && compilation_context.transaction.locktime >= LOCK_TIME_TYPE_BECOMES_TIMESTAMP
        {
            return CompilationResult::Error(CompilationResultError {
                error_type: CompilationErrorType::Parse,
                errors: vec![CompilationError {
                    error: format!(
                        "The script \"{script_id}\" requires a height-based locktime (less than 500,000,000), but this transaction uses a timestamp-based locktime (\"{}\").",
                        compilation_context.transaction.locktime
                    ),
                    range: create_empty_range(),
                    missing_identifier: None,
                    owning_entity: None,
                }],
                parse: None,
                reduce: None,
                resolve: None,
            });
        }
        if time_lock_type == Some(TimeLockType::Timestamp)
            && compilation_context.transaction.locktime < LOCK_TIME_TYPE_BECOMES_TIMESTAMP
        {
            return CompilationResult::Error(CompilationResultError {
                error_type: CompilationErrorType::Parse,
                errors: vec![CompilationError {
                    error: format!(
                        "The script \"{script_id}\" requires a timestamp-based locktime (greater than or equal to 500,000,000), but this transaction uses a height-based locktime (\"{}\").",
                        compilation_context.transaction.locktime
                    ),
                    range: create_empty_range(),
                    missing_identifier: None,
                    owning_entity: None,
                }],
                parse: None,
                reduce: None,
                resolve: None,
            });
        }
        if time_lock_type.is_some()
            && compilation_context
                .transaction
                .inputs
                .get(compilation_context.input_index)
                .is_some_and(|input| {
                    input.sequence_number == LOCKTIME_DISABLING_SEQUENCE_NUMBER
                })
        {
            return CompilationResult::Error(CompilationResultError {
                error_type: CompilationErrorType::Parse,
                errors: vec![CompilationError {
                    error: format!(
                        "The script \"{script_id}\" requires a locktime, but this input's sequence number is set to disable transaction locktime (0xffffffff). This will cause the OP_CHECKLOCKTIMEVERIFY operation to error when the transaction is verified. To be valid, this input must use a sequence number that does not disable locktime."
                    ),
                    range: create_empty_range(),
                    missing_identifier: None,
                    owning_entity: None,
                }],
                parse: None,
                reduce: None,
                resolve: None,
            });
        }
    }

    let raw_result = compile_script_raw(data, configuration, script_id);
    let raw_success = match &raw_result {
        CompilationResult::Success(success) => (**success).clone(),
        CompilationResult::Error(_) => return raw_result,
    };

    let unlocks = configuration
        .unlocking_scripts
        .as_ref()
        .and_then(|unlocking_scripts| unlocking_scripts.get(script_id));
    let locking_script_type_of = |script_id: &str| {
        configuration
            .locking_script_types
            .as_ref()
            .and_then(|locking_script_types| locking_script_types.get(script_id))
            .copied()
    };
    let unlocking_script_type = unlocks.and_then(|unlocks| locking_script_type_of(unlocks));
    let is_p2sh_unlock = matches!(
        unlocking_script_type,
        Some(LockingScriptType::P2sh20) | Some(LockingScriptType::P2sh32)
    );
    let locking_script_type = locking_script_type_of(script_id);
    let is_p2sh_lock = matches!(
        locking_script_type,
        Some(LockingScriptType::P2sh20) | Some(LockingScriptType::P2sh32)
    );
    if is_p2sh_lock {
        let mut transformed_configuration = configuration.clone();
        let mut scripts = BTreeMap::new();
        scripts.insert(
            "p2sh20Locking".to_string(),
            "OP_HASH160 <$(<lockingBytecode> OP_HASH160)> OP_EQUAL".to_string(),
        );
        scripts.insert(
            "p2sh32Locking".to_string(),
            "OP_HASH256 <$(<lockingBytecode> OP_HASH256)> OP_EQUAL".to_string(),
        );
        transformed_configuration.scripts = scripts;
        let mut variables = BTreeMap::new();
        variables.insert(
            "lockingBytecode".to_string(),
            address_data_variable(),
        );
        transformed_configuration.variables = Some(variables);
        let mut transform_data = CompilationData::default();
        let mut bytecode = BTreeMap::new();
        bytecode.insert("lockingBytecode".to_string(), raw_success.bytecode.clone());
        transform_data.bytecode = Some(bytecode);
        let transformed_result = compile_script_raw(
            &transform_data,
            &transformed_configuration,
            if locking_script_type == Some(LockingScriptType::P2sh20) {
                "p2sh20Locking"
            } else {
                "p2sh32Locking"
            },
        );
        let transformed_bytecode = match transformed_result {
            CompilationResult::Success(success) => success.bytecode.clone(),
            CompilationResult::Error(_) => return transformed_result,
        };
        let mut result = raw_success;
        result.bytecode = transformed_bytecode;
        result.transformed = Some(if locking_script_type == Some(LockingScriptType::P2sh20) {
            Transform::P2sh20Locking
        } else {
            Transform::P2sh32Locking
        });
        return CompilationResult::Success(Box::new(result));
    }

    if is_p2sh_unlock {
        let unlocks = unlocks.expect("P2SH unlocking scripts unlock a locking script");
        let locking_bytecode_result = compile_script_raw(data, configuration, unlocks);
        let locking_bytecode = match locking_bytecode_result {
            CompilationResult::Success(success) => success.bytecode.clone(),
            CompilationResult::Error(_) => return locking_bytecode_result,
        };
        let mut transformed_configuration = configuration.clone();
        let mut scripts = BTreeMap::new();
        scripts.insert(
            "p2shUnlocking".to_string(),
            "unlockingBytecode <lockingBytecode>".to_string(),
        );
        transformed_configuration.scripts = scripts;
        let mut variables = BTreeMap::new();
        variables.insert(
            "lockingBytecode".to_string(),
            address_data_variable(),
        );
        variables.insert(
            "unlockingBytecode".to_string(),
            address_data_variable(),
        );
        transformed_configuration.variables = Some(variables);
        let mut transform_data = CompilationData::default();
        let mut bytecode = BTreeMap::new();
        bytecode.insert("lockingBytecode".to_string(), locking_bytecode);
        bytecode.insert("unlockingBytecode".to_string(), raw_success.bytecode.clone());
        transform_data.bytecode = Some(bytecode);
        let transformed_result = compile_script_raw(&transform_data, &transformed_configuration, "p2shUnlocking");
        let transformed_bytecode = match transformed_result {
            CompilationResult::Success(success) => success.bytecode.clone(),
            CompilationResult::Error(_) => return transformed_result,
        };
        let mut result = raw_success;
        result.bytecode = transformed_bytecode;
        result.transformed = Some(
            if unlocking_script_type == Some(LockingScriptType::P2sh20) {
                Transform::P2sh20Unlocking
            } else {
                Transform::P2sh32Unlocking
            },
        );
        return CompilationResult::Success(Box::new(result));
    }

    raw_result
}

fn address_data_variable() -> WalletTemplateVariable {
    WalletTemplateVariable::AddressData(WalletTemplateAddressData {
        description: None,
        name: None,
        r#type: WalletTemplateVariableType::AddressData,
    })
}
