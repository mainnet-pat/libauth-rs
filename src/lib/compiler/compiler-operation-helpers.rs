use std::rc::Rc;

use crate::runtime::number::number_to_string;
use crate::engine::{WalletTemplateHdKey, WalletTemplateVariable};
use crate::format::assert_success;
use crate::key::{decode_hd_private_key, derive_hd_path, derive_hd_path_relative, HdNodeValid};
use crate::language::resolve_script_identifier;
use crate::compiler::{
    CompilationData, CompilationDataHdKeys, CompilerConfiguration, CompilerDefaults,
    CompilerOperation, CompilerOperationError, CompilerOperationErrorFatal,
    CompilerOperationResult, CompilerOperationSkip, CompilerOperationSuccess,
};

/// Attempt a series of compiler operations, skipping to the next operation if
/// the current operation returns a {@link CompilerOperationSkip} (indicating it
/// failed and can be skipped). The `finalOperation` may not be skipped, and must
/// either return {@link CompilerOperationSuccess} or
/// {@link CompilerOperationError}.
///
/// @param operations - an array of skippable operations to try
/// @param finalOperation - a final, un-skippable operation
pub fn attempt_compiler_operations(
    operations: Vec<CompilerOperation>,
    final_operation: CompilerOperation,
) -> CompilerOperation {
    Rc::new(move |identifier, data, configuration| {
        for operation in &operations {
            let result = operation(identifier, data, configuration);
            if !matches!(result, CompilerOperationResult::Skip(_)) {
                return result;
            }
        }
        final_operation(identifier, data, configuration)
    })
}

fn configuration_property_is_defined(configuration: &CompilerConfiguration, property: &str) -> bool {
    match property {
        "createAuthenticationProgram" => configuration.create_authentication_program.is_some(),
        "entityOwnership" => configuration.entity_ownership.is_some(),
        "lockingScriptTypes" => configuration.locking_script_types.is_some(),
        "opcodes" => configuration.opcodes.is_some(),
        "operations" => configuration.operations.is_some(),
        "ripemd160" => configuration.ripemd160.is_some(),
        "scenarios" => configuration.scenarios.is_some(),
        "scripts" => true,
        "secp256k1" => configuration.secp256k1.is_some(),
        "sha256" => configuration.sha256.is_some(),
        "sha512" => configuration.sha512.is_some(),
        "sourceScriptIds" => configuration.source_script_ids.is_some(),
        "unlockingScriptTimeLockTypes" => configuration.unlocking_script_time_lock_types.is_some(),
        "unlockingScripts" => configuration.unlocking_scripts.is_some(),
        "variables" => configuration.variables.is_some(),
        "vm" => configuration.vm.is_some(),
        _ => false,
    }
}

fn data_property_is_defined(data: &CompilationData, property: &str) -> bool {
    match property {
        "bytecode" => data.bytecode.is_some(),
        "compilationContext" => data.compilation_context.is_some(),
        "currentBlockHeight" => data.current_block_height.is_some(),
        "currentBlockTime" => data.current_block_time.is_some(),
        "hdKeys" => data.hd_keys.is_some(),
        "keys" => data.keys.is_some(),
        _ => false,
    }
}

/// Modify a compiler operation to verify that certain properties exist in the
/// {@link CompilationData} and {@link CompilerConfiguration} before executing
/// the provided operation. If the properties don't exist, an error message is
/// returned.
///
/// This is useful for eliminating repetitive existence checks.
///
/// @param canBeSkipped - if `true`, the accepted operation may return `false`,
/// and any missing properties will cause the returned operation to return
/// `false` (meaning the operation should be skipped)
/// @param dataProperties - an array of the top-level properties required in
/// the {@link CompilationData}
/// @param configurationProperties - an array of the top-level properties
/// required in the {@link CompilerConfiguration}
/// @param operation - the operation to run if all required properties exist
pub fn compiler_operation_requires(
    can_be_skipped: bool,
    data_properties: &'static [&'static str],
    configuration_properties: &'static [&'static str],
    operation: impl Fn(&str, &CompilationData, &CompilerConfiguration) -> CompilerOperationResult + 'static,
) -> CompilerOperation {
    Rc::new(move |identifier, data, configuration| {
        for property in configuration_properties {
            if !configuration_property_is_defined(configuration, property) {
                return if can_be_skipped {
                    CompilerOperationResult::Skip(CompilerOperationSkip)
                } else {
                    CompilerOperationResult::Error(CompilerOperationError {
                        debug: None,
                        error: format!(
                            "Cannot resolve \"{identifier}\" - the \"{property}\" property was not provided in the compiler configuration."
                        ),
                        recoverable: false,
                    })
                };
            }
        }
        for property in data_properties {
            if !data_property_is_defined(data, property) {
                return if can_be_skipped {
                    CompilerOperationResult::Skip(CompilerOperationSkip)
                } else {
                    CompilerOperationResult::Error(CompilerOperationError {
                        debug: None,
                        error: format!(
                            "Cannot resolve \"{identifier}\" - the \"{property}\" property was not provided in the compilation data."
                        ),
                        recoverable: false,
                    })
                };
            }
        }
        operation(identifier, data, configuration)
    })
}

/// Attempt to resolve an identifier from the pre-computed `bytecode` in the
/// compilation data (skipping if it is not available).
pub fn compiler_operation_attempt_bytecode_resolution(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(true, &["bytecode"], &[], |identifier, data, _| {
        match data.bytecode.as_ref().and_then(|bytecode| bytecode.get(identifier)) {
            Some(bytecode) => CompilerOperationResult::Success(CompilerOperationSuccess {
                bytecode: bytecode.clone(),
                debug: None,
                signature: None,
            }),
            None => CompilerOperationResult::Skip(CompilerOperationSkip),
        }
    })(identifier, data, configuration)
}

/// Test a private derivation path against
/// `/^(?:m|i|[0-9]+)'?(?:\/(?:[0-9]+|i)'?)*$/u`.
fn is_valid_private_path_with_index(path: &str) -> bool {
    let is_index = |segment: &str| segment == "i" || (!segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()));
    let strip_hardened = |segment: &str| segment.strip_suffix('\'').unwrap_or(segment).to_string();
    let mut segments = path.split('/');
    let Some(first) = segments.next() else {
        return false;
    };
    let first = strip_hardened(first);
    if first != "m" && !is_index(&first) {
        return false;
    }
    segments.all(|segment| is_index(&strip_hardened(segment)))
}

fn operation_error(error: String) -> CompilerOperationResult {
    CompilerOperationResult::Error(CompilerOperationError {
        debug: None,
        error,
        recoverable: false,
    })
}

/// Derive the private node of an `HdKey` for the provided address index.
///
/// The `configuration` must include `ripemd160`, `secp256k1`, `sha256`, and
/// `sha512`.
#[allow(clippy::too_many_arguments)]
pub fn compiler_operation_helper_derive_hd_private_node(
    address_index: f64,
    entity_id: &str,
    entity_hd_private_key: &str,
    configuration: &CompilerConfiguration,
    hd_key: &WalletTemplateHdKey,
    identifier: &str,
) -> CompilerOperationResult {
    let address_offset = hd_key.address_offset.unwrap_or(CompilerDefaults::hdKeyAddressOffset);
    let private_derivation_path = hd_key
        .private_derivation_path
        .as_deref()
        .unwrap_or(CompilerDefaults::hdKeyPrivateDerivationPath);
    let i = address_index + address_offset;
    if !is_valid_private_path_with_index(private_derivation_path) {
        return operation_error(format!(
            "Could not generate \"{identifier}\" - the path \"{private_derivation_path}\" is not a valid \"privateDerivationPath\"."
        ));
    }
    // Provided keys are already verified by `validate_compilation_data`.
    let master_contents = assert_success(
        decode_hd_private_key(
            entity_hd_private_key,
            configuration.secp256k1.as_ref().zip(configuration.sha256.as_ref()),
        ),
        None,
    );
    let instance_path = private_derivation_path.replacen('i', &number_to_string(i), 1);
    let uses_absolute_derivation = instance_path.contains('m');
    let crypto = (|| {
        Some((
            configuration.ripemd160.as_ref()?,
            configuration.secp256k1.as_ref()?,
            configuration.sha256.as_ref()?,
            configuration.sha512.as_ref()?,
        ))
    })();
    let instance_node = if uses_absolute_derivation { derive_hd_path } else { derive_hd_path_relative }(
        &HdNodeValid::Private(master_contents.node),
        &instance_path,
        crypto,
    )
    .map(|node| match node {
        HdNodeValid::Private(node) => node,
        HdNodeValid::Public(_) => unreachable!("private nodes derive private nodes"),
    });
    match instance_node {
        Err(instance_node) => operation_error(format!(
            "Could not generate \"{identifier}\" - the path \"{instance_path}\" could not be derived for entity \"{entity_id}\": {instance_node}"
        )),
        Ok(instance_node) => CompilerOperationResult::Success(CompilerOperationSuccess {
            bytecode: instance_node.private_key,
            debug: None,
            signature: None,
        }),
    }
}

/// The error returned when an `HdKey` identifier refers to a variable for which
/// no `entityOwnership` is available.
pub fn compiler_operation_helper_unknown_entity(identifier: &str, variable_id: &str) -> CompilerOperationResult {
    operation_error(format!(
        "Identifier \"{identifier}\" refers to an HdKey, but the \"entityOwnership\" for \"{variable_id}\" is not available in this compiler configuration."
    ))
}

/// The error returned when an `HdKey` identifier is resolved without an
/// `addressIndex` in the compilation data.
pub fn compiler_operation_helper_address_index(identifier: &str) -> CompilerOperationResult {
    operation_error(format!(
        "Identifier \"{identifier}\" refers to an HdKey, but \"hdKeys.addressIndex\" was not provided in the compilation data."
    ))
}

/// Derive the private key of the `HdKey` referenced by `identifier` from the
/// provided compilation data.
///
/// The `configuration` must include `entityOwnership`, `ripemd160`,
/// `secp256k1`, `sha256`, `sha512`, and `variables`.
pub fn compiler_operation_helper_derive_hd_key_private(
    configuration: &CompilerConfiguration,
    hd_keys: &CompilationDataHdKeys,
    identifier: &str,
) -> CompilerOperationResult {
    let CompilationDataHdKeys {
        address_index,
        hd_private_keys,
        ..
    } = hd_keys;
    let variable_id = identifier.split('.').next().unwrap_or_default();
    let Some(entity_id) = configuration
        .entity_ownership
        .as_ref()
        .and_then(|entity_ownership| entity_ownership.get(variable_id))
    else {
        return compiler_operation_helper_unknown_entity(identifier, variable_id);
    };
    let Some(address_index) = address_index else {
        return compiler_operation_helper_address_index(identifier);
    };
    let Some(entity_hd_private_key) = hd_private_keys
        .as_ref()
        .and_then(|hd_private_keys| hd_private_keys.get(entity_id))
    else {
        return CompilerOperationResult::Error(CompilerOperationError {
            debug: None,
            error: format!(
                "Identifier \"{identifier}\" refers to an HdKey owned by \"{entity_id}\", but an HD private key for this entity (or an existing signature) was not provided in the compilation data."
            ),
            recoverable: true,
        });
    };
    let Some(WalletTemplateVariable::HdKey(hd_key)) = configuration
        .variables
        .as_ref()
        .and_then(|variables| variables.get(variable_id))
    else {
        unreachable!("the variable is an HdKey");
    };
    compiler_operation_helper_derive_hd_private_node(
        *address_index,
        entity_id,
        entity_hd_private_key,
        configuration,
        hd_key,
        identifier,
    )
}

/// Compile the script with the provided `target_script_id`, returning its
/// bytecode, a fatal error if compilation fails, or `None` (libauth's
/// `false`) if the script does not exist.
pub fn compiler_operation_helper_compile_script(
    target_script_id: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> Option<Result<Vec<u8>, CompilerOperationErrorFatal>> {
    let signing_target = configuration.scripts.get(target_script_id);
    let compiled_target = resolve_script_identifier(data, configuration, target_script_id);
    let (Some(_), Some(compiled_target)) = (signing_target, compiled_target) else {
        return None;
    };
    Some(match compiled_target {
        Err(error) => Err(CompilerOperationError {
            debug: None,
            error,
            recoverable: false,
        }),
        Ok(compiled_target) => Ok(compiled_target.bytecode),
    })
}

/// Returns either the properly generated `coveredBytecode` or a
/// {@link CompilerOperationErrorFatal}.
pub fn compiler_operation_helper_generate_covered_bytecode(
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    identifier: &str,
    source_script_ids: &[String],
    unlocking_scripts: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<u8>, CompilerOperationErrorFatal> {
    let error = |error: String| CompilerOperationError {
        debug: None,
        error,
        recoverable: false,
    };
    let Some(current_script_id) = source_script_ids.last() else {
        return Err(error(format!(
            "Identifier \"{identifier}\" requires a signing serialization, but \"coveredBytecode\" cannot be determined because the compiler configuration's \"sourceScriptIds\" is empty."
        )));
    };
    let Some(target_locking_script_id) = unlocking_scripts.get(current_script_id) else {
        return Err(error(format!(
            "Identifier \"{identifier}\" requires a signing serialization, but \"coveredBytecode\" cannot be determined because \"{current_script_id}\" is not present in the compiler configuration's \"unlockingScripts\"."
        )));
    };
    match compiler_operation_helper_compile_script(target_locking_script_id, data, configuration) {
        None => Err(error(format!(
            "Identifier \"{identifier}\" requires a signing serialization that covers an unknown locking script, \"{target_locking_script_id}\"."
        ))),
        Some(result) => result,
    }
}
