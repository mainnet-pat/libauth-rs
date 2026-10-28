use std::collections::BTreeMap;
use crate::runtime::number::{number_to_string, to_uint32};
use std::rc::Rc;

use crate::engine::WalletTemplateVariable;
use crate::format::{assert_success, big_int_to_compact_uint, number_to_bin_uint32_le, value_satoshis_to_bin};
use crate::key::{decode_hd_public_key, derive_hd_path_relative, HdNodeValid};
use crate::message::{
    encode_transaction_input_sequence_numbers_for_signing, encode_transaction_outpoints,
    encode_transaction_outputs_for_signing,
};
use crate::runtime::bigint::BigInt;
use crate::vm::{big_int_to_vm_number, generate_signing_serialization_components_bch, CompilationContextBch};
use crate::compiler::{
    attempt_compiler_operations, compiler_operation_attempt_bytecode_resolution,
    compiler_operation_helper_address_index, compiler_operation_helper_derive_hd_private_node,
    compiler_operation_helper_generate_covered_bytecode, compiler_operation_helper_unknown_entity,
    compiler_operation_requires, CompilationData, CompilerConfiguration, CompilerDefaults,
    CompilerOperation, CompilerOperationError, CompilerOperationResult, CompilerOperationSet,
    CompilerOperationSuccess, CompilerOperations,
};

fn success(bytecode: Vec<u8>) -> CompilerOperationResult {
    CompilerOperationResult::Success(CompilerOperationSuccess {
        bytecode,
        debug: None,
        signature: None,
    })
}

fn error(error: String, recoverable: bool) -> CompilerOperationResult {
    CompilerOperationResult::Error(CompilerOperationError {
        debug: None,
        error,
        recoverable,
    })
}

fn context(data: &CompilationData) -> &CompilationContextBch {
    data.compilation_context
        .as_ref()
        .expect("compilerOperationRequires verified the compilationContext")
}

fn sha256_of(configuration: &CompilerConfiguration) -> &crate::crypto::Sha256 {
    configuration
        .sha256
        .as_ref()
        .expect("compilerOperationRequires verified sha256")
}

pub fn compiler_operation_address_data(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["bytecode"], &[], |identifier, data, _| {
        match data.bytecode.as_ref().and_then(|bytecode| bytecode.get(identifier)) {
            Some(bytecode) => success(bytecode.clone()),
            None => error(
                format!(
                    "Identifier \"{identifier}\" refers to an AddressData, but \"{identifier}\" was not provided in the CompilationData \"bytecode\"."
                ),
                true,
            ),
        }
    })(identifier, data, configuration)
}

pub fn compiler_operation_wallet_data(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["bytecode"], &[], |identifier, data, _| {
        match data.bytecode.as_ref().and_then(|bytecode| bytecode.get(identifier)) {
            Some(bytecode) => success(bytecode.clone()),
            None => error(
                format!(
                    "Identifier \"{identifier}\" refers to a WalletData, but \"{identifier}\" was not provided in the CompilationData \"bytecode\"."
                ),
                true,
            ),
        }
    })(identifier, data, configuration)
}

pub fn compiler_operation_current_block_time(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["currentBlockTime"], &[], |_, data, _| {
        success(number_to_bin_uint32_le(to_uint32(
            data.current_block_time.expect("verified currentBlockTime"),
        )))
    })(identifier, data, configuration)
}

pub fn compiler_operation_current_block_height(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["currentBlockHeight"], &[], |_, data, _| {
        success(big_int_to_vm_number(&BigInt::from_number(
            data.current_block_height.expect("verified currentBlockHeight"),
        )))
    })(identifier, data, configuration)
}

pub fn compiler_operation_signing_serialization_corresponding_output(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["compilationContext"], &[], |_, data, _| {
        let corresponding_output = generate_signing_serialization_components_bch(context(data)).corresponding_output;
        success(corresponding_output.unwrap_or_default())
    })(identifier, data, configuration)
}

pub fn compiler_operation_signing_serialization_corresponding_output_hash(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["compilationContext"], &["sha256"], |_, data, configuration| {
        let corresponding_output = generate_signing_serialization_components_bch(context(data)).corresponding_output;
        match corresponding_output {
            None => success(Vec::new()),
            Some(corresponding_output) => {
                let sha256 = sha256_of(configuration);
                success(sha256.hash(&sha256.hash(&corresponding_output)))
            }
        }
    })(identifier, data, configuration)
}

fn compiler_operation_helper_signing_serialization_covered_bytecode(return_length: bool) -> CompilerOperation {
    compiler_operation_requires(
        false,
        &["compilationContext"],
        &["sourceScriptIds", "unlockingScripts"],
        move |identifier, data, configuration| {
            let result = compiler_operation_helper_generate_covered_bytecode(
                data,
                configuration,
                identifier,
                configuration.source_script_ids.as_deref().expect("verified sourceScriptIds"),
                configuration.unlocking_scripts.as_ref().expect("verified unlockingScripts"),
            );
            match result {
                Err(result) => CompilerOperationResult::Error(result),
                Ok(result) => success(if return_length {
                    big_int_to_compact_uint(result.len() as u64)
                } else {
                    result
                }),
            }
        },
    )
}

pub fn compiler_operation_signing_serialization_covered_bytecode(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_signing_serialization_covered_bytecode(false)(identifier, data, configuration)
}

pub fn compiler_operation_signing_serialization_covered_bytecode_length(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_signing_serialization_covered_bytecode(true)(identifier, data, configuration)
}

/// Create a signing serialization component operation which requires only the
/// compilation context.
fn signing_serialization_component(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    component: impl Fn(&CompilationContextBch) -> Vec<u8> + 'static,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["compilationContext"], &[], move |_, data, _| {
        success(component(context(data)))
    })(identifier, data, configuration)
}

/// Create a hashed signing serialization component operation which requires the
/// compilation context and `sha256`.
fn signing_serialization_component_hash(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    component: impl Fn(&CompilationContextBch) -> Vec<u8> + 'static,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["compilationContext"], &["sha256"], move |_, data, configuration| {
        let sha256 = sha256_of(configuration);
        success(sha256.hash(&sha256.hash(&component(context(data)))))
    })(identifier, data, configuration)
}

pub fn compiler_operation_signing_serialization_locktime(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        number_to_bin_uint32_le(context.transaction.locktime)
    })
}

pub fn compiler_operation_signing_serialization_outpoint_index(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        number_to_bin_uint32_le(context.transaction.inputs[context.input_index].outpoint_index)
    })
}

pub fn compiler_operation_signing_serialization_outpoint_transaction_hash(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        context.transaction.inputs[context.input_index]
            .outpoint_transaction_hash
            .clone()
    })
}

pub fn compiler_operation_signing_serialization_output_value(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        value_satoshis_to_bin(context.source_outputs[context.input_index].value_satoshis)
    })
}

pub fn compiler_operation_signing_serialization_sequence_number(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        number_to_bin_uint32_le(context.transaction.inputs[context.input_index].sequence_number)
    })
}

pub fn compiler_operation_signing_serialization_transaction_outpoints(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        encode_transaction_outpoints(&context.transaction.inputs)
    })
}

pub fn compiler_operation_signing_serialization_transaction_outpoints_hash(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component_hash(identifier, data, configuration, |context| {
        encode_transaction_outpoints(&context.transaction.inputs)
    })
}

pub fn compiler_operation_signing_serialization_transaction_outputs(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        encode_transaction_outputs_for_signing(&context.transaction.outputs)
    })
}

pub fn compiler_operation_signing_serialization_transaction_outputs_hash(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component_hash(identifier, data, configuration, |context| {
        encode_transaction_outputs_for_signing(&context.transaction.outputs)
    })
}

pub fn compiler_operation_signing_serialization_transaction_sequence_numbers(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        encode_transaction_input_sequence_numbers_for_signing(&context.transaction.inputs)
    })
}

pub fn compiler_operation_signing_serialization_transaction_sequence_numbers_hash(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component_hash(identifier, data, configuration, |context| {
        encode_transaction_input_sequence_numbers_for_signing(&context.transaction.inputs)
    })
}

pub fn compiler_operation_signing_serialization_version(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    signing_serialization_component(identifier, data, configuration, |context| {
        number_to_bin_uint32_le(context.transaction.version)
    })
}

pub fn compiler_operation_key_public_key_common(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    attempt_compiler_operations(
        vec![Rc::new(compiler_operation_attempt_bytecode_resolution)],
        compiler_operation_requires(false, &["keys"], &["secp256k1"], |identifier, data, configuration| {
            let secp256k1 = configuration.secp256k1.as_ref().expect("verified secp256k1");
            let private_keys = data.keys.as_ref().and_then(|keys| keys.private_keys.as_ref());
            let variable_id = identifier.split('.').next().unwrap_or_default();
            match private_keys.and_then(|private_keys| private_keys.get(variable_id)) {
                Some(private_key) => success(
                    secp256k1
                        .derive_public_key_compressed(private_key)
                        .expect("compilation data private keys are validated"),
                ),
                None => error(
                    format!(
                        "Identifier \"{identifier}\" refers to a public key, but no public or private keys for \"{variable_id}\" were provided in the compilation data."
                    ),
                    true,
                ),
            }
        }),
    )(identifier, data, configuration)
}

/// Test a derivation path against `/^(?:m|[0-9]+)'?(?:\/(?:[0-9]+'?))*$/u`.
fn is_valid_hd_public_key_derivation_path(path: &str) -> bool {
    let is_number = |segment: &str| !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit());
    let mut segments = path.split('/');
    let Some(first) = segments.next() else {
        return false;
    };
    let first = first.strip_suffix('\'').unwrap_or(first);
    if first != "m" && !is_number(first) {
        return false;
    }
    segments.all(|segment| is_number(segment.strip_suffix('\'').unwrap_or(segment)))
}

pub fn compiler_operation_hd_key_public_key_common(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    attempt_compiler_operations(
        vec![Rc::new(compiler_operation_attempt_bytecode_resolution)],
        compiler_operation_requires(
            false,
            &["hdKeys"],
            &["entityOwnership", "ripemd160", "secp256k1", "sha256", "sha512", "variables"],
            |identifier, data, configuration| {
                let hd_keys = data.hd_keys.as_ref().expect("verified hdKeys");
                let variable_id = identifier.split('.').next().unwrap_or_default();
                let Some(entity_id) = configuration
                    .entity_ownership
                    .as_ref()
                    .and_then(|entity_ownership| entity_ownership.get(variable_id))
                else {
                    return compiler_operation_helper_unknown_entity(identifier, variable_id);
                };
                let Some(address_index) = hd_keys.address_index else {
                    return compiler_operation_helper_address_index(identifier);
                };
                let entity_hd_private_key = hd_keys
                    .hd_private_keys
                    .as_ref()
                    .and_then(|hd_private_keys| hd_private_keys.get(entity_id));
                let Some(WalletTemplateVariable::HdKey(hd_key)) = configuration
                    .variables
                    .as_ref()
                    .and_then(|variables| variables.get(variable_id))
                else {
                    unreachable!("the variable is an HdKey");
                };
                if let Some(entity_hd_private_key) = entity_hd_private_key {
                    let private_result = compiler_operation_helper_derive_hd_private_node(
                        address_index,
                        entity_id,
                        entity_hd_private_key,
                        configuration,
                        hd_key,
                        identifier,
                    );
                    return match private_result {
                        CompilerOperationResult::Success(private_result) => success(
                            configuration
                                .secp256k1
                                .as_ref()
                                .expect("verified secp256k1")
                                .derive_public_key_compressed(&private_result.bytecode)
                                .expect("derived private keys are valid"),
                        ),
                        other => other,
                    };
                }
                let Some(entity_hd_public_key) = hd_keys
                    .hd_public_keys
                    .as_ref()
                    .and_then(|hd_public_keys| hd_public_keys.get(entity_id))
                else {
                    return error(
                        format!(
                            "Identifier \"{identifier}\" refers to an HdKey owned by \"{entity_id}\", but an HD private key or HD public key for this entity was not provided in the compilation data."
                        ),
                        true,
                    );
                };
                let address_offset = hd_key.address_offset.unwrap_or(CompilerDefaults::hdKeyAddressOffset);
                let private_derivation_path = hd_key
                    .private_derivation_path
                    .clone()
                    .unwrap_or_else(|| CompilerDefaults::hdKeyPrivateDerivationPath.to_string());
                let hd_public_key_derivation_path = hd_key
                    .hd_public_key_derivation_path
                    .clone()
                    .unwrap_or_else(|| CompilerDefaults::hdKeyHdPublicKeyDerivationPath.to_string());
                let public_derivation_path = hd_key
                    .public_derivation_path
                    .clone()
                    .unwrap_or_else(|| private_derivation_path.replacen("m/", "", 1));
                if !hd_public_key_derivation_path.is_empty()
                    && !is_valid_hd_public_key_derivation_path(&hd_public_key_derivation_path)
                {
                    return error(
                        format!(
                            "Could not generate \"{identifier}\" - \"hdPublicKeyDerivationPath\" (\"{hd_public_key_derivation_path}\") must be a fixed (no \"i\" characters), valid absolute derivation path."
                        ),
                        false,
                    );
                }
                let expected = if hd_public_key_derivation_path.is_empty() {
                    public_derivation_path.clone()
                } else {
                    format!("{hd_public_key_derivation_path}/{public_derivation_path}")
                };
                if private_derivation_path != expected {
                    return error(
                        format!(
                            "Could not generate \"{identifier}\" - \"privateDerivationPath\" (\"{private_derivation_path}\") is expected to be the combination of \"hdPublicKeyDerivationPath\" and \"publicDerivationPath\": \"{expected}\"."
                        ),
                        false,
                    );
                }
                let master_contents = assert_success(
                    decode_hd_public_key(
                        entity_hd_public_key,
                        configuration.secp256k1.as_ref().zip(configuration.sha256.as_ref()),
                    ),
                    None,
                );
                let i = address_index + address_offset;
                let instance_path = public_derivation_path.replacen('i', &number_to_string(i), 1);
                let expected_depth = hd_public_key_derivation_path.split('/').count() - 1;
                if !hd_public_key_derivation_path.is_empty()
                    && master_contents.node.depth as usize != expected_depth
                {
                    return error(
                        format!(
                            "Could not generate \"{identifier}\" - the HD public key derivation path (\"{hd_public_key_derivation_path}\") indicates an expected depth of {expected_depth}, but the provided HD public key has a depth of {}.",
                            master_contents.node.depth
                        ),
                        false,
                    );
                }
                let crypto = (|| {
                    Some((
                        configuration.ripemd160.as_ref()?,
                        configuration.secp256k1.as_ref()?,
                        configuration.sha256.as_ref()?,
                        configuration.sha512.as_ref()?,
                    ))
                })();
                match derive_hd_path_relative(&HdNodeValid::Public(master_contents.node), &instance_path, crypto) {
                    Err(instance_node) => error(
                        format!(
                            "Could not generate \"{identifier}\" - the path \"{instance_path}\" could not be derived for entity \"{entity_id}\": {instance_node}"
                        ),
                        false,
                    ),
                    Ok(HdNodeValid::Public(instance_node)) => success(instance_node.public_key),
                    Ok(HdNodeValid::Private(_)) => unreachable!("public nodes derive public nodes"),
                }
            },
        ),
    )(identifier, data, configuration)
}

fn operations_of(operations: &[(&str, fn(&str, &CompilationData, &CompilerConfiguration) -> CompilerOperationResult)]) -> CompilerOperationSet {
    CompilerOperationSet::Multiple(
        operations
            .iter()
            .map(|(name, operation)| (name.to_string(), Rc::new(*operation) as CompilerOperation))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// The common compiler operations (used by {@link createCompilerCommon}).
pub fn compiler_operations_common() -> CompilerOperations {
    CompilerOperations {
        address_data: Some(CompilerOperationSet::Single(Rc::new(compiler_operation_address_data))),
        current_block_height: Some(CompilerOperationSet::Single(Rc::new(compiler_operation_current_block_height))),
        current_block_time: Some(CompilerOperationSet::Single(Rc::new(compiler_operation_current_block_time))),
        hd_key: Some(operations_of(&[("public_key", compiler_operation_hd_key_public_key_common)])),
        key: Some(operations_of(&[("public_key", compiler_operation_key_public_key_common)])),
        signing_serialization: Some(operations_of(&[
            ("corresponding_output", compiler_operation_signing_serialization_corresponding_output),
            ("corresponding_output_hash", compiler_operation_signing_serialization_corresponding_output_hash),
            ("covered_bytecode", compiler_operation_signing_serialization_covered_bytecode),
            ("covered_bytecode_length", compiler_operation_signing_serialization_covered_bytecode_length),
            ("locktime", compiler_operation_signing_serialization_locktime),
            ("outpoint_index", compiler_operation_signing_serialization_outpoint_index),
            ("outpoint_transaction_hash", compiler_operation_signing_serialization_outpoint_transaction_hash),
            ("output_value", compiler_operation_signing_serialization_output_value),
            ("sequence_number", compiler_operation_signing_serialization_sequence_number),
            ("transaction_outpoints", compiler_operation_signing_serialization_transaction_outpoints),
            ("transaction_outpoints_hash", compiler_operation_signing_serialization_transaction_outpoints_hash),
            ("transaction_outputs", compiler_operation_signing_serialization_transaction_outputs),
            ("transaction_outputs_hash", compiler_operation_signing_serialization_transaction_outputs_hash),
            ("transaction_sequence_numbers", compiler_operation_signing_serialization_transaction_sequence_numbers),
            (
                "transaction_sequence_numbers_hash",
                compiler_operation_signing_serialization_transaction_sequence_numbers_hash,
            ),
            ("version", compiler_operation_signing_serialization_version),
        ])),
        wallet_data: Some(CompilerOperationSet::Single(Rc::new(compiler_operation_wallet_data))),
    }
}
