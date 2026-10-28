use std::rc::Rc;

use crate::crypto::{hash256, Sha256};
use crate::engine::WalletTemplate;
use crate::language::SignatureInfo;
use crate::message::encode_token_prefix;
use crate::vm::{
    create_virtual_machine_bch_spec, generate_bytecode_map, generate_signing_serialization_bch,
    CompilationContextBch, OpcodesBchSpec, SigningSerializationFlag, SigningSerializationTypeBch,
};
use crate::compiler::{
    attempt_compiler_operations, compiler_configuration_to_compiler_bch,
    compiler_operation_attempt_bytecode_resolution, compiler_operation_helper_compile_script,
    compiler_operation_helper_derive_hd_key_private,
    compiler_operation_helper_generate_covered_bytecode, compiler_operation_requires,
    compiler_operations_common, create_authentication_program_evaluation_common,
    wallet_template_to_compiler_configuration, CompilationData, Compiler, CompilerConfiguration,
    CompilerOperation, CompilerOperationError, CompilerOperationResult, CompilerOperationSet,
    CompilerOperationSuccess, CompilerOperations,
};

/// The key operations available to the BCH compiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerOperationsKeyBch {
    EcdsaDataSignature,
    EcdsaSignature,
    PublicKey,
    SchnorrDataSignature,
    SchnorrSignature,
}

/// The identifiers of the signing serialization algorithms supported by the
/// BCH compiler.
pub struct SigningSerializationAlgorithmIdentifier;

#[allow(non_upper_case_globals)]
impl SigningSerializationAlgorithmIdentifier {
    /// A.K.A. `SIGHASH_ALL|SIGHASH_FORKID`
    pub const allOutputs: &'static str = "all_outputs";
    /// A.K.A. `SIGHASH_ALL|SIGHASH_UTXOS|SIGHASH_FORKID`
    pub const allOutputsAllUtxos: &'static str = "all_outputs_all_utxos";
    /// A.K.A. `SIGHASH_ALL|SIGHASH_FORKID|ANYONECANPAY`
    pub const allOutputsSingleInput: &'static str = "all_outputs_single_input";
    /// An invalid combination of flags, included for testing purposes.
    pub const allOutputsSingleInputInvalidAllUtxos: &'static str = "all_outputs_single_input_INVALID_all_utxos";
    /// A.K.A. `SIGHASH_SINGLE|SIGHASH_FORKID`
    pub const correspondingOutput: &'static str = "corresponding_output";
    /// A.K.A. `SIGHASH_SINGLE|SIGHASH_UTXOS|SIGHASH_FORKID`
    pub const correspondingOutputAllUtxos: &'static str = "corresponding_output_all_utxos";
    /// A.K.A. `SIGHASH_SINGLE|SIGHASH_FORKID|ANYONECANPAY`
    pub const correspondingOutputSingleInput: &'static str = "corresponding_output_single_input";
    /// An invalid combination of flags, included for testing purposes.
    pub const correspondingOutputSingleInputInvalidAllUtxos: &'static str =
        "corresponding_output_single_input_INVALID_all_utxos";
    pub const default: &'static str = "default";
    /// A.K.A. `SIGHASH_NONE|SIGHASH_FORKID`
    pub const noOutputs: &'static str = "no_outputs";
    /// A.K.A. `SIGHASH_NONE|SIGHASH_UTXOS|SIGHASH_FORKID`
    pub const noOutputsAllUtxos: &'static str = "no_outputs_all_utxos";
    /// A.K.A. `SIGHASH_NONE|SIGHASH_FORKID|ANYONECANPAY`
    pub const noOutputsSingleInput: &'static str = "no_outputs_single_input";
    /// An invalid combination of flags, included for testing purposes.
    pub const noOutputsSingleInputInvalidAllUtxos: &'static str = "no_outputs_single_input_INVALID_all_utxos";
}

fn get_signing_serialization_type(algorithm_identifier: &str, prefix: Option<&str>) -> Option<Vec<u8>> {
    let prefix = prefix.unwrap_or("");
    let Some(algorithm) = algorithm_identifier.strip_prefix(prefix) else {
        return None;
    };
    type Algorithm = SigningSerializationAlgorithmIdentifier;
    let signing_serialization_type = match algorithm {
        Algorithm::allOutputs => SigningSerializationTypeBch::allOutputs,
        Algorithm::allOutputsAllUtxos | Algorithm::default => SigningSerializationTypeBch::allOutputsAllUtxos,
        Algorithm::allOutputsSingleInput => SigningSerializationTypeBch::allOutputsSingleInput,
        Algorithm::allOutputsSingleInputInvalidAllUtxos => {
            SigningSerializationFlag::allOutputs
                | SigningSerializationFlag::singleInput
                | SigningSerializationFlag::utxos
                | SigningSerializationFlag::forkId
        }
        Algorithm::correspondingOutput => SigningSerializationTypeBch::correspondingOutput,
        Algorithm::correspondingOutputAllUtxos => SigningSerializationTypeBch::correspondingOutputAllUtxos,
        Algorithm::correspondingOutputSingleInput => SigningSerializationTypeBch::correspondingOutputSingleInput,
        Algorithm::correspondingOutputSingleInputInvalidAllUtxos => {
            SigningSerializationFlag::correspondingOutput
                | SigningSerializationFlag::singleInput
                | SigningSerializationFlag::utxos
                | SigningSerializationFlag::forkId
        }
        Algorithm::noOutputs => SigningSerializationTypeBch::noOutputs,
        Algorithm::noOutputsAllUtxos => SigningSerializationTypeBch::noOutputsAllUtxos,
        Algorithm::noOutputsSingleInput => SigningSerializationTypeBch::noOutputsSingleInput,
        Algorithm::noOutputsSingleInputInvalidAllUtxos => {
            SigningSerializationFlag::noOutputs
                | SigningSerializationFlag::singleInput
                | SigningSerializationFlag::utxos
                | SigningSerializationFlag::forkId
        }
        _ => return None,
    };
    Some(vec![signing_serialization_type])
}

fn error(error: String, recoverable: bool) -> CompilerOperationResult {
    CompilerOperationResult::Error(CompilerOperationError {
        debug: None,
        error,
        recoverable,
    })
}

/// A secp256k1 signing method (`signMessageHashDER` or `signMessageHashSchnorr`).
type SignMethod = fn(&crate::crypto::Secp256k1, &[u8], &[u8]) -> Result<Vec<u8>, String>;

fn sign_message_hash_der(secp256k1: &crate::crypto::Secp256k1, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
    secp256k1.sign_message_hash_der(private_key, message_hash)
}

fn sign_message_hash_schnorr(secp256k1: &crate::crypto::Secp256k1, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
    secp256k1.sign_message_hash_schnorr(private_key, message_hash)
}

fn sign_method(secp256k1_method: &str) -> SignMethod {
    match secp256k1_method {
        "signMessageHashDER" => sign_message_hash_der,
        "signMessageHashSchnorr" => sign_message_hash_schnorr,
        _ => unreachable!("only signing methods are used"),
    }
}

/// Compute a transaction signature for the provided private key.
#[allow(clippy::too_many_arguments)]
pub fn compiler_operation_helper_compute_signature_bch(
    covered_bytecode: &[u8],
    identifier: &str,
    compilation_context: &CompilationContextBch,
    operation_name: &str,
    private_key: &[u8],
    sha256: &Sha256,
    sign: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, String>,
) -> CompilerOperationResult {
    let parts: Vec<&str> = identifier.split('.').collect();
    let algorithm = parts.get(2);
    if let Some(unknown) = parts.get(3) {
        return error(
            format!("Unknown component in \"{identifier}\" - the fragment \"{unknown}\" is not recognized."),
            false,
        );
    }
    let Some(algorithm) = algorithm else {
        return error(
            format!(
                "Invalid signature identifier. Signatures must be of the form: \"[variable_id].{operation_name}.[signing_serialization_type]\"."
            ),
            false,
        );
    };
    let Some(signing_serialization_type) = get_signing_serialization_type(algorithm, None) else {
        return error(format!("Unknown signing serialization algorithm, \"{algorithm}\"."), false);
    };
    let serialization = generate_signing_serialization_bch(
        compilation_context,
        covered_bytecode,
        &signing_serialization_type,
        Some(sha256),
    );
    let digest = hash256(&serialization, Some(sha256));
    let signature = sign(private_key, &digest).expect("signing with a valid private key succeeds");
    let bitcoin_encoded_signature = [signature, signing_serialization_type].concat();
    CompilerOperationResult::Success(CompilerOperationSuccess {
        bytecode: bitcoin_encoded_signature,
        debug: None,
        signature: Some(SignatureInfo::Serialization(serialization)),
    })
}

/// Create an `HdKey` signature operation with the provided `operation_name`
/// and `secp256k1_method` (`signMessageHashDER` or `signMessageHashSchnorr`).
pub fn compiler_operation_helper_hd_key_signature_bch(
    operation_name: &'static str,
    secp256k1_method: &'static str,
) -> CompilerOperation {
    attempt_compiler_operations(
        vec![Rc::new(compiler_operation_attempt_bytecode_resolution)],
        compiler_operation_requires(
            false,
            &["hdKeys", "compilationContext"],
            &[
                "entityOwnership",
                "ripemd160",
                "secp256k1",
                "sha256",
                "sha512",
                "variables",
                "sourceScriptIds",
                "unlockingScripts",
            ],
            move |identifier, data, configuration| {
                let hd_keys = data.hd_keys.as_ref().expect("verified hdKeys");
                let compilation_context = data.compilation_context.as_ref().expect("verified compilationContext");
                let secp256k1 = configuration.secp256k1.as_ref().expect("verified secp256k1");
                let sha256 = configuration.sha256.as_ref().expect("verified sha256");
                let derivation_result =
                    compiler_operation_helper_derive_hd_key_private(configuration, hd_keys, identifier);
                let derivation_result = match derivation_result {
                    CompilerOperationResult::Success(result) => result,
                    other => return other,
                };
                let result = compiler_operation_helper_generate_covered_bytecode(
                    data,
                    configuration,
                    identifier,
                    configuration.source_script_ids.as_deref().expect("verified sourceScriptIds"),
                    configuration.unlocking_scripts.as_ref().expect("verified unlockingScripts"),
                );
                let covered_bytecode = match result {
                    Err(result) => return CompilerOperationResult::Error(result),
                    Ok(result) => result,
                };
                let sign = sign_method(secp256k1_method);
                compiler_operation_helper_compute_signature_bch(
                    &covered_bytecode,
                    identifier,
                    compilation_context,
                    operation_name,
                    &derivation_result.bytecode,
                    sha256,
                    &|private_key, message_hash| sign(secp256k1, private_key, message_hash),
                )
            },
        ),
    )
}

pub fn compiler_operation_hd_key_ecdsa_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_hd_key_signature_bch("ecdsa_signature", "signMessageHashDER")(identifier, data, configuration)
}

pub fn compiler_operation_hd_key_schnorr_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_hd_key_signature_bch("schnorr_signature", "signMessageHashSchnorr")(
        identifier,
        data,
        configuration,
    )
}

/// Create a `Key` signature operation with the provided `operation_name` and
/// `secp256k1_method` (`signMessageHashDER` or `signMessageHashSchnorr`).
pub fn compiler_operation_helper_key_signature_bch(
    operation_name: &'static str,
    secp256k1_method: &'static str,
) -> CompilerOperation {
    attempt_compiler_operations(
        vec![Rc::new(compiler_operation_attempt_bytecode_resolution)],
        compiler_operation_requires(
            false,
            &["keys", "compilationContext"],
            &["sha256", "secp256k1", "unlockingScripts", "sourceScriptIds"],
            move |identifier, data, configuration| {
                let compilation_context = data.compilation_context.as_ref().expect("verified compilationContext");
                let secp256k1 = configuration.secp256k1.as_ref().expect("verified secp256k1");
                let sha256 = configuration.sha256.as_ref().expect("verified sha256");
                let variable_id = identifier.split('.').next().unwrap_or_default();
                let Some(private_key) = data
                    .keys
                    .as_ref()
                    .and_then(|keys| keys.private_keys.as_ref())
                    .and_then(|private_keys| private_keys.get(variable_id))
                else {
                    return error(
                        format!(
                            "Identifier \"{identifier}\" refers to a Key, but a private key for \"{variable_id}\" (or an existing signature) was not provided in the compilation data."
                        ),
                        true,
                    );
                };
                let result = compiler_operation_helper_generate_covered_bytecode(
                    data,
                    configuration,
                    identifier,
                    configuration.source_script_ids.as_deref().expect("verified sourceScriptIds"),
                    configuration.unlocking_scripts.as_ref().expect("verified unlockingScripts"),
                );
                let covered_bytecode = match result {
                    Err(result) => return CompilerOperationResult::Error(result),
                    Ok(result) => result,
                };
                let sign = sign_method(secp256k1_method);
                compiler_operation_helper_compute_signature_bch(
                    &covered_bytecode,
                    identifier,
                    compilation_context,
                    operation_name,
                    private_key,
                    sha256,
                    &|private_key, message_hash| sign(secp256k1, private_key, message_hash),
                )
            },
        ),
    )
}

pub fn compiler_operation_key_ecdsa_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_key_signature_bch("ecdsa_signature", "signMessageHashDER")(identifier, data, configuration)
}

pub fn compiler_operation_key_schnorr_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_key_signature_bch("schnorr_signature", "signMessageHashSchnorr")(
        identifier,
        data,
        configuration,
    )
}

/// Compute a data signature (of the compiled target script) for the provided
/// private key.
#[allow(clippy::too_many_arguments)]
pub fn compiler_operation_helper_compute_data_signature_bch(
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    identifier: &str,
    operation_name: &str,
    private_key: &[u8],
    sha256: &Sha256,
    sign: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, String>,
) -> CompilerOperationResult {
    let parts: Vec<&str> = identifier.split('.').collect();
    let script_id = parts.get(2);
    if let Some(unknown) = parts.get(3) {
        return error(
            format!("Unknown component in \"{identifier}\" - the fragment \"{unknown}\" is not recognized."),
            false,
        );
    }
    let Some(script_id) = script_id else {
        return error(
            format!(
                "Invalid data signature identifier. Data signatures must be of the form: \"[variable_id].{operation_name}.[target_script_id]\"."
            ),
            false,
        );
    };
    let result = match compiler_operation_helper_compile_script(script_id, data, configuration) {
        None => {
            return error(format!("Data signature tried to sign an unknown target script, \"{script_id}\"."), false);
        }
        Some(Err(result)) => return CompilerOperationResult::Error(result),
        Some(Ok(result)) => result,
    };
    let digest = sha256.hash(&result);
    CompilerOperationResult::Success(CompilerOperationSuccess {
        bytecode: sign(private_key, &digest).expect("signing with a valid private key succeeds"),
        debug: None,
        signature: Some(SignatureInfo::Data {
            digest,
            message: result,
        }),
    })
}

/// Create a `Key` data signature operation with the provided `operation_name`
/// and `secp256k1_method` (`signMessageHashDER` or `signMessageHashSchnorr`).
pub fn compiler_operation_helper_key_data_signature_bch(
    operation_name: &'static str,
    secp256k1_method: &'static str,
) -> CompilerOperation {
    attempt_compiler_operations(
        vec![Rc::new(compiler_operation_attempt_bytecode_resolution)],
        compiler_operation_requires(false, &["keys"], &["sha256", "secp256k1"], move |identifier, data, configuration| {
            let secp256k1 = configuration.secp256k1.as_ref().expect("verified secp256k1");
            let sha256 = configuration.sha256.as_ref().expect("verified sha256");
            let variable_id = identifier.split('.').next().unwrap_or_default();
            let Some(private_key) = data
                .keys
                .as_ref()
                .and_then(|keys| keys.private_keys.as_ref())
                .and_then(|private_keys| private_keys.get(variable_id))
            else {
                return error(
                    format!(
                        "Identifier \"{identifier}\" refers to a Key, but a private key for \"{variable_id}\" (or an existing signature) was not provided in the compilation data."
                    ),
                    true,
                );
            };
            let sign = sign_method(secp256k1_method);
            compiler_operation_helper_compute_data_signature_bch(
                data,
                configuration,
                identifier,
                operation_name,
                private_key,
                sha256,
                &|private_key, message_hash| sign(secp256k1, private_key, message_hash),
            )
        }),
    )
}

pub fn compiler_operation_key_ecdsa_data_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_key_data_signature_bch("ecdsa_data_signature", "signMessageHashDER")(
        identifier,
        data,
        configuration,
    )
}

pub fn compiler_operation_key_schnorr_data_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_key_data_signature_bch("schnorr_data_signature", "signMessageHashSchnorr")(
        identifier,
        data,
        configuration,
    )
}

/// Create an `HdKey` data signature operation with the provided
/// `operation_name` and `secp256k1_method` (`signMessageHashDER` or
/// `signMessageHashSchnorr`).
pub fn compiler_operation_helper_hd_key_data_signature_bch(
    operation_name: &'static str,
    secp256k1_method: &'static str,
) -> CompilerOperation {
    attempt_compiler_operations(
        vec![Rc::new(compiler_operation_attempt_bytecode_resolution)],
        compiler_operation_requires(
            false,
            &["hdKeys"],
            &["entityOwnership", "ripemd160", "secp256k1", "sha256", "sha512", "variables"],
            move |identifier, data, configuration| {
                let hd_keys = data.hd_keys.as_ref().expect("verified hdKeys");
                let secp256k1 = configuration.secp256k1.as_ref().expect("verified secp256k1");
                let sha256 = configuration.sha256.as_ref().expect("verified sha256");
                let derivation_result =
                    compiler_operation_helper_derive_hd_key_private(configuration, hd_keys, identifier);
                let derivation_result = match derivation_result {
                    CompilerOperationResult::Success(result) => result,
                    other => return other,
                };
                let sign = sign_method(secp256k1_method);
                compiler_operation_helper_compute_data_signature_bch(
                    data,
                    configuration,
                    identifier,
                    operation_name,
                    &derivation_result.bytecode,
                    sha256,
                    &|private_key, message_hash| sign(secp256k1, private_key, message_hash),
                )
            },
        ),
    )
}

pub fn compiler_operation_hd_key_ecdsa_data_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_hd_key_data_signature_bch("ecdsa_data_signature", "signMessageHashDER")(
        identifier,
        data,
        configuration,
    )
}

pub fn compiler_operation_hd_key_schnorr_data_signature_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_helper_hd_key_data_signature_bch("schnorr_data_signature", "signMessageHashSchnorr")(
        identifier,
        data,
        configuration,
    )
}

pub fn compiler_operation_signing_serialization_token_prefix(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(false, &["compilationContext"], &[], |_, data, _| {
        let context = data.compilation_context.as_ref().expect("verified compilationContext");
        CompilerOperationResult::Success(CompilerOperationSuccess {
            bytecode: encode_token_prefix(context.source_outputs[context.input_index].token.as_ref()),
            debug: None,
            signature: None,
        })
    })(identifier, data, configuration)
}

/// The error returned for the renamed `signature` operation.
pub fn compiler_operation_signature_renamed(
    identifier: &str,
    _data: &CompilationData,
    _configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    error(
        format!(
            "The \"signature\" compiler operation was renamed to \"ecdsa_signature\". Consider fixing this error by changing \"{identifier}\" to \"{}\" (schnorr signatures reduce transaction sizes and enable multi-party signature aggregation).",
            identifier.replacen("signature", "schnorr_signature", 1)
        ),
        false,
    )
}

/// The error returned for the renamed `data_signature` operation.
pub fn compiler_operation_data_signature_renamed(
    identifier: &str,
    _data: &CompilationData,
    _configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    error(
        format!(
            "The \"data_signature\" compiler operation was renamed to \"ecdsa_data_signature\". Consider fixing this error by changing \"{identifier}\" to \"{}\" (schnorr signatures reduce transaction sizes and enable multi-party signature aggregation).",
            identifier.replacen("data_signature", "schnorr_data_signature", 1)
        ),
        false,
    )
}

pub fn compiler_operation_signing_serialization_full_bch(
    identifier: &str,
    data: &CompilationData,
    configuration: &CompilerConfiguration,
) -> CompilerOperationResult {
    compiler_operation_requires(
        false,
        &["compilationContext"],
        &["sha256", "sourceScriptIds", "unlockingScripts"],
        |identifier, data, configuration| {
            let parts: Vec<&str> = identifier.split('.').collect();
            let Some(algorithm_or_component) = parts.get(1) else {
                return error(
                    "Invalid signing serialization operation. Include the desired component or algorithm, e.g. \"signing_serialization.version\".".to_string(),
                    false,
                );
            };
            if let Some(unknown_part) = parts.get(2) {
                return error(
                    format!("Unknown component in \"{identifier}\" - the fragment \"{unknown_part}\" is not recognized."),
                    false,
                );
            }
            let Some(signing_serialization_type) =
                get_signing_serialization_type(algorithm_or_component, Some("full_"))
            else {
                return error(
                    format!("Unknown signing serialization algorithm, \"{algorithm_or_component}\"."),
                    false,
                );
            };
            let sha256 = configuration.sha256.as_ref().expect("verified sha256");
            let result = compiler_operation_helper_generate_covered_bytecode(
                data,
                configuration,
                identifier,
                configuration.source_script_ids.as_deref().expect("verified sourceScriptIds"),
                configuration.unlocking_scripts.as_ref().expect("verified unlockingScripts"),
            );
            let covered_bytecode = match result {
                Err(result) => return CompilerOperationResult::Error(result),
                Ok(result) => result,
            };
            let compilation_context = data.compilation_context.as_ref().expect("verified compilationContext");
            CompilerOperationResult::Success(CompilerOperationSuccess {
                bytecode: generate_signing_serialization_bch(
                    compilation_context,
                    &covered_bytecode,
                    &signing_serialization_type,
                    Some(sha256),
                ),
                debug: None,
                signature: None,
            })
        },
    )(identifier, data, configuration)
}

/// The compiler operations of the BCH compiler (used by
/// {@link createCompilerBch}).
pub fn compiler_operations_bch() -> CompilerOperations {
    let common = compiler_operations_common();
    let operation = |operation: fn(&str, &CompilationData, &CompilerConfiguration) -> CompilerOperationResult| {
        Rc::new(operation) as CompilerOperation
    };
    let common_operation = |set: &Option<CompilerOperationSet>, name: &str| match set {
        Some(CompilerOperationSet::Multiple(operations)) => Rc::clone(&operations[name]),
        _ => unreachable!("the common operations include {name}"),
    };
    let hd_key = CompilerOperationSet::Multiple(
        [
            ("data_signature", operation(compiler_operation_data_signature_renamed)),
            ("ecdsa_data_signature", operation(compiler_operation_hd_key_ecdsa_data_signature_bch)),
            ("ecdsa_signature", operation(compiler_operation_hd_key_ecdsa_signature_bch)),
            ("public_key", common_operation(&common.hd_key, "public_key")),
            ("schnorr_data_signature", operation(compiler_operation_hd_key_schnorr_data_signature_bch)),
            ("schnorr_signature", operation(compiler_operation_hd_key_schnorr_signature_bch)),
            ("signature", operation(compiler_operation_signature_renamed)),
        ]
        .into_iter()
        .map(|(name, operation)| (name.to_string(), operation))
        .collect(),
    );
    let key = CompilerOperationSet::Multiple(
        [
            ("data_signature", operation(compiler_operation_data_signature_renamed)),
            ("ecdsa_data_signature", operation(compiler_operation_key_ecdsa_data_signature_bch)),
            ("ecdsa_signature", operation(compiler_operation_key_ecdsa_signature_bch)),
            ("public_key", common_operation(&common.key, "public_key")),
            ("schnorr_data_signature", operation(compiler_operation_key_schnorr_data_signature_bch)),
            ("schnorr_signature", operation(compiler_operation_key_schnorr_signature_bch)),
            ("signature", operation(compiler_operation_signature_renamed)),
        ]
        .into_iter()
        .map(|(name, operation)| (name.to_string(), operation))
        .collect(),
    );
    let Some(CompilerOperationSet::Multiple(mut signing_serialization)) = common.signing_serialization.clone() else {
        unreachable!("the common operations include signingSerialization");
    };
    for name in [
        "full_all_outputs",
        "full_all_outputs_all_utxos",
        "full_all_outputs_single_input",
        "full_all_outputs_single_input_INVALID_all_utxos",
        "full_corresponding_output",
        "full_corresponding_output_all_utxos",
        "full_corresponding_output_single_input",
        "full_corresponding_output_single_input_INVALID_all_utxos",
        "full_default",
        "full_no_outputs",
        "full_no_outputs_all_utxos",
        "full_no_outputs_single_input",
        "full_no_outputs_single_input_INVALID_all_utxos",
    ] {
        signing_serialization.insert(name.to_string(), operation(compiler_operation_signing_serialization_full_bch));
    }
    signing_serialization.insert(
        "token_prefix".to_string(),
        operation(compiler_operation_signing_serialization_token_prefix),
    );
    CompilerOperations {
        hd_key: Some(hd_key),
        key: Some(key),
        signing_serialization: Some(CompilerOperationSet::Multiple(signing_serialization)),
        ..common
    }
}

pub use self::compiler_operations_bch as compiler_operations_BCH;

/// A compiler configuration with the BCH key operations.
pub type CompilerConfigurationBch = CompilerConfiguration;

/// @deprecated Alias of `CompilerConfigurationBch` for backwards-compatibility.
pub type CompilerConfigurationBCH = CompilerConfigurationBch;

/// Create a CashAssembly compiler using the default BCH environment.
///
/// Internally instantiates the necessary crypto and VM implementations – use
/// {@link compilerConfigurationToCompilerBch} for more control.
///
/// @param configuration - a compiler configuration from which properties
/// will be used to override properties of the default common compiler
/// configuration – must include the `scripts` property
pub fn create_compiler_bch(configuration: CompilerConfiguration) -> Compiler {
    compiler_configuration_to_compiler_bch(CompilerConfiguration {
        create_authentication_program: configuration
            .create_authentication_program
            .or_else(|| Some(Rc::new(create_authentication_program_evaluation_common))),
        opcodes: configuration
            .opcodes
            .or_else(|| Some(generate_bytecode_map(OpcodesBchSpec::MEMBERS))),
        operations: configuration.operations.or_else(|| Some(compiler_operations_bch())),
        ripemd160: configuration.ripemd160.or_else(|| Some(crate::crypto::ripemd160.clone())),
        secp256k1: configuration.secp256k1.or_else(|| Some(crate::crypto::secp256k1.clone())),
        sha256: configuration.sha256.or_else(|| Some(crate::crypto::sha256.clone())),
        sha512: configuration.sha512.or_else(|| Some(crate::crypto::sha512.clone())),
        vm: configuration.vm.or_else(|| Some(create_virtual_machine_bch_spec(None))),
        ..configuration
    })
}

pub use self::create_compiler_bch as create_compiler;
pub use self::create_compiler_bch as create_compiler_BCH;

/// Create a BCH `Compiler` from a `WalletTemplate` and an optional set of
/// overrides.
/// @param template - the `WalletTemplate` from which to create the BCH
/// compiler
/// @param overrides - a compiler configuration from which properties will be
/// used to override properties of the default BCH configuration
pub fn wallet_template_to_compiler_bch(template: &WalletTemplate, overrides: Option<CompilerConfiguration>) -> Compiler {
    let overrides = overrides.unwrap_or_default();
    let from_template = wallet_template_to_compiler_configuration(template);
    create_compiler_bch(CompilerConfiguration {
        entity_ownership: from_template.entity_ownership,
        locking_script_types: from_template.locking_script_types,
        scenarios: from_template.scenarios.or(overrides.scenarios.clone()),
        scripts: from_template.scripts,
        unlocking_script_time_lock_types: from_template.unlocking_script_time_lock_types,
        unlocking_scripts: from_template.unlocking_scripts,
        variables: from_template.variables,
        ..overrides
    })
}

pub use self::wallet_template_to_compiler_bch as wallet_template_to_compiler_BCH;
