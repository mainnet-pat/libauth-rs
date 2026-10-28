use std::collections::BTreeMap;

use crate::engine::{
    WalletTemplateScenario, WalletTemplateScenarioBytecode, WalletTemplateScenarioBytecodeDefinition,
    WalletTemplateScenarioBytecodeScript, WalletTemplateScenarioData, WalletTemplateScenarioDataHdKeys,
    WalletTemplateScenarioDataKeys, WalletTemplateScenarioInput, WalletTemplateScenarioOutput,
    WalletTemplateScenarioOutputLockingBytecode, WalletTemplateScenarioSourceOutput,
    WalletTemplateScenarioTokenAmount, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioTransactionOutput, WalletTemplateScenarioUnlockingBytecode,
    WalletTemplateScenarioValueSatoshis, WalletTemplateVariable,
};
use crate::format::{big_int_to_bin_uint256_be_clamped, bin_to_hex, bin_to_value_satoshis, hex_to_bin};
use crate::key::{derive_hd_private_node_from_seed, encode_hd_private_key, DecodedHdKey, HdKeyNetwork, HdPrivateNode};
use crate::language::{
    compile_script_raw, stringify_errors, CompilationError, CompilationErrorType, CompilationResult,
    CompilationResultError,
};
use crate::message::{Input, Nft, NonFungibleTokenCapability, Output, Token, TransactionCommon};
use crate::runtime::bigint::BigInt;
use crate::runtime::number::to_uint32;
use crate::runtime::string::locale_compare;
use crate::vm::{AuthenticationProgramCommon, CompilationContextBch};
use crate::compiler::{
    AnyCompilerConfigurationIgnoreOperations, CompilationData, CompilationDataHdKeys,
    CompilationDataKeys, CompilerDefaults, Scenario, ScenarioGenerationDebuggingResult,
};

/// The properties of a {@link WalletTemplateScenario} which define a scenario
/// (`data`, `sourceOutputs`, and `transaction`).
pub type ScenarioDefinition = WalletTemplateScenario;

/// A {@link ScenarioDefinition} in which `data`, `sourceOutputs`, and every
/// property of `transaction` are defined.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedScenarioDefinition {
    pub data: WalletTemplateScenarioData,
    pub source_outputs: Vec<WalletTemplateScenarioSourceOutput>,
    /// The scenario transaction (every property is `Some`).
    pub transaction: WalletTemplateScenarioTransaction,
}

/// Given a compiler configuration, generate the default scenario which is
/// extended by all the configuration's scenarios.
///
/// For details on default scenario generation, see
/// {@link WalletTemplateScenario.extends}.
///
/// @param configuration - the compiler configuration from which to generate
/// the default scenario
pub fn generate_default_scenario_definition(
    configuration: &AnyCompilerConfigurationIgnoreOperations,
) -> Result<ExtendedScenarioDefinition, String> {
    let variables = configuration.variables.as_ref();
    let key_variable_ids: Vec<&String> = variables
        .map(|variables| {
            variables
                .iter()
                .filter(|(_, variable)| matches!(variable, WalletTemplateVariable::Key(_)))
                .map(|(id, _)| id)
                .collect()
        })
        .unwrap_or_default();
    let entity_ids: Vec<String> = configuration
        .entity_ownership
        .as_ref()
        .map(|entity_ownership| {
            let mut entity_ids: Vec<String> = Vec::new();
            for entity_id in entity_ownership.values() {
                if !entity_ids.contains(entity_id) {
                    entity_ids.push(entity_id.clone());
                }
            }
            entity_ids
        })
        .unwrap_or_default();
    let mut ids: Vec<String> = key_variable_ids
        .into_iter()
        .cloned()
        .chain(entity_ids.iter().cloned())
        .collect();
    ids.sort_by(|id_a, id_b| locale_compare(id_a, id_b));
    let value_map: BTreeMap<String, Vec<u8>> = ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| (id, big_int_to_bin_uint256_be_clamped(&BigInt::from_u64(index as u64 + 1))))
        .collect();
    let private_keys: Option<BTreeMap<String, String>> = variables.map(|variables| {
        variables
            .iter()
            .filter(|(_, variable)| matches!(variable, WalletTemplateVariable::Key(_)))
            .map(|(variable_id, _)| (variable_id.clone(), bin_to_hex(&value_map[variable_id])))
            .collect()
    });
    let default_scenario = ExtendedScenarioDefinition {
        data: WalletTemplateScenarioData {
            bytecode: None,
            current_block_height: Some(CompilerDefaults::defaultScenarioCurrentBlockHeight),
            current_block_time: Some(CompilerDefaults::defaultScenarioCurrentBlockTime),
            hd_keys: None,
            keys: match private_keys {
                Some(private_keys) if !private_keys.is_empty() => Some(WalletTemplateScenarioDataKeys {
                    private_keys: Some(private_keys),
                }),
                _ => None,
            },
        },
        source_outputs: vec![WalletTemplateScenarioOutput {
            locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
            token: None,
            value_satoshis: None,
        }],
        transaction: WalletTemplateScenarioTransaction {
            inputs: Some(vec![WalletTemplateScenarioInput {
                outpoint_index: None,
                outpoint_transaction_hash: None,
                sequence_number: None,
                unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
            }]),
            locktime: Some(CompilerDefaults::defaultScenarioTransactionLocktime),
            outputs: Some(vec![WalletTemplateScenarioOutput {
                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                    WalletTemplateScenarioBytecode::Hex(
                        CompilerDefaults::defaultScenarioOutputLockingBytecode.to_string(),
                    ),
                )),
                token: None,
                value_satoshis: None,
            }]),
            version: Some(CompilerDefaults::defaultScenarioTransactionVersion),
        },
    };
    let has_hd_keys = variables.is_some_and(|variables| {
        variables
            .values()
            .any(|variable| matches!(variable, WalletTemplateVariable::HdKey(_)))
    });
    if !has_hd_keys {
        return Ok(default_scenario);
    }
    if configuration.sha256.is_none() {
        return Err("An implementations of \"sha256\" is required to generate defaults for HD keys, but the \"sha256\" property is not included in this compiler configuration.".to_string());
    }
    if configuration.sha512.is_none() {
        return Err("An implementations of \"sha512\" is required to generate defaults for HD keys, but the \"sha512\" property is not included in this compiler configuration.".to_string());
    }
    let hd_private_keys = entity_ids
        .iter()
        .map(|entity_id| {
            // The first 5,000,000,000 seeds have been tested, scenarios are
            // unlikely to exceed this number of entities.
            let assume_validity = true;
            let HdPrivateNode::Valid(master_node) =
                derive_hd_private_node_from_seed(&value_map[entity_id], Some(assume_validity), configuration.sha512.as_ref(), None)
            else {
                unreachable!("validity is assumed")
            };
            let hd_private_key = encode_hd_private_key(
                &DecodedHdKey {
                    network: HdKeyNetwork::Mainnet,
                    node: master_node,
                },
                configuration.sha256.as_ref(),
            )
            .expect("valid nodes can be encoded")
            .hd_private_key;
            (entity_id.clone(), hd_private_key)
        })
        .collect();
    Ok(ExtendedScenarioDefinition {
        data: WalletTemplateScenarioData {
            hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                address_index: Some(CompilerDefaults::defaultScenarioAddressIndex),
                hd_private_keys: Some(hd_private_keys),
                hd_public_keys: None,
            }),
            ..default_scenario.data
        },
        ..default_scenario
    })
}

fn merge_maps(
    parent: &Option<BTreeMap<String, String>>,
    child: &Option<BTreeMap<String, String>>,
) -> Option<BTreeMap<String, String>> {
    if parent.is_none() && child.is_none() {
        return None;
    }
    let mut merged = parent.clone().unwrap_or_default();
    merged.extend(child.clone().unwrap_or_default());
    Some(merged)
}

/// Extend the `data` property of a scenario definition with values from a
/// parent scenario definition. Returns the extended value for `data`.
///
/// @param parentData - the scenario `data` which is extended by the child
/// scenario
/// @param childData - the scenario `data` which may override values from the
/// parent scenario
pub fn extend_scenario_definition_data(
    parent_data: &WalletTemplateScenarioData,
    child_data: &WalletTemplateScenarioData,
) -> WalletTemplateScenarioData {
    WalletTemplateScenarioData {
        bytecode: merge_maps(&parent_data.bytecode, &child_data.bytecode),
        current_block_height: child_data.current_block_height.or(parent_data.current_block_height),
        current_block_time: child_data.current_block_time.or(parent_data.current_block_time),
        hd_keys: if parent_data.hd_keys.is_none() && child_data.hd_keys.is_none() {
            None
        } else {
            let parent = parent_data.hd_keys.as_ref();
            let child = child_data.hd_keys.as_ref();
            Some(WalletTemplateScenarioDataHdKeys {
                address_index: child
                    .and_then(|child| child.address_index)
                    .or_else(|| parent.and_then(|parent| parent.address_index)),
                hd_private_keys: merge_maps(
                    &parent.and_then(|parent| parent.hd_private_keys.clone()),
                    &child.and_then(|child| child.hd_private_keys.clone()),
                ),
                hd_public_keys: merge_maps(
                    &parent.and_then(|parent| parent.hd_public_keys.clone()),
                    &child.and_then(|child| child.hd_public_keys.clone()),
                ),
            })
        },
        keys: if parent_data.keys.is_none() && child_data.keys.is_none() {
            None
        } else {
            Some(WalletTemplateScenarioDataKeys {
                private_keys: Some(
                    merge_maps(
                        &parent_data.keys.as_ref().and_then(|keys| keys.private_keys.clone()),
                        &child_data.keys.as_ref().and_then(|keys| keys.private_keys.clone()),
                    )
                    .unwrap_or_default(),
                ),
            })
        },
    }
}

/// Extend a scenario definition (`parent_scenario`) with a child scenario
/// definition: properties of the child override those of the parent, with
/// `data` (and its `bytecode`, `hdKeys`, and `keys`) merged. Only the scenario
/// definition properties (`data`, `sourceOutputs`, and `transaction`) which are
/// defined by either scenario are included in the result.
///
/// The result has the type of the parent: extending an
/// [`ExtendedScenarioDefinition`] produces an [`ExtendedScenarioDefinition`],
/// and extending any other [`ScenarioDefinition`] produces a
/// [`ScenarioDefinition`].
pub fn extend_scenario_definition<ParentScenarioType>(
    parent_scenario: &ParentScenarioType,
    child_scenario: &WalletTemplateScenario,
) -> ParentScenarioType
where
    ParentScenarioType: Clone + Into<ScenarioDefinition> + TryFrom<ScenarioDefinition>,
{
    let parent_scenario: ScenarioDefinition = parent_scenario.clone().into();
    let extended = ScenarioDefinition {
        data: if parent_scenario.data.is_none() && child_scenario.data.is_none() {
            None
        } else {
            Some(extend_scenario_definition_data(
                parent_scenario.data.as_ref().unwrap_or(&empty_scenario_data()),
                child_scenario.data.as_ref().unwrap_or(&empty_scenario_data()),
            ))
        },
        description: None,
        extends: None,
        name: None,
        source_outputs: child_scenario.source_outputs.clone().or(parent_scenario.source_outputs),
        transaction: match (parent_scenario.transaction, &child_scenario.transaction) {
            (None, None) => None,
            (parent, child) => {
                let parent = parent.unwrap_or(empty_scenario_transaction());
                let child = child.clone().unwrap_or(empty_scenario_transaction());
                Some(WalletTemplateScenarioTransaction {
                    inputs: child.inputs.or(parent.inputs),
                    locktime: child.locktime.or(parent.locktime),
                    outputs: child.outputs.or(parent.outputs),
                    version: child.version.or(parent.version),
                })
            }
        },
    };
    ParentScenarioType::try_from(extended)
        .unwrap_or_else(|_| unreachable!("extending a scenario definition preserves its defined properties"))
}

fn empty_scenario_transaction() -> WalletTemplateScenarioTransaction {
    WalletTemplateScenarioTransaction {
        inputs: None,
        locktime: None,
        outputs: None,
        version: None,
    }
}

impl From<ExtendedScenarioDefinition> for ScenarioDefinition {
    fn from(definition: ExtendedScenarioDefinition) -> ScenarioDefinition {
        WalletTemplateScenario {
            data: Some(definition.data),
            description: None,
            extends: None,
            name: None,
            source_outputs: Some(definition.source_outputs),
            transaction: Some(definition.transaction),
        }
    }
}

/// Succeeds if `data`, `sourceOutputs`, and every property of `transaction`
/// are defined.
impl TryFrom<ScenarioDefinition> for ExtendedScenarioDefinition {
    type Error = String;
    fn try_from(definition: ScenarioDefinition) -> Result<ExtendedScenarioDefinition, String> {
        let incomplete = || "An extended scenario definition must define data, sourceOutputs, and every property of transaction.".to_string();
        let transaction = definition.transaction.ok_or_else(incomplete)?;
        if transaction.inputs.is_none()
            || transaction.locktime.is_none()
            || transaction.outputs.is_none()
            || transaction.version.is_none()
        {
            return Err(incomplete());
        }
        Ok(ExtendedScenarioDefinition {
            data: definition.data.ok_or_else(incomplete)?,
            source_outputs: definition.source_outputs.ok_or_else(incomplete)?,
            transaction,
        })
    }
}

fn empty_scenario_data() -> WalletTemplateScenarioData {
    WalletTemplateScenarioData {
        bytecode: None,
        current_block_height: None,
        current_block_time: None,
        hd_keys: None,
        keys: None,
    }
}

/// Generate the full scenario which is extended by the provided scenario
/// identifier. Scenarios for which `extends` is `undefined` extend the default
/// scenario for the provided compiler configuration.
pub fn generate_extended_scenario(
    configuration: &AnyCompilerConfigurationIgnoreOperations,
    scenario_id: Option<&str>,
    source_scenario_ids: Option<Vec<String>>,
) -> Result<ExtendedScenarioDefinition, String> {
    let source_scenario_ids = source_scenario_ids.unwrap_or_default();
    let Some(scenario_id) = scenario_id else {
        return generate_default_scenario_definition(configuration);
    };
    if source_scenario_ids.iter().any(|id| id == scenario_id) {
        return Err(format!(
            "Cannot extend scenario \"{scenario_id}\": scenario \"{scenario_id}\" extends itself. Scenario inheritance path: {}",
            source_scenario_ids.join(" → ")
        ));
    }
    let Some(scenario) = configuration
        .scenarios
        .as_ref()
        .and_then(|scenarios| scenarios.get(scenario_id))
    else {
        return Err(format!(
            "Cannot extend scenario \"{scenario_id}\": a scenario with the identifier {scenario_id} is not included in this compiler configuration."
        ));
    };
    let parent_scenario = match &scenario.extends {
        None => generate_default_scenario_definition(configuration),
        Some(extends) => {
            let mut source_scenario_ids = source_scenario_ids.clone();
            source_scenario_ids.push(scenario_id.to_string());
            generate_extended_scenario(configuration, Some(extends), Some(source_scenario_ids))
        }
    }?;
    Ok(extend_scenario_definition(&parent_scenario, scenario))
}

/// Derive standard {@link CompilationData} properties from an extended
/// scenario definition.
///
/// @param definition - a scenario definition which has been extended by the
/// default scenario definition
pub fn extended_scenario_definition_to_compilation_data(
    definition: &ScenarioDefinition,
) -> CompilationData {
    let empty = empty_scenario_data();
    // libauth requires `data` (`Required<Pick<ScenarioDefinition, 'data'>>`).
    let data = definition.data.as_ref().unwrap_or(&empty);
    CompilationData {
        bytecode: None,
        compilation_context: None,
        current_block_height: data.current_block_height,
        current_block_time: data.current_block_time,
        hd_keys: data.hd_keys.as_ref().map(|hd_keys| CompilationDataHdKeys {
            address_index: hd_keys.address_index,
            hd_private_keys: hd_keys
                .hd_private_keys
                .clone()
                .filter(|hd_private_keys| !hd_private_keys.is_empty()),
            hd_public_keys: hd_keys.hd_public_keys.clone(),
        }),
        keys: data
            .keys
            .as_ref()
            .and_then(|keys| keys.private_keys.as_ref())
            .filter(|private_keys| !private_keys.is_empty())
            .map(|private_keys| CompilationDataKeys {
                private_keys: Some(
                    private_keys
                        .iter()
                        .map(|(id, hex)| (id.clone(), hex_to_bin(hex)))
                        .collect(),
                ),
            }),
    }
}

/// Extend a {@link CompilationData} object with the compiled result of the
/// bytecode scripts provided by a {@link WalletTemplateScenarioData}.
///
/// @param compilationData - the compilation data to extend
/// @param configuration - the compiler configuration to use
/// @param scenarioDataBytecodeScripts - the {@link WalletTemplateScenarioData.bytecode}
/// property
pub fn extend_compilation_data_with_scenario_bytecode(
    compilation_data: &CompilationData,
    configuration: &AnyCompilerConfigurationIgnoreOperations,
    scenario_data_bytecode_scripts: &BTreeMap<String, String>,
) -> Result<CompilationData, String> {
    let prefix_bytecode_script_id = |id: &str| format!("{}{id}", CompilerDefaults::scenarioBytecodeScriptPrefix);
    let mut bytecode_script_extended_configuration = configuration.clone();
    for (id, script) in scenario_data_bytecode_scripts {
        bytecode_script_extended_configuration
            .scripts
            .insert(prefix_bytecode_script_id(id), script.clone());
    }
    let bytecode_compilations: Vec<(String, Result<Vec<u8>, Vec<CompilationError>>)> = scenario_data_bytecode_scripts
        .keys()
        .map(|id| {
            let result = compile_script_raw(
                compilation_data,
                &bytecode_script_extended_configuration,
                &prefix_bytecode_script_id(id),
            );
            (
                id.clone(),
                match result {
                    CompilationResult::Success(result) => Ok(result.bytecode),
                    CompilationResult::Error(result) => Err(result.errors),
                },
            )
        })
        .collect();
    let failed_results: Vec<String> = bytecode_compilations
        .iter()
        .filter_map(|(id, result)| {
            result.as_ref().err().map(|errors| {
                format!(
                    "Compilation error while generating bytecode for \"{id}\": {}",
                    stringify_errors(errors, None)
                )
            })
        })
        .collect();
    if !failed_results.is_empty() {
        return Err(failed_results.join("; "));
    }
    let compiled_bytecode: BTreeMap<String, Vec<u8>> = bytecode_compilations
        .into_iter()
        .map(|(id, result)| (id, result.expect("failed results were returned")))
        .collect();
    Ok(CompilationData {
        bytecode: compilation_data
            .bytecode
            .clone()
            .or((!compiled_bytecode.is_empty()).then_some(compiled_bytecode)),
        ..compilation_data.clone()
    })
}

/// Compile a {@link WalletTemplateScenarioOutput.valueSatoshis}, returning
/// the `bigint` value.
///
/// `value_satoshis_definition` defaults to
/// `CompilerDefaults.defaultScenarioOutputValueSatoshis`.
pub fn compile_wallet_template_scenario_value_satoshis(
    value_satoshis_definition: Option<&WalletTemplateScenarioValueSatoshis>,
) -> u64 {
    let value = match value_satoshis_definition {
        None => CompilerDefaults::defaultScenarioOutputValueSatoshis,
        Some(WalletTemplateScenarioValueSatoshis::Hex(hex)) => return bin_to_value_satoshis(&hex_to_bin(hex)),
        Some(WalletTemplateScenarioValueSatoshis::Number(value)) => *value,
    };
    big_int_as_uint64(&BigInt::from_number(value))
}

/// The `u64` holding a scenario's `bigint` satoshi value or token amount:
/// values outside of the `u64` range are reduced modulo 2^64, as libauth's
/// 8-byte encoders do.
fn big_int_as_uint64(value: &BigInt) -> u64 {
    BigInt::as_uint_n(64, value).to_u64().expect("a 64-bit value")
}

/// The result of {@link compileWalletTemplateScenarioBytecode}: a compilation
/// result, literal bytecode, or an error compiling the scenario's
/// `data.bytecode`.
fn scenario_data_error(error: String) -> CompilationResult {
    CompilationResult::Error(CompilationResultError {
        error_type: CompilationErrorType::Parse,
        errors: vec![CompilationError {
            error,
            missing_identifier: None,
            owning_entity: None,
            range: crate::language::create_empty_range(),
        }],
        parse: None,
        reduce: None,
        resolve: None,
    })
}

/// Compile a {@link WalletTemplateScenarioBytecode} definition for a
/// scenario, returning the literal bytecode (`Ok`) or the compilation result
/// (`Err`, either a successful or failed compilation).
#[allow(clippy::too_many_arguments)]
pub fn compile_wallet_template_scenario_bytecode(
    bytecode_definition: &WalletTemplateScenarioBytecode,
    compilation_context: Option<CompilationContextBch>,
    configuration: &AnyCompilerConfigurationIgnoreOperations,
    default_override: &WalletTemplateScenarioData,
    extended_scenario: &ExtendedScenarioDefinition,
    generate_bytecode: &dyn Fn(CompilationData, &str) -> CompilationResult,
    locking_or_unlocking_script_id_under_test: Option<&str>,
) -> Result<Vec<u8>, CompilationResult> {
    let WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition { script, overrides }) =
        bytecode_definition
    else {
        let WalletTemplateScenarioBytecode::Hex(hex) = bytecode_definition else {
            unreachable!()
        };
        return Ok(hex_to_bin(hex));
    };
    let script_id = match script {
        None | Some(WalletTemplateScenarioBytecodeScript::Copy) => locking_or_unlocking_script_id_under_test,
        Some(WalletTemplateScenarioBytecodeScript::Id(script)) => Some(script.as_str()),
    };
    let Some(script_id) = script_id else {
        return Ok(hex_to_bin(""));
    };
    let overrides = overrides.as_ref().unwrap_or(default_override);
    let overridden_data_definition = extend_scenario_definition_data(&extended_scenario.data, overrides);
    let data = extend_compilation_data_with_scenario_bytecode(
        &extended_scenario_definition_to_compilation_data(&ScenarioDefinition {
            data: Some(overridden_data_definition.clone()),
            description: None,
            extends: None,
            name: None,
            source_outputs: None,
            transaction: None,
        }),
        configuration,
        &overridden_data_definition.bytecode.clone().unwrap_or_default(),
    );
    match data {
        Err(data) => Err(scenario_data_error(format!(
            "Could not compile scenario \"data.bytecode\": {data}"
        ))),
        Ok(data) => Err(generate_bytecode(
            CompilationData {
                compilation_context,
                ..data
            },
            script_id,
        )),
    }
}

/// Compile the `token` property of a {@link WalletTemplateScenarioOutput}.
pub fn compile_scenario_output_token_data<const IS_SOURCE_OUTPUT: bool>(
    output: &WalletTemplateScenarioOutput<IS_SOURCE_OUTPUT>,
) -> Option<Token> {
    output.token.as_ref().map(|token| Token {
        amount: {
            let amount = match &token.amount {
                None => BigInt::zero(),
                Some(WalletTemplateScenarioTokenAmount::Number(amount)) => BigInt::from_number(*amount),
                Some(WalletTemplateScenarioTokenAmount::Decimal(amount)) => {
                    BigInt::parse(amount).unwrap_or_else(|error| panic!("{error}"))
                }
            };
            // libauth encodes amounts below 1 without an amount, as for 0.
            if amount.is_negative() { 0 } else { big_int_as_uint64(&amount) }
        },
        category: hex_to_bin(
            token
                .category
                .as_deref()
                .unwrap_or(CompilerDefaults::defaultScenarioOutputTokenCategory),
        ),
        nft: token.nft.as_ref().map(|nft| Nft {
            capability: nft.capability.unwrap_or(NonFungibleTokenCapability::None),
            commitment: hex_to_bin(nft.commitment.as_deref().unwrap_or("")),
        }),
    })
}

/// The compiled locking bytecode of a scenario output: literal bytecode or a
/// compilation result.
enum CompiledBytecode {
    Literal(Vec<u8>),
    Compilation(CompilationResult),
}

impl CompiledBytecode {
    fn errors(&self) -> Option<&[CompilationError]> {
        match self {
            CompiledBytecode::Compilation(CompilationResult::Error(result)) => Some(&result.errors),
            _ => None,
        }
    }

    fn bytecode(&self) -> Vec<u8> {
        match self {
            CompiledBytecode::Literal(bytecode) => bytecode.clone(),
            CompiledBytecode::Compilation(CompilationResult::Success(result)) => result.bytecode.clone(),
            CompiledBytecode::Compilation(CompilationResult::Error(_)) => unreachable!("errors were returned"),
        }
    }
}

fn compiled(result: Result<Vec<u8>, CompilationResult>) -> CompiledBytecode {
    match result {
        Ok(bytecode) => CompiledBytecode::Literal(bytecode),
        Err(result) => CompiledBytecode::Compilation(result),
    }
}

fn locking_bytecode_definition<const IS_SOURCE_OUTPUT: bool>(
    output: &WalletTemplateScenarioOutput<IS_SOURCE_OUTPUT>,
) -> WalletTemplateScenarioBytecode {
    match &output.locking_bytecode {
        Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(bytecode)) => bytecode.clone(),
        _ => WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
            overrides: None,
            script: None,
        }),
    }
}

/// Generate a scenario (or a scenario generation debugging result) from a
/// compiler configuration. See {@link Compiler.generateScenario}.
///
/// `generate_bytecode` is the compiler's debugging `generateBytecode`
/// (`debug: true`).
pub fn generate_scenario_bch(
    configuration: &AnyCompilerConfigurationIgnoreOperations,
    generate_bytecode: &dyn Fn(CompilationData, &str) -> CompilationResult,
    scenario_id: Option<&str>,
    unlocking_script_id: Option<&str>,
    locking_script_id: Option<&str>,
    debug: Option<bool>,
) -> Result<ScenarioGenerationDebuggingResult, String> {
    let debug = debug.unwrap_or(false);
    let provided_locking_script_id = locking_script_id;
    let (scenario_definition, scenario_name) = match scenario_id {
        None => (
            Some(WalletTemplateScenario {
                data: None,
                description: None,
                extends: None,
                name: None,
                source_outputs: None,
                transaction: None,
            }),
            "the default scenario".to_string(),
        ),
        Some(scenario_id) => (
            configuration
                .scenarios
                .as_ref()
                .and_then(|scenarios| scenarios.get(scenario_id))
                .cloned(),
            format!("scenario \"{scenario_id}\""),
        ),
    };
    let Some(scenario_definition) = scenario_definition else {
        return Err(format!(
            "Cannot generate {scenario_name}: a scenario definition with the identifier {} is not included in this compiler configuration.",
            scenario_id.unwrap_or_default()
        ));
    };
    let parent_scenario = generate_extended_scenario(configuration, scenario_id, None)
        .map_err(|parent_scenario| format!("Cannot generate {scenario_name}: {parent_scenario}"))?;
    let extended_scenario = extend_scenario_definition(&parent_scenario, &scenario_definition);
    let partial_compilation_data =
        extended_scenario_definition_to_compilation_data(&ScenarioDefinition::from(extended_scenario.clone()));
    let full_compilation_data = extend_compilation_data_with_scenario_bytecode(
        &partial_compilation_data,
        configuration,
        &extended_scenario.data.bytecode.clone().unwrap_or_default(),
    )
    .map_err(|full_compilation_data| format!("Cannot generate {scenario_name}. {full_compilation_data}"))?;
    let transaction_inputs = extended_scenario.transaction.inputs.clone().unwrap_or_default();
    let transaction_outputs = extended_scenario.transaction.outputs.clone().unwrap_or_default();
    let locktime = to_uint32(extended_scenario.transaction.locktime.unwrap_or_default());
    let version = to_uint32(extended_scenario.transaction.version.unwrap_or_default());
    if transaction_inputs.len() != extended_scenario.source_outputs.len() {
        return Err(format!(
            "Cannot generate {scenario_name}: could not match source outputs with inputs - \"sourceOutputs\" must be the same length as \"transaction.inputs\"."
        ));
    }
    let is_slot_input = |input: &WalletTemplateScenarioInput| {
        matches!(input.unlocking_bytecode, Some(WalletTemplateScenarioUnlockingBytecode::Slot))
    };
    let is_slot_output = |output: &WalletTemplateScenarioSourceOutput| {
        matches!(output.locking_bytecode, Some(WalletTemplateScenarioOutputLockingBytecode::Slot))
    };
    if transaction_inputs.iter().filter(|input| is_slot_input(input)).count() != 1 {
        return Err(format!(
            "Cannot generate {scenario_name}: the specific input under test in this scenario is ambiguous - \"transaction.inputs\" must include exactly one input that has \"unlockingBytecode\" set to [\"slot\"]."
        ));
    }
    let tested_input_index = transaction_inputs
        .iter()
        .position(is_slot_input)
        .expect("exactly one input is a slot");
    if extended_scenario.source_outputs.iter().filter(|output| is_slot_output(output)).count() != 1 {
        return Err(format!(
            "Cannot generate {scenario_name}: the source output unlocked by the input under test in this scenario is ambiguous - \"sourceOutputs\" must include exactly one output that has \"lockingBytecode\" set to [\"slot\"]."
        ));
    }
    if !extended_scenario
        .source_outputs
        .get(tested_input_index)
        .is_some_and(is_slot_output)
    {
        return Err(format!(
            "Cannot generate {scenario_name}: the source output unlocked by the input under test in this scenario is ambiguous - the [\"slot\"] in \"transaction.inputs\" and \"sourceOutputs\" must be at the same index."
        ));
    }
    if unlocking_script_id.is_some() && provided_locking_script_id.is_some() {
        return Err(format!(
            "Cannot generate {scenario_name}: a scenario cannot be generated with both unlocking and locking script IDs defined. If an unlocking script is provided, the associated locking script ID must be read from the template."
        ));
    }
    let locking_script_id: Option<String> = provided_locking_script_id.map(str::to_string).or_else(|| {
        unlocking_script_id.and_then(|unlocking_script_id| {
            configuration
                .unlocking_scripts
                .as_ref()
                .and_then(|unlocking_scripts| unlocking_scripts.get(unlocking_script_id))
                .cloned()
        })
    });
    if let (Some(unlocking_script_id), None) = (unlocking_script_id, &locking_script_id) {
        return Err(format!(
            "Cannot generate {scenario_name} using unlocking script \"{unlocking_script_id}\": the locking script unlocked by \"{unlocking_script_id}\" is not provided in this compiler configuration."
        ));
    }
    let empty_override = empty_scenario_data();
    let source_output_compilations: Vec<(CompiledBytecode, u64, Option<Token>, bool)> = extended_scenario
        .source_outputs
        .iter()
        .map(|source_output| {
            let slot = is_slot_output(source_output);
            let bytecode_definition = if slot {
                match &locking_script_id {
                    None => WalletTemplateScenarioBytecode::Hex(CompilerDefaults::defaultScenarioBytecode.to_string()),
                    Some(locking_script_id) => WalletTemplateScenarioBytecode::Definition(
                        WalletTemplateScenarioBytecodeDefinition {
                            overrides: None,
                            script: Some(WalletTemplateScenarioBytecodeScript::Id(locking_script_id.clone())),
                        },
                    ),
                }
            } else {
                locking_bytecode_definition(source_output)
            };
            (
                compiled(compile_wallet_template_scenario_bytecode(
                    &bytecode_definition,
                    None,
                    configuration,
                    &empty_override,
                    &extended_scenario,
                    generate_bytecode,
                    locking_script_id.as_deref(),
                )),
                compile_wallet_template_scenario_value_satoshis(source_output.value_satoshis.as_ref()),
                compile_scenario_output_token_data(source_output),
                slot,
            )
        })
        .collect();
    let locking_compilation = source_output_compilations
        .iter()
        .find(|(_, _, _, slot)| *slot)
        .and_then(|(compilation, ..)| match compilation {
            CompiledBytecode::Compilation(result) => Some(result.clone()),
            CompiledBytecode::Literal(_) => None,
        });
    let transaction_output_override = WalletTemplateScenarioData {
        hd_keys: Some(WalletTemplateScenarioDataHdKeys {
            address_index: Some(1.0),
            hd_private_keys: None,
            hd_public_keys: None,
        }),
        ..empty_scenario_data()
    };
    let transaction_output_compilations: Vec<(CompiledBytecode, u64, Option<Token>)> = transaction_outputs
        .iter()
        .map(|transaction_output: &WalletTemplateScenarioTransactionOutput| {
            (
                compiled(compile_wallet_template_scenario_bytecode(
                    &locking_bytecode_definition(transaction_output),
                    None,
                    configuration,
                    &transaction_output_override,
                    &extended_scenario,
                    generate_bytecode,
                    locking_script_id.as_deref(),
                )),
                compile_wallet_template_scenario_value_satoshis(transaction_output.value_satoshis.as_ref()),
                compile_scenario_output_token_data(transaction_output),
            )
        })
        .collect();
    let output_compilation_errors: Vec<String> = source_output_compilations
        .iter()
        .enumerate()
        .flat_map(|(index, (compilation, ..))| {
            compilation
                .errors()
                .unwrap_or_default()
                .iter()
                .map(move |error_object| {
                    format!("Failed compilation of source output at index {index}: {}", error_object.error)
                })
        })
        .chain(
            transaction_output_compilations
                .iter()
                .enumerate()
                .flat_map(|(index, (compilation, ..))| {
                    compilation
                        .errors()
                        .unwrap_or_default()
                        .iter()
                        .map(move |error_object| {
                            format!(
                                "Failed compilation of transaction output at index {index}: {}",
                                error_object.error
                            )
                        })
                }),
        )
        .collect();
    if !output_compilation_errors.is_empty() {
        let error = format!("Cannot generate {scenario_name}: {}", output_compilation_errors.join(" "));
        if debug {
            return Ok(ScenarioGenerationDebuggingResult {
                locking_compilation,
                scenario: Err(error),
                unlocking_compilation: None,
            });
        }
        return Err(error);
    }
    let extract_output = |(compilation, value_satoshis, token): (&CompiledBytecode, &u64, &Option<Token>)| Output {
        locking_bytecode: compilation.bytecode(),
        token: token.clone(),
        value_satoshis: *value_satoshis,
    };
    let source_outputs: Vec<Output> = source_output_compilations
        .iter()
        .map(|(compilation, value_satoshis, token, _)| extract_output((compilation, value_satoshis, token)))
        .collect();
    let outputs: Vec<Output> = transaction_output_compilations
        .iter()
        .map(|(compilation, value_satoshis, token)| extract_output((compilation, value_satoshis, token)))
        .collect();
    let inputs_context: Vec<Input<Option<Vec<u8>>>> = transaction_inputs
        .iter()
        .enumerate()
        .map(|(input_index, input)| Input {
            outpoint_index: input.outpoint_index.map_or(input_index as u32, to_uint32),
            outpoint_transaction_hash: hex_to_bin(
                input
                    .outpoint_transaction_hash
                    .as_deref()
                    .unwrap_or(CompilerDefaults::defaultScenarioInputOutpointTransactionHash),
            ),
            sequence_number: to_uint32(
                input
                    .sequence_number
                    .unwrap_or(CompilerDefaults::defaultScenarioInputSequenceNumber),
            ),
            unlocking_bytecode: None,
        })
        .collect();
    let transaction_input_compilations: Vec<(CompiledBytecode, bool)> = transaction_inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let slot = is_slot_input(input);
            let bytecode_definition = match &input.unlocking_bytecode {
                Some(WalletTemplateScenarioUnlockingBytecode::Slot) => match unlocking_script_id {
                    None => WalletTemplateScenarioBytecode::Hex(CompilerDefaults::defaultScenarioBytecode.to_string()),
                    Some(unlocking_script_id) => {
                        WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                            overrides: None,
                            script: Some(WalletTemplateScenarioBytecodeScript::Id(unlocking_script_id.to_string())),
                        })
                    }
                },
                Some(WalletTemplateScenarioUnlockingBytecode::Bytecode(bytecode)) => bytecode.clone(),
                None => WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                    overrides: None,
                    script: None,
                }),
            };
            (
                compiled(compile_wallet_template_scenario_bytecode(
                    &bytecode_definition,
                    Some(CompilationContextBch {
                        input_index: index,
                        source_outputs: source_outputs.clone(),
                        transaction: TransactionCommon {
                            inputs: inputs_context.clone(),
                            locktime,
                            outputs: outputs.clone(),
                            version,
                        },
                    }),
                    configuration,
                    &empty_override,
                    &extended_scenario,
                    generate_bytecode,
                    unlocking_script_id,
                )),
                slot,
            )
        })
        .collect();
    let unlocking_compilation = transaction_input_compilations
        .iter()
        .find(|(_, slot)| *slot)
        .and_then(|(compilation, _)| match compilation {
            CompiledBytecode::Compilation(result) => Some(result.clone()),
            CompiledBytecode::Literal(_) => None,
        });
    let input_compilation_errors: Vec<String> = transaction_input_compilations
        .iter()
        .enumerate()
        .flat_map(|(index, (compilation, _))| {
            compilation
                .errors()
                .unwrap_or_default()
                .iter()
                .map(move |error_object| format!("Failed compilation of input at index {index}: {}", error_object.error))
        })
        .collect();
    if !input_compilation_errors.is_empty() {
        let error = format!("Cannot generate {scenario_name}: {}", input_compilation_errors.join(" "));
        if debug {
            return Ok(ScenarioGenerationDebuggingResult {
                locking_compilation,
                scenario: Err(error),
                unlocking_compilation,
            });
        }
        return Err(error);
    }
    let inputs: Vec<Input> = transaction_input_compilations
        .iter()
        .zip(&inputs_context)
        .map(|((compilation, _), context)| Input {
            outpoint_index: context.outpoint_index,
            outpoint_transaction_hash: context.outpoint_transaction_hash.clone(),
            sequence_number: context.sequence_number,
            unlocking_bytecode: compilation.bytecode(),
        })
        .collect();
    let scenario = Scenario {
        data: full_compilation_data,
        program: AuthenticationProgramCommon {
            input_index: tested_input_index,
            source_outputs,
            transaction: TransactionCommon {
                inputs,
                locktime,
                outputs,
                version,
            },
        },
    };
    Ok(ScenarioGenerationDebuggingResult {
        locking_compilation,
        scenario: Ok(scenario),
        unlocking_compilation,
    })
}

pub use self::generate_scenario_bch as generate_scenario_BCH;
