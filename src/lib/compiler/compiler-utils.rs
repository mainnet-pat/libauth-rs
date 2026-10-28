use std::collections::BTreeMap;
use std::rc::Rc;

use crate::engine::{WalletTemplate, WalletTemplateLockingType, WalletTemplateScriptDefinition};
use crate::language::{compile_script, CompilationResult, CompilationResultError};
use crate::message::{Input, Output, TransactionCommon};
use crate::vm::{
    create_virtual_machine_bch_spec, generate_bytecode_map, AuthenticationProgramCommon,
    AuthenticationProgramStateCommon, AuthenticationVirtualMachineBch, OpcodesBchSpec, OpcodesBtc,
};
use crate::compiler::{
    compiler_operations_common, generate_scenario_bch, BytecodeGenerationResult, CompilationData,
    Compiler, CompilerConfiguration, ScenarioGenerationDebuggingResult,
};

/// Create a `generateBytecode` method (the debugging variant, which returns
/// the full compilation result) for the provided compiler configuration.
pub fn create_compiler_generate_bytecode_function(
    compiler_configuration: CompilerConfiguration,
) -> Rc<dyn Fn(&CompilationData, &str) -> CompilationResult> {
    Rc::new(move |data, script_id| compile_script(script_id, data, &compiler_configuration))
}

impl Compiler {
    /// Generate the bytecode for the script with the provided `script_id`
    /// (libauth's `generateBytecode({ data, scriptId })`).
    pub fn generate_bytecode(&self, data: &CompilationData, script_id: &str) -> BytecodeGenerationResult {
        match compile_script(script_id, data, &self.configuration) {
            CompilationResult::Success(result) => BytecodeGenerationResult::Success {
                bytecode: result.bytecode,
            },
            CompilationResult::Error(result) => BytecodeGenerationResult::Error(CompilationResultError {
                error_type: result.error_type,
                errors: result.errors,
                parse: None,
                reduce: None,
                resolve: None,
            }),
        }
    }

    /// Generate the bytecode for the script with the provided `script_id`,
    /// returning the full compilation result (libauth's
    /// `generateBytecode({ data, debug: true, scriptId })`).
    pub fn generate_bytecode_debug(&self, data: &CompilationData, script_id: &str) -> CompilationResult {
        create_compiler_generate_bytecode_function(self.configuration.clone())(data, script_id)
    }

    /// Generate the scenario with the provided `scenario_id` (or the default
    /// scenario) for the provided locking or unlocking script (libauth's
    /// `generateScenario`), returning the scenario or an error message.
    pub fn generate_scenario(
        &self,
        locking_script_id: Option<&str>,
        scenario_id: Option<&str>,
        unlocking_script_id: Option<&str>,
    ) -> Result<crate::compiler::Scenario, String> {
        self.generate_scenario_with_debug(locking_script_id, scenario_id, unlocking_script_id, false)
            .and_then(|result| result.scenario)
    }

    /// As {@link Compiler.generate_scenario}, returning the compilations of the
    /// scripts under test (libauth's `generateScenario({ debug: true, ... })`).
    pub fn generate_scenario_debug(
        &self,
        locking_script_id: Option<&str>,
        scenario_id: Option<&str>,
        unlocking_script_id: Option<&str>,
    ) -> Result<ScenarioGenerationDebuggingResult, String> {
        self.generate_scenario_with_debug(locking_script_id, scenario_id, unlocking_script_id, true)
    }

    fn generate_scenario_with_debug(
        &self,
        locking_script_id: Option<&str>,
        scenario_id: Option<&str>,
        unlocking_script_id: Option<&str>,
        debug: bool,
    ) -> Result<ScenarioGenerationDebuggingResult, String> {
        let generate_bytecode = create_compiler_generate_bytecode_function(self.configuration.clone());
        generate_scenario_bch(
            &self.configuration,
            &|data: CompilationData, script_id: &str| generate_bytecode(&data, script_id),
            scenario_id,
            unlocking_script_id,
            locking_script_id,
            Some(debug),
        )
    }
}

/// Create a {@link Compiler} from the provided compiler configuration. This
/// method requires a full {@link CompilerConfiguration} and does not provide
/// any crypto or VM implementations.
///
/// @param configuration - the configuration from which to create the compiler
pub fn compiler_configuration_to_compiler_bch(configuration: CompilerConfiguration) -> Compiler {
    Compiler { configuration }
}

/// @deprecated Alias of `compilerConfigurationToCompilerBch` for
/// backwards-compatibility.
pub use self::compiler_configuration_to_compiler_bch as compiler_configuration_to_compiler_BCH;

pub use self::compiler_configuration_to_compiler_bch as compiler_configuration_to_compiler;

const NULL_HASH_LENGTH: usize = 32;
const OP_RETURN: u8 = 0x6a;

/// A common {@link createAuthenticationProgram} implementation for most
/// compilers.
///
/// Accepts the compiled contents of an evaluation and produces a
/// {@link AuthenticationProgramCommon} which can be evaluated to produce the
/// resulting program state.
///
/// The precise shape of the authentication program produced by this method is
/// critical to the determinism of CashAssembly evaluations for the compiler in
/// which it is used, it therefore must be standardized between compiler
/// implementations.
///
/// @param evaluationBytecode - the compiled bytecode to incorporate in the
/// created authentication program
pub fn create_authentication_program_evaluation_common(evaluation_bytecode: &[u8]) -> AuthenticationProgramCommon {
    AuthenticationProgramCommon {
        input_index: 0,
        source_outputs: vec![Output {
            locking_bytecode: evaluation_bytecode.to_vec(),
            token: None,
            value_satoshis: 0,
        }],
        transaction: TransactionCommon {
            inputs: vec![Input {
                outpoint_index: 0,
                outpoint_transaction_hash: vec![0; NULL_HASH_LENGTH],
                sequence_number: 0,
                unlocking_bytecode: Vec::new(),
            }],
            locktime: 0,
            outputs: vec![Output {
                locking_bytecode: vec![OP_RETURN],
                token: None,
                value_satoshis: 0,
            }],
            version: 0,
        },
    }
}

/// Create a compiler using the default common compiler configuration. Because
/// this compiler has no access to a VM, it cannot reduce evaluations.
///
/// @param scriptsAndOverrides - a compiler configuration from which properties
/// will be used to override properties of the default common compiler
/// configuration – must include the `scripts` property
pub fn create_compiler_common(scripts_and_overrides: CompilerConfiguration) -> Compiler {
    compiler_configuration_to_compiler_bch(CompilerConfiguration {
        create_authentication_program: scripts_and_overrides
            .create_authentication_program
            .or_else(|| Some(Rc::new(create_authentication_program_evaluation_common))),
        opcodes: scripts_and_overrides
            .opcodes
            .or_else(|| Some(generate_bytecode_map(crate::vm::Opcodes::MEMBERS))),
        operations: scripts_and_overrides.operations.or_else(|| Some(compiler_operations_common())),
        ripemd160: scripts_and_overrides.ripemd160.or_else(|| Some(crate::crypto::ripemd160.clone())),
        secp256k1: scripts_and_overrides.secp256k1.or_else(|| Some(crate::crypto::secp256k1.clone())),
        sha256: scripts_and_overrides.sha256.or_else(|| Some(crate::crypto::sha256.clone())),
        sha512: scripts_and_overrides.sha512.or_else(|| Some(crate::crypto::sha512.clone())),
        ..scripts_and_overrides
    })
}

/// Perform a simplified compilation on a CashAssembly script containing only
/// hex literals, bigint literals, UTF8 literals, and push statements. Scripts
/// may not contain variables/operations, evaluations, or opcode identifiers
/// (use hex literals instead).
///
/// This is useful for accepting complex user input in advanced interfaces,
/// especially for `AddressData` and `WalletData`.
///
/// Returns the compiled bytecode as a `Uint8Array`, or throws an error message.
///
/// @param script - a simple CashAssembly script containing no variables or
/// evaluations
pub fn compile_cash_assembly(script: &str) -> Result<Vec<u8>, String> {
    let result = create_compiler_common(CompilerConfiguration {
        opcodes: Some(BTreeMap::new()),
        operations: Some(Default::default()),
        scripts: BTreeMap::from([("script".to_string(), script.to_string())]),
        ..Default::default()
    })
    .generate_bytecode(&CompilationData::default(), "script");
    match result {
        BytecodeGenerationResult::Success { bytecode } => Ok(bytecode),
        BytecodeGenerationResult::Error(result) => Err(format!(
            "CashAssembly compilation error:{}",
            result.errors.iter().fold(String::new(), |all, error| format!(
                "{all} [{}, {}]: {}",
                error.range.start_line_number, error.range.start_column, error.error
            ))
        )),
    }
}

fn default_vm() -> AuthenticationVirtualMachineBch {
    create_virtual_machine_bch_spec(None)
}

/// Generate a debugging scenario for the provided CashAssembly `script` (as
/// the locking script `script`), using the provided compiler configuration
/// overrides (the default VM is `createVirtualMachineBchSpec()`).
pub fn debug_cash_assembly_compilation(
    script: &str,
    scripts_and_overrides: Option<CompilerConfiguration>,
) -> Result<ScenarioGenerationDebuggingResult, String> {
    let scripts_and_overrides = scripts_and_overrides.unwrap_or_default();
    let mut scripts = BTreeMap::from([("script".to_string(), script.to_string())]);
    scripts.extend(scripts_and_overrides.scripts.clone());
    let merged = CompilerConfiguration {
        scripts,
        vm: scripts_and_overrides.vm.clone().or_else(|| Some(default_vm())),
        ..scripts_and_overrides
    };
    create_compiler_common(merged).generate_scenario_debug(Some("script"), None, None)
}

/// The result of {@link debugCashAssembly}.
#[derive(Clone, Debug)]
pub enum DebugCashAssemblyResult {
    /// The scenario could not be generated (`{ error, result?, success: false }`).
    Error {
        error: String,
        result: Option<ScenarioGenerationDebuggingResult>,
    },
    /// The scenario was generated and evaluated
    /// (`{ compilation, success: true, trace, verify }`).
    Success {
        compilation: ScenarioGenerationDebuggingResult,
        trace: Vec<AuthenticationProgramStateCommon>,
        verify: Result<(), String>,
    },
}

/// Compile and debug the provided CashAssembly `script` (as a locking script)
/// in the default scenario, returning the compilation, the debug trace, and the
/// verification result.
pub fn debug_cash_assembly(script: &str, scripts_and_overrides: Option<CompilerConfiguration>) -> DebugCashAssemblyResult {
    let scripts_and_overrides = scripts_and_overrides.unwrap_or_default();
    let vm = scripts_and_overrides.vm.clone().unwrap_or_else(default_vm);
    let result = debug_cash_assembly_compilation(
        script,
        Some(CompilerConfiguration {
            vm: Some(vm.clone()),
            ..scripts_and_overrides
        }),
    );
    let result = match result {
        Err(error) => return DebugCashAssemblyResult::Error { error, result: None },
        Ok(result) => result,
    };
    let scenario = match &result.scenario {
        Err(error) => {
            return DebugCashAssemblyResult::Error {
                error: error.clone(),
                result: Some(result.clone()),
            };
        }
        Ok(scenario) => scenario.clone(),
    };
    let trace = vm.debug(&scenario.program, None);
    let verify = vm.verify(&crate::vm::ResolvedTransactionCommon {
        source_outputs: scenario.program.source_outputs.clone(),
        transaction: scenario.program.transaction.clone(),
    });
    DebugCashAssemblyResult::Success {
        compilation: result,
        trace,
        verify,
    }
}

/// Compile and evaluate the provided CashAssembly `script` (as a locking
/// script) in the default scenario, returning the final program state or an
/// error message.
pub fn evaluate_cash_assembly(
    script: &str,
    scripts_and_overrides: Option<CompilerConfiguration>,
) -> Result<AuthenticationProgramStateCommon, String> {
    match debug_cash_assembly(script, scripts_and_overrides) {
        DebugCashAssemblyResult::Error { error, .. } => Err(error),
        DebugCashAssemblyResult::Success { trace, .. } => {
            Ok(trace.last().cloned().expect("a debug trace includes the final state"))
        }
    }
}

/// Assemble a disassembled bytecode string ("ASM") into bytecode using the
/// provided opcode map.
///
/// @param opcodes - a mapping of opcodes to their respective Uint8Array
/// representation
/// @param disassembledBytecode - the disassembled bytecode to re-assemble
pub fn assemble_bytecode(opcodes: &BTreeMap<String, Vec<u8>>, disassembled_bytecode: &str) -> BytecodeGenerationResult {
    let configuration = CompilerConfiguration {
        opcodes: Some(opcodes.clone()),
        scripts: BTreeMap::from([("asm".to_string(), disassembled_bytecode.to_string())]),
        ..Default::default()
    };
    create_compiler_common(configuration).generate_bytecode(&CompilationData::default(), "asm")
}

/// Assemble BCH bytecode (using {@link OpcodesBchSpec}).
///
/// @param disassembledBytecode - the disassembled BCH bytecode
pub fn assemble_bytecode_bch(disassembled_bytecode: &str) -> BytecodeGenerationResult {
    assemble_bytecode(&generate_bytecode_map(OpcodesBchSpec::MEMBERS), disassembled_bytecode)
}

/// @deprecated Alias of `assembleBytecodeBch` for backwards-compatibility.
pub use self::assemble_bytecode_bch as assemble_bytecode_BCH;

/// A convenience method to compile CashAssembly (using
/// {@link assembleBytecodeBch}) to bytecode. If compilation fails, errors are
/// returned as a string.
pub fn cash_assembly_to_bin(cash_assembly_script: &str) -> Result<Vec<u8>, String> {
    match assemble_bytecode_bch(cash_assembly_script) {
        BytecodeGenerationResult::Success { bytecode } => Ok(bytecode),
        BytecodeGenerationResult::Error(result) => Err(format!(
            "CashAssembly compilation {} error: {}",
            result.error_type.as_str(),
            result
                .errors
                .iter()
                .map(|error| error.error.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        )),
    }
}

/// Assemble BTC bytecode (using {@link OpcodesBtc}).
///
/// @param disassembledBytecode - the disassembled BTC bytecode
pub fn assemble_bytecode_btc(disassembled_bytecode: &str) -> BytecodeGenerationResult {
    assemble_bytecode(&generate_bytecode_map(OpcodesBtc::MEMBERS), disassembled_bytecode)
}

/// @deprecated Alias of `assembleBytecodeBtc` for backwards-compatibility.
pub use self::assemble_bytecode_btc as assemble_bytecode_BTC;

/// Create a partial {@link CompilerConfiguration} from a
/// {@link WalletTemplate} by extracting and formatting the `scripts` and
/// `variables` properties (the `entityOwnership`, `lockingScriptTypes`,
/// `scenarios`, `scripts`, `unlockingScripts`, `unlockingScriptTimeLockTypes`,
/// and `variables` of the returned configuration are set).
///
/// Note, if this {@link WalletTemplate} might be malformed, first validate it
/// with {@link importWalletTemplate}.
///
/// @param template - the {@link WalletTemplate} from which to extract the
/// compiler configuration
pub fn wallet_template_to_compiler_configuration(template: &WalletTemplate) -> CompilerConfiguration {
    let mut scripts = BTreeMap::new();
    let mut unlocking_scripts = BTreeMap::new();
    let mut unlocking_script_time_lock_types = BTreeMap::new();
    let mut locking_script_types = BTreeMap::new();
    for (id, definition) in &template.scripts {
        match definition {
            WalletTemplateScriptDefinition::Script(script) => {
                scripts.insert(id.clone(), script.script.clone());
            }
            WalletTemplateScriptDefinition::Locking(locking) => {
                scripts.insert(id.clone(), locking.script.clone());
                locking_script_types.insert(id.clone(), locking.locking_type);
            }
            WalletTemplateScriptDefinition::Unlocking(unlocking) => {
                scripts.insert(id.clone(), unlocking.script.clone());
                unlocking_scripts.insert(id.clone(), unlocking.unlocks.clone());
                if let Some(time_lock_type) = unlocking.time_lock_type {
                    unlocking_script_time_lock_types.insert(id.clone(), time_lock_type);
                }
            }
            WalletTemplateScriptDefinition::Tested(tested) => {
                scripts.insert(id.clone(), tested.script.clone());
            }
        }
    }
    // Virtualize the tests of tested scripts as P2SH20 locking scripts (with
    // a "check" script) and their unlocking scripts (the "setup").
    for (script_id, definition) in &template.scripts {
        let WalletTemplateScriptDefinition::Tested(script) = definition else {
            continue;
        };
        for (test_id, test) in &script.tests {
            let push_tested_script = script.pushed == Some(true);
            let check_script_id = format!("{script_id}.{test_id}.check");
            let virtualized_locking_script_id = format!("{script_id}.{test_id}.lock");
            let virtualized_unlocking_script_id = format!("{script_id}.{test_id}.unlock");
            scripts.insert(check_script_id.clone(), test.check.clone());
            scripts.insert(
                virtualized_locking_script_id.clone(),
                if push_tested_script {
                    format!("<{script_id}> {check_script_id}")
                } else {
                    format!("{script_id} {check_script_id}")
                },
            );
            locking_script_types.insert(virtualized_locking_script_id.clone(), WalletTemplateLockingType::P2sh20);
            scripts.insert(
                virtualized_unlocking_script_id.clone(),
                test.setup.clone().unwrap_or_default(),
            );
            unlocking_scripts.insert(virtualized_unlocking_script_id, virtualized_locking_script_id);
        }
    }
    let mut variables = BTreeMap::new();
    let mut entity_ownership = BTreeMap::new();
    for (entity_id, entity) in &template.entities {
        for (variable_id, variable) in entity.variables.iter().flatten() {
            variables.insert(variable_id.clone(), variable.clone());
            entity_ownership.insert(variable_id.clone(), entity_id.clone());
        }
    }
    CompilerConfiguration {
        entity_ownership: Some(entity_ownership),
        locking_script_types: Some(locking_script_types),
        scenarios: template.scenarios.clone(),
        scripts,
        unlocking_script_time_lock_types: Some(unlocking_script_time_lock_types),
        unlocking_scripts: Some(unlocking_scripts),
        variables: Some(variables),
        ..Default::default()
    }
}
