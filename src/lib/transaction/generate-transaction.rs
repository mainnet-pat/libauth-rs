//! Transaction generation from wallet template compilation directives.
//!
//! Port of libauth's `transaction/generate-transaction.ts`.

use std::collections::BTreeMap;

use crate::compiler::CompilationData;
use crate::vm::CompilationContextBch;
use crate::language::{
    CompilationError, CompilationErrorType, CompilationResult,
};
use crate::language::{
    all_errors_are_recoverable, extract_resolved_variable_bytecode_map,
};
use crate::message::{
    BytecodeGenerationCompletion, BytecodeGenerationCompletionInput, BytecodeGenerationCompletionOutput,
    BytecodeGenerationErrorBase, BytecodeGenerationType, Input, InputTemplate, InputUnlockingBytecode,
    Output, OutputLockingBytecode, OutputTemplate, TransactionCommon, TransactionGenerationAttempt,
    TransactionGenerationError, TransactionGenerationStage, TransactionGenerationSuccess,
    TransactionTemplateFixed,
};

fn return_failed_compilation_directive(
    index: usize,
    result: crate::language::CompilationResultError,
    bytecode_type: BytecodeGenerationType,
) -> BytecodeGenerationErrorBase {
    let resolved = if result.error_type == CompilationErrorType::Parse {
        None
    } else {
        result.resolve.clone()
    };
    BytecodeGenerationErrorBase {
        errors: result
            .errors
            .into_iter()
            .map(|error| CompilationError {
                error: format!(
                    "Failed compilation of {} directive at index \"{index}\": {}",
                    bytecode_type.as_str(),
                    error.error
                ),
                ..error
            })
            .collect(),
        index,
        resolved,
        bytecode_type,
    }
}

/// Compile an [`OutputTemplate`], returning either a generated [`Output`] or a
/// bytecode generation error.
pub fn compile_output_template(
    output_template: &OutputTemplate,
    index: usize,
) -> Result<Output, BytecodeGenerationErrorBase> {
    match &output_template.locking_bytecode {
        OutputLockingBytecode::Compilation(directive) => {
            let data = directive.data.clone().unwrap_or_default();
            match directive.compiler.generate_bytecode_debug(&data, &directive.script) {
                CompilationResult::Success(success) => Ok(Output {
                    locking_bytecode: success.bytecode,
                    token: output_template.token.clone(),
                    value_satoshis: output_template.value_satoshis,
                }),
                CompilationResult::Error(error) => Err(return_failed_compilation_directive(
                    index,
                    error,
                    BytecodeGenerationType::Locking,
                )),
            }
        }
        OutputLockingBytecode::Bytecode(bytecode) => Ok(Output {
            locking_bytecode: bytecode.clone(),
            token: output_template.token.clone(),
            value_satoshis: output_template.value_satoshis,
        }),
    }
}

/// Compile an [`InputTemplate`], returning either a generated [`Input`] or a
/// bytecode generation error.
pub fn compile_input_template(
    input_template: &InputTemplate,
    index: usize,
    template: &TransactionTemplateFixed,
    outputs: &[Output],
) -> Result<Input, BytecodeGenerationErrorBase> {
    match &input_template.unlocking_bytecode {
        InputUnlockingBytecode::Compilation(directive) => {
            // libauth populates `sourceOutputs` only at the index of the input
            // being compiled; entries before that index are holes. Default
            // outputs are used here for the equivalent placeholder values.
            let mut source_outputs = vec![
                Output {
                    locking_bytecode: Vec::new(),
                    token: None,
                    value_satoshis: 0,
                };
                index + 1
            ];
            source_outputs[index] = Output {
                locking_bytecode: Vec::new(),
                token: directive.token.clone(),
                value_satoshis: directive.value_satoshis,
            };
            let transaction = TransactionCommon {
                inputs: template
                    .inputs
                    .iter()
                    .map(|input| Input {
                        outpoint_transaction_hash: input.outpoint_transaction_hash.clone(),
                        outpoint_index: input.outpoint_index,
                        unlocking_bytecode: None,
                        sequence_number: input.sequence_number,
                    })
                    .collect(),
                locktime: template.locktime,
                outputs: outputs.to_vec(),
                version: template.version,
            };
            let mut data = directive.data.clone().unwrap_or_default();
            data.compilation_context = Some(CompilationContextBch {
                input_index: index,
                source_outputs,
                transaction,
            });
            match directive
                .compiler
                .generate_bytecode_debug(&data, &directive.script)
            {
                CompilationResult::Success(success) => Ok(Input {
                    outpoint_index: input_template.outpoint_index,
                    outpoint_transaction_hash: input_template
                        .outpoint_transaction_hash
                        .clone(),
                    sequence_number: input_template.sequence_number,
                    unlocking_bytecode: success.bytecode,
                }),
                CompilationResult::Error(error) => Err(return_failed_compilation_directive(
                    index,
                    error,
                    BytecodeGenerationType::Unlocking,
                )),
            }
        }
        InputUnlockingBytecode::Bytecode(bytecode) => Ok(Input {
            outpoint_index: input_template.outpoint_index,
            outpoint_transaction_hash: input_template.outpoint_transaction_hash.clone(),
            sequence_number: input_template.sequence_number,
            unlocking_bytecode: bytecode.clone(),
        }),
    }
}

/// Generate a [`TransactionCommon`](crate::message::TransactionCommon) given a [`TransactionTemplateFixed`] and any
/// applicable compilers and compilation data.
pub fn generate_transaction(
    template: &TransactionTemplateFixed,
) -> TransactionGenerationAttempt {
    let output_results: Vec<Result<Output, BytecodeGenerationErrorBase>> = template
        .outputs
        .iter()
        .enumerate()
        .map(|(index, output_template)| compile_output_template(output_template, index))
        .collect();

    let output_compilation_errors: Vec<BytecodeGenerationErrorBase> = output_results
        .iter()
        .filter_map(|result| result.as_ref().err().cloned())
        .collect();
    if !output_compilation_errors.is_empty() {
        let completions = output_results
            .iter()
            .enumerate()
            .filter_map(|(index, result)| match result {
                Ok(output) => Some(BytecodeGenerationCompletion::Output(BytecodeGenerationCompletionOutput {
                    index,
                    output: output.clone(),
                })),
                Err(_) => None,
            })
            .collect();
        return TransactionGenerationAttempt::Error(TransactionGenerationError {
            completions,
            errors: output_compilation_errors,
            stage: TransactionGenerationStage::Outputs,
        });
    }
    let outputs: Vec<Output> = output_results
        .into_iter()
        .map(|result| result.expect("output compilation succeeded"))
        .collect();

    let input_results: Vec<Result<Input, BytecodeGenerationErrorBase>> = template
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input_template)| {
            compile_input_template(input_template, index, template, &outputs)
        })
        .collect();

    let input_compilation_errors: Vec<BytecodeGenerationErrorBase> = input_results
        .iter()
        .filter_map(|result| result.as_ref().err().cloned())
        .collect();
    if !input_compilation_errors.is_empty() {
        let completions = input_results
            .iter()
            .enumerate()
            .filter_map(|(index, result)| match result {
                Ok(input) => Some(BytecodeGenerationCompletion::Input(BytecodeGenerationCompletionInput {
                    index,
                    input: input.clone(),
                })),
                Err(_) => None,
            })
            .collect();
        return TransactionGenerationAttempt::Error(TransactionGenerationError {
            completions,
            errors: input_compilation_errors,
            stage: TransactionGenerationStage::Inputs,
        });
    }
    let inputs: Vec<Input> = input_results
        .into_iter()
        .map(|result| result.expect("input compilation succeeded"))
        .collect();

    TransactionGenerationAttempt::Success(TransactionGenerationSuccess {
        transaction: TransactionCommon {
            inputs,
            locktime: template.locktime,
            outputs,
            version: template.version,
        },
    })
}

/// Extract a map of successfully resolved variables to their resolved
/// bytecode.
pub fn extract_resolved_variables(
    transaction_generation_error: &TransactionGenerationError,
) -> BTreeMap<String, Vec<u8>> {
    let mut resolved_variables = BTreeMap::new();
    for error in &transaction_generation_error.errors {
        if let Some(resolved) = &error.resolved {
            resolved_variables.extend(extract_resolved_variable_bytecode_map(resolved));
        }
    }
    resolved_variables
}

/// Given an unsuccessful transaction generation result, extract a map of the
/// identifiers missing from the compilation mapped to the entity that owns
/// each variable.
///
/// Returns `None` if any errors are fatal (the error either cannot be resolved
/// by providing a variable, or the entity ownership of the required variable
/// was not provided in the compilation data).
pub fn extract_missing_variables(
    transaction_generation_error: &TransactionGenerationError,
) -> Option<BTreeMap<String, String>> {
    let all_errors: Vec<CompilationError> = transaction_generation_error
        .errors
        .iter()
        .flat_map(|error| error.errors.iter().cloned())
        .collect();

    if !all_errors_are_recoverable(&all_errors) {
        return None;
    }

    Some(
        all_errors
            .into_iter()
            .filter_map(|error| Some((error.missing_identifier?, error.owning_entity?)))
            .collect(),
    )
}

/// Safely extend compilation data with resolutions provided by other entities
/// (via [`extract_resolved_variables`]).
///
/// Returns `None` if any errors are fatal (the error either cannot be resolved
/// by providing a variable, or the entity ownership of the required variable
/// was not provided in the compilation data).
pub fn safely_extend_compilation_data(
    transaction_generation_error: &TransactionGenerationError,
    trusted_compilation_data: &CompilationData,
    untrusted_resolutions: &BTreeMap<String, BTreeMap<String, Vec<u8>>>,
) -> Option<CompilationData> {
    let missing = extract_missing_variables(transaction_generation_error)?;
    let mut bytecode = BTreeMap::new();
    for (identifier, entity_id) in &missing {
        let Some(entity_resolution) = untrusted_resolutions.get(entity_id) else {
            continue;
        };
        let Some(resolution) = entity_resolution.get(identifier) else {
            continue;
        };
        bytecode.insert(identifier.clone(), resolution.clone());
    }
    if let Some(trusted_bytecode) = &trusted_compilation_data.bytecode {
        bytecode.extend(trusted_bytecode.clone());
    }
    Some(CompilationData {
        bytecode: Some(bytecode),
        ..trusted_compilation_data.clone()
    })
}
