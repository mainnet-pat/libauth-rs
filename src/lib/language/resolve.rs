use crate::compiler::{
    CompilationData, CompilerConfiguration, CompilerOperationError, CompilerOperationResult,
    CompilerOperationSet, CompilerOperationSkip,
};
use crate::engine::WalletTemplateVariable;
use crate::format::{bin_string_to_bin, hex_to_bin, utf8_to_bin};
use crate::key::{decode_hd_private_key, decode_hd_public_key, validate_secp256k1_private_key};
use crate::runtime::bigint::BigInt;
use crate::vm::big_int_to_vm_number;

use super::language_types::*;
use super::language_utils::{get_resolution_errors, stringify_errors};
use super::parse::parse_script;
use super::reduce::reduce_script;

fn pluck_range(node: &Segment) -> Range {
    node.range()
}

fn remove_numeric_separators(numeric_literal: &str) -> String {
    numeric_literal.replace('_', "")
}

/// Resolve every segment of a parsed script.
pub fn resolve_script_segment(
    segment: &Segment,
    resolve_identifiers: &dyn Fn(&str) -> IdentifierResolution,
) -> Vec<ResolvedSegment> {
    let mut resolved = Vec::with_capacity(segment.children().len());
    for child in segment.children() {
        let range = pluck_range(child);
        match child.name {
            SegmentName::Identifier => {
                let identifier = child.text().unwrap_or_default();
                resolved.push(match resolve_identifiers(identifier) {
                    IdentifierResolution::Opcode { bytecode } => {
                        ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(
                            ResolvedSegmentOpcodeBytecode {
                                range,
                                opcode: identifier.to_string(),
                                value: bytecode,
                            },
                        ))
                    }
                    IdentifierResolution::Variable { bytecode, signature } => {
                        ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Variable(
                            ResolvedSegmentVariableBytecode {
                                range,
                                signature,
                                value: bytecode,
                                variable: identifier.to_string(),
                            },
                        ))
                    }
                    IdentifierResolution::Script { bytecode, source } => {
                        ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Script(
                            ResolvedSegmentScriptBytecode {
                                range,
                                script: identifier.to_string(),
                                source,
                                value: bytecode,
                            },
                        ))
                    }
                    IdentifierResolution::VariableError {
                        error,
                        recoverable,
                        entity_ownership,
                    } => ResolvedSegment::Error(ResolvedSegmentError {
                        range,
                        value: error,
                        missing_identifier: if recoverable {
                            Some(identifier.to_string())
                        } else {
                            None
                        },
                        owning_entity: if recoverable {
                            entity_ownership
                        } else {
                            None
                        },
                    }),
                    IdentifierResolution::ScriptError { error, .. }
                    | IdentifierResolution::UnknownError { error } => ResolvedSegment::Error(ResolvedSegmentError {
                        range,
                        value: error,
                        missing_identifier: None,
                        owning_entity: None,
                    }),
                });
            }
            SegmentName::Push => resolved.push(ResolvedSegment::Push(ResolvedSegmentPush {
                range,
                value: resolve_script_segment(
                    child.inner_script().expect("push segments include a script"),
                    resolve_identifiers,
                ),
            })),
            SegmentName::Evaluation => resolved.push(ResolvedSegment::Evaluation(ResolvedSegmentEvaluation {
                range,
                value: resolve_script_segment(
                    child.inner_script().expect("evaluation segments include a script"),
                    resolve_identifiers,
                ),
            })),
            SegmentName::BigIntLiteral => {
                let literal = child.text().unwrap_or_default();
                let value = big_int_to_vm_number(
                    &BigInt::parse(&remove_numeric_separators(literal))
                        .expect("BigIntLiterals are parsed as decimal digits"),
                );
                resolved.push(ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                    ResolvedSegmentLiteralBytecode {
                        range,
                        literal: literal.to_string(),
                        literal_type: ResolvedSegmentLiteralType::BigIntLiteral,
                        value,
                    },
                )));
            }
            SegmentName::BinaryLiteral => {
                let literal = child.text().unwrap_or_default();
                resolved.push(ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                    ResolvedSegmentLiteralBytecode {
                        range,
                        literal: literal.to_string(),
                        literal_type: ResolvedSegmentLiteralType::BinaryLiteral,
                        value: bin_string_to_bin(&remove_numeric_separators(literal)),
                    },
                )));
            }
            SegmentName::HexLiteral => {
                let literal = child.text().unwrap_or_default();
                resolved.push(ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                    ResolvedSegmentLiteralBytecode {
                        range,
                        literal: literal.to_string(),
                        literal_type: ResolvedSegmentLiteralType::HexLiteral,
                        value: hex_to_bin(&remove_numeric_separators(literal)),
                    },
                )));
            }
            SegmentName::Utf8Literal => {
                let literal = child.text().unwrap_or_default();
                resolved.push(ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                    ResolvedSegmentLiteralBytecode {
                        range,
                        literal: literal.to_string(),
                        literal_type: ResolvedSegmentLiteralType::Utf8Literal,
                        value: utf8_to_bin(literal),
                    },
                )));
            }
            SegmentName::Comment => resolved.push(ResolvedSegment::Comment(ResolvedSegmentComment {
                range,
                value: child.text().unwrap_or_default().to_string(),
            })),
            SegmentName::Script => {
                resolved.push(ResolvedSegment::Error(ResolvedSegmentError {
                    range,
                    value: format!("Unrecognized segment: {}", child.name.as_str()),
                    missing_identifier: None,
                    owning_entity: None,
                }));
            }
        }
    }
    if resolved.is_empty() {
        vec![ResolvedSegment::Comment(ResolvedSegmentComment {
            range: pluck_range(segment),
            value: String::new(),
        })]
    } else {
        resolved
    }
}

/// The variables which are built in to every compiler (and may not be used as
/// template variable identifiers).
pub struct BuiltInVariables;

#[allow(non_upper_case_globals)]
impl BuiltInVariables {
    pub const currentBlockTime: &'static str = "current_block_time";
    pub const currentBlockHeight: &'static str = "current_block_height";
    pub const signingSerialization: &'static str = "signing_serialization";
}

fn fatal(error: String) -> CompilerOperationResult {
    CompilerOperationResult::Error(CompilerOperationError {
        debug: None,
        error,
        recoverable: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn attempt_compiler_operation(
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    identifier: &str,
    matching_operations: Option<&CompilerOperationSet>,
    operation_id: Option<&str>,
    variable_id: &str,
    variable_type: &str,
    operation_example: Option<&str>,
) -> CompilerOperationResult {
    let operation_example = operation_example.unwrap_or("operation_identifier");
    let Some(matching_operations) = matching_operations else {
        return fatal(format!(
            "The \"{variable_id}\" variable type can not be resolved because the \"{variable_type}\" operation has not been included in this compiler's configuration."
        ));
    };
    let operations = match matching_operations {
        CompilerOperationSet::Single(operation) => return operation(identifier, data, configuration),
        CompilerOperationSet::Multiple(operations) => operations,
    };
    let Some(operation_id) = operation_id else {
        return fatal(format!(
            "This \"{variable_id}\" variable could not be resolved because this compiler's \"{variable_type}\" operations require an operation identifier, e.g. '{variable_id}.{operation_example}'."
        ));
    };
    let Some(operation) = operations.get(operation_id) else {
        return fatal(format!(
            "The identifier \"{identifier}\" could not be resolved because the \"{variable_id}.{operation_id}\" operation is not available to this compiler."
        ));
    };
    operation(identifier, data, configuration)
}

/// If the identifier can be successfully resolved as a variable, the result is
/// returned as a Uint8Array. If the identifier references a known variable, but
/// an error occurs in resolving it, the error is returned as a string.
/// Otherwise, the identifier is not recognized as a variable, and this method
/// simply returns `false`.
pub fn resolve_variable_identifier(
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    identifier: &str,
) -> CompilerOperationResult {
    let mut parts = identifier.split('.');
    let variable_id = parts.next().unwrap_or_default();
    let operation_id = parts.next();
    let operations = configuration.operations.as_ref();
    match variable_id {
        BuiltInVariables::currentBlockHeight => attempt_compiler_operation(
            data,
            configuration,
            identifier,
            operations.and_then(|operations| operations.current_block_height.as_ref()),
            operation_id,
            variable_id,
            "currentBlockHeight",
            None,
        ),
        BuiltInVariables::currentBlockTime => attempt_compiler_operation(
            data,
            configuration,
            identifier,
            operations.and_then(|operations| operations.current_block_time.as_ref()),
            operation_id,
            variable_id,
            "currentBlockTime",
            None,
        ),
        BuiltInVariables::signingSerialization => attempt_compiler_operation(
            data,
            configuration,
            identifier,
            operations.and_then(|operations| operations.signing_serialization.as_ref()),
            operation_id,
            variable_id,
            "signingSerialization",
            Some("version"),
        ),
        _ => {
            let Some(expected_variable) = configuration
                .variables
                .as_ref()
                .and_then(|variables| variables.get(variable_id))
            else {
                return CompilerOperationResult::Skip(CompilerOperationSkip);
            };
            let (matching_operations, operation_example, variable_type) = match expected_variable {
                WalletTemplateVariable::AddressData(_) => (
                    operations.and_then(|operations| operations.address_data.as_ref()),
                    None,
                    "addressData",
                ),
                WalletTemplateVariable::HdKey(_) => (
                    operations.and_then(|operations| operations.hd_key.as_ref()),
                    Some("public_key"),
                    "hdKey",
                ),
                WalletTemplateVariable::Key(_) => (
                    operations.and_then(|operations| operations.key.as_ref()),
                    Some("public_key"),
                    "key",
                ),
                WalletTemplateVariable::WalletData(_) => (
                    operations.and_then(|operations| operations.wallet_data.as_ref()),
                    None,
                    "walletData",
                ),
            };
            attempt_compiler_operation(
                data,
                configuration,
                identifier,
                matching_operations,
                operation_id,
                variable_id,
                variable_type,
                operation_example,
            )
        }
    }
}

/// Format the list of expected inputs produced by a failed parse.
pub fn describe_expected_input(expected_array: &[String]) -> String {
    const EOF: &str = "EOF";
    let mut new_array: Vec<String> = expected_array
        .iter()
        .filter(|value| value.as_str() != EOF)
        .cloned()
        .collect();
    if new_array.len() != expected_array.len() {
        new_array.push("the end of the script".to_string());
    }
    let without_last_element = &new_array[..new_array.len().saturating_sub(1)];
    let last_element = new_array.last().cloned().unwrap_or_else(|| "undefined".to_string());
    let array_requires_commas = 3;
    let array_requires_or = 2;
    format!(
        "Encountered unexpected input while parsing script. Expected {}.",
        if new_array.len() >= array_requires_commas {
            format!("{}, or {last_element}", without_last_element.join(", "))
        } else if new_array.len() == array_requires_or {
            new_array.join(" or ")
        } else {
            last_element
        }
    )
}

/// Create an empty range (all positions are `0`).
pub fn create_empty_range() -> Range {
    Range {
        end_column: 0,
        end_line_number: 0,
        start_column: 0,
        start_line_number: 0,
    }
}

fn compilation_error(error: String) -> CompilationError {
    CompilationError {
        error,
        missing_identifier: None,
        owning_entity: None,
        range: create_empty_range(),
    }
}

/// This method is generally for internal use. The {@link compileScript} method
/// is the recommended API for direct compilation.
pub fn validate_compilation_data(
    configuration: &CompilerConfiguration,
    data: &CompilationData,
) -> Vec<CompilationError> {
    let mut errors = Vec::new();
    if let Some(bytecode) = &data.bytecode {
        for (identifier, public_key) in bytecode.iter().filter(|(identifier, _)| identifier.ends_with(".public_key")) {
            let valid = configuration
                .secp256k1
                .as_ref()
                .is_some_and(|secp256k1| secp256k1.validate_public_key(public_key));
            if valid {
                continue;
            }
            errors.push(compilation_error(if configuration.secp256k1.is_none() {
                format!(
                    "Could not validate compilation data: the public key provided for \"{identifier}\" could not be validated because the \"secp256k1\" property was not provided in the compiler configuration."
                )
            } else {
                format!(
                    "Invalid compilation data detected: the public key provided for \"{identifier}\" is not a valid Secp256k1 public key."
                )
            }));
        }
    }
    if let Some(private_keys) = data.keys.as_ref().and_then(|keys| keys.private_keys.as_ref()) {
        for (variable_id, private_key) in private_keys {
            if !validate_secp256k1_private_key(private_key) {
                errors.push(compilation_error(format!(
                    "Invalid compilation data detected: the private key provided for the \"{variable_id}\" variable is not a valid Secp256k1 private key."
                )));
            }
        }
    }
    if let Some(hd_private_keys) = data.hd_keys.as_ref().and_then(|hd_keys| hd_keys.hd_private_keys.as_ref()) {
        for (entity_id, hd_private_key) in hd_private_keys {
            if let Err(decoded) = decode_hd_private_key(hd_private_key, None) {
                errors.push(compilation_error(format!(
                    "Invalid compilation data detected: the HD private key provided for the \"{entity_id}\" entity is not a valid HD private key. {decoded}"
                )));
            }
        }
    }
    if let Some(hd_public_keys) = data.hd_keys.as_ref().and_then(|hd_keys| hd_keys.hd_public_keys.as_ref()) {
        for (entity_id, hd_public_key) in hd_public_keys {
            if let Err(decoded) = decode_hd_public_key(hd_public_key, None) {
                errors.push(compilation_error(format!(
                    "Invalid compilation data detected: the HD public key provided for the \"{entity_id}\" entity is not a valid HD public key. {decoded}"
                )));
            }
        }
    }
    errors
}

fn parse_error(errors: Vec<CompilationError>) -> CompilationResult {
    CompilationResult::Error(CompilationResultError {
        error_type: CompilationErrorType::Parse,
        errors,
        parse: None,
        reduce: None,
        resolve: None,
    })
}

/// This method is generally for internal use. The {@link compileScript} method
/// is the recommended API for direct compilation.
pub fn compile_script_raw(
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    script_id: &str,
) -> CompilationResult {
    let Some(script) = configuration.scripts.get(script_id) else {
        return parse_error(vec![compilation_error(format!(
            "No script with an ID of \"{script_id}\" was provided in the compiler configuration."
        ))]);
    };
    if configuration
        .source_script_ids
        .as_ref()
        .is_some_and(|source_script_ids| source_script_ids.iter().any(|id| id == script_id))
    {
        return parse_error(vec![compilation_error(format!(
            "A circular dependency was encountered: script \"{script_id}\" relies on itself to be generated. (Source scripts: {})",
            configuration.source_script_ids.as_ref().expect("checked above").join(" → ")
        ))]);
    }
    let source_script_ids = match &configuration.source_script_ids {
        None => vec![script_id.to_string()],
        Some(source_script_ids) => {
            let mut source_script_ids = source_script_ids.clone();
            source_script_ids.push(script_id.to_string());
            source_script_ids
        }
    };
    let data_errors = validate_compilation_data(configuration, data);
    if !data_errors.is_empty() {
        return parse_error(data_errors);
    }
    compile_script_contents(
        data,
        &CompilerConfiguration {
            source_script_ids: Some(source_script_ids),
            ..configuration.clone()
        },
        script,
    )
}

/// Resolve a script identifier: compile the script, returning the successful
/// compilation, an error message (if compilation failed), or `None`
/// (libauth's `false`) if no script with the identifier exists.
pub fn resolve_script_identifier(
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    identifier: &str,
) -> Option<Result<CompilationResultSuccess, String>> {
    configuration.scripts.get(identifier)?;
    Some(match compile_script_raw(data, configuration, identifier) {
        CompilationResult::Success(success) => Ok(*success),
        CompilationResult::Error(result) => Err(format!(
            "Compilation error in resolved script \"{identifier}\": {}",
            stringify_errors(&result.errors, None)
        )),
    })
}

/// Return an {@link IdentifierResolutionFunction} for use in
/// {@link resolveScriptSegment}.
///
/// @param scriptId - the `id` of the script for which the resulting
/// `IdentifierResolutionFunction` will be used.
/// @param environment - a snapshot of the configuration around `scriptId`. See
/// {@link CompilerConfiguration} for details.
/// @param data - the actual variable values (private keys, shared wallet data,
/// shared address data, etc.) to use in resolving variables.
pub fn create_identifier_resolver<'a>(
    data: &'a CompilationData,
    configuration: &'a CompilerConfiguration,
) -> Box<IdentifierResolutionFunction<'a>> {
    Box::new(move |identifier: &str| {
        if let Some(opcode_result) = configuration
            .opcodes
            .as_ref()
            .and_then(|opcodes| opcodes.get(identifier))
        {
            return IdentifierResolution::Opcode {
                bytecode: opcode_result.clone(),
            };
        }
        match resolve_variable_identifier(data, configuration, identifier) {
            CompilerOperationResult::Skip(_) => {}
            CompilerOperationResult::Error(variable_result) => {
                return IdentifierResolution::VariableError {
                    entity_ownership: configuration.entity_ownership.as_ref().and_then(|entity_ownership| {
                        entity_ownership
                            .get(identifier.split('.').next().unwrap_or_default())
                            .cloned()
                    }),
                    error: variable_result.error,
                    recoverable: variable_result.recoverable,
                };
            }
            CompilerOperationResult::Success(variable_result) => {
                return IdentifierResolution::Variable {
                    bytecode: variable_result.bytecode,
                    signature: variable_result.signature,
                };
            }
        }
        match resolve_script_identifier(data, configuration, identifier) {
            Some(Err(script_result)) => IdentifierResolution::ScriptError {
                error: script_result,
                script_id: identifier.to_string(),
            },
            Some(Ok(script_result)) => IdentifierResolution::Script {
                bytecode: script_result.bytecode.clone(),
                source: Box::new(script_result),
            },
            None => IdentifierResolution::UnknownError {
                error: format!("Unknown identifier \"{identifier}\"."),
            },
        }
    })
}

/// This method is generally for internal use. The {@link compileScript} method
/// is the recommended API for direct compilation.
pub fn compile_script_contents(
    data: &CompilationData,
    configuration: &CompilerConfiguration,
    script: &str,
) -> CompilationResult {
    let parse = match parse_script(script) {
        ParseResult::Failure { expected, index } => {
            return parse_error(vec![CompilationError {
                error: describe_expected_input(&expected),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: index.column,
                    end_line_number: index.line,
                    start_column: index.column,
                    start_line_number: index.line,
                },
            }]);
        }
        ParseResult::Success(parse) => parse,
    };
    let resolver = create_identifier_resolver(data, configuration);
    let resolved_script = resolve_script_segment(&parse, resolver.as_ref());
    let resolution_errors = get_resolution_errors(&resolved_script);
    if !resolution_errors.is_empty() {
        return CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: resolution_errors,
            parse: Some(parse),
            reduce: None,
            resolve: Some(resolved_script),
        });
    }
    let create_authentication_program = configuration
        .create_authentication_program
        .as_ref()
        .map(|create| create.as_ref() as &dyn Fn(&[u8]) -> crate::vm::AuthenticationProgramBch);
    let reduction = reduce_script(&resolved_script, configuration.vm.as_ref(), create_authentication_program);
    match reduction.errors.clone() {
        None => CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: reduction.bytecode.clone(),
            parse,
            reduce: reduction,
            resolve: resolved_script,
            transformed: None,
        })),
        Some(errors) => CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Reduce,
            errors,
            parse: Some(parse),
            reduce: Some(reduction),
            resolve: Some(resolved_script),
        }),
    }
}
