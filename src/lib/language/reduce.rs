use crate::format::flatten_bin_array;
use crate::vm::{
    encode_data_push, AuthenticationProgramBch, AuthenticationProgramStateCommon,
    AuthenticationVirtualMachineBch,
};

use super::language_types::*;
use super::language_utils::merge_ranges;

fn empty_reduction_trace_node(range: Range) -> ScriptReductionTraceNode {
    ScriptReductionTraceNode {
        bytecode: Vec::new(),
        errors: None,
        range,
    }
}

/// Perform the standard verification of CashAssembly evaluation results. This
/// ensures that evaluations complete as expected: if an error occurs while
/// computing an evaluation, script compilation should fail.
///
/// Three requirements are enforced:
/// - the evaluation may not produce an `error`
/// - the resulting stack must contain exactly 1 item
/// - the resulting execution stack must be empty (no missing `OP_ENDIF`s)
///
/// This differs from the virtual machine's built-in `vm.verify` in that it is
/// often more lenient, for example, evaluations can succeed with a non-truthy
/// value on top of the stack.
///
/// @param state - the final program state to verify
pub fn verify_cash_assembly_evaluation_state(state: &AuthenticationProgramStateCommon) -> Result<(), String> {
    if let Some(error) = &state.error {
        return Err(error.clone());
    }
    if !state.control_stack.is_empty() {
        return Err(
            "The CashAssembly internal evaluation completed with a non-empty control stack.".to_string(),
        );
    }
    if state.stack.len() != 1 {
        return Err("The CashAssembly internal evaluation completed with an unexpected number of items on the stack (must be exactly 1).".to_string());
    }
    Ok(())
}

/// Reduce a resolved script, returning the resulting bytecode and a trace of the
/// reduction process.
///
/// This method will return an error if provided a `resolvedScript` with
/// resolution errors. To check for resolution errors, use
/// {@link getResolutionErrors}.
///
/// @param resolvedScript - the `CompiledScript` to reduce
/// @param vm - the {@link AuthenticationVirtualMachine} to use for evaluations
/// @param createEvaluationProgram - a method which accepts the compiled
/// bytecode contents of a CashAssembly evaluation and produces the equivalent
/// {@link AuthenticationProgram} to be evaluated by the VM. This method is used
/// internally to compute CashAssembly evaluations. See
/// {@link createAuthenticationProgramEvaluationCommon} for details.
pub fn reduce_script(
    resolved_script: &[ResolvedSegment],
    vm: Option<&AuthenticationVirtualMachineBch>,
    create_evaluation_program: Option<&dyn Fn(&[u8]) -> AuthenticationProgramBch>,
) -> ScriptReductionTraceScriptNode {
    let script: Vec<ScriptReductionTraceChildNode> = resolved_script
        .iter()
        .map(|segment| match segment {
            ResolvedSegment::Bytecode(segment) => ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: segment.value().to_vec(),
                errors: None,
                range: segment.range(),
            }),
            ResolvedSegment::Push(ResolvedSegmentPush { range, value }) => {
                let push = reduce_script(value, vm, create_evaluation_program);
                let bytecode = encode_data_push(&push.bytecode);
                ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                    bytecode,
                    errors: push.errors.clone(),
                    push: Box::new(push),
                    range: *range,
                })
            }
            ResolvedSegment::Evaluation(ResolvedSegmentEvaluation { range, value }) => {
                let (Some(vm), Some(create_evaluation_program)) = (vm, create_evaluation_program) else {
                    return ScriptReductionTraceChildNode::Error(ScriptReductionTraceErrorNode {
                        bytecode: Vec::new(),
                        errors: vec![CompilationError {
                            error: "Both a VM and a createAuthenticationProgram method are required to reduce evaluations.".to_string(),
                            missing_identifier: None,
                            owning_entity: None,
                            range: *range,
                        }],
                        range: *range,
                    });
                };
                let reduction_trace = reduce_script(value, Some(vm), Some(create_evaluation_program));
                if let Some(errors) = reduction_trace.errors.clone() {
                    return ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                        bytecode: empty_reduction_trace_node(*range).bytecode,
                        errors: Some(errors),
                        range: *range,
                        source: Box::new(reduction_trace),
                        trace: Vec::new(),
                    });
                }
                let trace = vm.debug(&create_evaluation_program(&reduction_trace.bytecode), None);
                let last_state = trace.last().expect("a debug trace includes the final state");
                let result = verify_cash_assembly_evaluation_state(last_state);
                let (bytecode, errors) = match result {
                    Err(result) => (
                        Vec::new(),
                        Some(vec![CompilationError {
                            error: format!("Failed to reduce evaluation: {result}"),
                            missing_identifier: None,
                            owning_entity: None,
                            range: *range,
                        }]),
                    ),
                    Ok(()) => (last_state.stack.last().cloned().unwrap_or_default(), None),
                };
                ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                    bytecode,
                    errors,
                    range: *range,
                    source: Box::new(reduction_trace),
                    trace,
                })
            }
            ResolvedSegment::Comment(ResolvedSegmentComment { range, value }) => {
                let empty = empty_reduction_trace_node(*range);
                ScriptReductionTraceChildNode::Comment(ScriptReductionTraceCommentNode {
                    bytecode: empty.bytecode,
                    comment: value.clone(),
                    errors: None,
                    range: empty.range,
                })
            }
            ResolvedSegment::Error(ResolvedSegmentError { range, value, .. }) => {
                ScriptReductionTraceChildNode::Error(ScriptReductionTraceErrorNode {
                    bytecode: Vec::new(),
                    errors: vec![CompilationError {
                        error: format!("Tried to reduce a CashAssembly script with resolution errors: {value}"),
                        missing_identifier: None,
                        owning_entity: None,
                        range: *range,
                    }],
                    range: *range,
                })
            }
        })
        .collect();
    let mut bytecode = Vec::with_capacity(script.len());
    let mut ranges = Vec::with_capacity(script.len());
    let mut errors: Option<Vec<CompilationError>> = None;
    for segment in &script {
        bytecode.push(segment.bytecode().to_vec());
        ranges.push(segment.range());
        if errors.is_some() || segment.errors().is_some() {
            errors
                .get_or_insert_with(Vec::new)
                .extend(segment.errors().unwrap_or_default().iter().cloned());
        }
    }
    ScriptReductionTraceScriptNode {
        bytecode: flatten_bin_array(&bytecode),
        errors,
        range: merge_ranges(&ranges, resolved_script.first().map(|segment| segment.range())),
        script,
    }
}
