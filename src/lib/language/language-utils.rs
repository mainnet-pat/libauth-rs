use std::borrow::Borrow;
use std::collections::BTreeMap;

use super::language_types::*;
use crate::format::bin_to_hex;
use crate::vm::{
    authentication_instruction_is_malformed, decode_authentication_instructions,
    encode_authentication_instruction_malformed, execution_is_active, vm_number_to_big_int,
    AuthenticationInstruction, AuthenticationInstructionMaybeMalformed,
    AuthenticationProgramStateCommon, AuthenticationProgramStateControlStackItem, OpcodesBch,
};

fn pluck_start(range: &Range) -> (usize, usize) {
    (range.start_line_number, range.start_column)
}

fn pluck_end(range: &Range) -> (usize, usize) {
    (range.end_line_number, range.end_column)
}

/// Combine an array of ranges into a single larger range.
pub fn merge_ranges(ranges: &[Range], parent_range: Option<Range>) -> Range {
    let parent = parent_range.unwrap_or_default();
    let merged = match ranges.len() {
        0 => parent,
        1 => ranges[0],
        _ => ranges[1..].iter().fold(ranges[0], |merged, range| {
            let (mut end_line, mut end_column) = pluck_end(&merged);
            let (range_end_line, range_end_column) = pluck_end(range);
            if range_end_line > end_line
                || (range_end_line == end_line && range_end_column > end_column)
            {
                end_line = range_end_line;
                end_column = range_end_column;
            }
            let (mut start_line, mut start_column) = pluck_start(&merged);
            let (range_start_line, range_start_column) = pluck_start(range);
            if range_start_line < start_line
                || (range_start_line == start_line && range_start_column < start_column)
            {
                start_line = range_start_line;
                start_column = range_start_column;
            }
            Range {
                start_line_number: start_line,
                start_column,
                end_line_number: end_line,
                end_column,
            }
        }),
    };
    merged
}

/// Returns `true` if `outer_range` fully contains `inner_range`.
///
/// `exclusive` defaults to `true`.
pub fn contains_range(outer_range: &Range, inner_range: &Range, exclusive: Option<bool>) -> bool {
    let exclusive = exclusive.unwrap_or(true);
    let starts_after = if outer_range.start_line_number < inner_range.start_line_number {
        true
    } else if outer_range.start_line_number == inner_range.start_line_number {
        if exclusive {
            outer_range.start_column < inner_range.start_column
        } else {
            outer_range.start_column <= inner_range.start_column
        }
    } else {
        false
    };
    let ends_before = if outer_range.end_line_number > inner_range.end_line_number {
        true
    } else if outer_range.end_line_number == inner_range.end_line_number {
        if exclusive {
            outer_range.end_column > inner_range.end_column
        } else {
            outer_range.end_column >= inner_range.end_column
        }
    } else {
        false
    };
    starts_after && ends_before
}

/// Returns `true` if the provided ranges are exactly equivalent.
pub fn ranges_are_equal(a: &Range, b: &Range) -> bool {
    a.start_line_number == b.start_line_number
        && a.start_column == b.start_column
        && a.end_line_number == b.end_line_number
        && a.end_column == b.end_column
}

/// Extract the errors that occurred while resolving a script.
pub fn get_resolution_errors(resolved_script: &[ResolvedSegment]) -> Vec<CompilationError> {
    let mut errors = Vec::new();
    for segment in resolved_script {
        match segment {
            ResolvedSegment::Error(ResolvedSegmentError {
                range,
                value,
                missing_identifier,
                owning_entity,
            }) => errors.push(CompilationError {
                error: value.clone(),
                range: *range,
                missing_identifier: missing_identifier.clone(),
                owning_entity: owning_entity.clone(),
            }),
            ResolvedSegment::Evaluation(ResolvedSegmentEvaluation { value, .. }) | ResolvedSegment::Push(ResolvedSegmentPush { value, .. }) => {
                errors.extend(get_resolution_errors(value));
            }
            _ => {}
        }
    }
    errors
}

/// Verify that every error can be resolved by providing additional variables.
pub fn all_errors_are_recoverable(errors: &[CompilationError]) -> bool {
    errors.iter().all(CompilationError::is_recoverable)
}

/// A single resolution used in a resolved script.
#[derive(Clone, Debug)]
pub struct CashAssemblyResolution {
    pub bytecode: Vec<u8>,
    pub text: String,
    pub resolution_type: ResolutionType,
}

/// The type of a {@link CashAssemblyResolution}.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionType {
    BigIntLiteral,
    BinaryLiteral,
    HexLiteral,
    Opcode,
    Script,
    Utf8Literal,
    Variable,
}

fn literal_resolution_type(literal_type: ResolvedSegmentLiteralType) -> ResolutionType {
    match literal_type {
        ResolvedSegmentLiteralType::BigIntLiteral => ResolutionType::BigIntLiteral,
        ResolvedSegmentLiteralType::BinaryLiteral => ResolutionType::BinaryLiteral,
        ResolvedSegmentLiteralType::HexLiteral => ResolutionType::HexLiteral,
        ResolvedSegmentLiteralType::Utf8Literal => ResolutionType::Utf8Literal,
    }
}

/// Get all resolutions used in a resolved script.
pub fn extract_bytecode_resolutions(
    resolved_script: &[ResolvedSegment],
) -> Vec<CashAssemblyResolution> {
    let mut all = Vec::new();
    for segment in resolved_script {
        match segment {
            ResolvedSegment::Evaluation(ResolvedSegmentEvaluation { value, .. }) | ResolvedSegment::Push(ResolvedSegmentPush { value, .. }) => {
                all.extend(extract_bytecode_resolutions(value));
            }
            ResolvedSegment::Bytecode(bytecode) => match bytecode {
                ResolvedSegmentBytecode::Variable(segment) => all.push(CashAssemblyResolution {
                    bytecode: segment.value.clone(),
                    text: segment.variable.clone(),
                    resolution_type: ResolutionType::Variable,
                }),
                ResolvedSegmentBytecode::Script(segment) => {
                    all.extend(extract_bytecode_resolutions(&segment.source.resolve));
                    all.push(CashAssemblyResolution {
                        bytecode: segment.value.clone(),
                        text: segment.script.clone(),
                        resolution_type: ResolutionType::Script,
                    });
                }
                ResolvedSegmentBytecode::Opcode(segment) => all.push(CashAssemblyResolution {
                    bytecode: segment.value.clone(),
                    text: segment.opcode.clone(),
                    resolution_type: ResolutionType::Opcode,
                }),
                ResolvedSegmentBytecode::Literal(segment) => all.push(CashAssemblyResolution {
                    bytecode: segment.value.clone(),
                    text: segment.literal.clone(),
                    resolution_type: literal_resolution_type(segment.literal_type),
                }),
            },
            _ => {}
        }
    }
    all
}

/// Extract a map of variable identifiers to their resolved bytecode.
pub fn extract_resolved_variable_bytecode_map(
    resolved_script: &[ResolvedSegment],
) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut map = std::collections::BTreeMap::new();
    for resolution in extract_bytecode_resolutions(resolved_script) {
        if resolution.resolution_type == ResolutionType::Variable {
            map.insert(resolution.text, resolution.bytecode);
        }
    }
    map
}

/// Format a list of compilation errors into a single string, with each error's
/// start position (e.g. `[1, 2] The error message.`).
///
/// `separator` defaults to `"; "`.
pub fn stringify_errors(errors: &[CompilationError], separator: Option<&str>) -> String {
    let separator = separator.unwrap_or("; ");
    errors
        .iter()
        .map(|error| {
            format!(
                "[{}, {}] {}",
                error.range.start_line_number, error.range.start_column, error.error
            )
        })
        .collect::<Vec<String>>()
        .join(separator)
}

const ONE_BELOW_HASH160: usize = 19;

/// Given a stack, return a summary of the stack's contents, encoding valid VM
/// numbers as numbers, and all other stack items as hex literals.
pub fn summarize_stack(stack: &[Vec<u8>]) -> Vec<String> {
    stack
        .iter()
        .map(|item| {
            let as_number = vm_number_to_big_int(item, Some(ONE_BELOW_HASH160), None);
            format!(
                "0x{}{}",
                bin_to_hex(item),
                match as_number {
                    Err(_) => String::new(),
                    Ok(number) => format!("({number})"),
                }
            )
        })
        .collect()
}

/// A step of the summary produced by {@link summarizeDebugTrace}.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugTraceSummary {
    pub alternate_stack: Vec<String>,
    pub error: Option<String>,
    pub execute: bool,
    pub instruction: Option<AuthenticationInstruction>,
    pub ip: isize,
    pub stack: Vec<String>,
}

/// Given a debug trace (produced by {@link AuthenticationVirtualMachine.debug},
/// optionally masked), summarize each step of the trace, showing the stacks
/// resulting from each evaluation step.
pub fn summarize_debug_trace<State: Borrow<AuthenticationProgramStateCommon>>(
    trace: &[State],
) -> Vec<DebugTraceSummary> {
    trace
        .windows(2)
        .map(|pair| {
            let state: &AuthenticationProgramStateCommon = pair[0].borrow();
            let next_state: &AuthenticationProgramStateCommon = pair[1].borrow();
            DebugTraceSummary {
                alternate_stack: summarize_stack(&next_state.alternate_stack),
                error: next_state.error.clone(),
                execute: execution_is_active(state),
                instruction: usize::try_from(state.ip)
                    .ok()
                    .and_then(|ip| state.instructions.get(ip).cloned()),
                ip: state.ip,
                stack: summarize_stack(&next_state.stack),
            }
        })
        .collect()
}

const REASONABLE_PADDING_FOR_INSTRUCTION_SET_BCH: usize = 23;
const REASONABLE_LINE_COUNT_FOR_INSTRUCTION_SET_BCH: usize = 30;

/// Return a string with the result of {@link summarizeDebugTrace}, with one
/// step per line.
///
/// `opcodes` defaults to {@link OpcodesBch}, `pad_instruction` to `23`, and
/// `print_line_count` to `30`.
pub fn stringify_debug_trace_summary(
    summary: &[DebugTraceSummary],
    opcodes: Option<&[(&str, u8)]>,
    pad_instruction: Option<usize>,
    print_line_count: Option<usize>,
) -> String {
    let opcodes = opcodes.unwrap_or(OpcodesBch::MEMBERS);
    let pad_instruction = pad_instruction.unwrap_or(REASONABLE_PADDING_FOR_INSTRUCTION_SET_BCH);
    let print_line_count = print_line_count.unwrap_or(REASONABLE_LINE_COUNT_FOR_INSTRUCTION_SET_BCH);
    let truncated = if summary.len() > print_line_count {
        format!("[{} steps truncated]\n", summary.len() - print_line_count)
    } else {
        String::new()
    };
    // `Array.prototype.slice(-0)` is `slice(0)`.
    let first = if print_line_count == 0 {
        0
    } else {
        summary.len().saturating_sub(print_line_count)
    };
    let lines: Vec<String> = summary[first..]
        .iter()
        .map(|line| {
            let instruction_column = match &line.instruction {
                None => "=>".to_string(),
                Some(instruction) => {
                    let opcode = instruction.opcode();
                    let name = opcodes
                        .iter()
                        .rev()
                        .find(|(_, value)| *value == opcode)
                        .map_or_else(|| format!("OP_UNKNOWN{opcode}"), |(name, _)| name.to_string());
                    format!("{}. {}{name}:", line.ip, if line.execute { "" } else { "(skip)" })
                }
            };
            let body = match &line.error {
                Some(error) => error.clone(),
                None => format!(
                    "{}{}",
                    line.stack.join(" "),
                    if line.alternate_stack.is_empty() {
                        String::new()
                    } else {
                        format!("| alt: {}", line.alternate_stack.join(" "))
                    }
                ),
            };
            format!("{instruction_column:<pad_instruction$} {body}")
        })
        .collect();
    format!("{truncated}{}", lines.join("\n"))
}

/// A stack item labeling hint extracted from a comment, e.g. the
/// `// [[ top, second ]]` comment in
/// `<0xab> <0xcd> // we'll call these: [[ ab, cd ]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackItemLabel {
    /// The index of the sample from which the label's value was extracted.
    pub source_sample: usize,
    /// The depth of the labeled stack item, with the top being `0`.
    pub item_depth: usize,
    /// The extracted label (with whitespace trimmed).
    pub label: String,
    /// The hex encoded value of the labeled stack item.
    pub value: String,
}

/// The result of {@link extractEvaluationSamples}.
#[derive(Clone, Debug, Default)]
pub struct SampleExtractionResult<ProgramState = AuthenticationProgramStateCommon> {
    /// The samples extracted from the provided nodes and trace, ordered by the
    /// ending position of their range.
    pub samples: Vec<EvaluationSample<ProgramState>>,
    /// Program states which were not paired with any node. In a successful
    /// evaluation this is the final state of the trace; an empty array
    /// indicates an error halted evaluation before all nodes were matched.
    pub unmatched_states: Vec<ProgramState>,
    /// Stack item labels extracted during sample extraction.
    pub labeled_stack_items: Vec<StackItemLabel>,
}

fn instruction_from_decoded(
    instruction: &AuthenticationInstructionMaybeMalformed,
) -> Option<AuthenticationInstruction> {
    match instruction {
        AuthenticationInstructionMaybeMalformed::Instruction(instruction) => Some(instruction.clone()),
        AuthenticationInstructionMaybeMalformed::Malformed(_) => None,
    }
}

fn encode_malformed(instruction: &AuthenticationInstructionMaybeMalformed) -> Vec<u8> {
    match instruction {
        AuthenticationInstructionMaybeMalformed::Malformed(instruction) => {
            encode_authentication_instruction_malformed(instruction)
        }
        AuthenticationInstructionMaybeMalformed::Instruction(_) => {
            unreachable!("only malformed instructions remain incomplete")
        }
    }
}

/// Extract the first `[[ ... ]]` hint from a comment.
fn extract_label_hint(comment: &str) -> Option<&str> {
    let start = comment.find("[[")? + 2;
    let end = comment[start..].find("]]")? + start;
    Some(&comment[start..end])
}

/// A state paired with an instruction, used while walking the trace.
struct PairedState<'a> {
    instruction: Option<AuthenticationInstruction>,
    iterations: Option<Vec<AuthenticationProgramStateCommon>>,
    state: Option<&'a AuthenticationProgramStateCommon>,
}

/// Extract a set of "evaluation samples" from the result of a CashAssembly
/// compilation and a matching debug trace, pairing program states with the
/// source ranges that produced them (libauth's `extractEvaluationSamples`).
///
/// `evaluation_range` is the range of the script node that was evaluated to
/// produce `trace`, and `ip_offset` is subtracted from every `ip` when mapping
/// states to nodes. The provided `trace` must begin with the initial program
/// state, contain one program state per instruction, and end with the final
/// program state (as produced by
/// [`AuthenticationVirtualMachine::debug`](crate::vm::AuthenticationVirtualMachine::debug)
/// after removing the initial state of the unlocking phase).
pub fn extract_evaluation_samples(
    evaluation_range: Range,
    ip_offset: Option<isize>,
    nodes: &[ScriptReductionTraceChildNode],
    trace: &[AuthenticationProgramStateCommon],
) -> SampleExtractionResult {
    let ip_offset = ip_offset.unwrap_or(0);
    let mut labeled_stack_items = Vec::new();
    let trace_without_final_state = if trace.len() > 1 {
        &trace[..trace.len() - 1]
    } else {
        trace
    };
    if trace_without_final_state.is_empty() {
        return SampleExtractionResult {
            labeled_stack_items,
            samples: Vec::new(),
            unmatched_states: Vec::new(),
        };
    }

    let mut samples = vec![EvaluationSample {
        evaluation_range,
        instruction: None,
        internal_states: Vec::new(),
        iterations: None,
        range: Range {
            end_column: evaluation_range.start_column,
            end_line_number: evaluation_range.start_line_number,
            start_column: evaluation_range.start_column,
            start_line_number: evaluation_range.start_line_number,
        },
        state: trace_without_final_state[0].clone(),
    }];

    // Group the trace states by (adjusted) instruction pointer.
    let mut state_by_ip: Vec<Vec<AuthenticationProgramStateCommon>> = Vec::new();
    for state in trace_without_final_state {
        let adjusted_ip = state.ip - ip_offset;
        if adjusted_ip < 0 {
            continue;
        }
        let index = adjusted_ip as usize;
        if state_by_ip.len() <= index {
            state_by_ip.resize_with(index + 1, Vec::new);
        }
        state_by_ip[index].push(state.clone());
    }

    let mut next_state = 1_usize;
    let mut next_node = 0_usize;
    let mut incomplete: Option<(Vec<u8>, Range)> = None;

    while next_state < state_by_ip.len() && next_node < nodes.len() {
        let current_node = &nodes[next_node];
        let (merged_bytecode, merged_range) = match &incomplete {
            None => (current_node.bytecode().to_vec(), current_node.range()),
            Some((bytecode, range)) => {
                let mut merged = bytecode.clone();
                merged.extend_from_slice(current_node.bytecode());
                (merged, merge_ranges(&[*range, current_node.range()], None))
            }
        };

        let decoded = decode_authentication_instructions(&merged_bytecode);
        let has_non_malformed_instructions = decoded
            .first()
            .is_some_and(|instruction| !authentication_instruction_is_malformed(instruction));

        if let ScriptReductionTraceChildNode::Comment(ScriptReductionTraceCommentNode { comment, .. }) = current_node {
            let source_sample = samples.len() - 1;
            let last_sample_stack = samples[source_sample].state.stack.clone();
            if let Some(hint) = extract_label_hint(comment) {
                let labels: Vec<&str> = hint.split(',').map(str::trim).rev().collect();
                for (item_depth, label) in labels.iter().enumerate() {
                    // Labels for excessive depths are silently ignored.
                    let Some(stack_item) = stack_item_at_depth(&last_sample_stack, item_depth) else {
                        continue;
                    };
                    labeled_stack_items.push(StackItemLabel {
                        source_sample,
                        item_depth,
                        label: (*label).to_string(),
                        value: bin_to_hex(stack_item),
                    });
                }
            }
        }

        if has_non_malformed_instructions {
            let last_instruction = decoded.last().expect("non-empty");
            let valid_instructions = if authentication_instruction_is_malformed(last_instruction) {
                &decoded[..decoded.len() - 1]
            } else {
                &decoded[..]
            };
            let first_unmatched_state_index = next_state + valid_instructions.len();
            let paired: Vec<PairedState> = valid_instructions
                .iter()
                .enumerate()
                .map(|(index, instruction)| {
                    let group = state_by_ip
                        .get(next_state + index)
                        .filter(|group| !group.is_empty());
                    PairedState {
                        instruction: instruction_from_decoded(instruction),
                        iterations: group.map(|group| group[1..].to_vec()),
                        state: group.map(|group| &group[0]),
                    }
                })
                .collect();

            // A well-formed trace contains a state for each instruction index.
            let Some(first_paired_state) = paired.first().and_then(|entry| entry.state) else {
                break;
            };

            let closes_currently_open_sample = incomplete.is_some();
            if closes_currently_open_sample {
                samples.push(EvaluationSample {
                    evaluation_range,
                    instruction: paired[0].instruction.clone(),
                    internal_states: Vec::new(),
                    iterations: paired[0].iterations.clone(),
                    range: merged_range,
                    state: first_paired_state.clone(),
                });
            }

            let first_undefined_state_index = paired.iter().position(|entry| entry.state.is_none());
            let sample_closing_index = match first_undefined_state_index {
                Some(index) => index as isize - 1,
                None => paired.len() as isize - 1,
            };

            let closes_a_second_sample =
                !closes_currently_open_sample || sample_closing_index > 0;
            if closes_a_second_sample && sample_closing_index < 0 {
                break;
            }
            if closes_a_second_sample {
                let closing_index = sample_closing_index as usize;
                let second_sample_pairs_begin = if closes_currently_open_sample { 1 } else { 0 };
                let internal_states = paired[second_sample_pairs_begin..closing_index]
                    .iter()
                    .filter_map(|entry| {
                        Some(EvaluationInternalState {
                            instruction: entry.instruction.clone()?,
                            state: entry.state?.clone(),
                        })
                    })
                    .collect();
                let Some(final_state) = paired[closing_index].state else {
                    break;
                };
                samples.push(EvaluationSample {
                    evaluation_range,
                    instruction: paired[closing_index].instruction.clone(),
                    internal_states,
                    iterations: paired[closing_index].iterations.clone(),
                    range: current_node.range(),
                    state: final_state.clone(),
                });
            }

            next_state = first_unmatched_state_index;
            incomplete = if authentication_instruction_is_malformed(last_instruction) {
                Some((encode_malformed(last_instruction), current_node.range()))
            } else {
                None
            };
        } else {
            incomplete = decoded
                .last()
                .map(|last| (encode_malformed(last), merged_range));
        }

        next_node += 1;
    }

    // Running out of trace states before all nodes were matched indicates an
    // error which halted evaluation.
    let error_occurred = next_node < nodes.len();
    let unmatched_states = if error_occurred {
        Vec::new()
    } else {
        trace.get(next_state..).unwrap_or(&[]).to_vec()
    };

    SampleExtractionResult {
        labeled_stack_items,
        samples,
        unmatched_states,
    }
}

fn stack_item_at_depth<'a>(stack: &'a [Vec<u8>], item_depth: usize) -> Option<&'a Vec<u8>> {
    stack
        .len()
        .checked_sub(1 + item_depth)
        .and_then(|index| stack.get(index))
}

/// Return `true` for states which were not produced by a function invocation
/// (i.e. states without a control stack frame).
fn states_not_produced_by_function_invocation(state: &AuthenticationProgramStateCommon) -> bool {
    !state
        .control_stack
        .iter()
        .any(|item| matches!(item, AuthenticationProgramStateControlStackItem::Frame(_)))
}

/// The `$(` and `)` token lengths used to trim evaluation ranges.
const EVALUATION_BEGIN_TOKEN_LENGTH: usize = 2;
const EVALUATION_END_TOKEN_LENGTH: usize = 1;

/// Recursively extract samples from each nested evaluation within `node`.
fn extract_nested_evaluations(node: &ScriptReductionTraceChildNode, samples: &mut Vec<EvaluationSample>) {
    match node {
        ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode { push, .. }) => {
            for child in &push.script {
                extract_nested_evaluations(child, samples);
            }
        }
        ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode { trace, source, range, .. }) => {
            let mut child_samples = Vec::new();
            for child in &source.script {
                extract_nested_evaluations(child, &mut child_samples);
            }
            let trace_without_unlocking_phase: Vec<AuthenticationProgramStateCommon> = trace
                .iter()
                .skip(1)
                .filter(|state| states_not_produced_by_function_invocation(state))
                .cloned()
                .collect();
            let evaluation_range = Range {
                end_column: range.end_column.saturating_sub(EVALUATION_END_TOKEN_LENGTH),
                end_line_number: range.end_line_number,
                start_column: range.start_column + EVALUATION_BEGIN_TOKEN_LENGTH,
                start_line_number: range.start_line_number,
            };
            let extracted = extract_evaluation_samples(
                evaluation_range,
                None,
                &source.script,
                &trace_without_unlocking_phase,
            );
            samples.extend(extracted.samples);
            samples.extend(child_samples);
        }
        _ => {}
    }
}

/// As [`extract_evaluation_samples`], but recursively extracting samples from
/// evaluations within the provided array of nodes (libauth's
/// `extractEvaluationSamplesRecursive`).
///
/// Returned samples are ordered by the ending position of their range; samples
/// from CashAssembly evaluations within an outer evaluation appear before their
/// parent sample.
pub fn extract_evaluation_samples_recursive(
    evaluation_range: Range,
    nodes: &[ScriptReductionTraceChildNode],
    trace: &[AuthenticationProgramStateCommon],
    ip_offset: Option<isize>,
) -> SampleExtractionResult {
    let trace_without_function_invocations: Vec<AuthenticationProgramStateCommon> = trace
        .iter()
        .filter(|state| states_not_produced_by_function_invocation(state))
        .cloned()
        .collect();
    let extracted = extract_evaluation_samples(
        evaluation_range,
        ip_offset,
        nodes,
        &trace_without_function_invocations,
    );

    let mut child_samples = Vec::new();
    for node in nodes {
        extract_nested_evaluations(node, &mut child_samples);
    }

    let mut samples = extracted.samples;
    samples.extend(child_samples);
    samples.sort_by_key(|sample| (sample.range.end_line_number, sample.range.end_column));

    SampleExtractionResult {
        labeled_stack_items: extracted.labeled_stack_items,
        samples,
        unmatched_states: extracted.unmatched_states,
    }
}

/// Extract an array of ranges which were unused by an evaluation. This is
/// useful in development tooling for fading out or hiding code which is
/// unimportant to the current evaluation being tested.
///
/// Only ranges which are guaranteed to be unimportant to an evaluation are
/// returned by this method: those from samples which are preceded by a sample
/// that ends with execution disabled, end with execution disabled, and contain
/// no internal states that enable execution.
///
/// `evaluation_begins` (the line and column, e.g. `"1,1"`, at which the
/// initial sample's evaluation range begins) defaults to `"1,1"`.
pub fn extract_unexecuted_ranges(samples: &[EvaluationSample], evaluation_begins: Option<&str>) -> Vec<Range> {
    let evaluation_begins = evaluation_begins.unwrap_or("1,1");
    let mut preceding_state_skips_by_evaluation: BTreeMap<String, bool> = BTreeMap::new();
    preceding_state_skips_by_evaluation.insert(evaluation_begins.to_string(), false);
    let mut unexecuted_ranges = Vec::new();
    for sample in samples {
        let current_evaluation_start_line_and_column = format!(
            "{},{}",
            sample.evaluation_range.start_line_number, sample.evaluation_range.start_column
        );
        let preceding_state_skips = preceding_state_skips_by_evaluation
            .get(&current_evaluation_start_line_and_column)
            .copied()
            .unwrap_or(false);
        let ends_with_skip = !execution_is_active(&sample.state);
        let sample_has_no_executed_instructions = ends_with_skip
            && sample
                .internal_states
                .iter()
                .all(|group| !execution_is_active(&group.state));
        if preceding_state_skips && sample_has_no_executed_instructions {
            preceding_state_skips_by_evaluation.insert(current_evaluation_start_line_and_column, true);
            unexecuted_ranges.push(sample.range);
        } else {
            preceding_state_skips_by_evaluation.insert(current_evaluation_start_line_and_column, ends_with_skip);
        }
    }
    const CAN_HAVE_CONTAINED_RANGES: usize = 2;
    if unexecuted_ranges.len() < CAN_HAVE_CONTAINED_RANGES {
        return unexecuted_ranges;
    }
    let mut contained_ranges_excluded = vec![unexecuted_ranges[unexecuted_ranges.len() - 1]];
    for range in unexecuted_ranges[..unexecuted_ranges.len() - 1].iter().rev() {
        if contains_range(&contained_ranges_excluded[0], range, None) {
            continue;
        }
        contained_ranges_excluded.insert(0, *range);
    }
    contained_ranges_excluded
}
