//! Port of `language/language-utils.spec.ts`.

use std::collections::BTreeMap;
use std::rc::Rc;

use libauth::{
    assert_success, compile_cash_assembly, contains_range,
    create_authentication_program_evaluation_common, create_compiler_bch, create_compiler_common,
    create_virtual_machine_bch, create_virtual_machine_bch_spec, evaluate_cash_assembly,
    extract_bytecode_resolutions, extract_evaluation_samples, extract_evaluation_samples_recursive,
    extract_unexecuted_ranges, hex_to_bin, merge_ranges, stringify_debug_trace_summary,
    stringify_errors, summarize_debug_trace, wallet_template_to_compiler_bch,
    AuthenticationInstruction, AuthenticationInstructionOperation, AuthenticationInstructionPush,
    AuthenticationProgramCommon, AuthenticationProgramStateCommon,
    AuthenticationProgramStateControlStackItem, AuthenticationProgramStateMetrics,
    AuthenticationProgramStateSignedMessage, AuthenticationVirtualMachineBch,
    AuthenticationVirtualMachineBchSpec, AuthenticationVirtualMachineIdentifier,
    CashAssemblyResolution, CompilationData, CompilationResult, CompilationResultError, Compiler,
    CompilerConfiguration, EvaluationInternalState, EvaluationSample, Input, Opcodes, OpcodesBch,
    Output, Range, ResolutionType, SampleExtractionResult, Scenario, ScriptReductionTraceChildNode,
    ScriptReductionTraceEvaluationNode, ScriptReductionTraceNode, ScriptReductionTracePushNode,
    ScriptReductionTraceScriptNode, TransactionCommon, WalletTemplate, WalletTemplateAddressData,
    WalletTemplateLockingType, WalletTemplateScriptDefinition, WalletTemplateScriptLocking,
    WalletTemplateScriptUnlocking, WalletTemplateVariable, WalletTemplateVariableType,
};

/// `t.deepEqual` for values whose types do not implement `PartialEq`: compares
/// the complete values through their derived `Debug` representations,
/// reporting the first differing line (with its enclosing structure).
#[track_caller]
fn assert_debug_eq<T: std::fmt::Debug>(actual: &T, expected: &T) {
    assert_debug_eq_labeled("t.deepEqual", actual, expected);
}

/// As [`assert_debug_eq`], identifying the assertion with `label` in the panic
/// message.
#[track_caller]
fn assert_debug_eq_labeled<T: std::fmt::Debug>(label: &str, actual: &T, expected: &T) {
    let actual = format!("{actual:#?}");
    let expected = format!("{expected:#?}");
    if actual == expected {
        return;
    }
    let actual_lines: Vec<&str> = actual.lines().collect();
    let expected_lines: Vec<&str> = expected.lines().collect();
    let first_difference = actual_lines
        .iter()
        .zip(&expected_lines)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| actual_lines.len().min(expected_lines.len()));
    let indentation = |line: &str| line.len() - line.trim_start().len();
    let mut path = Vec::new();
    let mut depth = actual_lines
        .get(first_difference)
        .map_or(usize::MAX, |line| indentation(line));
    for line in actual_lines[..first_difference].iter().rev() {
        if indentation(line) < depth {
            depth = indentation(line);
            path.push(line.trim());
        }
    }
    path.reverse();
    let context = |lines: &[&str]| {
        lines[first_difference.saturating_sub(6)..(first_difference + 6).min(lines.len())]
            .join("\n")
    };
    panic!(
        "{label}: values differ at line {} of their Debug representations\n--- path ---\n{}\n--- actual ---\n{}\n--- expected ---\n{}",
        first_difference + 1,
        path.join("\n"),
        context(&actual_lines),
        context(&expected_lines),
    );
}

/// JavaScript's `Array.prototype.slice(start, end)` (negative indexes count
/// from the end).
fn slice<T: Clone>(items: &[T], start: isize, end: Option<isize>) -> Vec<T> {
    let length = items.len() as isize;
    let resolve = |index: isize| {
        if index < 0 {
            (length + index).max(0)
        } else {
            index.min(length)
        }
    };
    let (start, end) = (resolve(start), resolve(end.unwrap_or(length)));
    if start >= end {
        return Vec::new();
    }
    items[start as usize..end as usize].to_vec()
}

#[test]
fn merge_ranges_() {
    assert_eq!(
        merge_ranges(
            &vec![
                Range {
                    end_column: 3,
                    end_line_number: 1,
                    start_column: 0,
                    start_line_number: 1,
                },
                Range {
                    end_column: 1,
                    end_line_number: 3,
                    start_column: 6,
                    start_line_number: 0,
                },
            ],
            None
        ),
        Range {
            end_column: 1,
            end_line_number: 3,
            start_column: 6,
            start_line_number: 0,
        },
    );
    assert_eq!(
        merge_ranges(
            &vec![
                Range {
                    end_column: 4,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
                Range {
                    end_column: 8,
                    end_line_number: 1,
                    start_column: 6,
                    start_line_number: 1,
                },
            ],
            None
        ),
        Range {
            end_column: 8,
            end_line_number: 1,
            start_column: 0,
            start_line_number: 0,
        },
    );
    assert_eq!(
        merge_ranges(
            &vec![
                Range {
                    end_column: 1,
                    end_line_number: 1,
                    start_column: 5,
                    start_line_number: 0,
                },
                Range {
                    end_column: 8,
                    end_line_number: 1,
                    start_column: 0,
                    start_line_number: 0,
                },
            ],
            None
        ),
        Range {
            end_column: 8,
            end_line_number: 1,
            start_column: 0,
            start_line_number: 0,
        },
    );
}

#[test]
fn contains_range_() {
    assert_eq!(
        contains_range(
            &Range {
                end_column: 1,
                end_line_number: 3,
                start_column: 6,
                start_line_number: 0,
            },
            &Range {
                end_column: 3,
                end_line_number: 1,
                start_column: 0,
                start_line_number: 1,
            },
            None
        ),
        true,
    );
    assert_eq!(
        contains_range(
            &Range {
                end_column: 4,
                end_line_number: 0,
                start_column: 0,
                start_line_number: 0,
            },
            &Range {
                end_column: 8,
                end_line_number: 1,
                start_column: 6,
                start_line_number: 1,
            },
            None
        ),
        false,
    );
    assert_eq!(
        contains_range(
            &Range {
                end_column: 8,
                end_line_number: 1,
                start_column: 0,
                start_line_number: 0,
            },
            &Range {
                end_column: 1,
                end_line_number: 1,
                start_column: 5,
                start_line_number: 0,
            },
            None
        ),
        true,
    );
    assert_eq!(
        contains_range(
            &Range {
                end_column: 5,
                end_line_number: 1,
                start_column: 1,
                start_line_number: 1,
            },
            &Range {
                end_column: 5,
                end_line_number: 1,
                start_column: 1,
                start_line_number: 1,
            },
            Some(false)
        ),
        true,
    );
}

#[test]
fn evaluate_cash_assembly_() {
    let successful = assert_success(evaluate_cash_assembly("<2> <2> OP_ADD", None), None);
    assert_eq!(successful.stack[0], hex_to_bin("04"), "{successful:?}");
    let failed = evaluate_cash_assembly("<bad>", None);
    assert_eq!(
        failed,
        Err("Cannot generate the default scenario: Failed compilation of source output at index 0: Unknown identifier \"bad\".".to_string()),
    );
}

#[test]
fn compile_cash_assembly_() {
    let successful = compile_cash_assembly("<0x010203>");
    assert_eq!(successful, Ok(hex_to_bin("03010203")));
    let failed = compile_cash_assembly("<bad>");
    assert_eq!(
        failed,
        Err("CashAssembly compilation error: [1, 2]: Unknown identifier \"bad\".".to_string()),
    );
}

#[test]
fn extract_bytecode_resolutions_() {
    let compiler = create_compiler_common(CompilerConfiguration {
        scripts: BTreeMap::from([
            ("pushNumbers".to_string(), "<1> var".to_string()),
            (
                "t".to_string(),
                "pushNumbers OP_ADD <0x03> OP_EQUAL <\"abc\"> OP_DROP <0b11> OP_EQUAL var2"
                    .to_string(),
            ),
        ]),
        variables: Some(BTreeMap::from([
            ("var".to_string(), address_data_variable()),
            ("var2".to_string(), address_data_variable()),
        ])),
        ..Default::default()
    });

    let compiled = compiler.generate_bytecode_debug(
        &CompilationData {
            bytecode: Some(BTreeMap::from([("var".to_string(), vec![0])])),
            ..Default::default()
        },
        "t",
    );

    // libauth: `if (!('resolve' in compiled)) { t.fail(stringifyTestVector(compiled)); return; }`
    let resolve = match &compiled {
        CompilationResult::Success(success) => &success.resolve,
        CompilationResult::Error(CompilationResultError {
            resolve: Some(resolve),
            ..
        }) => resolve,
        CompilationResult::Error(_) => panic!("{compiled:?}"),
    };
    let result = extract_bytecode_resolutions(resolve);
    assert_debug_eq(
        &result,
        &vec![
            CashAssemblyResolution {
                bytecode: hex_to_bin("01"),
                text: "1".to_string(),
                resolution_type: ResolutionType::BigIntLiteral,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("00"),
                text: "var".to_string(),
                resolution_type: ResolutionType::Variable,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("5100"),
                text: "pushNumbers".to_string(),
                resolution_type: ResolutionType::Script,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("93"),
                text: "OP_ADD".to_string(),
                resolution_type: ResolutionType::Opcode,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("03"),
                text: "03".to_string(),
                resolution_type: ResolutionType::HexLiteral,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("87"),
                text: "OP_EQUAL".to_string(),
                resolution_type: ResolutionType::Opcode,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("616263"),
                text: "abc".to_string(),
                resolution_type: ResolutionType::Utf8Literal,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("75"),
                text: "OP_DROP".to_string(),
                resolution_type: ResolutionType::Opcode,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("03"),
                text: "11".to_string(),
                resolution_type: ResolutionType::BinaryLiteral,
            },
            CashAssemblyResolution {
                bytecode: hex_to_bin("87"),
                text: "OP_EQUAL".to_string(),
                resolution_type: ResolutionType::Opcode,
            },
        ],
    );
}

/// `{ type: 'AddressData' }`
fn address_data_variable() -> WalletTemplateVariable {
    WalletTemplateVariable::AddressData(WalletTemplateAddressData {
        description: None,
        name: None,
        r#type: WalletTemplateVariableType::AddressData,
    })
}

#[test]
fn extract_evaluation_samples_empty_trace() {
    let result = extract_evaluation_samples(
        Range {
            end_column: 0,
            end_line_number: 0,
            start_column: 0,
            start_line_number: 0,
        },
        None,
        &[],
        &[],
    );
    assert_debug_eq(
        &result,
        &SampleExtractionResult {
            labeled_stack_items: vec![],
            samples: vec![],
            unmatched_states: vec![],
        },
    );
}

const UNEXECUTED_LOCK: &str = r#"OP_TOALTSTACK
OP_IF
    <2>
    OP_FROMALTSTACK
    OP_IF
        <3>
        $(
            <1>
            OP_IF
                <<4>>
            OP_ELSE
                <<5>>
            OP_ENDIF
        )
    0x675667 // OP_ELSE OP_6 OP_ELSE
    OP_ENDIF
OP_ELSE
    <7>
    OP_FROMALTSTACK
    OP_IF
        <$(
            <7> <1> OP_ADD
        )>
    OP_ENDIF
OP_ENDIF"#;

/// libauth's module-level `vm` (`createVirtualMachineBch()`).
fn vm() -> AuthenticationVirtualMachineBch {
    create_virtual_machine_bch(None)
}

/// libauth's module-level `vmSpec` (`createVirtualMachineBchSpec()`).
fn vm_spec() -> AuthenticationVirtualMachineBchSpec {
    create_virtual_machine_bch_spec(None)
}

/// libauth's module-level `compiler` (`createCompilerBch({ scripts })`).
fn compiler() -> Compiler {
    create_compiler_bch(CompilerConfiguration {
        scripts: BTreeMap::from([
            (
                "docs".to_string(),
                "0x00 0x01 0xab01 0xcd9300 $(OP_3 <0x00> OP_SWAP OP_CAT) 0x010203".to_string(),
            ),
            // Second node closes an open sample, then fails during an internal state.
            // The sample should use the error state and the instruction that caused
            // it, ignoring any later (unexecuted) instructions.
            (
                "error1".to_string(),
                "0x01 $(<0xab OP_RETURN OP_0>)".to_string(),
            ),
            // `OP_0 OP_PUSHDATA_2 600 0x62[600 times]` - fails as first instruction of
            // second node: `Push exceeds the push size limit of 520 bytes.`
            (
                "error2".to_string(),
                "0x004d5802 \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"".to_string(),
            ),
            // The second node causes an error, so only two samples and no unmatched
            // states are returned.
            (
                "error3".to_string(),
                "OP_0 OP_RETURN OP_0 OP_0".to_string(),
            ),
            (
                "loops".to_string(),
                r#"<0> <0>
OP_BEGIN
  <0> OP_BEGIN OP_1ADD OP_DUP <2> OP_EQUAL OP_UNTIL // hidden nested loop
  OP_ADD
  OP_SWAP OP_1ADD OP_SWAP
  OP_OVER 
  <0> OP_BEGIN // visible nested loop
    OP_1ADD
    OP_DUP <3>
    OP_EQUAL
  OP_UNTIL
  OP_EQUAL
OP_UNTIL
OP_NIP"#.to_string(),
            ),
            (
                "loopsInternalConditional".to_string(),
                r#"
<5>
OP_BEGIN
OP_1SUB
OP_SIZE
OP_IF
   <0>
OP_ELSE
   <1>
OP_ENDIF
OP_UNTIL"#.to_string(),
            ),
            (
                "nested".to_string(),
                r#"OP_0

<
  $(
  0x0000
    $($(<OP_1>)

      OP_2
      OP_ADD

    )
    $( <"abc">
    )
  OP_CAT
  OP_CAT
  )
  $(
    <0>
    <0>
  $(<OP_CAT>))
>"#.to_string(),
            ),
            (
                "nonPushingOpcodeUnlock".to_string(),
                "OP_1 OP_DUP".to_string(),
            ),
            (
                "unexecuted00".to_string(),
                format!("<0> <0> {UNEXECUTED_LOCK}"),
            ),
            (
                "unexecuted01".to_string(),
                format!("<0> <1> {UNEXECUTED_LOCK}"),
            ),
            (
                "unexecuted10".to_string(),
                format!("<1> <0> {UNEXECUTED_LOCK}"),
            ),
            (
                "unexecuted11".to_string(),
                format!("<1> <1> {UNEXECUTED_LOCK}"),
            ),
            (
                "unexecutedEmpty".to_string(),
                "".to_string(),
            ),
        ]),
        ..Default::default()
    })
}

/// libauth's `compiler.generateBytecode({ data: {}, debug: true, scriptId })`,
/// followed by `if (!result.success) { t.fail(stringifyErrors(result.errors)); return; }`.
fn generate_bytecode_successfully(script_id: &str) -> libauth::CompilationResultSuccess {
    match compiler().generate_bytecode_debug(&CompilationData::default(), script_id) {
        CompilationResult::Success(result) => *result,
        CompilationResult::Error(result) => panic!("{}", stringify_errors(&result.errors, None)),
    }
}

/// A program state as written in the expectations of libauth's `test.failing`
/// tests below.
///
/// Those expectations predate libauth's current program state: their `metrics`
/// contain `executedInstructionCount` (since renamed to
/// `evaluatedInstructionCount`), `maxMemoryUsage` (no longer initialized), and
/// only some of the current metrics, and they include neither `functionTable`
/// nor `functionCount`. [`ExpectedState::into_state`] fills the fields such an
/// expectation omits with zero values, so – as in libauth, where these tests
/// are expected to fail – comparisons against the actual program states fail.
struct ExpectedState {
    alternate_stack: Vec<Vec<u8>>,
    control_stack: Vec<AuthenticationProgramStateControlStackItem>,
    error: Option<String>,
    instructions: Vec<AuthenticationInstruction>,
    ip: isize,
    last_code_separator: isize,
    metrics: ExpectedMetrics,
    operation_count: usize,
    program: AuthenticationProgramCommon,
    signed_messages: Vec<AuthenticationProgramStateSignedMessage>,
    stack: Vec<Vec<u8>>,
}

/// The `metrics` of an [`ExpectedState`].
struct ExpectedMetrics {
    executed_instruction_count: u64,
    hash_digest_iterations: Option<u64>,
    max_memory_usage: Option<u64>,
    signature_check_count: u64,
}

impl ExpectedState {
    fn into_state(self) -> AuthenticationProgramStateCommon {
        AuthenticationProgramStateCommon {
            alternate_stack: self.alternate_stack,
            control_stack: self.control_stack,
            error: self.error,
            // Absent from the expectation.
            function_table: BTreeMap::new(),
            // Absent from the expectation.
            function_count: 0,
            instructions: Rc::new(self.instructions),
            ip: self.ip,
            last_code_separator: self.last_code_separator,
            metrics: AuthenticationProgramStateMetrics {
                // libauth's former name for `evaluatedInstructionCount`.
                evaluated_instruction_count: self.metrics.executed_instruction_count as f64,
                hash_digest_iterations: self.metrics.hash_digest_iterations.unwrap_or(0) as f64,
                max_memory_usage: self.metrics.max_memory_usage.map(|value| value as f64),
                signature_check_count: self.metrics.signature_check_count as f64,
                // The remaining metrics are absent from the expectation.
                ..Default::default()
            },
            operation_count: self.operation_count,
            program: Rc::new(self.program),
            signed_messages: self.signed_messages,
            stack: self.stack,
        }
    }
}

/// libauth: `test.failing` (the expected nodes include program states in the
/// outdated shape described at [`ExpectedState`]).
#[test]
#[should_panic(expected = "assertion 1 (nodes)")]
fn extract_evaluation_samples_documentation_example() {
    let result = generate_bytecode_successfully("docs");
    let program = create_authentication_program_evaluation_common(&result.bytecode);
    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace_with_unlocking_phase_and_final_state = vm().debug(&program, None);
    let actual_trace = slice(&trace_with_unlocking_phase_and_final_state, 1, Some(-1));
    // We double the debugging trace just to test that the extra states are
    // returned in `unmatchedStates`.
    let trace = [actual_trace.clone(), actual_trace.clone()].concat();
    let extracted = extract_evaluation_samples(evaluation_range, None, &nodes, &trace);

    let internal_program =
        create_authentication_program_evaluation_common(&hex_to_bin("5301007c7e"));

    assert_debug_eq_labeled(
        "assertion 1 (nodes)",
        &nodes,
        &vec![
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("01"),
                errors: None,
                range: Range {
                    end_column: 10,
                    end_line_number: 1,
                    start_column: 6,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("ab01"),
                errors: None,
                range: Range {
                    end_column: 17,
                    end_line_number: 1,
                    start_column: 11,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("cd9300"),
                errors: None,
                range: Range {
                    end_column: 26,
                    end_line_number: 1,
                    start_column: 18,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                bytecode: hex_to_bin("0003"),
                errors: None,
                range: Range {
                    end_column: 56,
                    end_line_number: 1,
                    start_column: 27,
                    start_line_number: 1,
                },
                source: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin("5301007c7e"),
                    errors: None,
                    range: Range {
                        end_column: 55,
                        end_line_number: 1,
                        start_column: 29,
                        start_line_number: 1,
                    },
                    script: vec![
                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                            bytecode: hex_to_bin("53"),
                            errors: None,
                            range: Range {
                                end_column: 33,
                                end_line_number: 1,
                                start_column: 29,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                            bytecode: hex_to_bin("0100"),
                            errors: None,
                            push: Box::new(ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin("00"),
                                errors: None,
                                range: Range {
                                    end_column: 39,
                                    end_line_number: 1,
                                    start_column: 35,
                                    start_line_number: 1,
                                },
                                script: vec![ScriptReductionTraceChildNode::Bytecode(
                                    ScriptReductionTraceNode {
                                        bytecode: hex_to_bin("00"),
                                        errors: None,
                                        range: Range {
                                            end_column: 39,
                                            end_line_number: 1,
                                            start_column: 35,
                                            start_line_number: 1,
                                        },
                                    },
                                )],
                            }),
                            range: Range {
                                end_column: 40,
                                end_line_number: 1,
                                start_column: 34,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                            bytecode: hex_to_bin("7c"),
                            errors: None,
                            range: Range {
                                end_column: 48,
                                end_line_number: 1,
                                start_column: 41,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                            bytecode: hex_to_bin("7e"),
                            errors: None,
                            range: Range {
                                end_column: 55,
                                end_line_number: 1,
                                start_column: 49,
                                start_line_number: 1,
                            },
                        }),
                    ],
                }),
                trace: vec![
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 83 },
                            ),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("00"),
                                opcode: 1,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 124 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 83 },
                            ),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("00"),
                                opcode: 1,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 124 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(1),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("03")],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 83 },
                            ),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("00"),
                                opcode: 1,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 124 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 2,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 2,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(2),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("03"), hex_to_bin("00")],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 83 },
                            ),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("00"),
                                opcode: 1,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 124 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 3,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 3,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(2),
                            signature_check_count: 0,
                        },
                        operation_count: 1,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("00"), hex_to_bin("03")],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 83 },
                            ),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("00"),
                                opcode: 1,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 124 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 4,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 4,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(2),
                            signature_check_count: 0,
                        },
                        operation_count: 2,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("0003")],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 83 },
                            ),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("00"),
                                opcode: 1,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 124 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 4,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 4,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(2),
                            signature_check_count: 0,
                        },
                        operation_count: 2,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("0003")],
                    }
                    .into_state(),
                ],
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("010203"),
                errors: None,
                range: Range {
                    end_column: 65,
                    end_line_number: 1,
                    start_column: 57,
                    start_line_number: 1,
                },
            }),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 2 (trace)",
        &trace_with_unlocking_phase_and_final_state,
        &vec![
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 1,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 1,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("ab")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 3,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 3,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("ab"), hex_to_bin("cd")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 4,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 4,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("f8")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 5,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 5,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("f8"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 6,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 6,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin("f8"),
                    hex_to_bin(""),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 7,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin("f8"),
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("010203"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("cd"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 147,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("010203"),
                        opcode: 3,
                    }),
                ],
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 7,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin("f8"),
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("010203"),
                ],
            }
            .into_state(),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 3 (extracted)",
        &extracted,
        &SampleExtractionResult {
            // `labeledStackItems` is absent from libauth's expectation.
            labeled_stack_items: vec![],
            samples: vec![
                EvaluationSample {
                    evaluation_range,
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 1,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    state: trace[0].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: vec![],
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: nodes[0].range(),
                    state: trace[1].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("ab"),
                            opcode: 1,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: merge_ranges(&[nodes[1].range(), nodes[2].range()], None),
                    state: trace[2].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("cd"),
                            opcode: 1,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: merge_ranges(&[nodes[2].range(), nodes[3].range()], None),
                    state: trace[3].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: vec![],
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![EvaluationInternalState {
                        instruction: AuthenticationInstruction::Operation(
                            AuthenticationInstructionOperation { opcode: 0x93 },
                        ),
                        state: trace[4].clone(),
                    }],
                    iterations: None,
                    range: nodes[3].range(),
                    state: trace[5].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: vec![],
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: nodes[4].range(),
                    state: trace[6].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("010203"),
                            opcode: 3,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: merge_ranges(&[nodes[4].range(), nodes[5].range()], None),
                    state: trace[7].clone(),
                },
            ],
            unmatched_states: actual_trace.clone(),
        },
    );
}

/// libauth: `test.failing` (the expected trace uses the outdated program state
/// shape described at [`ExpectedState`] and the outdated error message
/// `Unlocking bytecode may contain only push operations.`).
#[test]
#[should_panic(expected = "assertion 2 (trace)")]
fn extract_evaluation_samples_error_in_initial_validation() {
    let result = generate_bytecode_successfully("nonPushingOpcodeUnlock");
    let null_hash_length = 32;
    let program = AuthenticationProgramCommon {
        input_index: 0,
        source_outputs: vec![Output {
            locking_bytecode: vec![Opcodes::OP_1],
            token: None,
            value_satoshis: 0,
        }],
        transaction: TransactionCommon {
            inputs: vec![Input {
                outpoint_index: 0,
                outpoint_transaction_hash: vec![0; null_hash_length],
                sequence_number: 0,
                unlocking_bytecode: result.bytecode.clone(),
            }],
            locktime: 0,
            outputs: vec![Output {
                locking_bytecode: vec![],
                token: None,
                value_satoshis: 0,
            }],
            version: 0,
        },
    };

    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace = vm().debug(&program, None);
    let extracted = extract_evaluation_samples(evaluation_range, None, &nodes, &trace);
    assert_debug_eq_labeled(
        "assertion 1 (nodes)",
        &nodes,
        &vec![
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("51"),
                errors: None,
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("76"),
                errors: None,
                range: Range {
                    end_column: 12,
                    end_line_number: 1,
                    start_column: 6,
                    start_line_number: 1,
                },
            }),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 2 (trace)",
        &trace,
        &vec![ExpectedState {
            alternate_stack: vec![],
            control_stack: vec![],
            error: Some("Unlocking bytecode may contain only push operations.".to_string()),
            instructions: vec![
                AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                    opcode: 81,
                }),
                AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                    opcode: 118,
                }),
            ],
            ip: 0,
            last_code_separator: -1,
            metrics: ExpectedMetrics {
                executed_instruction_count: 0,
                hash_digest_iterations: None,
                max_memory_usage: None,
                signature_check_count: 0,
            },
            operation_count: 0,
            program: program.clone(),
            signed_messages: vec![],
            stack: vec![],
        }
        .into_state()],
    );

    assert_debug_eq_labeled(
        "assertion 3 (extracted)",
        &extracted,
        &SampleExtractionResult {
            // `labeledStackItems` is absent from libauth's expectation.
            labeled_stack_items: vec![],
            samples: vec![EvaluationSample {
                evaluation_range,
                instruction: None,
                internal_states: vec![],
                iterations: None,
                range: Range {
                    end_column: 1,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                state: trace[0].clone(),
            }],
            unmatched_states: vec![],
        },
    );
}

/// libauth: `test.failing` (the expected nodes include program states in the
/// outdated shape described at [`ExpectedState`]).
#[test]
#[should_panic(expected = "assertion 1 (nodes)")]
fn extract_evaluation_samples_node_closes_an_open_sample_then_errors_before_the_nodes_last_instruction(
) {
    let result = generate_bytecode_successfully("error1");
    let program = create_authentication_program_evaluation_common(&result.bytecode);
    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace_with_unlocking_phase_and_final_state = vm().debug(&program, None);
    let trace = slice(&trace_with_unlocking_phase_and_final_state, 1, None);
    let extracted = extract_evaluation_samples(evaluation_range, None, &nodes, &trace);

    let internal_program = create_authentication_program_evaluation_common(&hex_to_bin("03ab6a00"));
    assert_debug_eq_labeled(
        "assertion 1 (nodes)",
        &nodes,
        &vec![
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("01"),
                errors: None,
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                bytecode: hex_to_bin("ab6a00"),
                errors: None,
                range: Range {
                    end_column: 30,
                    end_line_number: 1,
                    start_column: 6,
                    start_line_number: 1,
                },
                source: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin("03ab6a00"),
                    errors: None,
                    range: Range {
                        end_column: 29,
                        end_line_number: 1,
                        start_column: 8,
                        start_line_number: 1,
                    },
                    script: vec![ScriptReductionTraceChildNode::Push(
                        ScriptReductionTracePushNode {
                            bytecode: hex_to_bin("03ab6a00"),
                            errors: None,
                            push: Box::new(ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin("ab6a00"),
                                errors: None,
                                range: Range {
                                    end_column: 28,
                                    end_line_number: 1,
                                    start_column: 9,
                                    start_line_number: 1,
                                },
                                script: vec![
                                    ScriptReductionTraceChildNode::Bytecode(
                                        ScriptReductionTraceNode {
                                            bytecode: hex_to_bin("ab"),
                                            errors: None,
                                            range: Range {
                                                end_column: 13,
                                                end_line_number: 1,
                                                start_column: 9,
                                                start_line_number: 1,
                                            },
                                        },
                                    ),
                                    ScriptReductionTraceChildNode::Bytecode(
                                        ScriptReductionTraceNode {
                                            bytecode: hex_to_bin("6a"),
                                            errors: None,
                                            range: Range {
                                                end_column: 23,
                                                end_line_number: 1,
                                                start_column: 14,
                                                start_line_number: 1,
                                            },
                                        },
                                    ),
                                    ScriptReductionTraceChildNode::Bytecode(
                                        ScriptReductionTraceNode {
                                            bytecode: hex_to_bin("00"),
                                            errors: None,
                                            range: Range {
                                                end_column: 28,
                                                end_line_number: 1,
                                                start_column: 24,
                                                start_line_number: 1,
                                            },
                                        },
                                    ),
                                ],
                            }),
                            range: Range {
                                end_column: 29,
                                end_line_number: 1,
                                start_column: 8,
                                start_line_number: 1,
                            },
                        },
                    )],
                }),
                trace: vec![
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("ab6a00"),
                                opcode: 3,
                            },
                        )],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("ab6a00"),
                                opcode: 3,
                            },
                        )],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(3),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("ab6a00")],
                    }
                    .into_state(),
                    ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("ab6a00"),
                                opcode: 3,
                            },
                        )],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(3),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: internal_program.clone(),
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("ab6a00")],
                    }
                    .into_state(),
                ],
            }),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 2 (trace)",
        &trace_with_unlocking_phase_and_final_state,
        &vec![
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 1,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 1,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("ab")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: Some("Program called an OP_RETURN operation.".to_string()),
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("ab")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: Some("Program called an OP_RETURN operation.".to_string()),
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("ab"),
                        opcode: 1,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("ab")],
            }
            .into_state(),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 3 (extracted)",
        &extracted,
        &SampleExtractionResult {
            // `labeledStackItems` is absent from libauth's expectation.
            labeled_stack_items: vec![],
            samples: vec![
                EvaluationSample {
                    evaluation_range,
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 1,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    state: trace[0].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("ab"),
                            opcode: 1,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: merge_ranges(&[nodes[0].range(), nodes[1].range()], None),
                    state: trace[1].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Operation(
                        AuthenticationInstructionOperation {
                            opcode: Opcodes::OP_RETURN,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: nodes[1].range(),
                    state: trace[2].clone(),
                },
            ],
            unmatched_states: vec![],
        },
    );
}

/// libauth: `test.failing` (the expected trace uses the outdated program state
/// shape described at [`ExpectedState`]).
#[test]
#[should_panic(expected = "assertion 2 (trace)")]
fn extract_evaluation_samples_node_that_closes_an_open_sample_with_an_error() {
    let result = generate_bytecode_successfully("error2");
    let program = create_authentication_program_evaluation_common(&result.bytecode);
    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace_with_unlocking_phase_and_final_state = vm().debug(&program, None);
    let trace = slice(&trace_with_unlocking_phase_and_final_state, 1, None);
    let extracted = extract_evaluation_samples(evaluation_range, None, &nodes, &trace);
    assert_debug_eq_labeled(
        "assertion 1 (nodes)",
        &nodes,
        &vec![
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("004d5802"),
                errors: None,
                range: Range {
                    end_column: 11,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"),
                errors: None,
                range: Range {
                    end_column: 614,
                    end_line_number: 1,
                    start_column: 12,
                    start_line_number: 1,
                },
            }),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 2 (trace)",
        &trace_with_unlocking_phase_and_final_state,
        &vec![
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"),
                        opcode: 77,
                    }),
                ],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"),
                        opcode: 77,
                    }),
                ],
                ip: 1,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 1,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: Some("Program attempted to push a stack item that exceeded the maximum stack item length (520 bytes). Item length: 600 bytes.".to_string()),
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"),
                        opcode: 77,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: Some("Program attempted to push a stack item that exceeded the maximum stack item length (520 bytes). Item length: 600 bytes.".to_string()),
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"),
                        opcode: 77,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 3 (extracted)",
        &extracted,
        &SampleExtractionResult {
            // `labeledStackItems` is absent from libauth's expectation.
            labeled_stack_items: vec![],
            samples: vec![
                EvaluationSample {
                    evaluation_range,
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 1,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    state: trace[0].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: vec![],
                        opcode: 0,
                    })),
                    internal_states: vec![],
                    iterations: None,
                    range: nodes[0].range(),
                    state: trace[1].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"),
                        opcode: 77,
                    })),
                    internal_states: vec![],
                    iterations: None,
                    range: merge_ranges(&[nodes[0].range(), nodes[1].range()], None),
                    state: trace[2].clone(),
                },
            ],
            unmatched_states: vec![trace[3].clone()],
        },
    );
}

/// libauth: `test.failing` (the expected trace uses the outdated program state
/// shape described at [`ExpectedState`]).
#[test]
#[should_panic(expected = "assertion 2 (trace)")]
fn extract_evaluation_samples_error3_error_occurs_so_final_state_is_dropped() {
    let result = generate_bytecode_successfully("error3");
    let program = create_authentication_program_evaluation_common(&result.bytecode);
    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace_with_unlocking_phase_and_final_state = vm().debug(&program, None);
    let trace = slice(&trace_with_unlocking_phase_and_final_state, 1, Some(-1));
    let extracted = extract_evaluation_samples(evaluation_range, None, &nodes, &trace);
    assert_debug_eq_labeled(
        "assertion 1 (nodes)",
        &nodes,
        &vec![
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("6a"),
                errors: None,
                range: Range {
                    end_column: 15,
                    end_line_number: 1,
                    start_column: 6,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                range: Range {
                    end_column: 20,
                    end_line_number: 1,
                    start_column: 16,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                range: Range {
                    end_column: 25,
                    end_line_number: 1,
                    start_column: 21,
                    start_line_number: 1,
                },
            }),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 2 (trace)",
        &trace_with_unlocking_phase_and_final_state,
        &vec![
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 1,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 1,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: Some("Program called an OP_RETURN operation.".to_string()),
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: Some("Program called an OP_RETURN operation.".to_string()),
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                        opcode: 106,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 3 (extracted)",
        &extracted,
        &SampleExtractionResult {
            // `labeledStackItems` is absent from libauth's expectation.
            labeled_stack_items: vec![],
            samples: vec![
                EvaluationSample {
                    evaluation_range,
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 1,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    state: trace[0].clone(),
                },
                EvaluationSample {
                    evaluation_range,
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: vec![],
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: nodes[0].range(),
                    state: trace[1].clone(),
                },
            ],
            unmatched_states: vec![],
        },
    );
}

/// libauth: `test.failing` (the expected nodes predate the `comment` property
/// of comment nodes, and the expected trace uses the outdated program state
/// shape described at [`ExpectedState`]).
#[test]
#[should_panic(expected = "assertion 1 (nodes)")]
fn extract_evaluation_samples_supports_loops() {
    let result = generate_bytecode_successfully("loops");
    let program = create_authentication_program_evaluation_common(&result.bytecode);
    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace_with_unlocking_phase_and_final_state = vm_spec().debug(&program, None);
    let trace = slice(&trace_with_unlocking_phase_and_final_state, 1, Some(-1));
    let extracted = extract_evaluation_samples(evaluation_range, None, &nodes, &trace);
    assert_debug_eq_labeled(
        "assertion 1 (nodes)",
        &nodes,
        &vec![
            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                push: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin(""),
                    errors: None,
                    range: Range {
                        end_column: 3,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                    script: vec![ScriptReductionTraceChildNode::Bytecode(
                        ScriptReductionTraceNode {
                            bytecode: hex_to_bin(""),
                            errors: None,
                            range: Range {
                                end_column: 3,
                                end_line_number: 1,
                                start_column: 2,
                                start_line_number: 1,
                            },
                        },
                    )],
                }),
                range: Range {
                    end_column: 4,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                push: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin(""),
                    errors: None,
                    range: Range {
                        end_column: 7,
                        end_line_number: 1,
                        start_column: 6,
                        start_line_number: 1,
                    },
                    script: vec![ScriptReductionTraceChildNode::Bytecode(
                        ScriptReductionTraceNode {
                            bytecode: hex_to_bin(""),
                            errors: None,
                            range: Range {
                                end_column: 7,
                                end_line_number: 1,
                                start_column: 6,
                                start_line_number: 1,
                            },
                        },
                    )],
                }),
                range: Range {
                    end_column: 8,
                    end_line_number: 1,
                    start_column: 5,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("65"),
                errors: None,
                range: Range {
                    end_column: 9,
                    end_line_number: 2,
                    start_column: 1,
                    start_line_number: 2,
                },
            }),
            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                push: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin(""),
                    errors: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 3,
                        start_column: 4,
                        start_line_number: 3,
                    },
                    script: vec![ScriptReductionTraceChildNode::Bytecode(
                        ScriptReductionTraceNode {
                            bytecode: hex_to_bin(""),
                            errors: None,
                            range: Range {
                                end_column: 5,
                                end_line_number: 3,
                                start_column: 4,
                                start_line_number: 3,
                            },
                        },
                    )],
                }),
                range: Range {
                    end_column: 6,
                    end_line_number: 3,
                    start_column: 3,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("65"),
                errors: None,
                range: Range {
                    end_column: 15,
                    end_line_number: 3,
                    start_column: 7,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("8b"),
                errors: None,
                range: Range {
                    end_column: 23,
                    end_line_number: 3,
                    start_column: 16,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("76"),
                errors: None,
                range: Range {
                    end_column: 30,
                    end_line_number: 3,
                    start_column: 24,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                bytecode: hex_to_bin("52"),
                errors: None,
                push: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin("02"),
                    errors: None,
                    range: Range {
                        end_column: 33,
                        end_line_number: 3,
                        start_column: 32,
                        start_line_number: 3,
                    },
                    script: vec![ScriptReductionTraceChildNode::Bytecode(
                        ScriptReductionTraceNode {
                            bytecode: hex_to_bin("02"),
                            errors: None,
                            range: Range {
                                end_column: 33,
                                end_line_number: 3,
                                start_column: 32,
                                start_line_number: 3,
                            },
                        },
                    )],
                }),
                range: Range {
                    end_column: 34,
                    end_line_number: 3,
                    start_column: 31,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("87"),
                errors: None,
                range: Range {
                    end_column: 43,
                    end_line_number: 3,
                    start_column: 35,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("66"),
                errors: None,
                range: Range {
                    end_column: 52,
                    end_line_number: 3,
                    start_column: 44,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin(""),
                errors: None,
                range: Range {
                    end_column: 74,
                    end_line_number: 3,
                    start_column: 53,
                    start_line_number: 3,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("93"),
                errors: None,
                range: Range {
                    end_column: 9,
                    end_line_number: 4,
                    start_column: 3,
                    start_line_number: 4,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("7c"),
                errors: None,
                range: Range {
                    end_column: 10,
                    end_line_number: 5,
                    start_column: 3,
                    start_line_number: 5,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("8b"),
                errors: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 5,
                    start_column: 11,
                    start_line_number: 5,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("7c"),
                errors: None,
                range: Range {
                    end_column: 26,
                    end_line_number: 5,
                    start_column: 19,
                    start_line_number: 5,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("78"),
                errors: None,
                range: Range {
                    end_column: 10,
                    end_line_number: 6,
                    start_column: 3,
                    start_line_number: 6,
                },
            }),
            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                push: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin(""),
                    errors: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 7,
                        start_column: 4,
                        start_line_number: 7,
                    },
                    script: vec![ScriptReductionTraceChildNode::Bytecode(
                        ScriptReductionTraceNode {
                            bytecode: hex_to_bin(""),
                            errors: None,
                            range: Range {
                                end_column: 5,
                                end_line_number: 7,
                                start_column: 4,
                                start_line_number: 7,
                            },
                        },
                    )],
                }),
                range: Range {
                    end_column: 6,
                    end_line_number: 7,
                    start_column: 3,
                    start_line_number: 7,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("65"),
                errors: None,
                range: Range {
                    end_column: 15,
                    end_line_number: 7,
                    start_column: 7,
                    start_line_number: 7,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin(""),
                errors: None,
                range: Range {
                    end_column: 38,
                    end_line_number: 7,
                    start_column: 16,
                    start_line_number: 7,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("8b"),
                errors: None,
                range: Range {
                    end_column: 12,
                    end_line_number: 8,
                    start_column: 5,
                    start_line_number: 8,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("76"),
                errors: None,
                range: Range {
                    end_column: 11,
                    end_line_number: 9,
                    start_column: 5,
                    start_line_number: 9,
                },
            }),
            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                bytecode: hex_to_bin("53"),
                errors: None,
                push: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin("03"),
                    errors: None,
                    range: Range {
                        end_column: 14,
                        end_line_number: 9,
                        start_column: 13,
                        start_line_number: 9,
                    },
                    script: vec![ScriptReductionTraceChildNode::Bytecode(
                        ScriptReductionTraceNode {
                            bytecode: hex_to_bin("03"),
                            errors: None,
                            range: Range {
                                end_column: 14,
                                end_line_number: 9,
                                start_column: 13,
                                start_line_number: 9,
                            },
                        },
                    )],
                }),
                range: Range {
                    end_column: 15,
                    end_line_number: 9,
                    start_column: 12,
                    start_line_number: 9,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("87"),
                errors: None,
                range: Range {
                    end_column: 13,
                    end_line_number: 10,
                    start_column: 5,
                    start_line_number: 10,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("66"),
                errors: None,
                range: Range {
                    end_column: 11,
                    end_line_number: 11,
                    start_column: 3,
                    start_line_number: 11,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("87"),
                errors: None,
                range: Range {
                    end_column: 11,
                    end_line_number: 12,
                    start_column: 3,
                    start_line_number: 12,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("66"),
                errors: None,
                range: Range {
                    end_column: 9,
                    end_line_number: 13,
                    start_column: 1,
                    start_line_number: 13,
                },
            }),
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("77"),
                errors: None,
                range: Range {
                    end_column: 7,
                    end_line_number: 14,
                    start_column: 1,
                    start_line_number: 14,
                },
            }),
        ],
    );

    let instructions: Vec<AuthenticationInstruction> = vec![
        AuthenticationInstruction::Push(AuthenticationInstructionPush {
            data: hex_to_bin(""),
            opcode: 0,
        }),
        AuthenticationInstruction::Push(AuthenticationInstructionPush {
            data: hex_to_bin(""),
            opcode: 0,
        }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 101 }),
        AuthenticationInstruction::Push(AuthenticationInstructionPush {
            data: hex_to_bin(""),
            opcode: 0,
        }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 101 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 139 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 118 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 82 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 135 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 102 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 147 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 124 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 139 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 124 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 120 }),
        AuthenticationInstruction::Push(AuthenticationInstructionPush {
            data: hex_to_bin(""),
            opcode: 0,
        }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 101 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 139 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 118 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 83 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 135 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 102 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 135 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 102 }),
        AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: 119 }),
    ];

    assert_debug_eq_labeled(
        "assertion 2 (trace)",
        &trace_with_unlocking_phase_and_final_state,
        &vec![
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(0),
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(0),
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 1,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 1,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(0),
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(0),
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 3,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 3,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(0),
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 4,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 4,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(0),
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 5,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 5,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(0),
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 6,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 6,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(1),
                    signature_check_count: 0,
                },
                operation_count: 1,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 7,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(2),
                    signature_check_count: 0,
                },
                operation_count: 2,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 8,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 8,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 2,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 9,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 9,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 3,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 4,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 10,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 3,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 5,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 11,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 3,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 6,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 12,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 4,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 13,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 5,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 8,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 14,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 5,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 9,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 15,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 6,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin(""),
                    hex_to_bin(""),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 10,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 16,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 6,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 11,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 17,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 7,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 12,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 18,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 8,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 13,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 19,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 9,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 14,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 20,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 10,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 15,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 21,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 11,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 22,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 11,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 23,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(3),
                    signature_check_count: 0,
                },
                operation_count: 11,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 24,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(4),
                    signature_check_count: 0,
                },
                operation_count: 12,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 25,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(5),
                    signature_check_count: 0,
                },
                operation_count: 13,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 26,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 13,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 27,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 14,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 28,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 14,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 29,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 14,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 30,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 15,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 31,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 16,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 32,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 16,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 33,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 17,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 34,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 17,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 35,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 17,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 36,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 18,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 37,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 19,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 38,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 19,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 39,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 20,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 22,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 40,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 20,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 23,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 41,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 21,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 42,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 21,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 3,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 43,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 21,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 4,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 44,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 21,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 5,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 45,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 21,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 6,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 46,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 22,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 47,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 23,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 8,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 48,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 23,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 9,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 49,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 24,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 4,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 50,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 24,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 5,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 51,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 24,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 6,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 52,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 25,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 53,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 26,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 8,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 54,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 26,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 9,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 55,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 27,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 10,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 56,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 27,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("02"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 11,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 57,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 28,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("01"), hex_to_bin("04")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 12,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 58,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 29,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("04"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 13,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 59,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 30,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("04"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 14,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 60,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 31,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 15,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 61,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 32,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 62,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 32,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 63,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 32,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 64,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 33,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 65,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 34,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 66,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 34,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 67,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 35,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 68,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 35,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 69,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 35,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 70,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 36,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 71,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 37,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 72,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 37,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 73,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 38,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 74,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 38,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 75,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 38,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 76,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 39,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 77,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 40,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 78,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 40,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 79,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 41,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 22,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 80,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 41,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 23,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 81,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 42,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 82,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 42,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 3,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 83,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 42,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 4,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 84,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 42,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 5,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 85,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 42,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 6,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 86,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 43,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 87,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 44,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 8,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 88,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 44,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 9,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 89,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 45,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 4,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 90,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 45,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 5,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 91,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 45,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 6,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 92,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 46,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 7,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 93,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 47,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 8,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 94,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 47,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(4),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 9,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 95,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 48,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("02"),
                    hex_to_bin("04"),
                    hex_to_bin("02"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 10,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 96,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 48,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("04"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 11,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 97,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 49,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("02"), hex_to_bin("06")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 12,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 98,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 50,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("06"), hex_to_bin("02")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 13,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 99,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 51,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("06"), hex_to_bin("03")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 14,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 100,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 52,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("03"), hex_to_bin("06")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 15,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 101,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 53,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("03"), hex_to_bin("06"), hex_to_bin("03")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 102,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 53,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 103,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 53,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 104,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 54,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 105,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 55,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 106,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 55,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                    hex_to_bin("01"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 107,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 56,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 108,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 56,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 109,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 56,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 110,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 57,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 111,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 58,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 112,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 58,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("02"),
                    hex_to_bin("02"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 113,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 59,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("02"),
                    hex_to_bin(""),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 16,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 114,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 59,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 17,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 115,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 59,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("02"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 18,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 116,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 60,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 19,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 117,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 61,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 20,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 118,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 61,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![
                    AuthenticationProgramStateControlStackItem::Number(2),
                    AuthenticationProgramStateControlStackItem::Number(16),
                ],
                error: None,
                instructions: instructions.clone(),
                ip: 21,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 119,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 62,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                    hex_to_bin("01"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 22,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 120,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 62,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![
                    hex_to_bin("03"),
                    hex_to_bin("06"),
                    hex_to_bin("03"),
                    hex_to_bin("03"),
                ],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![AuthenticationProgramStateControlStackItem::Number(2)],
                error: None,
                instructions: instructions.clone(),
                ip: 23,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 121,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 63,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("03"), hex_to_bin("06"), hex_to_bin("01")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 24,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 122,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 63,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("03"), hex_to_bin("06")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 25,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 123,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 64,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("06")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: instructions.clone(),
                ip: 25,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 123,
                    hash_digest_iterations: Some(0),
                    max_memory_usage: Some(6),
                    signature_check_count: 0,
                },
                operation_count: 64,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("06")],
            }
            .into_state(),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 3 (extracted)",
        &extracted,
        &SampleExtractionResult {
            // `labeledStackItems` is absent from libauth's expectation.
            labeled_stack_items: vec![],
            samples: vec![],
            unmatched_states: vec![],
        },
    );
}

/// libauth: `test.failing` (the expected nodes include program states in the
/// outdated shape described at [`ExpectedState`]).
#[test]
#[should_panic(expected = "assertion 1 (nodes)")]
fn extract_evaluation_samples_recursive_complex_deeply_nested_script_with_irregular_spacing() {
    let result = generate_bytecode_successfully("nested");
    let program = create_authentication_program_evaluation_common(&result.bytecode);
    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace_with_unlocking_phase_and_final_state = vm().debug(&program, None);
    let trace = slice(&trace_with_unlocking_phase_and_final_state, 1, None);

    let internal_program1 = create_authentication_program_evaluation_common(&hex_to_bin("0151"));
    let internal_program2 = create_authentication_program_evaluation_common(&hex_to_bin("515293"));
    let internal_program3 =
        create_authentication_program_evaluation_common(&hex_to_bin("03616263"));
    let internal_program4 =
        create_authentication_program_evaluation_common(&hex_to_bin("0000036162637e7e"));
    let internal_program5 = create_authentication_program_evaluation_common(&hex_to_bin("017e"));
    let internal_program6 = create_authentication_program_evaluation_common(&hex_to_bin("00007e"));

    let sample_result =
        extract_evaluation_samples_recursive(evaluation_range, &nodes, &trace, None);
    assert_debug_eq_labeled(
        "assertion 1 (nodes)",
        &nodes,
        &vec![
            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                bytecode: hex_to_bin("00"),
                errors: None,
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            }),
            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                bytecode: hex_to_bin("03616263"),
                errors: None,
                push: Box::new(ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin("616263"),
                    errors: None,
                    range: Range {
                        end_column: 15,
                        end_line_number: 20,
                        start_column: 3,
                        start_line_number: 4,
                    },
                    script: vec![
                        ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                            bytecode: hex_to_bin("616263"),
                            errors: None,
                            range: Range {
                                end_column: 4,
                                end_line_number: 16,
                                start_column: 3,
                                start_line_number: 4,
                            },
                            source: Box::new(ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin("0000036162637e7e"),
                                errors: None,
                                range: Range {
                                    end_column: 9,
                                    end_line_number: 15,
                                    start_column: 3,
                                    start_line_number: 5,
                                },
                                script: vec![
                                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                        bytecode: hex_to_bin("0000"),
                                        errors: None,
                                        range: Range {
                                            end_column: 9,
                                            end_line_number: 5,
                                            start_column: 3,
                                            start_line_number: 5,
                                        },
                                    }),
                                    ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                                        bytecode: hex_to_bin("03"),
                                        errors: None,
                                        range: Range {
                                            end_column: 6,
                                            end_line_number: 11,
                                            start_column: 5,
                                            start_line_number: 6,
                                        },
                                        source: Box::new(ScriptReductionTraceScriptNode {
                                            bytecode: hex_to_bin("515293"),
                                            errors: None,
                                            range: Range {
                                                end_column: 13,
                                                end_line_number: 9,
                                                start_column: 7,
                                                start_line_number: 6,
                                            },
                                            script: vec![
                                                ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                                                    bytecode: hex_to_bin("51"),
                                                    errors: None,
                                                    range: Range {
                                                        end_column: 16,
                                                        end_line_number: 6,
                                                        start_column: 7,
                                                        start_line_number: 6,
                                                    },
                                                    source: Box::new(ScriptReductionTraceScriptNode {
                                                        bytecode: hex_to_bin("0151"),
                                                        errors: None,
                                                        range: Range {
                                                            end_column: 15,
                                                            end_line_number: 6,
                                                            start_column: 9,
                                                            start_line_number: 6,
                                                        },
                                                        script: vec![
                                                            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                                                                bytecode: hex_to_bin("0151"),
                                                                errors: None,
                                                                push: Box::new(ScriptReductionTraceScriptNode {
                                                                    bytecode: hex_to_bin("51"),
                                                                    errors: None,
                                                                    range: Range {
                                                                        end_column: 14,
                                                                        end_line_number: 6,
                                                                        start_column: 10,
                                                                        start_line_number: 6,
                                                                    },
                                                                    script: vec![
                                                                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                                            bytecode: hex_to_bin("51"),
                                                                            errors: None,
                                                                            range: Range {
                                                                                end_column: 14,
                                                                                end_line_number: 6,
                                                                                start_column: 10,
                                                                                start_line_number: 6,
                                                                            },
                                                                        }),
                                                                    ],
                                                                }),
                                                                range: Range {
                                                                    end_column: 15,
                                                                    end_line_number: 6,
                                                                    start_column: 9,
                                                                    start_line_number: 6,
                                                                },
                                                            }),
                                                        ],
                                                    }),
                                                    trace: vec![
                                                        ExpectedState {
                                                            alternate_stack: vec![],
                                                            control_stack: vec![],
                                                            error: None,
                                                            instructions: vec![],
                                                            ip: 0,
                                                            last_code_separator: -1,
                                                            metrics: ExpectedMetrics {
                                                                executed_instruction_count: 0,
                                                                hash_digest_iterations: Some(0),
                                                                max_memory_usage: Some(0),
                                                                signature_check_count: 0,
                                                            },
                                                            operation_count: 0,
                                                            program: internal_program1.clone(),
                                                            signed_messages: vec![],
                                                            stack: vec![],
                                                        }
                                                        .into_state(),
                                                        ExpectedState {
                                                            alternate_stack: vec![],
                                                            control_stack: vec![],
                                                            error: None,
                                                            instructions: vec![
                                                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                                    data: hex_to_bin("51"),
                                                                    opcode: 1,
                                                                }),
                                                            ],
                                                            ip: 0,
                                                            last_code_separator: -1,
                                                            metrics: ExpectedMetrics {
                                                                executed_instruction_count: 0,
                                                                hash_digest_iterations: Some(0),
                                                                max_memory_usage: Some(0),
                                                                signature_check_count: 0,
                                                            },
                                                            operation_count: 0,
                                                            program: internal_program1.clone(),
                                                            signed_messages: vec![],
                                                            stack: vec![],
                                                        }
                                                        .into_state(),
                                                        ExpectedState {
                                                            alternate_stack: vec![],
                                                            control_stack: vec![],
                                                            error: None,
                                                            instructions: vec![
                                                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                                    data: hex_to_bin("51"),
                                                                    opcode: 1,
                                                                }),
                                                            ],
                                                            ip: 1,
                                                            last_code_separator: -1,
                                                            metrics: ExpectedMetrics {
                                                                executed_instruction_count: 1,
                                                                hash_digest_iterations: Some(0),
                                                                max_memory_usage: Some(1),
                                                                signature_check_count: 0,
                                                            },
                                                            operation_count: 0,
                                                            program: internal_program1.clone(),
                                                            signed_messages: vec![],
                                                            stack: vec![hex_to_bin("51")],
                                                        }
                                                        .into_state(),
                                                        ExpectedState {
                                                            alternate_stack: vec![],
                                                            control_stack: vec![],
                                                            error: None,
                                                            instructions: vec![
                                                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                                    data: hex_to_bin("51"),
                                                                    opcode: 1,
                                                                }),
                                                            ],
                                                            ip: 1,
                                                            last_code_separator: -1,
                                                            metrics: ExpectedMetrics {
                                                                executed_instruction_count: 1,
                                                                hash_digest_iterations: Some(0),
                                                                max_memory_usage: Some(1),
                                                                signature_check_count: 0,
                                                            },
                                                            operation_count: 0,
                                                            program: internal_program1.clone(),
                                                            signed_messages: vec![],
                                                            stack: vec![hex_to_bin("51")],
                                                        }
                                                        .into_state(),
                                                    ],
                                                }),
                                                ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                    bytecode: hex_to_bin("52"),
                                                    errors: None,
                                                    range: Range {
                                                        end_column: 11,
                                                        end_line_number: 8,
                                                        start_column: 7,
                                                        start_line_number: 8,
                                                    },
                                                }),
                                                ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                    bytecode: hex_to_bin("93"),
                                                    errors: None,
                                                    range: Range {
                                                        end_column: 13,
                                                        end_line_number: 9,
                                                        start_column: 7,
                                                        start_line_number: 9,
                                                    },
                                                }),
                                            ],
                                        }),
                                        trace: vec![
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![],
                                                ip: 0,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 0,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(0),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program2.clone(),
                                                signed_messages: vec![],
                                                stack: vec![],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 81,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 82,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 147,
                                                    }),
                                                ],
                                                ip: 0,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 0,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(0),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program2.clone(),
                                                signed_messages: vec![],
                                                stack: vec![],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 81,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 82,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 147,
                                                    }),
                                                ],
                                                ip: 1,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 1,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(1),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program2.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("01")],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 81,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 82,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 147,
                                                    }),
                                                ],
                                                ip: 2,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 2,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(2),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program2.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("01"), hex_to_bin("02")],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 81,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 82,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 147,
                                                    }),
                                                ],
                                                ip: 3,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 3,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(2),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 1,
                                                program: internal_program2.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("03")],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 81,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 82,
                                                    }),
                                                    AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                        opcode: 147,
                                                    }),
                                                ],
                                                ip: 3,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 3,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(2),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 1,
                                                program: internal_program2.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("03")],
                                            }
                                            .into_state(),
                                        ],
                                    }),
                                    ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                                        bytecode: hex_to_bin("616263"),
                                        errors: None,
                                        range: Range {
                                            end_column: 6,
                                            end_line_number: 13,
                                            start_column: 5,
                                            start_line_number: 12,
                                        },
                                        source: Box::new(ScriptReductionTraceScriptNode {
                                            bytecode: hex_to_bin("03616263"),
                                            errors: None,
                                            range: Range {
                                                end_column: 15,
                                                end_line_number: 12,
                                                start_column: 8,
                                                start_line_number: 12,
                                            },
                                            script: vec![
                                                ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                                                    bytecode: hex_to_bin("03616263"),
                                                    errors: None,
                                                    push: Box::new(ScriptReductionTraceScriptNode {
                                                        bytecode: hex_to_bin("616263"),
                                                        errors: None,
                                                        range: Range {
                                                            end_column: 14,
                                                            end_line_number: 12,
                                                            start_column: 9,
                                                            start_line_number: 12,
                                                        },
                                                        script: vec![
                                                            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                                bytecode: hex_to_bin("616263"),
                                                                errors: None,
                                                                range: Range {
                                                                    end_column: 14,
                                                                    end_line_number: 12,
                                                                    start_column: 9,
                                                                    start_line_number: 12,
                                                                },
                                                            }),
                                                        ],
                                                    }),
                                                    range: Range {
                                                        end_column: 15,
                                                        end_line_number: 12,
                                                        start_column: 8,
                                                        start_line_number: 12,
                                                    },
                                                }),
                                            ],
                                        }),
                                        trace: vec![
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![],
                                                ip: 0,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 0,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(0),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program3.clone(),
                                                signed_messages: vec![],
                                                stack: vec![],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                        data: hex_to_bin("616263"),
                                                        opcode: 3,
                                                    }),
                                                ],
                                                ip: 0,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 0,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(0),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program3.clone(),
                                                signed_messages: vec![],
                                                stack: vec![],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                        data: hex_to_bin("616263"),
                                                        opcode: 3,
                                                    }),
                                                ],
                                                ip: 1,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 1,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(3),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program3.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("616263")],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                        data: hex_to_bin("616263"),
                                                        opcode: 3,
                                                    }),
                                                ],
                                                ip: 1,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 1,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(3),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program3.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("616263")],
                                            }
                                            .into_state(),
                                        ],
                                    }),
                                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                        bytecode: hex_to_bin("7e"),
                                        errors: None,
                                        range: Range {
                                            end_column: 9,
                                            end_line_number: 14,
                                            start_column: 3,
                                            start_line_number: 14,
                                        },
                                    }),
                                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                        bytecode: hex_to_bin("7e"),
                                        errors: None,
                                        range: Range {
                                            end_column: 9,
                                            end_line_number: 15,
                                            start_column: 3,
                                            start_line_number: 15,
                                        },
                                    }),
                                ],
                            }),
                            trace: vec![
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![],
                                    ip: 0,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 0,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin("616263"),
                                            opcode: 3,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 0,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 0,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin("616263"),
                                            opcode: 3,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 1,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 1,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin("")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin("616263"),
                                            opcode: 3,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 2,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 2,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin(""), hex_to_bin("")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin("616263"),
                                            opcode: 3,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 3,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 3,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(3),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("616263")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin("616263"),
                                            opcode: 3,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 4,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 4,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(3),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 1,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin(""), hex_to_bin("616263")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin("616263"),
                                            opcode: 3,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 5,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 5,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(3),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 2,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin("616263")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin("616263"),
                                            opcode: 3,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 5,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 5,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(3),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 2,
                                    program: internal_program4.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin("616263")],
                                }
                                .into_state(),
                            ],
                        }),
                        ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                            bytecode: hex_to_bin(""),
                            errors: None,
                            range: Range {
                                end_column: 15,
                                end_line_number: 20,
                                start_column: 3,
                                start_line_number: 17,
                            },
                            source: Box::new(ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin("00007e"),
                                errors: None,
                                range: Range {
                                    end_column: 14,
                                    end_line_number: 20,
                                    start_column: 5,
                                    start_line_number: 18,
                                },
                                script: vec![
                                    ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                                        bytecode: hex_to_bin("00"),
                                        errors: None,
                                        push: Box::new(ScriptReductionTraceScriptNode {
                                            bytecode: hex_to_bin(""),
                                            errors: None,
                                            range: Range {
                                                end_column: 7,
                                                end_line_number: 18,
                                                start_column: 6,
                                                start_line_number: 18,
                                            },
                                            script: vec![
                                                ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                    bytecode: hex_to_bin(""),
                                                    errors: None,
                                                    range: Range {
                                                        end_column: 7,
                                                        end_line_number: 18,
                                                        start_column: 6,
                                                        start_line_number: 18,
                                                    },
                                                }),
                                            ],
                                        }),
                                        range: Range {
                                            end_column: 8,
                                            end_line_number: 18,
                                            start_column: 5,
                                            start_line_number: 18,
                                        },
                                    }),
                                    ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                                        bytecode: hex_to_bin("00"),
                                        errors: None,
                                        push: Box::new(ScriptReductionTraceScriptNode {
                                            bytecode: hex_to_bin(""),
                                            errors: None,
                                            range: Range {
                                                end_column: 7,
                                                end_line_number: 19,
                                                start_column: 6,
                                                start_line_number: 19,
                                            },
                                            script: vec![
                                                ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                    bytecode: hex_to_bin(""),
                                                    errors: None,
                                                    range: Range {
                                                        end_column: 7,
                                                        end_line_number: 19,
                                                        start_column: 6,
                                                        start_line_number: 19,
                                                    },
                                                }),
                                            ],
                                        }),
                                        range: Range {
                                            end_column: 8,
                                            end_line_number: 19,
                                            start_column: 5,
                                            start_line_number: 19,
                                        },
                                    }),
                                    ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                                        bytecode: hex_to_bin("7e"),
                                        errors: None,
                                        range: Range {
                                            end_column: 14,
                                            end_line_number: 20,
                                            start_column: 3,
                                            start_line_number: 20,
                                        },
                                        source: Box::new(ScriptReductionTraceScriptNode {
                                            bytecode: hex_to_bin("017e"),
                                            errors: None,
                                            range: Range {
                                                end_column: 13,
                                                end_line_number: 20,
                                                start_column: 5,
                                                start_line_number: 20,
                                            },
                                            script: vec![
                                                ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                                                    bytecode: hex_to_bin("017e"),
                                                    errors: None,
                                                    push: Box::new(ScriptReductionTraceScriptNode {
                                                        bytecode: hex_to_bin("7e"),
                                                        errors: None,
                                                        range: Range {
                                                            end_column: 12,
                                                            end_line_number: 20,
                                                            start_column: 6,
                                                            start_line_number: 20,
                                                        },
                                                        script: vec![
                                                            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                                bytecode: hex_to_bin("7e"),
                                                                errors: None,
                                                                range: Range {
                                                                    end_column: 12,
                                                                    end_line_number: 20,
                                                                    start_column: 6,
                                                                    start_line_number: 20,
                                                                },
                                                            }),
                                                        ],
                                                    }),
                                                    range: Range {
                                                        end_column: 13,
                                                        end_line_number: 20,
                                                        start_column: 5,
                                                        start_line_number: 20,
                                                    },
                                                }),
                                            ],
                                        }),
                                        trace: vec![
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![],
                                                ip: 0,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 0,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(0),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program5.clone(),
                                                signed_messages: vec![],
                                                stack: vec![],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                        data: hex_to_bin("7e"),
                                                        opcode: 1,
                                                    }),
                                                ],
                                                ip: 0,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 0,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(0),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program5.clone(),
                                                signed_messages: vec![],
                                                stack: vec![],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                        data: hex_to_bin("7e"),
                                                        opcode: 1,
                                                    }),
                                                ],
                                                ip: 1,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 1,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(1),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program5.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("7e")],
                                            }
                                            .into_state(),
                                            ExpectedState {
                                                alternate_stack: vec![],
                                                control_stack: vec![],
                                                error: None,
                                                instructions: vec![
                                                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                        data: hex_to_bin("7e"),
                                                        opcode: 1,
                                                    }),
                                                ],
                                                ip: 1,
                                                last_code_separator: -1,
                                                metrics: ExpectedMetrics {
                                                    executed_instruction_count: 1,
                                                    hash_digest_iterations: Some(0),
                                                    max_memory_usage: Some(1),
                                                    signature_check_count: 0,
                                                },
                                                operation_count: 0,
                                                program: internal_program5.clone(),
                                                signed_messages: vec![],
                                                stack: vec![hex_to_bin("7e")],
                                            }
                                            .into_state(),
                                        ],
                                    }),
                                ],
                            }),
                            trace: vec![
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![],
                                    ip: 0,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 0,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program6.clone(),
                                    signed_messages: vec![],
                                    stack: vec![],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 0,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 0,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program6.clone(),
                                    signed_messages: vec![],
                                    stack: vec![],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 1,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 1,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program6.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin("")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 2,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 2,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 0,
                                    program: internal_program6.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin(""), hex_to_bin("")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 3,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 3,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 1,
                                    program: internal_program6.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin("")],
                                }
                                .into_state(),
                                ExpectedState {
                                    alternate_stack: vec![],
                                    control_stack: vec![],
                                    error: None,
                                    instructions: vec![
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                            data: hex_to_bin(""),
                                            opcode: 0,
                                        }),
                                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                            opcode: 126,
                                        }),
                                    ],
                                    ip: 3,
                                    last_code_separator: -1,
                                    metrics: ExpectedMetrics {
                                        executed_instruction_count: 3,
                                        hash_digest_iterations: Some(0),
                                        max_memory_usage: Some(0),
                                        signature_check_count: 0,
                                    },
                                    operation_count: 1,
                                    program: internal_program6.clone(),
                                    signed_messages: vec![],
                                    stack: vec![hex_to_bin("")],
                                }
                                .into_state(),
                            ],
                        }),
                    ],
                }),
                range: Range {
                    end_column: 2,
                    end_line_number: 21,
                    start_column: 1,
                    start_line_number: 3,
                },
            }),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 2 (trace)",
        &trace_with_unlocking_phase_and_final_state,
        &vec![
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("616263"),
                        opcode: 3,
                    }),
                ],
                ip: 0,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 0,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("616263"),
                        opcode: 3,
                    }),
                ],
                ip: 1,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 1,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin("")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("616263"),
                        opcode: 3,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("616263")],
            }
            .into_state(),
            ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("616263"),
                        opcode: 3,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: program.clone(),
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("616263")],
            }
            .into_state(),
        ],
    );

    assert_debug_eq_labeled(
        "assertion 3 (sampleResult)",
        &sample_result,
        &SampleExtractionResult {
            // `labeledStackItems` is absent from libauth's expectation.
            labeled_stack_items: vec![],
            samples: vec![
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 2,
                        end_line_number: 21,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 1,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                        ],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: None,
                            max_memory_usage: None,
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0003616263"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 2,
                        end_line_number: 21,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin(""),
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                        ],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: None,
                            max_memory_usage: None,
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0003616263"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 3,
                        end_line_number: 16,
                        start_column: 5,
                        start_line_number: 4,
                    },
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 4,
                        start_column: 5,
                        start_line_number: 4,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0000036162637e7e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 3,
                        end_line_number: 16,
                        start_column: 5,
                        start_line_number: 4,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin(""),
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![EvaluationInternalState {
                        instruction: AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            },
                        ),
                        state: ExpectedState {
                            alternate_stack: vec![],
                            control_stack: vec![],
                            error: None,
                            instructions: vec![
                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                    data: hex_to_bin(""),
                                    opcode: 0,
                                }),
                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                    data: hex_to_bin(""),
                                    opcode: 0,
                                }),
                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                    data: hex_to_bin("616263"),
                                    opcode: 3,
                                }),
                                AuthenticationInstruction::Operation(
                                    AuthenticationInstructionOperation { opcode: 126 },
                                ),
                                AuthenticationInstruction::Operation(
                                    AuthenticationInstructionOperation { opcode: 126 },
                                ),
                            ],
                            ip: 1,
                            last_code_separator: -1,
                            metrics: ExpectedMetrics {
                                executed_instruction_count: 1,
                                hash_digest_iterations: Some(0),
                                max_memory_usage: Some(0),
                                signature_check_count: 0,
                            },
                            operation_count: 0,
                            program: AuthenticationProgramCommon {
                                input_index: 0,
                                source_outputs: vec![Output {
                                    locking_bytecode: hex_to_bin("0000036162637e7e"),
                                    token: None,
                                    value_satoshis: 0,
                                }],
                                transaction: program.transaction.clone(),
                            },
                            signed_messages: vec![],
                            stack: vec![hex_to_bin("")],
                        }
                        .into_state(),
                    }],
                    iterations: None,
                    range: Range {
                        end_column: 9,
                        end_line_number: 5,
                        start_column: 3,
                        start_line_number: 5,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 2,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 2,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0000036162637e7e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin(""), hex_to_bin("")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 5,
                        end_line_number: 11,
                        start_column: 7,
                        start_line_number: 6,
                    },
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 7,
                        end_line_number: 6,
                        start_column: 7,
                        start_line_number: 6,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 81 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 82 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 147 },
                            ),
                        ],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("515293"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 15,
                        end_line_number: 6,
                        start_column: 9,
                        start_line_number: 6,
                    },
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 9,
                        end_line_number: 6,
                        start_column: 9,
                        start_line_number: 6,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("51"),
                                opcode: 1,
                            },
                        )],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0151"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 15,
                        end_line_number: 6,
                        start_column: 9,
                        start_line_number: 6,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("51"),
                            opcode: 1,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 15,
                        end_line_number: 6,
                        start_column: 9,
                        start_line_number: 6,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("51"),
                                opcode: 1,
                            },
                        )],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(1),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0151"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("51")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 5,
                        end_line_number: 11,
                        start_column: 7,
                        start_line_number: 6,
                    },
                    instruction: Some(AuthenticationInstruction::Operation(
                        AuthenticationInstructionOperation { opcode: 81 },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 16,
                        end_line_number: 6,
                        start_column: 7,
                        start_line_number: 6,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 81 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 82 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 147 },
                            ),
                        ],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(1),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("515293"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("01")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 5,
                        end_line_number: 11,
                        start_column: 7,
                        start_line_number: 6,
                    },
                    instruction: Some(AuthenticationInstruction::Operation(
                        AuthenticationInstructionOperation { opcode: 82 },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 11,
                        end_line_number: 8,
                        start_column: 7,
                        start_line_number: 8,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 81 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 82 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 147 },
                            ),
                        ],
                        ip: 2,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 2,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(2),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("515293"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("01"), hex_to_bin("02")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 5,
                        end_line_number: 11,
                        start_column: 7,
                        start_line_number: 6,
                    },
                    instruction: Some(AuthenticationInstruction::Operation(
                        AuthenticationInstructionOperation { opcode: 147 },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 13,
                        end_line_number: 9,
                        start_column: 7,
                        start_line_number: 9,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 81 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 82 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 147 },
                            ),
                        ],
                        ip: 3,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 3,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(2),
                            signature_check_count: 0,
                        },
                        operation_count: 1,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("515293"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("03")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 5,
                        end_line_number: 13,
                        start_column: 7,
                        start_line_number: 12,
                    },
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 7,
                        end_line_number: 12,
                        start_column: 7,
                        start_line_number: 12,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            },
                        )],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("03616263"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 5,
                        end_line_number: 13,
                        start_column: 7,
                        start_line_number: 12,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("616263"),
                            opcode: 3,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 15,
                        end_line_number: 12,
                        start_column: 8,
                        start_line_number: 12,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            },
                        )],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(3),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("03616263"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("616263")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 3,
                        end_line_number: 16,
                        start_column: 5,
                        start_line_number: 4,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("616263"),
                            opcode: 3,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 6,
                        end_line_number: 13,
                        start_column: 5,
                        start_line_number: 6,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 3,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 3,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(3),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0000036162637e7e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin(""), hex_to_bin(""), hex_to_bin("616263")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 3,
                        end_line_number: 16,
                        start_column: 5,
                        start_line_number: 4,
                    },
                    instruction: Some(AuthenticationInstruction::Operation(
                        AuthenticationInstructionOperation { opcode: 126 },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 9,
                        end_line_number: 14,
                        start_column: 3,
                        start_line_number: 14,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 4,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 4,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(3),
                            signature_check_count: 0,
                        },
                        operation_count: 1,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0000036162637e7e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin(""), hex_to_bin("616263")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 3,
                        end_line_number: 16,
                        start_column: 5,
                        start_line_number: 4,
                    },
                    instruction: Some(AuthenticationInstruction::Operation(
                        AuthenticationInstructionOperation { opcode: 126 },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 9,
                        end_line_number: 15,
                        start_column: 3,
                        start_line_number: 15,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 5,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 5,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(3),
                            signature_check_count: 0,
                        },
                        operation_count: 2,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0000036162637e7e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("616263")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 14,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 17,
                    },
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 17,
                        start_column: 5,
                        start_line_number: 17,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("00007e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 14,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 17,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin(""),
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 8,
                        end_line_number: 18,
                        start_column: 5,
                        start_line_number: 18,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("00007e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 14,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 17,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin(""),
                            opcode: 0,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 8,
                        end_line_number: 19,
                        start_column: 5,
                        start_line_number: 19,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 2,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 2,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("00007e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin(""), hex_to_bin("")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 13,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 20,
                    },
                    instruction: None,
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 5,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 20,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("7e"),
                                opcode: 1,
                            },
                        )],
                        ip: 0,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 0,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("017e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 13,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 20,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("7e"),
                            opcode: 1,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 13,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 20,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![AuthenticationInstruction::Push(
                            AuthenticationInstructionPush {
                                data: hex_to_bin("7e"),
                                opcode: 1,
                            },
                        )],
                        ip: 1,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 1,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(1),
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("017e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("7e")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 14,
                        end_line_number: 20,
                        start_column: 5,
                        start_line_number: 17,
                    },
                    instruction: Some(AuthenticationInstruction::Operation(
                        AuthenticationInstructionOperation { opcode: 126 },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 14,
                        end_line_number: 20,
                        start_column: 3,
                        start_line_number: 20,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Operation(
                                AuthenticationInstructionOperation { opcode: 126 },
                            ),
                        ],
                        ip: 3,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 3,
                            hash_digest_iterations: Some(0),
                            max_memory_usage: Some(0),
                            signature_check_count: 0,
                        },
                        operation_count: 1,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("00007e"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin("")],
                    }
                    .into_state(),
                },
                EvaluationSample {
                    evaluation_range: Range {
                        end_column: 2,
                        end_line_number: 21,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    instruction: Some(AuthenticationInstruction::Push(
                        AuthenticationInstructionPush {
                            data: hex_to_bin("616263"),
                            opcode: 3,
                        },
                    )),
                    internal_states: vec![],
                    iterations: None,
                    range: Range {
                        end_column: 2,
                        end_line_number: 21,
                        start_column: 1,
                        start_line_number: 3,
                    },
                    state: ExpectedState {
                        alternate_stack: vec![],
                        control_stack: vec![],
                        error: None,
                        instructions: vec![
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin(""),
                                opcode: 0,
                            }),
                            AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                data: hex_to_bin("616263"),
                                opcode: 3,
                            }),
                        ],
                        ip: 2,
                        last_code_separator: -1,
                        metrics: ExpectedMetrics {
                            executed_instruction_count: 2,
                            hash_digest_iterations: None,
                            max_memory_usage: None,
                            signature_check_count: 0,
                        },
                        operation_count: 0,
                        program: AuthenticationProgramCommon {
                            input_index: 0,
                            source_outputs: vec![Output {
                                locking_bytecode: hex_to_bin("0003616263"),
                                token: None,
                                value_satoshis: 0,
                            }],
                            transaction: program.transaction.clone(),
                        },
                        signed_messages: vec![],
                        stack: vec![hex_to_bin(""), hex_to_bin("616263")],
                    }
                    .into_state(),
                },
            ],
            unmatched_states: vec![ExpectedState {
                alternate_stack: vec![],
                control_stack: vec![],
                error: None,
                instructions: vec![
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin(""),
                        opcode: 0,
                    }),
                    AuthenticationInstruction::Push(AuthenticationInstructionPush {
                        data: hex_to_bin("616263"),
                        opcode: 3,
                    }),
                ],
                ip: 2,
                last_code_separator: -1,
                metrics: ExpectedMetrics {
                    executed_instruction_count: 2,
                    hash_digest_iterations: None,
                    max_memory_usage: None,
                    signature_check_count: 0,
                },
                operation_count: 0,
                program: AuthenticationProgramCommon {
                    input_index: 0,
                    source_outputs: vec![Output {
                        locking_bytecode: hex_to_bin("0003616263"),
                        token: None,
                        value_satoshis: 0,
                    }],
                    transaction: program.transaction.clone(),
                },
                signed_messages: vec![],
                stack: vec![hex_to_bin(""), hex_to_bin("616263")],
            }
            .into_state()],
        },
    );
}

/// libauth's `extractUnexecutedRangesMacro` (titled
/// `extractUnexecutedRangesMacro: ${scriptId}`).
#[track_caller]
fn extract_unexecuted_ranges_macro(
    script_id: &str,
    ranges: Vec<Range>,
    specify_start: Option<bool>,
) {
    let result = generate_bytecode_successfully(script_id);
    let test_program = create_authentication_program_evaluation_common(&result.bytecode);
    let nodes = result.reduce.script.clone();
    let evaluation_range = result.reduce.range;
    let trace_with_unlocking_phase_and_final_state = vm().debug(&test_program, None);
    let trace = slice(&trace_with_unlocking_phase_and_final_state, 1, Some(-1));
    let samples =
        extract_evaluation_samples_recursive(evaluation_range, &nodes, &trace, None).samples;
    let unexecuted_ranges = extract_unexecuted_ranges(
        &samples,
        if specify_start.is_none() {
            None
        } else {
            Some("1,1")
        },
    );
    assert_eq!(unexecuted_ranges, ranges);
}

#[test]
fn extract_unexecuted_ranges_macro_unexecuted00() {
    extract_unexecuted_ranges_macro(
        "unexecuted00",
        vec![
            Range {
                end_column: 8,
                end_line_number: 3,
                start_column: 5,
                start_line_number: 3,
            },
            Range {
                end_column: 20,
                end_line_number: 4,
                start_column: 5,
                start_line_number: 4,
            },
            Range {
                end_column: 10,
                end_line_number: 5,
                start_column: 5,
                start_line_number: 5,
            },
            Range {
                end_column: 12,
                end_line_number: 6,
                start_column: 9,
                start_line_number: 6,
            },
            Range {
                end_column: 10,
                end_line_number: 14,
                start_column: 9,
                start_line_number: 7,
            },
            Range {
                end_column: 13,
                end_line_number: 15,
                start_column: 5,
                start_line_number: 15,
            },
            Range {
                end_column: 13,
                end_line_number: 16,
                start_column: 5,
                start_line_number: 16,
            },
            Range {
                end_column: 11,
                end_line_number: 23,
                start_column: 9,
                start_line_number: 21,
            },
        ],
        Some(true),
    );
}

#[test]
fn extract_unexecuted_ranges_macro_unexecuted01() {
    extract_unexecuted_ranges_macro(
        "unexecuted01",
        vec![
            Range {
                end_column: 8,
                end_line_number: 3,
                start_column: 5,
                start_line_number: 3,
            },
            Range {
                end_column: 20,
                end_line_number: 4,
                start_column: 5,
                start_line_number: 4,
            },
            Range {
                end_column: 10,
                end_line_number: 5,
                start_column: 5,
                start_line_number: 5,
            },
            Range {
                end_column: 12,
                end_line_number: 6,
                start_column: 9,
                start_line_number: 6,
            },
            Range {
                end_column: 10,
                end_line_number: 14,
                start_column: 9,
                start_line_number: 7,
            },
            Range {
                end_column: 13,
                end_line_number: 15,
                start_column: 5,
                start_line_number: 15,
            },
            Range {
                end_column: 13,
                end_line_number: 16,
                start_column: 5,
                start_line_number: 16,
            },
        ],
        None,
    );
}

#[test]
fn extract_unexecuted_ranges_macro_unexecuted10() {
    extract_unexecuted_ranges_macro(
        "unexecuted10",
        vec![
            Range {
                end_column: 12,
                end_line_number: 6,
                start_column: 9,
                start_line_number: 6,
            },
            Range {
                end_column: 10,
                end_line_number: 14,
                start_column: 9,
                start_line_number: 7,
            },
            Range {
                end_column: 8,
                end_line_number: 18,
                start_column: 5,
                start_line_number: 18,
            },
            Range {
                end_column: 20,
                end_line_number: 19,
                start_column: 5,
                start_line_number: 19,
            },
            Range {
                end_column: 10,
                end_line_number: 20,
                start_column: 5,
                start_line_number: 20,
            },
            Range {
                end_column: 11,
                end_line_number: 23,
                start_column: 9,
                start_line_number: 21,
            },
            Range {
                end_column: 13,
                end_line_number: 24,
                start_column: 5,
                start_line_number: 24,
            },
        ],
        None,
    );
}

#[test]
fn extract_unexecuted_ranges_macro_unexecuted11() {
    extract_unexecuted_ranges_macro(
        "unexecuted11",
        vec![
            Range {
                end_column: 22,
                end_line_number: 12,
                start_column: 17,
                start_line_number: 12,
            },
            Range {
                end_column: 8,
                end_line_number: 18,
                start_column: 5,
                start_line_number: 18,
            },
            Range {
                end_column: 20,
                end_line_number: 19,
                start_column: 5,
                start_line_number: 19,
            },
            Range {
                end_column: 10,
                end_line_number: 20,
                start_column: 5,
                start_line_number: 20,
            },
            Range {
                end_column: 11,
                end_line_number: 23,
                start_column: 9,
                start_line_number: 21,
            },
            Range {
                end_column: 13,
                end_line_number: 24,
                start_column: 5,
                start_line_number: 24,
            },
        ],
        None,
    );
}

#[test]
fn extract_unexecuted_ranges_macro_unexecuted_empty() {
    extract_unexecuted_ranges_macro("unexecutedEmpty", vec![], None);
}

#[test]
#[ignore = "test.todo: extractUnexecutedRangesMacro: loopsInternalConditional at loop 0 iteration 0"]
fn extract_unexecuted_ranges_macro_loops_internal_conditional_at_loop_0_iteration_0() {}

#[test]
#[ignore = "test.todo: extractUnexecutedRangesMacro: loopsInternalConditional at loop 0 iteration 4"]
fn extract_unexecuted_ranges_macro_loops_internal_conditional_at_loop_0_iteration_4() {}

/// The wallet template used by the `summarizeDebugTrace` tests below, with the
/// provided unlocking script.
fn summarize_debug_trace_template(unlock: &str) -> WalletTemplate {
    WalletTemplate {
        schema: None,
        description: None,
        entities: BTreeMap::new(),
        name: None,
        scenarios: None,
        scripts: BTreeMap::from([
            (
                "lock".to_string(),
                WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                    name: None,
                    script: "OP_DUP OP_TOALTSTACK OP_IF <2> OP_ELSE 0xff OP_ENDIF OP_FROMALTSTACK OP_ADD <3> OP_EQUAL".to_string(),
                    locking_type: WalletTemplateLockingType::Standard,
                }),
            ),
            (
                "unlock".to_string(),
                WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                    name: None,
                    script: unlock.to_string(),
                    age_lock: None,
                    estimate: None,
                    fails: None,
                    invalid: None,
                    passes: None,
                    time_lock_type: None,
                    unlocks: "lock".to_string(),
                }),
            ),
        ]),
        supported: vec![AuthenticationVirtualMachineIdentifier::Bch2022_05],
        version: Some(0),
    }
}

/// libauth's `{ ...OpcodesBch, [OpcodesBch.OP_UNKNOWN255]: undefined }`.
fn opcodes_bch_without_op_unknown255() -> Vec<(&'static str, u8)> {
    OpcodesBch::MEMBERS
        .iter()
        .copied()
        .filter(|(_, opcode)| *opcode != OpcodesBch::OP_UNKNOWN255)
        .collect()
}

#[test]
fn summarize_debug_trace_stringify_debug_trace_summary() {
    let Scenario { program, .. } = assert_success(
        wallet_template_to_compiler_bch(&summarize_debug_trace_template("<1>"), None)
            .generate_scenario(None, None, Some("unlock")),
        None,
    );
    let trace = create_virtual_machine_bch(Some(true)).debug(&program, None);
    let summary = summarize_debug_trace(&trace);
    let formatted = stringify_debug_trace_summary(
        &summary,
        Some(&opcodes_bch_without_op_unknown255()),
        None,
        None,
    );
    assert_eq!(
        formatted,
        r#"0. OP_1:                0x01(1)
=>                      0x01(1)
0. OP_DUP:              0x01(1) 0x01(1)
1. OP_TOALTSTACK:       0x01(1)| alt: 0x01(1)
2. OP_IF:               | alt: 0x01(1)
3. OP_2:                0x02(2)| alt: 0x01(1)
4. OP_ELSE:             0x02(2)| alt: 0x01(1)
5. (skip)OP_UNKNOWN255: 0x02(2)| alt: 0x01(1)
6. (skip)OP_ENDIF:      0x02(2)| alt: 0x01(1)
7. OP_FROMALTSTACK:     0x02(2) 0x01(1)
8. OP_ADD:              0x03(3)
9. OP_3:                0x03(3) 0x03(3)
10. OP_EQUAL:           0x01(1)
=>                      0x01(1)"#
    );
}

#[test]
fn summarize_debug_trace_stringify_debug_trace_summary_truncated() {
    let Scenario { program, .. } = assert_success(
        wallet_template_to_compiler_bch(&summarize_debug_trace_template("<1>"), None)
            .generate_scenario(None, None, Some("unlock")),
        None,
    );
    let trace = create_virtual_machine_bch(Some(true)).debug(&program, None);
    let summary = summarize_debug_trace(&trace);
    let formatted = stringify_debug_trace_summary(
        &summary,
        Some(&opcodes_bch_without_op_unknown255()),
        None,
        Some(5),
    );
    assert_eq!(
        formatted,
        r#"[9 steps truncated]
7. OP_FROMALTSTACK:     0x02(2) 0x01(1)
8. OP_ADD:              0x03(3)
9. OP_3:                0x03(3) 0x03(3)
10. OP_EQUAL:           0x01(1)
=>                      0x01(1)"#
    );
}

#[test]
fn summarize_debug_trace_stringify_debug_trace_summary_error() {
    let Scenario { program, .. } = assert_success(
        wallet_template_to_compiler_bch(&summarize_debug_trace_template("<0>"), None)
            .generate_scenario(None, None, Some("unlock")),
        None,
    );
    let trace = create_virtual_machine_bch(Some(true)).debug(&program, None);
    let summary = summarize_debug_trace(&trace);
    let formatted = stringify_debug_trace_summary(&summary, None, None, None);
    assert_eq!(
        formatted,
        r#"0. OP_0:                0x(0)
=>                      0x(0)
0. OP_DUP:              0x(0) 0x(0)
1. OP_TOALTSTACK:       0x(0)| alt: 0x(0)
2. OP_IF:               | alt: 0x(0)
3. (skip)OP_2:          | alt: 0x(0)
4. (skip)OP_ELSE:       | alt: 0x(0)
5. OP_UNKNOWN255:       Called an unknown opcode.
6. OP_ENDIF:            Called an unknown opcode."#
    );
}

#[test]
#[ignore = "test.todo: extraction of labeledStackItems"]
fn extraction_of_labeled_stack_items() {}

#[test]
#[ignore = "test.todo: consider adding support for recursive extraction of labeledStackItems"]
fn consider_adding_support_for_recursive_extraction_of_labeled_stack_items() {}
