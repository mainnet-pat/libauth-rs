//! Port of `compiler/compiler-bch/compiler-bch.spec.ts`.
#![allow(non_upper_case_globals)]

use std::collections::BTreeMap;
use std::rc::Rc;

use libauth::{
    create_compilation_context_common_testing, create_compiler_bch, hex_to_bin, AuthenticationInstruction,
    AuthenticationInstructionOperation, AuthenticationInstructionPush, AuthenticationProgramCommon,
    AuthenticationProgramStateCommon, AuthenticationProgramStateMetrics, BytecodeGenerationResult, CompilationData,
    CompilationDataKeys, CompilationResult, CompilationResultSuccess, CompilerConfiguration, Input, Output, Range,
    ResolvedSegment, ResolvedSegmentBytecode, ResolvedSegmentEvaluation, ResolvedSegmentOpcodeBytecode,
    ResolvedSegmentPush, ResolvedSegmentVariableBytecode, ScriptReductionTraceChildNode,
    ScriptReductionTraceEvaluationNode, ScriptReductionTraceNode, ScriptReductionTracePushNode,
    ScriptReductionTraceScriptNode, Segment, SegmentName, SegmentValue, SignatureInfo, SourcePosition,
    TransactionCommon, WalletTemplateKey, WalletTemplateVariable, WalletTemplateVariableType,
};

const privkey: [u8; 32] = [
    0xf8, 0x5d, 0x4b, 0xd8, 0xa0, 0x3c, 0xa1, 0x06, 0xc9, 0xde, 0xb4, 0x7b, 0x79, 0x18, 0x03, 0xda, 0xc7, 0xf0, 0x33,
    0x38, 0x09, 0xe3, 0xf1, 0xdd, 0x04, 0xd1, 0x82, 0xe0, 0xab, 0xa6, 0xe5, 0x53,
];

fn compiler_configuration(unlock: &str) -> CompilerConfiguration {
    CompilerConfiguration {
        scripts: BTreeMap::from([
            (
                "lock".to_string(),
                "OP_DUP OP_HASH160 <$(<a.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG".to_string(),
            ),
            ("unlock".to_string(), unlock.to_string()),
        ]),
        unlocking_scripts: Some(BTreeMap::from([("unlock".to_string(), "lock".to_string())])),
        variables: Some(BTreeMap::from([(
            "a".to_string(),
            WalletTemplateVariable::Key(WalletTemplateKey {
                description: None,
                name: None,
                never_sign_twice: None,
                r#type: WalletTemplateVariableType::Key,
            }),
        )])),
        ..Default::default()
    }
}

fn keys() -> Option<CompilationDataKeys> {
    Some(CompilationDataKeys {
        private_keys: Some(BTreeMap::from([("a".to_string(), privkey.to_vec())])),
    })
}

// [BCH compiler] createCompilerBch: generateBytecode
#[test]
fn bch_compiler_create_compiler_bch_generate_bytecode() {
    let compiler = create_compiler_bch(compiler_configuration(
        "<a.schnorr_signature.all_outputs> <a.public_key>",
    ));
    let result_lock = compiler.generate_bytecode(
        &CompilationData {
            keys: keys(),
            ..Default::default()
        },
        "lock",
    );
    assert_eq!(
        format!("{result_lock:?}"),
        format!(
            "{:?}",
            BytecodeGenerationResult::Success {
                bytecode: hex_to_bin("76a91415d16c84669ab46059313bf0747e781f1d13936d88ac"),
            }
        ),
        "{result_lock:?}"
    );

    let result_unlock = compiler.generate_bytecode(
        &CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(None, None, None, None, None)),
            keys: keys(),
            ..Default::default()
        },
        "unlock",
    );
    assert_eq!(
        format!("{result_unlock:?}"),
        format!(
            "{:?}",
            BytecodeGenerationResult::Success {
                bytecode: hex_to_bin(
                    "412000c439d7eb94cb7b501560a2e96fe9eb7d9a4083f0ab84408fb0fab97e51f6ed4d8a4d7aae3bc805afe3aa8b75f6bf74fa102529349c9d0d112d2c34ec9b2b41210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5"
                ),
            }
        ),
        "{result_unlock:?}"
    );
}

// [BCH compiler] createCompilerBch: debug
// TS: `test.failing` (expected to fail). The expected evaluation traces use an
// outdated libauth program state (`metrics: { executedInstructionCount,
// signatureCheckCount }`, no `functionTable`/`functionCount`, and an empty
// evaluation output locking bytecode); they are expressed with the closest
// Rust values (`executedInstructionCount` as `evaluated_instruction_count`,
// defaults for absent properties). Debug results (`generateBytecode({ debug:
// true })`) are compared via their derived `Debug` representations, as
// `CompilationResult` does not implement `PartialEq`.
#[should_panic]
#[test]
fn bch_compiler_create_compiler_bch_debug() {
    let compiler = create_compiler_bch(compiler_configuration("<a.ecdsa_signature.all_outputs> <a.public_key>"));
    let result_lock = compiler.generate_bytecode_debug(
        &CompilationData {
            keys: keys(),
            ..Default::default()
        },
        "lock",
    );
    assert_eq!(
        format!("{result_lock:#?}"),
        format!(
            "{:#?}",
            CompilationResult::Success(Box::new(CompilationResultSuccess {
                bytecode: hex_to_bin("76a91415d16c84669ab46059313bf0747e781f1d13936d88ac"),
                parse: Segment {
                    end: SourcePosition {
                        column: 76,
                        line: 1,
                        offset: 75,
                    },
                    name: SegmentName::Script,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Script(vec![
                        Segment {
                            end: SourcePosition {
                                column: 7,
                                line: 1,
                                offset: 6,
                            },
                            name: SegmentName::Identifier,
                            start: SourcePosition {
                                column: 1,
                                line: 1,
                                offset: 0,
                            },
                            value: SegmentValue::Text("OP_DUP".to_string()),
                        },
                        Segment {
                            end: SourcePosition {
                                column: 18,
                                line: 1,
                                offset: 17,
                            },
                            name: SegmentName::Identifier,
                            start: SourcePosition {
                                column: 8,
                                line: 1,
                                offset: 7,
                            },
                            value: SegmentValue::Text("OP_HASH160".to_string()),
                        },
                        Segment {
                            end: SourcePosition {
                                column: 49,
                                line: 1,
                                offset: 48,
                            },
                            name: SegmentName::Push,
                            start: SourcePosition {
                                column: 19,
                                line: 1,
                                offset: 18,
                            },
                            value: SegmentValue::Push(Box::new(Segment {
                                end: SourcePosition {
                                    column: 48,
                                    line: 1,
                                    offset: 47,
                                },
                                name: SegmentName::Script,
                                start: SourcePosition {
                                    column: 20,
                                    line: 1,
                                    offset: 19,
                                },
                                value: SegmentValue::Script(vec![Segment {
                                    end: SourcePosition {
                                        column: 48,
                                        line: 1,
                                        offset: 47,
                                    },
                                    name: SegmentName::Evaluation,
                                    start: SourcePosition {
                                        column: 20,
                                        line: 1,
                                        offset: 19,
                                    },
                                    value: SegmentValue::Evaluation(Box::new(Segment {
                                        end: SourcePosition {
                                            column: 47,
                                            line: 1,
                                            offset: 46,
                                        },
                                        name: SegmentName::Script,
                                        start: SourcePosition {
                                            column: 22,
                                            line: 1,
                                            offset: 21,
                                        },
                                        value: SegmentValue::Script(vec![
                                            Segment {
                                                end: SourcePosition {
                                                    column: 36,
                                                    line: 1,
                                                    offset: 35,
                                                },
                                                name: SegmentName::Push,
                                                start: SourcePosition {
                                                    column: 22,
                                                    line: 1,
                                                    offset: 21,
                                                },
                                                value: SegmentValue::Push(Box::new(Segment {
                                                    end: SourcePosition {
                                                        column: 35,
                                                        line: 1,
                                                        offset: 34,
                                                    },
                                                    name: SegmentName::Script,
                                                    start: SourcePosition {
                                                        column: 23,
                                                        line: 1,
                                                        offset: 22,
                                                    },
                                                    value: SegmentValue::Script(vec![Segment {
                                                        end: SourcePosition {
                                                            column: 35,
                                                            line: 1,
                                                            offset: 34,
                                                        },
                                                        name: SegmentName::Identifier,
                                                        start: SourcePosition {
                                                            column: 23,
                                                            line: 1,
                                                            offset: 22,
                                                        },
                                                        value: SegmentValue::Text("a.public_key".to_string()),
                                                    }]),
                                                })),
                                            },
                                            Segment {
                                                end: SourcePosition {
                                                    column: 47,
                                                    line: 1,
                                                    offset: 46,
                                                },
                                                name: SegmentName::Identifier,
                                                start: SourcePosition {
                                                    column: 37,
                                                    line: 1,
                                                    offset: 36,
                                                },
                                                value: SegmentValue::Text("OP_HASH160".to_string()),
                                            },
                                        ]),
                                    })),
                                }]),
                            })),
                        },
                        Segment {
                            end: SourcePosition {
                                column: 64,
                                line: 1,
                                offset: 63,
                            },
                            name: SegmentName::Identifier,
                            start: SourcePosition {
                                column: 50,
                                line: 1,
                                offset: 49,
                            },
                            value: SegmentValue::Text("OP_EQUALVERIFY".to_string()),
                        },
                        Segment {
                            end: SourcePosition {
                                column: 76,
                                line: 1,
                                offset: 75,
                            },
                            name: SegmentName::Identifier,
                            start: SourcePosition {
                                column: 65,
                                line: 1,
                                offset: 64,
                            },
                            value: SegmentValue::Text("OP_CHECKSIG".to_string()),
                        },
                    ]),
                },
                reduce: ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin("76a91415d16c84669ab46059313bf0747e781f1d13936d88ac"),
                    errors: None,
                    range: Range {
                        end_column: 76,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    script: vec![
                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                            bytecode: hex_to_bin("76"),
                            errors: None,
                            range: Range {
                                end_column: 7,
                                end_line_number: 1,
                                start_column: 1,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                            bytecode: hex_to_bin("a9"),
                            errors: None,
                            range: Range {
                                end_column: 18,
                                end_line_number: 1,
                                start_column: 8,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                            bytecode: hex_to_bin("1415d16c84669ab46059313bf0747e781f1d13936d"),
                            errors: None,
                            push: Box::new(ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d"),
                                errors: None,
                                range: Range {
                                    end_column: 48,
                                    end_line_number: 1,
                                    start_column: 20,
                                    start_line_number: 1,
                                },
                                script: vec![ScriptReductionTraceChildNode::Evaluation(ScriptReductionTraceEvaluationNode {
                                    bytecode: hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d"),
                                    errors: None,
                                    range: Range {
                                        end_column: 48,
                                        end_line_number: 1,
                                        start_column: 20,
                                        start_line_number: 1,
                                    },
                                    source: Box::new(ScriptReductionTraceScriptNode {
                                        bytecode: hex_to_bin(
                                            "210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5a9",
                                        ),
                                        errors: None,
                                        range: Range {
                                            end_column: 47,
                                            end_line_number: 1,
                                            start_column: 22,
                                            start_line_number: 1,
                                        },
                                        script: vec![
                                            ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                                                bytecode: hex_to_bin(
                                                    "210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                                ),
                                                errors: None,
                                                push: Box::new(ScriptReductionTraceScriptNode {
                                                    bytecode: hex_to_bin(
                                                        "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                                    ),
                                                    errors: None,
                                                    range: Range {
                                                        end_column: 35,
                                                        end_line_number: 1,
                                                        start_column: 23,
                                                        start_line_number: 1,
                                                    },
                                                    script: vec![ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                        bytecode: hex_to_bin(
                                                            "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                                        ),
                                                        errors: None,
                                                        range: Range {
                                                            end_column: 35,
                                                            end_line_number: 1,
                                                            start_column: 23,
                                                            start_line_number: 1,
                                                        },
                                                    })],
                                                }),
                                                range: Range {
                                                    end_column: 36,
                                                    end_line_number: 1,
                                                    start_column: 22,
                                                    start_line_number: 1,
                                                },
                                            }),
                                            ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                                bytecode: hex_to_bin("a9"),
                                                errors: None,
                                                range: Range {
                                                    end_column: 47,
                                                    end_line_number: 1,
                                                    start_column: 37,
                                                    start_line_number: 1,
                                                },
                                            }),
                                        ],
                                    }),
                                    trace: vec![
                                        AuthenticationProgramStateCommon {
                                            alternate_stack: vec![],
                                            control_stack: vec![],
                                            error: None,
                                            function_count: 0,
                                            function_table: BTreeMap::new(),
                                            instructions: Rc::new(vec![]),
                                            ip: 0,
                                            last_code_separator: -1,
                                            metrics: AuthenticationProgramStateMetrics {
                                                evaluated_instruction_count: 0.0,
                                                signature_check_count: 0.0,
                                                ..Default::default()
                                            },
                                            operation_count: 0,
                                            program: Rc::new(AuthenticationProgramCommon {
                                                input_index: 0,
                                                source_outputs: vec![Output {
                                                    locking_bytecode: hex_to_bin(
                                                        "210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5a9",
                                                    ),
                                                    token: None,
                                                    value_satoshis: 0,
                                                }],
                                                transaction: TransactionCommon {
                                                    inputs: vec![Input {
                                                        outpoint_index: 0,
                                                        outpoint_transaction_hash: hex_to_bin(
                                                            "0000000000000000000000000000000000000000000000000000000000000000",
                                                        ),
                                                        sequence_number: 0,
                                                        unlocking_bytecode: hex_to_bin(""),
                                                    }],
                                                    locktime: 0,
                                                    outputs: vec![Output {
                                                        locking_bytecode: hex_to_bin(""),
                                                        token: None,
                                                        value_satoshis: 0,
                                                    }],
                                                    version: 0,
                                                },
                                            }),
                                            signed_messages: vec![],
                                            stack: vec![],
                                        },
                                        AuthenticationProgramStateCommon {
                                            alternate_stack: vec![],
                                            control_stack: vec![],
                                            error: None,
                                            function_count: 0,
                                            function_table: BTreeMap::new(),
                                            instructions: Rc::new(vec![
                                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                    data: hex_to_bin(
                                                        "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                                    ),
                                                    opcode: 33,
                                                }),
                                                AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                    opcode: 169,
                                                }),
                                            ]),
                                            ip: 0,
                                            last_code_separator: -1,
                                            metrics: AuthenticationProgramStateMetrics {
                                                evaluated_instruction_count: 0.0,
                                                signature_check_count: 0.0,
                                                ..Default::default()
                                            },
                                            operation_count: 0,
                                            program: Rc::new(AuthenticationProgramCommon {
                                                input_index: 0,
                                                source_outputs: vec![Output {
                                                    locking_bytecode: hex_to_bin(
                                                        "210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5a9",
                                                    ),
                                                    token: None,
                                                    value_satoshis: 0,
                                                }],
                                                transaction: TransactionCommon {
                                                    inputs: vec![Input {
                                                        outpoint_index: 0,
                                                        outpoint_transaction_hash: hex_to_bin(
                                                            "0000000000000000000000000000000000000000000000000000000000000000",
                                                        ),
                                                        sequence_number: 0,
                                                        unlocking_bytecode: hex_to_bin(""),
                                                    }],
                                                    locktime: 0,
                                                    outputs: vec![Output {
                                                        locking_bytecode: hex_to_bin(""),
                                                        token: None,
                                                        value_satoshis: 0,
                                                    }],
                                                    version: 0,
                                                },
                                            }),
                                            signed_messages: vec![],
                                            stack: vec![],
                                        },
                                        AuthenticationProgramStateCommon {
                                            alternate_stack: vec![],
                                            control_stack: vec![],
                                            error: None,
                                            function_count: 0,
                                            function_table: BTreeMap::new(),
                                            instructions: Rc::new(vec![
                                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                    data: hex_to_bin(
                                                        "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                                    ),
                                                    opcode: 33,
                                                }),
                                                AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                    opcode: 169,
                                                }),
                                            ]),
                                            ip: 1,
                                            last_code_separator: -1,
                                            metrics: AuthenticationProgramStateMetrics {
                                                evaluated_instruction_count: 1.0,
                                                signature_check_count: 0.0,
                                                ..Default::default()
                                            },
                                            operation_count: 0,
                                            program: Rc::new(AuthenticationProgramCommon {
                                                input_index: 0,
                                                source_outputs: vec![Output {
                                                    locking_bytecode: hex_to_bin(
                                                        "210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5a9",
                                                    ),
                                                    token: None,
                                                    value_satoshis: 0,
                                                }],
                                                transaction: TransactionCommon {
                                                    inputs: vec![Input {
                                                        outpoint_index: 0,
                                                        outpoint_transaction_hash: hex_to_bin(
                                                            "0000000000000000000000000000000000000000000000000000000000000000",
                                                        ),
                                                        sequence_number: 0,
                                                        unlocking_bytecode: hex_to_bin(""),
                                                    }],
                                                    locktime: 0,
                                                    outputs: vec![Output {
                                                        locking_bytecode: hex_to_bin(""),
                                                        token: None,
                                                        value_satoshis: 0,
                                                    }],
                                                    version: 0,
                                                },
                                            }),
                                            signed_messages: vec![],
                                            stack: vec![hex_to_bin(
                                                "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                            )],
                                        },
                                        AuthenticationProgramStateCommon {
                                            alternate_stack: vec![],
                                            control_stack: vec![],
                                            error: None,
                                            function_count: 0,
                                            function_table: BTreeMap::new(),
                                            instructions: Rc::new(vec![
                                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                    data: hex_to_bin(
                                                        "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                                    ),
                                                    opcode: 33,
                                                }),
                                                AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                    opcode: 169,
                                                }),
                                            ]),
                                            ip: 2,
                                            last_code_separator: -1,
                                            metrics: AuthenticationProgramStateMetrics {
                                                evaluated_instruction_count: 2.0,
                                                signature_check_count: 0.0,
                                                ..Default::default()
                                            },
                                            operation_count: 1,
                                            program: Rc::new(AuthenticationProgramCommon {
                                                input_index: 0,
                                                source_outputs: vec![Output {
                                                    locking_bytecode: hex_to_bin(
                                                        "210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5a9",
                                                    ),
                                                    token: None,
                                                    value_satoshis: 0,
                                                }],
                                                transaction: TransactionCommon {
                                                    inputs: vec![Input {
                                                        outpoint_index: 0,
                                                        outpoint_transaction_hash: hex_to_bin(
                                                            "0000000000000000000000000000000000000000000000000000000000000000",
                                                        ),
                                                        sequence_number: 0,
                                                        unlocking_bytecode: hex_to_bin(""),
                                                    }],
                                                    locktime: 0,
                                                    outputs: vec![Output {
                                                        locking_bytecode: hex_to_bin(""),
                                                        token: None,
                                                        value_satoshis: 0,
                                                    }],
                                                    version: 0,
                                                },
                                            }),
                                            signed_messages: vec![],
                                            stack: vec![hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d")],
                                        },
                                        AuthenticationProgramStateCommon {
                                            alternate_stack: vec![],
                                            control_stack: vec![],
                                            error: None,
                                            function_count: 0,
                                            function_table: BTreeMap::new(),
                                            instructions: Rc::new(vec![
                                                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                                                    data: hex_to_bin(
                                                        "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                                    ),
                                                    opcode: 33,
                                                }),
                                                AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                                                    opcode: 169,
                                                }),
                                            ]),
                                            ip: 2,
                                            last_code_separator: -1,
                                            metrics: AuthenticationProgramStateMetrics {
                                                evaluated_instruction_count: 2.0,
                                                signature_check_count: 0.0,
                                                ..Default::default()
                                            },
                                            operation_count: 1,
                                            program: Rc::new(AuthenticationProgramCommon {
                                                input_index: 0,
                                                source_outputs: vec![Output {
                                                    locking_bytecode: hex_to_bin(
                                                        "210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5a9",
                                                    ),
                                                    token: None,
                                                    value_satoshis: 0,
                                                }],
                                                transaction: TransactionCommon {
                                                    inputs: vec![Input {
                                                        outpoint_index: 0,
                                                        outpoint_transaction_hash: hex_to_bin(
                                                            "0000000000000000000000000000000000000000000000000000000000000000",
                                                        ),
                                                        sequence_number: 0,
                                                        unlocking_bytecode: hex_to_bin(""),
                                                    }],
                                                    locktime: 0,
                                                    outputs: vec![Output {
                                                        locking_bytecode: hex_to_bin(""),
                                                        token: None,
                                                        value_satoshis: 0,
                                                    }],
                                                    version: 0,
                                                },
                                            }),
                                            signed_messages: vec![],
                                            stack: vec![hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d")],
                                        },
                                    ],
                                })],
                            }),
                            range: Range {
                                end_column: 49,
                                end_line_number: 1,
                                start_column: 19,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                            bytecode: hex_to_bin("88"),
                            errors: None,
                            range: Range {
                                end_column: 64,
                                end_line_number: 1,
                                start_column: 50,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                            bytecode: hex_to_bin("ac"),
                            errors: None,
                            range: Range {
                                end_column: 76,
                                end_line_number: 1,
                                start_column: 65,
                                start_line_number: 1,
                            },
                        }),
                    ],
                },
                resolve: vec![
                    ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(ResolvedSegmentOpcodeBytecode {
                        opcode: "OP_DUP".to_string(),
                        range: Range {
                            end_column: 7,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                        value: hex_to_bin("76"),
                    })),
                    ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(ResolvedSegmentOpcodeBytecode {
                        opcode: "OP_HASH160".to_string(),
                        range: Range {
                            end_column: 18,
                            end_line_number: 1,
                            start_column: 8,
                            start_line_number: 1,
                        },
                        value: hex_to_bin("a9"),
                    })),
                    ResolvedSegment::Push(ResolvedSegmentPush {
                        range: Range {
                            end_column: 49,
                            end_line_number: 1,
                            start_column: 19,
                            start_line_number: 1,
                        },
                        value: vec![ResolvedSegment::Evaluation(ResolvedSegmentEvaluation {
                            range: Range {
                                end_column: 48,
                                end_line_number: 1,
                                start_column: 20,
                                start_line_number: 1,
                            },
                            value: vec![
                                ResolvedSegment::Push(ResolvedSegmentPush {
                                    range: Range {
                                        end_column: 36,
                                        end_line_number: 1,
                                        start_column: 22,
                                        start_line_number: 1,
                                    },
                                    value: vec![ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Variable(ResolvedSegmentVariableBytecode {
                                        range: Range {
                                            end_column: 35,
                                            end_line_number: 1,
                                            start_column: 23,
                                            start_line_number: 1,
                                        },
                                        signature: None,
                                        value: hex_to_bin(
                                            "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                        ),
                                        variable: "a.public_key".to_string(),
                                    }))],
                                }),
                                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(ResolvedSegmentOpcodeBytecode {
                                    opcode: "OP_HASH160".to_string(),
                                    range: Range {
                                        end_column: 47,
                                        end_line_number: 1,
                                        start_column: 37,
                                        start_line_number: 1,
                                    },
                                    value: hex_to_bin("a9"),
                                })),
                            ],
                        })],
                    }),
                    ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(ResolvedSegmentOpcodeBytecode {
                        opcode: "OP_EQUALVERIFY".to_string(),
                        range: Range {
                            end_column: 64,
                            end_line_number: 1,
                            start_column: 50,
                            start_line_number: 1,
                        },
                        value: hex_to_bin("88"),
                    })),
                    ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(ResolvedSegmentOpcodeBytecode {
                        opcode: "OP_CHECKSIG".to_string(),
                        range: Range {
                            end_column: 76,
                            end_line_number: 1,
                            start_column: 65,
                            start_line_number: 1,
                        },
                        value: hex_to_bin("ac"),
                    })),
                ],
                transformed: None,
            })),
        ),
    );

    let result_unlock = compiler.generate_bytecode_debug(
        &CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(None, None, None, None, None)),
            keys: keys(),
            ..Default::default()
        },
        "unlock",
    );
    assert_eq!(
        format!("{result_unlock:#?}"),
        format!(
            "{:#?}",
            CompilationResult::Success(Box::new(CompilationResultSuccess {
                bytecode: hex_to_bin(
                    "483045022100f129fea5cb875fe5f35e3b2cf919aaf2211340cb49de5253db1d0726cf5f3b7c0220747c59400a81473510883199f59a3f957adf0418dff9d1549ed985bf0b66c4af41210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                ),
                parse: Segment {
                    end: SourcePosition {
                        column: 47,
                        line: 1,
                        offset: 46,
                    },
                    name: SegmentName::Script,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Script(vec![
                        Segment {
                            end: SourcePosition {
                                column: 32,
                                line: 1,
                                offset: 31,
                            },
                            name: SegmentName::Push,
                            start: SourcePosition {
                                column: 1,
                                line: 1,
                                offset: 0,
                            },
                            value: SegmentValue::Push(Box::new(Segment {
                                end: SourcePosition {
                                    column: 31,
                                    line: 1,
                                    offset: 30,
                                },
                                name: SegmentName::Script,
                                start: SourcePosition {
                                    column: 2,
                                    line: 1,
                                    offset: 1,
                                },
                                value: SegmentValue::Script(vec![Segment {
                                    end: SourcePosition {
                                        column: 31,
                                        line: 1,
                                        offset: 30,
                                    },
                                    name: SegmentName::Identifier,
                                    start: SourcePosition {
                                        column: 2,
                                        line: 1,
                                        offset: 1,
                                    },
                                    value: SegmentValue::Text("a.ecdsa_signature.all_outputs".to_string()),
                                }]),
                            })),
                        },
                        Segment {
                            end: SourcePosition {
                                column: 47,
                                line: 1,
                                offset: 46,
                            },
                            name: SegmentName::Push,
                            start: SourcePosition {
                                column: 33,
                                line: 1,
                                offset: 32,
                            },
                            value: SegmentValue::Push(Box::new(Segment {
                                end: SourcePosition {
                                    column: 46,
                                    line: 1,
                                    offset: 45,
                                },
                                name: SegmentName::Script,
                                start: SourcePosition {
                                    column: 34,
                                    line: 1,
                                    offset: 33,
                                },
                                value: SegmentValue::Script(vec![Segment {
                                    end: SourcePosition {
                                        column: 46,
                                        line: 1,
                                        offset: 45,
                                    },
                                    name: SegmentName::Identifier,
                                    start: SourcePosition {
                                        column: 34,
                                        line: 1,
                                        offset: 33,
                                    },
                                    value: SegmentValue::Text("a.public_key".to_string()),
                                }]),
                            })),
                        },
                    ]),
                },
                reduce: ScriptReductionTraceScriptNode {
                    bytecode: hex_to_bin(
                        "483045022100f129fea5cb875fe5f35e3b2cf919aaf2211340cb49de5253db1d0726cf5f3b7c0220747c59400a81473510883199f59a3f957adf0418dff9d1549ed985bf0b66c4af41210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                    ),
                    errors: None,
                    range: Range {
                        end_column: 47,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    script: vec![
                        ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                            bytecode: hex_to_bin(
                                "483045022100f129fea5cb875fe5f35e3b2cf919aaf2211340cb49de5253db1d0726cf5f3b7c0220747c59400a81473510883199f59a3f957adf0418dff9d1549ed985bf0b66c4af41",
                            ),
                            errors: None,
                            push: Box::new(ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin(
                                    "3045022100f129fea5cb875fe5f35e3b2cf919aaf2211340cb49de5253db1d0726cf5f3b7c0220747c59400a81473510883199f59a3f957adf0418dff9d1549ed985bf0b66c4af41",
                                ),
                                errors: None,
                                range: Range {
                                    end_column: 31,
                                    end_line_number: 1,
                                    start_column: 2,
                                    start_line_number: 1,
                                },
                                script: vec![ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                    bytecode: hex_to_bin(
                                        "3045022100f129fea5cb875fe5f35e3b2cf919aaf2211340cb49de5253db1d0726cf5f3b7c0220747c59400a81473510883199f59a3f957adf0418dff9d1549ed985bf0b66c4af41",
                                    ),
                                    errors: None,
                                    range: Range {
                                        end_column: 31,
                                        end_line_number: 1,
                                        start_column: 2,
                                        start_line_number: 1,
                                    },
                                })],
                            }),
                            range: Range {
                                end_column: 32,
                                end_line_number: 1,
                                start_column: 1,
                                start_line_number: 1,
                            },
                        }),
                        ScriptReductionTraceChildNode::Push(ScriptReductionTracePushNode {
                            bytecode: hex_to_bin("210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5"),
                            errors: None,
                            push: Box::new(ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin(
                                    "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                ),
                                errors: None,
                                range: Range {
                                    end_column: 46,
                                    end_line_number: 1,
                                    start_column: 34,
                                    start_line_number: 1,
                                },
                                script: vec![ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                                    bytecode: hex_to_bin(
                                        "0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5",
                                    ),
                                    errors: None,
                                    range: Range {
                                        end_column: 46,
                                        end_line_number: 1,
                                        start_column: 34,
                                        start_line_number: 1,
                                    },
                                })],
                            }),
                            range: Range {
                                end_column: 47,
                                end_line_number: 1,
                                start_column: 33,
                                start_line_number: 1,
                            },
                        }),
                    ],
                },
                resolve: vec![
                    ResolvedSegment::Push(ResolvedSegmentPush {
                        range: Range {
                            end_column: 32,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                        value: vec![ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Variable(ResolvedSegmentVariableBytecode {
                            range: Range {
                                end_column: 31,
                                end_line_number: 1,
                                start_column: 2,
                                start_line_number: 1,
                            },
                            signature: Some(SignatureInfo::Serialization(hex_to_bin(
                                "000000002d6c6135bed260db00d1b9ad203fbd17ee6c8b009850fc407bfec29fc45e3d4d8cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb90101010101010101010101010101010101010101010101010101010101010101000000001976a91415d16c84669ab46059313bf0747e781f1d13936d88acffffffffffffffff00000000dd2aed19e2aa2ddc93b21ca9e9bb5e89016be12113ea1746ebb4e1d0417eca550000000041000000",
                            ))),
                            value: hex_to_bin(
                                "3045022100f129fea5cb875fe5f35e3b2cf919aaf2211340cb49de5253db1d0726cf5f3b7c0220747c59400a81473510883199f59a3f957adf0418dff9d1549ed985bf0b66c4af41",
                            ),
                            variable: "a.ecdsa_signature.all_outputs".to_string(),
                        }))],
                    }),
                    ResolvedSegment::Push(ResolvedSegmentPush {
                        range: Range {
                            end_column: 47,
                            end_line_number: 1,
                            start_column: 33,
                            start_line_number: 1,
                        },
                        value: vec![ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Variable(ResolvedSegmentVariableBytecode {
                            range: Range {
                                end_column: 46,
                                end_line_number: 1,
                                start_column: 34,
                                start_line_number: 1,
                            },
                            signature: None,
                            value: hex_to_bin("0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5"),
                            variable: "a.public_key".to_string(),
                        }))],
                    }),
                ],
                transformed: None,
            })),
        ),
    );
}
