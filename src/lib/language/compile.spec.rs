//! Port of `language/compile.spec.ts`.

use std::collections::BTreeMap;
use std::rc::Rc;

use libauth::{
    compile_script, compile_script_contents, compiler_operation_address_data,
    describe_expected_input, hex_to_bin, CompilationData, CompilationError, CompilationErrorType,
    CompilationResult, CompilationResultError, CompilationResultSuccess, CompilerConfiguration,
    CompilerOperationSet, CompilerOperations, Range, ResolvedSegment, ResolvedSegmentBytecode,
    ResolvedSegmentComment, ResolvedSegmentError, ResolvedSegmentLiteralBytecode,
    ResolvedSegmentLiteralType, ResolvedSegmentOpcodeBytecode, ResolvedSegmentPush,
    ResolvedSegmentScriptBytecode, ResolvedSegmentVariableBytecode, ScriptReductionTraceChildNode,
    ScriptReductionTraceCommentNode, ScriptReductionTraceNode, ScriptReductionTracePushNode,
    ScriptReductionTraceScriptNode, Segment, SegmentName, SegmentValue, SourcePosition,
    WalletTemplateAddressData, WalletTemplateVariable, WalletTemplateVariableType,
};

/// `t.deepEqual` for values whose types do not implement `PartialEq`: compares
/// the complete values through their derived `Debug` representations,
/// reporting the first differing line (with its enclosing structure).
#[track_caller]
fn assert_debug_eq<T: std::fmt::Debug>(actual: &T, expected: &T) {
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
        "values differ at line {} of their Debug representations\n--- path ---\n{}\n--- actual ---\n{}\n--- expected ---\n{}",
        first_difference + 1,
        path.join("\n"),
        context(&actual_lines),
        context(&expected_lines),
    );
}

#[test]
fn compile_script_unprovided_id() {
    assert_debug_eq(
        &compile_script(
            "test",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("typo".to_string(), "1".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error:
                    "No script with an ID of \"test\" was provided in the compiler configuration."
                        .to_string(),
                range: Range {
                    end_column: 0,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
                missing_identifier: None,
                owning_entity: None,
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
    );
}

#[test]
fn compile_script_clean_errors_on_unexpected_input() {
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("t".to_string(), "te$t".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![
                CompilationError {
                    error: "Encountered unexpected input while parsing script. Expected the opening parenthesis of this evaluation ('(').".to_string(),
                    range: Range {
                        end_column: 4,
                        end_line_number: 1,
                        start_column: 4,
                        start_line_number: 1,
                    },
                    missing_identifier: None,
                    owning_entity: None,
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
    );
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("t".to_string(), "<$(<1> <2> OP_ADD >".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![
                CompilationError {
                    error: "Encountered unexpected input while parsing script. Expected a binary literal ('0b...'), a double quote (\"), a hex literal ('0x...'), a single quote ('), a valid identifier, an integer literal, the closing parenthesis of this evaluation (')'), the start of a multi-line comment ('/*'), the start of a push statement ('<'), the start of a single-line comment ('//'), or the start of an evaluation ('$').".to_string(),
                    range: Range {
                        end_column: 19,
                        end_line_number: 1,
                        start_column: 19,
                        start_line_number: 1,
                    },
                    missing_identifier: None,
                    owning_entity: None,
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
    );
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("t".to_string(), "\"incomplete".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![
                CompilationError {
                    error: "Encountered unexpected input while parsing script. Expected a closing double quote (\").".to_string(),
                    range: Range {
                        end_column: 12,
                        end_line_number: 1,
                        start_column: 12,
                        start_line_number: 1,
                    },
                    missing_identifier: None,
                    owning_entity: None,
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
    );
}

#[test]
fn compile_script_empty_string() {
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("t".to_string(), "".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![],
            parse: Segment {
                end: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![],
                errors: None,
                range: Range {
                    end_column: 1,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![ScriptReductionTraceChildNode::Comment(
                    ScriptReductionTraceCommentNode {
                        bytecode: vec![],
                        comment: "".to_string(),
                        errors: None,
                        range: Range {
                            end_column: 1,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    },
                )],
            },
            resolve: vec![ResolvedSegment::Comment(ResolvedSegmentComment {
                range: Range {
                    end_column: 1,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                value: "".to_string(),
            })],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_contents_empty_string() {
    assert_debug_eq(
        &compile_script_contents(
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::new(),
                ..Default::default()
            },
            "",
        ),
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![],
            parse: Segment {
                end: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![],
                errors: None,
                range: Range {
                    end_column: 1,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![ScriptReductionTraceChildNode::Comment(
                    ScriptReductionTraceCommentNode {
                        bytecode: vec![],
                        comment: "".to_string(),
                        errors: None,
                        range: Range {
                            end_column: 1,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    },
                )],
            },
            resolve: vec![ResolvedSegment::Comment(ResolvedSegmentComment {
                range: Range {
                    end_column: 1,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                value: "".to_string(),
            })],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_contents_empty_script_script_with_space() {
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("t".to_string(), "    ".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![],
            parse: Segment {
                end: SourcePosition {
                    column: 5,
                    line: 1,
                    offset: 4,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![],
                errors: None,
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![ScriptReductionTraceChildNode::Comment(
                    ScriptReductionTraceCommentNode {
                        bytecode: vec![],
                        comment: "".to_string(),
                        errors: None,
                        range: Range {
                            end_column: 5,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    },
                )],
            },
            resolve: vec![ResolvedSegment::Comment(ResolvedSegmentComment {
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                value: "".to_string(),
            })],
            transformed: None,
        })),
    );
}

#[test]
fn describe_expected_input_handles_eof() {
    assert_eq!(
        describe_expected_input(&vec!["one thing".to_string(), "EOF".to_string()]),
        "Encountered unexpected input while parsing script. Expected one thing or the end of the script.",
    );
}

#[test]
fn describe_expected_input_handles_2_options() {
    assert_eq!(
        describe_expected_input(&vec!["one thing".to_string(), "another thing".to_string()]),
        "Encountered unexpected input while parsing script. Expected one thing or another thing.",
    );
}

#[test]
fn compile_script_parse_error() {
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("t".to_string(), "$".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![
                CompilationError {
                    error: "Encountered unexpected input while parsing script. Expected the opening parenthesis of this evaluation ('(').".to_string(),
                    range: Range {
                        end_column: 2,
                        end_line_number: 1,
                        start_column: 2,
                        start_line_number: 1,
                    },
                    missing_identifier: None,
                    owning_entity: None,
                },
            ],
            parse: None,
            reduce: None,
            resolve: None,
        }),
    );
}

#[test]
fn compile_script_0x51() {
    let result = compile_script(
        "t",
        &CompilationData::default(),
        &CompilerConfiguration {
            scripts: BTreeMap::from([("t".to_string(), "0x51".to_string())]),
            ..Default::default()
        },
    );
    assert_debug_eq(
        &result,
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![0x51],
            parse: Segment {
                end: SourcePosition {
                    column: 5,
                    line: 1,
                    offset: 4,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![Segment {
                    end: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("51".to_string()),
                }]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![0x51],
                errors: None,
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![ScriptReductionTraceChildNode::Bytecode(
                    ScriptReductionTraceNode {
                        bytecode: vec![0x51],
                        errors: None,
                        range: Range {
                            end_column: 5,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    },
                )],
            },
            resolve: vec![ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                ResolvedSegmentLiteralBytecode {
                    range: Range {
                        end_column: 5,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    literal: "51".to_string(),
                    literal_type: ResolvedSegmentLiteralType::HexLiteral,
                    value: vec![0x51],
                },
            ))],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_1() {
    let result = compile_script(
        "t",
        &CompilationData::default(),
        &CompilerConfiguration {
            scripts: BTreeMap::from([("t".to_string(), "<1>".to_string())]),
            ..Default::default()
        },
    );
    assert_debug_eq(
        &result,
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![0x51],
            parse: Segment {
                end: SourcePosition {
                    column: 4,
                    line: 1,
                    offset: 3,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![Segment {
                    end: SourcePosition {
                        column: 4,
                        line: 1,
                        offset: 3,
                    },
                    name: SegmentName::Push,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Push(Box::new(Segment {
                        end: SourcePosition {
                            column: 3,
                            line: 1,
                            offset: 2,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 2,
                            line: 1,
                            offset: 1,
                        },
                        value: SegmentValue::Script(vec![Segment {
                            end: SourcePosition {
                                column: 3,
                                line: 1,
                                offset: 2,
                            },
                            name: SegmentName::BigIntLiteral,
                            start: SourcePosition {
                                column: 2,
                                line: 1,
                                offset: 1,
                            },
                            value: SegmentValue::Text("1".to_string()),
                        }]),
                    })),
                }]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![0x51],
                errors: None,
                range: Range {
                    end_column: 4,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![ScriptReductionTraceChildNode::Push(
                    ScriptReductionTracePushNode {
                        bytecode: vec![0x51],
                        errors: None,
                        push: Box::new(ScriptReductionTraceScriptNode {
                            bytecode: vec![0x01],
                            errors: None,
                            range: Range {
                                end_column: 3,
                                end_line_number: 1,
                                start_column: 2,
                                start_line_number: 1,
                            },
                            script: vec![ScriptReductionTraceChildNode::Bytecode(
                                ScriptReductionTraceNode {
                                    bytecode: vec![0x01],
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
                    },
                )],
            },
            resolve: vec![ResolvedSegment::Push(ResolvedSegmentPush {
                range: Range {
                    end_column: 4,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                value: vec![ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                    ResolvedSegmentLiteralBytecode {
                        range: Range {
                            end_column: 3,
                            end_line_number: 1,
                            start_column: 2,
                            start_line_number: 1,
                        },
                        literal: "1".to_string(),
                        literal_type: ResolvedSegmentLiteralType::BigIntLiteral,
                        value: vec![0x01],
                    },
                ))],
            })],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_0xabcdef() {
    let result = compile_script(
        "t",
        &CompilationData::default(),
        &CompilerConfiguration {
            scripts: BTreeMap::from([("t".to_string(), "<0xabcdef>".to_string())]),
            ..Default::default()
        },
    );
    assert_debug_eq(
        &result,
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![0x03, 0xab, 0xcd, 0xef],
            parse: Segment {
                end: SourcePosition {
                    column: 11,
                    line: 1,
                    offset: 10,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![Segment {
                    end: SourcePosition {
                        column: 11,
                        line: 1,
                        offset: 10,
                    },
                    name: SegmentName::Push,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Push(Box::new(Segment {
                        end: SourcePosition {
                            column: 10,
                            line: 1,
                            offset: 9,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 2,
                            line: 1,
                            offset: 1,
                        },
                        value: SegmentValue::Script(vec![Segment {
                            end: SourcePosition {
                                column: 10,
                                line: 1,
                                offset: 9,
                            },
                            name: SegmentName::HexLiteral,
                            start: SourcePosition {
                                column: 2,
                                line: 1,
                                offset: 1,
                            },
                            value: SegmentValue::Text("abcdef".to_string()),
                        }]),
                    })),
                }]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![0x03, 0xab, 0xcd, 0xef],
                errors: None,
                range: Range {
                    end_column: 11,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![ScriptReductionTraceChildNode::Push(
                    ScriptReductionTracePushNode {
                        bytecode: vec![0x03, 0xab, 0xcd, 0xef],
                        errors: None,
                        push: Box::new(ScriptReductionTraceScriptNode {
                            bytecode: vec![0xab, 0xcd, 0xef],
                            errors: None,
                            range: Range {
                                end_column: 10,
                                end_line_number: 1,
                                start_column: 2,
                                start_line_number: 1,
                            },
                            script: vec![ScriptReductionTraceChildNode::Bytecode(
                                ScriptReductionTraceNode {
                                    bytecode: vec![0xab, 0xcd, 0xef],
                                    errors: None,
                                    range: Range {
                                        end_column: 10,
                                        end_line_number: 1,
                                        start_column: 2,
                                        start_line_number: 1,
                                    },
                                },
                            )],
                        }),
                        range: Range {
                            end_column: 11,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    },
                )],
            },
            resolve: vec![ResolvedSegment::Push(ResolvedSegmentPush {
                range: Range {
                    end_column: 11,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                value: vec![ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                    ResolvedSegmentLiteralBytecode {
                        range: Range {
                            end_column: 10,
                            end_line_number: 1,
                            start_column: 2,
                            start_line_number: 1,
                        },
                        literal: "abcdef".to_string(),
                        literal_type: ResolvedSegmentLiteralType::HexLiteral,
                        value: vec![0xab, 0xcd, 0xef],
                    },
                ))],
            })],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_abc() {
    let result = compile_script(
        "t",
        &CompilationData::default(),
        &CompilerConfiguration {
            scripts: BTreeMap::from([("t".to_string(), "<\"abc 👍\">".to_string())]),
            ..Default::default()
        },
    );
    assert_debug_eq(
        &result,
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: hex_to_bin("0861626320f09f918d"),
            parse: Segment {
                end: SourcePosition {
                    column: 11,
                    line: 1,
                    offset: 10,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![Segment {
                    end: SourcePosition {
                        column: 11,
                        line: 1,
                        offset: 10,
                    },
                    name: SegmentName::Push,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Push(Box::new(Segment {
                        end: SourcePosition {
                            column: 10,
                            line: 1,
                            offset: 9,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 2,
                            line: 1,
                            offset: 1,
                        },
                        value: SegmentValue::Script(vec![Segment {
                            end: SourcePosition {
                                column: 10,
                                line: 1,
                                offset: 9,
                            },
                            name: SegmentName::Utf8Literal,
                            start: SourcePosition {
                                column: 2,
                                line: 1,
                                offset: 1,
                            },
                            value: SegmentValue::Text("abc 👍".to_string()),
                        }]),
                    })),
                }]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: hex_to_bin("0861626320f09f918d"),
                errors: None,
                range: Range {
                    end_column: 11,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![ScriptReductionTraceChildNode::Push(
                    ScriptReductionTracePushNode {
                        bytecode: hex_to_bin("0861626320f09f918d"),
                        errors: None,
                        push: Box::new(ScriptReductionTraceScriptNode {
                            bytecode: hex_to_bin("61626320f09f918d"),
                            errors: None,
                            range: Range {
                                end_column: 10,
                                end_line_number: 1,
                                start_column: 2,
                                start_line_number: 1,
                            },
                            script: vec![ScriptReductionTraceChildNode::Bytecode(
                                ScriptReductionTraceNode {
                                    bytecode: hex_to_bin("61626320f09f918d"),
                                    errors: None,
                                    range: Range {
                                        end_column: 10,
                                        end_line_number: 1,
                                        start_column: 2,
                                        start_line_number: 1,
                                    },
                                },
                            )],
                        }),
                        range: Range {
                            end_column: 11,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    },
                )],
            },
            resolve: vec![ResolvedSegment::Push(ResolvedSegmentPush {
                range: Range {
                    end_column: 11,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                value: vec![ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Literal(
                    ResolvedSegmentLiteralBytecode {
                        range: Range {
                            end_column: 10,
                            end_line_number: 1,
                            start_column: 2,
                            start_line_number: 1,
                        },
                        literal: "abc 👍".to_string(),
                        literal_type: ResolvedSegmentLiteralType::Utf8Literal,
                        value: hex_to_bin("61626320f09f918d"),
                    },
                ))],
            })],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_no_identifiers_op_1() {
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([("t".to_string(), "OP_1".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown identifier \"OP_1\".".to_string(),
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                missing_identifier: None,
                owning_entity: None,
            }],
            parse: Some(Segment {
                end: SourcePosition {
                    column: 5,
                    line: 1,
                    offset: 4,
                },
                name: SegmentName::Script,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Script(vec![Segment {
                    end: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("OP_1".to_string()),
                }]),
            }),
            reduce: None,
            resolve: Some(vec![ResolvedSegment::Error(ResolvedSegmentError {
                range: Range {
                    end_column: 5,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                value: "Unknown identifier \"OP_1\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
            })]),
        }),
    );
}

#[test]
fn compile_script_op_1_op_2_op_add() {
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                opcodes: Some(BTreeMap::from([
                    ("OP_1".to_string(), vec![0x51]),
                    ("OP_2".to_string(), vec![0x52]),
                    ("OP_ADD".to_string(), vec![0x93]),
                ])),
                scripts: BTreeMap::from([("t".to_string(), "OP_1 OP_2 OP_ADD".to_string())]),
                ..Default::default()
            },
        ),
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![0x51, 0x52, 0x93],
            parse: Segment {
                end: SourcePosition {
                    column: 17,
                    line: 1,
                    offset: 16,
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
                            column: 5,
                            line: 1,
                            offset: 4,
                        },
                        name: SegmentName::Identifier,
                        start: SourcePosition {
                            column: 1,
                            line: 1,
                            offset: 0,
                        },
                        value: SegmentValue::Text("OP_1".to_string()),
                    },
                    Segment {
                        end: SourcePosition {
                            column: 10,
                            line: 1,
                            offset: 9,
                        },
                        name: SegmentName::Identifier,
                        start: SourcePosition {
                            column: 6,
                            line: 1,
                            offset: 5,
                        },
                        value: SegmentValue::Text("OP_2".to_string()),
                    },
                    Segment {
                        end: SourcePosition {
                            column: 17,
                            line: 1,
                            offset: 16,
                        },
                        name: SegmentName::Identifier,
                        start: SourcePosition {
                            column: 11,
                            line: 1,
                            offset: 10,
                        },
                        value: SegmentValue::Text("OP_ADD".to_string()),
                    },
                ]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![0x51, 0x52, 0x93],
                errors: None,
                range: Range {
                    end_column: 17,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![
                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                        bytecode: vec![0x51],
                        errors: None,
                        range: Range {
                            end_column: 5,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    }),
                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                        bytecode: vec![0x52],
                        errors: None,
                        range: Range {
                            end_column: 10,
                            end_line_number: 1,
                            start_column: 6,
                            start_line_number: 1,
                        },
                    }),
                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                        bytecode: vec![0x93],
                        errors: None,
                        range: Range {
                            end_column: 17,
                            end_line_number: 1,
                            start_column: 11,
                            start_line_number: 1,
                        },
                    }),
                ],
            },
            resolve: vec![
                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(
                    ResolvedSegmentOpcodeBytecode {
                        range: Range {
                            end_column: 5,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                        opcode: "OP_1".to_string(),
                        value: vec![0x51],
                    },
                )),
                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(
                    ResolvedSegmentOpcodeBytecode {
                        range: Range {
                            end_column: 10,
                            end_line_number: 1,
                            start_column: 6,
                            start_line_number: 1,
                        },
                        opcode: "OP_2".to_string(),
                        value: vec![0x52],
                    },
                )),
                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(
                    ResolvedSegmentOpcodeBytecode {
                        range: Range {
                            end_column: 17,
                            end_line_number: 1,
                            start_column: 11,
                            start_line_number: 1,
                        },
                        opcode: "OP_ADD".to_string(),
                        value: vec![0x93],
                    },
                )),
            ],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_variable_and_script_inclusion() {
    let comp = compile_script(
        "t",
        &CompilationData {
            bytecode: Some(BTreeMap::from([("varOp2".to_string(), vec![0x52])])),
            ..Default::default()
        },
        &CompilerConfiguration {
            opcodes: Some(BTreeMap::from([
                ("OP_1".to_string(), vec![0x51]),
                ("OP_ADD".to_string(), vec![0x93]),
            ])),
            operations: Some(CompilerOperations {
                address_data: Some(CompilerOperationSet::Single(Rc::new(
                    compiler_operation_address_data,
                ))),
                ..Default::default()
            }),
            scripts: BTreeMap::from([
                ("pushNumbers".to_string(), "OP_1 varOp2".to_string()),
                ("t".to_string(), "pushNumbers OP_ADD".to_string()),
            ]),
            variables: Some(BTreeMap::from([(
                "varOp2".to_string(),
                WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                    description: Some("Gets added to OP_1".to_string()),
                    name: Some("OP_2 as a variable".to_string()),
                    r#type: WalletTemplateVariableType::AddressData,
                }),
            )])),
            ..Default::default()
        },
    );
    assert_debug_eq(
        &comp,
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![0x51, 0x52, 0x93],
            parse: Segment {
                end: SourcePosition {
                    column: 19,
                    line: 1,
                    offset: 18,
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
                            column: 12,
                            line: 1,
                            offset: 11,
                        },
                        name: SegmentName::Identifier,
                        start: SourcePosition {
                            column: 1,
                            line: 1,
                            offset: 0,
                        },
                        value: SegmentValue::Text("pushNumbers".to_string()),
                    },
                    Segment {
                        end: SourcePosition {
                            column: 19,
                            line: 1,
                            offset: 18,
                        },
                        name: SegmentName::Identifier,
                        start: SourcePosition {
                            column: 13,
                            line: 1,
                            offset: 12,
                        },
                        value: SegmentValue::Text("OP_ADD".to_string()),
                    },
                ]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![0x51, 0x52, 0x93],
                errors: None,
                range: Range {
                    end_column: 19,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![
                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                        bytecode: vec![0x51, 0x52],
                        errors: None,
                        range: Range {
                            end_column: 12,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    }),
                    ScriptReductionTraceChildNode::Bytecode(ScriptReductionTraceNode {
                        bytecode: vec![0x93],
                        errors: None,
                        range: Range {
                            end_column: 19,
                            end_line_number: 1,
                            start_column: 13,
                            start_line_number: 1,
                        },
                    }),
                ],
            },
            resolve: vec![
                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Script(
                    ResolvedSegmentScriptBytecode {
                        range: Range {
                            end_column: 12,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                        script: "pushNumbers".to_string(),
                        source: Box::new(CompilationResultSuccess {
                            bytecode: hex_to_bin("5152"),
                            parse: Segment {
                                end: SourcePosition {
                                    column: 12,
                                    line: 1,
                                    offset: 11,
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
                                            column: 5,
                                            line: 1,
                                            offset: 4,
                                        },
                                        name: SegmentName::Identifier,
                                        start: SourcePosition {
                                            column: 1,
                                            line: 1,
                                            offset: 0,
                                        },
                                        value: SegmentValue::Text("OP_1".to_string()),
                                    },
                                    Segment {
                                        end: SourcePosition {
                                            column: 12,
                                            line: 1,
                                            offset: 11,
                                        },
                                        name: SegmentName::Identifier,
                                        start: SourcePosition {
                                            column: 6,
                                            line: 1,
                                            offset: 5,
                                        },
                                        value: SegmentValue::Text("varOp2".to_string()),
                                    },
                                ]),
                            },
                            reduce: ScriptReductionTraceScriptNode {
                                bytecode: hex_to_bin("5152"),
                                errors: None,
                                range: Range {
                                    end_column: 12,
                                    end_line_number: 1,
                                    start_column: 1,
                                    start_line_number: 1,
                                },
                                script: vec![
                                    ScriptReductionTraceChildNode::Bytecode(
                                        ScriptReductionTraceNode {
                                            bytecode: hex_to_bin("51"),
                                            errors: None,
                                            range: Range {
                                                end_column: 5,
                                                end_line_number: 1,
                                                start_column: 1,
                                                start_line_number: 1,
                                            },
                                        },
                                    ),
                                    ScriptReductionTraceChildNode::Bytecode(
                                        ScriptReductionTraceNode {
                                            bytecode: hex_to_bin("52"),
                                            errors: None,
                                            range: Range {
                                                end_column: 12,
                                                end_line_number: 1,
                                                start_column: 6,
                                                start_line_number: 1,
                                            },
                                        },
                                    ),
                                ],
                            },
                            resolve: vec![
                                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(
                                    ResolvedSegmentOpcodeBytecode {
                                        range: Range {
                                            end_column: 5,
                                            end_line_number: 1,
                                            start_column: 1,
                                            start_line_number: 1,
                                        },
                                        opcode: "OP_1".to_string(),
                                        value: hex_to_bin("51"),
                                    },
                                )),
                                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Variable(
                                    ResolvedSegmentVariableBytecode {
                                        range: Range {
                                            end_column: 12,
                                            end_line_number: 1,
                                            start_column: 6,
                                            start_line_number: 1,
                                        },
                                        signature: None,
                                        value: hex_to_bin("52"),
                                        variable: "varOp2".to_string(),
                                    },
                                )),
                            ],
                            transformed: None,
                        }),
                        value: vec![0x51, 0x52],
                    },
                )),
                ResolvedSegment::Bytecode(ResolvedSegmentBytecode::Opcode(
                    ResolvedSegmentOpcodeBytecode {
                        range: Range {
                            end_column: 19,
                            end_line_number: 1,
                            start_column: 13,
                            start_line_number: 1,
                        },
                        opcode: "OP_ADD".to_string(),
                        value: vec![0x93],
                    },
                )),
            ],
            transformed: None,
        })),
    );
}

#[test]
fn compile_script_comments() {
    assert_debug_eq(
        &compile_script(
            "t",
            &CompilationData::default(),
            &CompilerConfiguration {
                scripts: BTreeMap::from([(
                    "t".to_string(),
                    "// single-line\n  /* multi-\nline */".to_string(),
                )]),
                ..Default::default()
            },
        ),
        &CompilationResult::Success(Box::new(CompilationResultSuccess {
            bytecode: vec![],
            parse: Segment {
                end: SourcePosition {
                    column: 8,
                    line: 3,
                    offset: 34,
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
                            column: 15,
                            line: 1,
                            offset: 14,
                        },
                        name: SegmentName::Comment,
                        start: SourcePosition {
                            column: 1,
                            line: 1,
                            offset: 0,
                        },
                        value: SegmentValue::Text("single-line".to_string()),
                    },
                    Segment {
                        end: SourcePosition {
                            column: 8,
                            line: 3,
                            offset: 34,
                        },
                        name: SegmentName::Comment,
                        start: SourcePosition {
                            column: 3,
                            line: 2,
                            offset: 17,
                        },
                        value: SegmentValue::Text("multi-\nline".to_string()),
                    },
                ]),
            },
            reduce: ScriptReductionTraceScriptNode {
                bytecode: vec![],
                errors: None,
                range: Range {
                    end_column: 8,
                    end_line_number: 3,
                    start_column: 1,
                    start_line_number: 1,
                },
                script: vec![
                    ScriptReductionTraceChildNode::Comment(ScriptReductionTraceCommentNode {
                        bytecode: vec![],
                        comment: "single-line".to_string(),
                        errors: None,
                        range: Range {
                            end_column: 15,
                            end_line_number: 1,
                            start_column: 1,
                            start_line_number: 1,
                        },
                    }),
                    ScriptReductionTraceChildNode::Comment(ScriptReductionTraceCommentNode {
                        bytecode: vec![],
                        comment: "multi-\nline".to_string(),
                        errors: None,
                        range: Range {
                            end_column: 8,
                            end_line_number: 3,
                            start_column: 3,
                            start_line_number: 2,
                        },
                    }),
                ],
            },
            resolve: vec![
                ResolvedSegment::Comment(ResolvedSegmentComment {
                    range: Range {
                        end_column: 15,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    value: "single-line".to_string(),
                }),
                ResolvedSegment::Comment(ResolvedSegmentComment {
                    range: Range {
                        end_column: 8,
                        end_line_number: 3,
                        start_column: 3,
                        start_line_number: 2,
                    },
                    value: "multi-\nline".to_string(),
                }),
            ],
            transformed: None,
        })),
    );
}
