//! Port of `language/reduce.spec.ts`.

use libauth::{
    reduce_script, CompilationError, Range, ResolvedSegment, ResolvedSegmentError,
    ScriptReductionTraceChildNode, ScriptReductionTraceErrorNode, ScriptReductionTraceScriptNode,
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
fn reduce_script_does_not_throw_on_empty_array() {
    let reduced = reduce_script(&[], None, None);
    assert_debug_eq(
        &reduced,
        &ScriptReductionTraceScriptNode {
            bytecode: vec![],
            errors: None,
            range: Range {
                end_column: 0,
                end_line_number: 0,
                start_column: 0,
                start_line_number: 0,
            },
            script: vec![],
        },
    );
}

#[test]
fn reduce_script_resolution_error() {
    let reduced = reduce_script(
        &[ResolvedSegment::Error(ResolvedSegmentError {
            range: Range {
                end_column: 8,
                end_line_number: 1,
                start_column: 1,
                start_line_number: 1,
            },
            value: "Unknown identifier \"unknown\".".to_string(),
            missing_identifier: None,
            owning_entity: None,
        })],
        None,
        None,
    );
    assert_debug_eq(
        &reduced,
        &ScriptReductionTraceScriptNode {
            bytecode: vec![],
            errors: Some(vec![CompilationError {
                error: "Tried to reduce a CashAssembly script with resolution errors: Unknown identifier \"unknown\".".to_string(),
                range: Range {
                    end_column: 8,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
                missing_identifier: None,
                owning_entity: None,
            }]),
            range: Range {
                end_column: 8,
                end_line_number: 1,
                start_column: 1,
                start_line_number: 1,
            },
            script: vec![ScriptReductionTraceChildNode::Error(ScriptReductionTraceErrorNode {
                bytecode: vec![],
                errors: vec![CompilationError {
                    error: "Tried to reduce a CashAssembly script with resolution errors: Unknown identifier \"unknown\".".to_string(),
                    range: Range {
                        end_column: 8,
                        end_line_number: 1,
                        start_column: 1,
                        start_line_number: 1,
                    },
                    missing_identifier: None,
                    owning_entity: None,
                }],
                range: Range {
                    end_column: 8,
                    end_line_number: 1,
                    start_column: 1,
                    start_line_number: 1,
                },
            })],
        },
    );
}

#[test]
#[ignore = "MISSING-API: ResolvedSegment is a closed enum, so a segment with an unknown `type` (which libauth's reduceScript rejects by throwing) cannot be constructed"]
fn reduce_script_invalid_resolved_script() {
    // libauth (as JavaScript consumers can bypass the `ResolvedSegment` type):
    //
    //   t.throws(() =>
    //     reduceScript([
    //       {
    //         range: { endColumn: 2, endLineNumber: 1, startColumn: 1, startLineNumber: 1 },
    //         type: "uncaught because the consumer isn't using TypeScript" as 'error',
    //         value: 'Another kind of value',
    //       },
    //     ]),
    //   );
    //
    // Intended Rust (not expressible: `ResolvedSegment` has no variant for an
    // unknown segment type):
    //
    //   assert!(std::panic::catch_unwind(|| {
    //       reduce_script(&[/* ResolvedSegment with type "uncaught because ..." */], None, None)
    //   })
    //   .is_err());
}
