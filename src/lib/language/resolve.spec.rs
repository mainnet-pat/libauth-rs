//! Port of `language/resolve.spec.ts`.

use libauth::{
    parse_script, resolve_script_segment, CashAssemblyScriptSegment, IdentifierResolution,
    ParseResult, Range, ResolvedSegment, ResolvedSegmentError, SegmentName, SegmentValue,
    SourcePosition,
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
fn resolve_script_segment_error_on_unrecognized_parse_results() {
    // Deviation: libauth casts an unknown segment name into the parse tree
    // (`name: 'Unknown' as 'Identifier'`), expecting
    // `'Unrecognized segment: Unknown'`. `SegmentName` is a closed enum, so the
    // only segment name `resolveScriptSegment` does not recognize as a child
    // is `Script`; libauth handles a nested `Script` child with the same
    // (default) branch, producing `'Unrecognized segment: Script'` (confirmed
    // by running libauth's `resolveScriptSegment` on this input in Node).
    let segment: CashAssemblyScriptSegment = CashAssemblyScriptSegment {
        end: SourcePosition {
            column: 24,
            line: 1,
            offset: 23,
        },
        name: SegmentName::Script,
        start: SourcePosition {
            column: 1,
            line: 1,
            offset: 0,
        },
        value: SegmentValue::Script(vec![CashAssemblyScriptSegment {
            end: SourcePosition {
                column: 24,
                line: 1,
                offset: 23,
            },
            // libauth: `name: 'Unknown' as 'Identifier'`
            name: SegmentName::Script,
            start: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
            value: SegmentValue::Text("unrecognized_expression".to_string()),
        }]),
    };
    assert_debug_eq(
        &resolve_script_segment(&segment, &|_: &str| IdentifierResolution::Variable {
            bytecode: vec![],
            signature: None,
        }),
        &vec![ResolvedSegment::Error(ResolvedSegmentError {
            range: Range {
                end_column: 24,
                end_line_number: 1,
                start_column: 1,
                start_line_number: 1,
            },
            // libauth: 'Unrecognized segment: Unknown'
            value: "Unrecognized segment: Script".to_string(),
            missing_identifier: None,
            owning_entity: None,
        })],
    );
}

#[test]
#[ignore = "MISSING-API: IdentifierResolution is a closed enum, so a resolution with an unknown `type` cannot be returned (and ResolvedSegmentBytecode has no variant for libauth's `{ type: 'bytecode', unknown, value }` segments)"]
fn resolve_script_segment_marks_unknown_identifier_types() {
    let ParseResult::Success(parse_result) = parse_script("some_identifier") else {
        panic!("Parse failed.");
    };
    // libauth's malformed resolver returns
    // `{ bytecode: Uint8Array.of(), status: true, type: 'unknown-type' }`; the
    // closest compiling version returns a variable resolution instead.
    let malformed_resolver = |_: &str| IdentifierResolution::Variable {
        bytecode: vec![],
        signature: None,
    };
    let resolved = resolve_script_segment(&parse_result, &malformed_resolver);
    // Intended (not expressible):
    //
    //   assert_debug_eq(&resolved, &vec![ResolvedSegment::Bytecode(
    //       /* { range: { endColumn: 16, endLineNumber: 1, startColumn: 1,
    //            startLineNumber: 1 }, type: 'bytecode',
    //            unknown: 'some_identifier', value: Uint8Array.of() } */
    //   )]);
    let _ = resolved;
    panic!("libauth's `unknown` bytecode segments are not representable in the Rust port");
}
