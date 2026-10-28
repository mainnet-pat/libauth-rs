//! Port of `language/parse.spec.ts`.

use libauth::{parse_script, ParseResult, Segment, SegmentName, SegmentValue, SourcePosition};

#[test]
fn parse_script_empty_string() {
    assert_eq!(
        parse_script(""),
        ParseResult::Success(Segment {
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
        })
    );
}

#[test]
fn parse_script_big_int_literal() {
    assert_eq!(
        parse_script("42"),
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 3,
                line: 1,
                offset: 2,
            },
            name: SegmentName::Script,
            start: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
            value: SegmentValue::Script(vec![Segment {
                end: SourcePosition {
                    column: 3,
                    line: 1,
                    offset: 2,
                },
                name: SegmentName::BigIntLiteral,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("42".to_string()),
            },]),
        })
    );
    assert_eq!(
        parse_script("-42"),
        ParseResult::Success(Segment {
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
                name: SegmentName::BigIntLiteral,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("-42".to_string()),
            },]),
        })
    );
    let allowed = parse_script("0 1 -1 01 0_1 -1__000_000");
    assert_eq!(
        allowed,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 26,
                line: 1,
                offset: 25,
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
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 4,
                        line: 1,
                        offset: 3,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 3,
                        line: 1,
                        offset: 2,
                    },
                    value: SegmentValue::Text("1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 7,
                        line: 1,
                        offset: 6,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    value: SegmentValue::Text("-1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 10,
                        line: 1,
                        offset: 9,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 8,
                        line: 1,
                        offset: 7,
                    },
                    value: SegmentValue::Text("01".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 14,
                        line: 1,
                        offset: 13,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 11,
                        line: 1,
                        offset: 10,
                    },
                    value: SegmentValue::Text("0_1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 26,
                        line: 1,
                        offset: 25,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 15,
                        line: 1,
                        offset: 14,
                    },
                    value: SegmentValue::Text("-1__000_000".to_string()),
                },
            ]),
        })
    );
    let maybe_unexpected = parse_script("_1 1_");
    assert_eq!(
        maybe_unexpected,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 6,
                line: 1,
                offset: 5,
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
                        column: 3,
                        line: 1,
                        offset: 2,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("_1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 4,
                        line: 1,
                        offset: 3,
                    },
                    value: SegmentValue::Text("1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 6,
                        line: 1,
                        offset: 5,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    value: SegmentValue::Text("_".to_string()),
                },
            ]),
        })
    );
    let errors = parse_script("-_1");
    assert_eq!(
        errors,
        ParseResult::Failure {
            expected: vec![
                "EOF".to_string(),
                "a binary literal ('0b...')".to_string(),
                "a double quote (\")".to_string(),
                "a hex literal ('0x...')".to_string(),
                "a single quote (')".to_string(),
                "a valid identifier".to_string(),
                "an integer literal".to_string(),
                "the start of a multi-line comment ('/*')".to_string(),
                "the start of a push statement ('<')".to_string(),
                "the start of a single-line comment ('//')".to_string(),
                "the start of an evaluation ('$')".to_string(),
            ],
            index: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
        }
    );
}

#[test]
fn parse_script_identifier() {
    assert_eq!(
        parse_script("a_variable"),
        ParseResult::Success(Segment {
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
                name: SegmentName::Identifier,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("a_variable".to_string()),
            },]),
        })
    );
}

#[test]
fn parse_script_utf8_literal() {
    assert_eq!(
        parse_script("\"a'b`c 👍\""),
        ParseResult::Success(Segment {
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
                name: SegmentName::Utf8Literal,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("a'b`c 👍".to_string()),
            },]),
        })
    );
    assert_eq!(
        parse_script("'a\"b`c 🚀'"),
        ParseResult::Success(Segment {
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
                name: SegmentName::Utf8Literal,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("a\"b`c 🚀".to_string()),
            },]),
        })
    );
}

#[test]
fn parse_script_always_lossy_normalizes_unicode_characters_before_parsing() {
    let normalized = parse_script("\"fit\"");
    let ligature = parse_script("\"ﬁt\"");
    assert_eq!(
        normalized,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 6,
                line: 1,
                offset: 5,
            },
            name: SegmentName::Script,
            start: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
            value: SegmentValue::Script(vec![Segment {
                end: SourcePosition {
                    column: 6,
                    line: 1,
                    offset: 5,
                },
                name: SegmentName::Utf8Literal,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("fit".to_string()),
            },]),
        })
    );
    assert_eq!(ligature, normalized);
}

#[test]
fn parse_script_hex_literal() {
    assert_eq!(
        parse_script("0xdeadbeef"),
        ParseResult::Success(Segment {
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
                name: SegmentName::HexLiteral,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("deadbeef".to_string()),
            },]),
        })
    );
    let allowed = parse_script("0x01 0x0101 0x0_1 0x00_00__11_11");
    assert_eq!(
        allowed,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 33,
                line: 1,
                offset: 32,
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
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("01".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 12,
                        line: 1,
                        offset: 11,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 6,
                        line: 1,
                        offset: 5,
                    },
                    value: SegmentValue::Text("0101".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 18,
                        line: 1,
                        offset: 17,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 13,
                        line: 1,
                        offset: 12,
                    },
                    value: SegmentValue::Text("0_1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 33,
                        line: 1,
                        offset: 32,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 19,
                        line: 1,
                        offset: 18,
                    },
                    value: SegmentValue::Text("00_00__11_11".to_string()),
                },
            ]),
        })
    );
    let maybe_unexpected = parse_script("0x 0x0_ 0x0_11 0x0_1_ 0x_01");
    assert_eq!(
        maybe_unexpected,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 28,
                line: 1,
                offset: 27,
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
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 3,
                        line: 1,
                        offset: 2,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    value: SegmentValue::Text("x".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 4,
                        line: 1,
                        offset: 3,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 8,
                        line: 1,
                        offset: 7,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    value: SegmentValue::Text("x0_".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 14,
                        line: 1,
                        offset: 13,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 9,
                        line: 1,
                        offset: 8,
                    },
                    value: SegmentValue::Text("0_1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 15,
                        line: 1,
                        offset: 14,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 14,
                        line: 1,
                        offset: 13,
                    },
                    value: SegmentValue::Text("1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 21,
                        line: 1,
                        offset: 20,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 16,
                        line: 1,
                        offset: 15,
                    },
                    value: SegmentValue::Text("0_1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 22,
                        line: 1,
                        offset: 21,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 21,
                        line: 1,
                        offset: 20,
                    },
                    value: SegmentValue::Text("_".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 24,
                        line: 1,
                        offset: 23,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 23,
                        line: 1,
                        offset: 22,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 28,
                        line: 1,
                        offset: 27,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 24,
                        line: 1,
                        offset: 23,
                    },
                    value: SegmentValue::Text("x_01".to_string()),
                },
            ]),
        })
    );
}

#[test]
fn parse_script_binary_literal() {
    let b1 = parse_script("0b1");
    assert_eq!(
        b1,
        ParseResult::Success(Segment {
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
                name: SegmentName::BinaryLiteral,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("1".to_string()),
            },]),
        })
    );
    let b010101 = parse_script("0b010101");
    assert_eq!(
        b010101,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 9,
                line: 1,
                offset: 8,
            },
            name: SegmentName::Script,
            start: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
            value: SegmentValue::Script(vec![Segment {
                end: SourcePosition {
                    column: 9,
                    line: 1,
                    offset: 8,
                },
                name: SegmentName::BinaryLiteral,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("010101".to_string()),
            },]),
        })
    );
    let allowed = parse_script("0b0 0b1 0b111 0b0_0 0b0000_0000__0000_0000");
    assert_eq!(
        allowed,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 43,
                line: 1,
                offset: 42,
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
                        column: 4,
                        line: 1,
                        offset: 3,
                    },
                    name: SegmentName::BinaryLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 8,
                        line: 1,
                        offset: 7,
                    },
                    name: SegmentName::BinaryLiteral,
                    start: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    value: SegmentValue::Text("1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 14,
                        line: 1,
                        offset: 13,
                    },
                    name: SegmentName::BinaryLiteral,
                    start: SourcePosition {
                        column: 9,
                        line: 1,
                        offset: 8,
                    },
                    value: SegmentValue::Text("111".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 20,
                        line: 1,
                        offset: 19,
                    },
                    name: SegmentName::BinaryLiteral,
                    start: SourcePosition {
                        column: 15,
                        line: 1,
                        offset: 14,
                    },
                    value: SegmentValue::Text("0_0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 43,
                        line: 1,
                        offset: 42,
                    },
                    name: SegmentName::BinaryLiteral,
                    start: SourcePosition {
                        column: 21,
                        line: 1,
                        offset: 20,
                    },
                    value: SegmentValue::Text("0000_0000__0000_0000".to_string()),
                },
            ]),
        })
    );
    let maybe_unexpected = parse_script("0b 0b_ 0b_1 0b1_");
    assert_eq!(
        maybe_unexpected,
        ParseResult::Success(Segment {
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
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 3,
                        line: 1,
                        offset: 2,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    value: SegmentValue::Text("b".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 4,
                        line: 1,
                        offset: 3,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 7,
                        line: 1,
                        offset: 6,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    value: SegmentValue::Text("b_".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 9,
                        line: 1,
                        offset: 8,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 8,
                        line: 1,
                        offset: 7,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 12,
                        line: 1,
                        offset: 11,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 9,
                        line: 1,
                        offset: 8,
                    },
                    value: SegmentValue::Text("b_1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 16,
                        line: 1,
                        offset: 15,
                    },
                    name: SegmentName::BinaryLiteral,
                    start: SourcePosition {
                        column: 13,
                        line: 1,
                        offset: 12,
                    },
                    value: SegmentValue::Text("1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 17,
                        line: 1,
                        offset: 16,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 16,
                        line: 1,
                        offset: 15,
                    },
                    value: SegmentValue::Text("_".to_string()),
                },
            ]),
        })
    );
}

#[test]
fn parse_script_comments() {
    let single = parse_script("// single-line comment");
    assert_eq!(
        single,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 23,
                line: 1,
                offset: 22,
            },
            name: SegmentName::Script,
            start: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
            value: SegmentValue::Script(vec![Segment {
                end: SourcePosition {
                    column: 23,
                    line: 1,
                    offset: 22,
                },
                name: SegmentName::Comment,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("single-line comment".to_string()),
            },]),
        })
    );
    let multi = parse_script("/* \nmulti-line\n comment\n */");
    assert_eq!(
        multi,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 4,
                line: 4,
                offset: 27,
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
                    line: 4,
                    offset: 27,
                },
                name: SegmentName::Comment,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Text("multi-line\n comment".to_string()),
            },]),
        })
    );
    let multiple = parse_script("/* comment before */ OP_1 /* comment after */");
    assert_eq!(
        multiple,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 46,
                line: 1,
                offset: 45,
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
                        column: 21,
                        line: 1,
                        offset: 20,
                    },
                    name: SegmentName::Comment,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("comment before".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 26,
                        line: 1,
                        offset: 25,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 22,
                        line: 1,
                        offset: 21,
                    },
                    value: SegmentValue::Text("OP_1".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 46,
                        line: 1,
                        offset: 45,
                    },
                    name: SegmentName::Comment,
                    start: SourcePosition {
                        column: 27,
                        line: 1,
                        offset: 26,
                    },
                    value: SegmentValue::Text("comment after".to_string()),
                },
            ]),
        })
    );
}

#[test]
fn parse_script_empty_push_statement() {
    assert_eq!(
        parse_script("<>"),
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 3,
                line: 1,
                offset: 2,
            },
            name: SegmentName::Script,
            start: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
            value: SegmentValue::Script(vec![Segment {
                end: SourcePosition {
                    column: 3,
                    line: 1,
                    offset: 2,
                },
                name: SegmentName::Push,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Push(Box::new(Segment {
                    end: SourcePosition {
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    name: SegmentName::Script,
                    start: SourcePosition {
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    value: SegmentValue::Script(vec![]),
                })),
            },]),
        })
    );
}

#[test]
fn parse_script_push_of_a_literal() {
    assert_eq!(
        parse_script("<\"abc\">"),
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 8,
                line: 1,
                offset: 7,
            },
            name: SegmentName::Script,
            start: SourcePosition {
                column: 1,
                line: 1,
                offset: 0,
            },
            value: SegmentValue::Script(vec![Segment {
                end: SourcePosition {
                    column: 8,
                    line: 1,
                    offset: 7,
                },
                name: SegmentName::Push,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Push(Box::new(Segment {
                    end: SourcePosition {
                        column: 7,
                        line: 1,
                        offset: 6,
                    },
                    name: SegmentName::Script,
                    start: SourcePosition {
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    value: SegmentValue::Script(vec![Segment {
                        end: SourcePosition {
                            column: 7,
                            line: 1,
                            offset: 6,
                        },
                        name: SegmentName::Utf8Literal,
                        start: SourcePosition {
                            column: 2,
                            line: 1,
                            offset: 1,
                        },
                        value: SegmentValue::Text("abc".to_string()),
                    },]),
                })),
            },]),
        })
    );
}

#[test]
fn parse_script_push_of_a_push_statement() {
    assert_eq!(
        parse_script("<<>>"),
        ParseResult::Success(Segment {
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
                name: SegmentName::Push,
                start: SourcePosition {
                    column: 1,
                    line: 1,
                    offset: 0,
                },
                value: SegmentValue::Push(Box::new(Segment {
                    end: SourcePosition {
                        column: 4,
                        line: 1,
                        offset: 3,
                    },
                    name: SegmentName::Script,
                    start: SourcePosition {
                        column: 2,
                        line: 1,
                        offset: 1,
                    },
                    value: SegmentValue::Script(vec![Segment {
                        end: SourcePosition {
                            column: 4,
                            line: 1,
                            offset: 3,
                        },
                        name: SegmentName::Push,
                        start: SourcePosition {
                            column: 2,
                            line: 1,
                            offset: 1,
                        },
                        value: SegmentValue::Push(Box::new(Segment {
                            end: SourcePosition {
                                column: 3,
                                line: 1,
                                offset: 2,
                            },
                            name: SegmentName::Script,
                            start: SourcePosition {
                                column: 3,
                                line: 1,
                                offset: 2,
                            },
                            value: SegmentValue::Script(vec![]),
                        })),
                    },]),
                })),
            },]),
        })
    );
}

#[test]
fn parse_script_push_of_an_evaluation() {
    assert_eq!(
        parse_script("<$(<1><2> OP_ADD)> OP_EQUAL"),
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 28,
                line: 1,
                offset: 27,
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
                        column: 19,
                        line: 1,
                        offset: 18,
                    },
                    name: SegmentName::Push,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Push(Box::new(Segment {
                        end: SourcePosition {
                            column: 18,
                            line: 1,
                            offset: 17,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 2,
                            line: 1,
                            offset: 1,
                        },
                        value: SegmentValue::Script(vec![Segment {
                            end: SourcePosition {
                                column: 18,
                                line: 1,
                                offset: 17,
                            },
                            name: SegmentName::Evaluation,
                            start: SourcePosition {
                                column: 2,
                                line: 1,
                                offset: 1,
                            },
                            value: SegmentValue::Evaluation(Box::new(Segment {
                                end: SourcePosition {
                                    column: 17,
                                    line: 1,
                                    offset: 16,
                                },
                                name: SegmentName::Script,
                                start: SourcePosition {
                                    column: 4,
                                    line: 1,
                                    offset: 3,
                                },
                                value: SegmentValue::Script(vec![
                                    Segment {
                                        end: SourcePosition {
                                            column: 7,
                                            line: 1,
                                            offset: 6,
                                        },
                                        name: SegmentName::Push,
                                        start: SourcePosition {
                                            column: 4,
                                            line: 1,
                                            offset: 3,
                                        },
                                        value: SegmentValue::Push(Box::new(Segment {
                                            end: SourcePosition {
                                                column: 6,
                                                line: 1,
                                                offset: 5,
                                            },
                                            name: SegmentName::Script,
                                            start: SourcePosition {
                                                column: 5,
                                                line: 1,
                                                offset: 4,
                                            },
                                            value: SegmentValue::Script(vec![Segment {
                                                end: SourcePosition {
                                                    column: 6,
                                                    line: 1,
                                                    offset: 5,
                                                },
                                                name: SegmentName::BigIntLiteral,
                                                start: SourcePosition {
                                                    column: 5,
                                                    line: 1,
                                                    offset: 4,
                                                },
                                                value: SegmentValue::Text("1".to_string()),
                                            },]),
                                        })),
                                    },
                                    Segment {
                                        end: SourcePosition {
                                            column: 10,
                                            line: 1,
                                            offset: 9,
                                        },
                                        name: SegmentName::Push,
                                        start: SourcePosition {
                                            column: 7,
                                            line: 1,
                                            offset: 6,
                                        },
                                        value: SegmentValue::Push(Box::new(Segment {
                                            end: SourcePosition {
                                                column: 9,
                                                line: 1,
                                                offset: 8,
                                            },
                                            name: SegmentName::Script,
                                            start: SourcePosition {
                                                column: 8,
                                                line: 1,
                                                offset: 7,
                                            },
                                            value: SegmentValue::Script(vec![Segment {
                                                end: SourcePosition {
                                                    column: 9,
                                                    line: 1,
                                                    offset: 8,
                                                },
                                                name: SegmentName::BigIntLiteral,
                                                start: SourcePosition {
                                                    column: 8,
                                                    line: 1,
                                                    offset: 7,
                                                },
                                                value: SegmentValue::Text("2".to_string()),
                                            },]),
                                        })),
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
                            })),
                        },]),
                    })),
                },
                Segment {
                    end: SourcePosition {
                        column: 28,
                        line: 1,
                        offset: 27,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 20,
                        line: 1,
                        offset: 19,
                    },
                    value: SegmentValue::Text("OP_EQUAL".to_string()),
                },
            ]),
        })
    );
}

#[test]
fn parse_script_invalid_identifier_characters() {
    assert_eq!(
        parse_script("test_$variable"),
        ParseResult::Failure {
            expected: vec!["the opening parenthesis of this evaluation ('(')".to_string(),],
            index: SourcePosition {
                column: 7,
                line: 1,
                offset: 6,
            },
        }
    );
}

#[test]
fn parse_script_incomplete_utf8_literal() {
    assert_eq!(
        parse_script("'incomplete"),
        ParseResult::Failure {
            expected: vec!["a closing single quote (')".to_string()],
            index: SourcePosition {
                column: 12,
                line: 1,
                offset: 11,
            },
        }
    );
    assert_eq!(
        parse_script("\"incomplete"),
        ParseResult::Failure {
            expected: vec!["a closing double quote (\")".to_string()],
            index: SourcePosition {
                column: 12,
                line: 1,
                offset: 11,
            },
        }
    );
}

#[test]
fn parse_script_big_int_literal_without_trailing_whitespace() {
    assert_eq!(
        parse_script("1234a"),
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 6,
                line: 1,
                offset: 5,
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
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("1234".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 6,
                        line: 1,
                        offset: 5,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 5,
                        line: 1,
                        offset: 4,
                    },
                    value: SegmentValue::Text("a".to_string()),
                },
            ]),
        })
    );
}

#[test]
fn parse_script_hex_literal_without_trailing_whitespace() {
    assert_eq!(
        parse_script("0x010203f"),
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 10,
                line: 1,
                offset: 9,
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
                        column: 9,
                        line: 1,
                        offset: 8,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 1,
                        line: 1,
                        offset: 0,
                    },
                    value: SegmentValue::Text("010203".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 10,
                        line: 1,
                        offset: 9,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 9,
                        line: 1,
                        offset: 8,
                    },
                    value: SegmentValue::Text("f".to_string()),
                },
            ]),
        })
    );
}

#[test]
fn parse_script_incomplete_push() {
    assert_eq!(
        parse_script("<my_var"),
        ParseResult::Failure {
            expected: vec![
                "a binary literal ('0b...')".to_string(),
                "a double quote (\")".to_string(),
                "a hex literal ('0x...')".to_string(),
                "a single quote (')".to_string(),
                "a valid identifier".to_string(),
                "an integer literal".to_string(),
                "the end of this push statement ('>')".to_string(),
                "the start of a multi-line comment ('/*')".to_string(),
                "the start of a push statement ('<')".to_string(),
                "the start of a single-line comment ('//')".to_string(),
                "the start of an evaluation ('$')".to_string(),
            ],
            index: SourcePosition {
                column: 8,
                line: 1,
                offset: 7,
            },
        }
    );
}

#[test]
fn parse_script_incomplete_multi_line_comment() {
    assert_eq!(
        parse_script("identifier /* \n multi-line\ncomment\n"),
        ParseResult::Failure {
            expected: vec!["the end of this multi-line comment ('*/')".to_string()],
            index: SourcePosition {
                column: 14,
                line: 1,
                offset: 13,
            },
        }
    );
}

#[test]
fn parse_script_incomplete_evaluation() {
    assert_eq!(
        parse_script("<$"),
        ParseResult::Failure {
            expected: vec!["the opening parenthesis of this evaluation ('(')".to_string(),],
            index: SourcePosition {
                column: 3,
                line: 1,
                offset: 2,
            },
        }
    );
    assert_eq!(
        parse_script("<$(<1> <2> OP_ADD >"),
        ParseResult::Failure {
            expected: vec![
                "a binary literal ('0b...')".to_string(),
                "a double quote (\")".to_string(),
                "a hex literal ('0x...')".to_string(),
                "a single quote (')".to_string(),
                "a valid identifier".to_string(),
                "an integer literal".to_string(),
                "the closing parenthesis of this evaluation (')')".to_string(),
                "the start of a multi-line comment ('/*')".to_string(),
                "the start of a push statement ('<')".to_string(),
                "the start of a single-line comment ('//')".to_string(),
                "the start of an evaluation ('$')".to_string(),
            ],
            index: SourcePosition {
                column: 19,
                line: 1,
                offset: 18,
            },
        }
    );
}

#[test]
fn parse_script_complex_script() {
    let script = r#"
// there are plenty of ways to push 0/call OP_0
<0> OP_0 0 0x00 $(OP_0) <$(OP_0)> $(< -1 > < 1 > OP_ADD)
/**
 * A multi-line comment 🚀
 * Followed by some UTF8Literals
 */
'abc' "'🧙'"
// a comment at the end
"#;
    let result = parse_script(script);
    assert_eq!(
        result,
        ParseResult::Success(Segment {
            end: SourcePosition {
                column: 1,
                line: 10,
                offset: 211,
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
                        column: 48,
                        line: 2,
                        offset: 48,
                    },
                    name: SegmentName::Comment,
                    start: SourcePosition {
                        column: 1,
                        line: 2,
                        offset: 1,
                    },
                    value: SegmentValue::Text(
                        "there are plenty of ways to push 0/call OP_0".to_string()
                    ),
                },
                Segment {
                    end: SourcePosition {
                        column: 4,
                        line: 3,
                        offset: 52,
                    },
                    name: SegmentName::Push,
                    start: SourcePosition {
                        column: 1,
                        line: 3,
                        offset: 49,
                    },
                    value: SegmentValue::Push(Box::new(Segment {
                        end: SourcePosition {
                            column: 3,
                            line: 3,
                            offset: 51,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 2,
                            line: 3,
                            offset: 50,
                        },
                        value: SegmentValue::Script(vec![Segment {
                            end: SourcePosition {
                                column: 3,
                                line: 3,
                                offset: 51,
                            },
                            name: SegmentName::BigIntLiteral,
                            start: SourcePosition {
                                column: 2,
                                line: 3,
                                offset: 50,
                            },
                            value: SegmentValue::Text("0".to_string()),
                        },]),
                    })),
                },
                Segment {
                    end: SourcePosition {
                        column: 9,
                        line: 3,
                        offset: 57,
                    },
                    name: SegmentName::Identifier,
                    start: SourcePosition {
                        column: 5,
                        line: 3,
                        offset: 53,
                    },
                    value: SegmentValue::Text("OP_0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 11,
                        line: 3,
                        offset: 59,
                    },
                    name: SegmentName::BigIntLiteral,
                    start: SourcePosition {
                        column: 10,
                        line: 3,
                        offset: 58,
                    },
                    value: SegmentValue::Text("0".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 16,
                        line: 3,
                        offset: 64,
                    },
                    name: SegmentName::HexLiteral,
                    start: SourcePosition {
                        column: 12,
                        line: 3,
                        offset: 60,
                    },
                    value: SegmentValue::Text("00".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 24,
                        line: 3,
                        offset: 72,
                    },
                    name: SegmentName::Evaluation,
                    start: SourcePosition {
                        column: 17,
                        line: 3,
                        offset: 65,
                    },
                    value: SegmentValue::Evaluation(Box::new(Segment {
                        end: SourcePosition {
                            column: 23,
                            line: 3,
                            offset: 71,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 19,
                            line: 3,
                            offset: 67,
                        },
                        value: SegmentValue::Script(vec![Segment {
                            end: SourcePosition {
                                column: 23,
                                line: 3,
                                offset: 71,
                            },
                            name: SegmentName::Identifier,
                            start: SourcePosition {
                                column: 19,
                                line: 3,
                                offset: 67,
                            },
                            value: SegmentValue::Text("OP_0".to_string()),
                        },]),
                    })),
                },
                Segment {
                    end: SourcePosition {
                        column: 34,
                        line: 3,
                        offset: 82,
                    },
                    name: SegmentName::Push,
                    start: SourcePosition {
                        column: 25,
                        line: 3,
                        offset: 73,
                    },
                    value: SegmentValue::Push(Box::new(Segment {
                        end: SourcePosition {
                            column: 33,
                            line: 3,
                            offset: 81,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 26,
                            line: 3,
                            offset: 74,
                        },
                        value: SegmentValue::Script(vec![Segment {
                            end: SourcePosition {
                                column: 33,
                                line: 3,
                                offset: 81,
                            },
                            name: SegmentName::Evaluation,
                            start: SourcePosition {
                                column: 26,
                                line: 3,
                                offset: 74,
                            },
                            value: SegmentValue::Evaluation(Box::new(Segment {
                                end: SourcePosition {
                                    column: 32,
                                    line: 3,
                                    offset: 80,
                                },
                                name: SegmentName::Script,
                                start: SourcePosition {
                                    column: 28,
                                    line: 3,
                                    offset: 76,
                                },
                                value: SegmentValue::Script(vec![Segment {
                                    end: SourcePosition {
                                        column: 32,
                                        line: 3,
                                        offset: 80,
                                    },
                                    name: SegmentName::Identifier,
                                    start: SourcePosition {
                                        column: 28,
                                        line: 3,
                                        offset: 76,
                                    },
                                    value: SegmentValue::Text("OP_0".to_string()),
                                },]),
                            })),
                        },]),
                    })),
                },
                Segment {
                    end: SourcePosition {
                        column: 57,
                        line: 3,
                        offset: 105,
                    },
                    name: SegmentName::Evaluation,
                    start: SourcePosition {
                        column: 35,
                        line: 3,
                        offset: 83,
                    },
                    value: SegmentValue::Evaluation(Box::new(Segment {
                        end: SourcePosition {
                            column: 56,
                            line: 3,
                            offset: 104,
                        },
                        name: SegmentName::Script,
                        start: SourcePosition {
                            column: 37,
                            line: 3,
                            offset: 85,
                        },
                        value: SegmentValue::Script(vec![
                            Segment {
                                end: SourcePosition {
                                    column: 43,
                                    line: 3,
                                    offset: 91,
                                },
                                name: SegmentName::Push,
                                start: SourcePosition {
                                    column: 37,
                                    line: 3,
                                    offset: 85,
                                },
                                value: SegmentValue::Push(Box::new(Segment {
                                    end: SourcePosition {
                                        column: 42,
                                        line: 3,
                                        offset: 90,
                                    },
                                    name: SegmentName::Script,
                                    start: SourcePosition {
                                        column: 38,
                                        line: 3,
                                        offset: 86,
                                    },
                                    value: SegmentValue::Script(vec![Segment {
                                        end: SourcePosition {
                                            column: 41,
                                            line: 3,
                                            offset: 89,
                                        },
                                        name: SegmentName::BigIntLiteral,
                                        start: SourcePosition {
                                            column: 39,
                                            line: 3,
                                            offset: 87,
                                        },
                                        value: SegmentValue::Text("-1".to_string()),
                                    },]),
                                })),
                            },
                            Segment {
                                end: SourcePosition {
                                    column: 49,
                                    line: 3,
                                    offset: 97,
                                },
                                name: SegmentName::Push,
                                start: SourcePosition {
                                    column: 44,
                                    line: 3,
                                    offset: 92,
                                },
                                value: SegmentValue::Push(Box::new(Segment {
                                    end: SourcePosition {
                                        column: 48,
                                        line: 3,
                                        offset: 96,
                                    },
                                    name: SegmentName::Script,
                                    start: SourcePosition {
                                        column: 45,
                                        line: 3,
                                        offset: 93,
                                    },
                                    value: SegmentValue::Script(vec![Segment {
                                        end: SourcePosition {
                                            column: 47,
                                            line: 3,
                                            offset: 95,
                                        },
                                        name: SegmentName::BigIntLiteral,
                                        start: SourcePosition {
                                            column: 46,
                                            line: 3,
                                            offset: 94,
                                        },
                                        value: SegmentValue::Text("1".to_string()),
                                    },]),
                                })),
                            },
                            Segment {
                                end: SourcePosition {
                                    column: 56,
                                    line: 3,
                                    offset: 104,
                                },
                                name: SegmentName::Identifier,
                                start: SourcePosition {
                                    column: 50,
                                    line: 3,
                                    offset: 98,
                                },
                                value: SegmentValue::Text("OP_ADD".to_string()),
                            },
                        ]),
                    })),
                },
                Segment {
                    end: SourcePosition {
                        column: 4,
                        line: 7,
                        offset: 173,
                    },
                    name: SegmentName::Comment,
                    start: SourcePosition {
                        column: 1,
                        line: 4,
                        offset: 106,
                    },
                    value: SegmentValue::Text(
                        "*\n * A multi-line comment 🚀\n * Followed by some UTF8Literals"
                            .to_string()
                    ),
                },
                Segment {
                    end: SourcePosition {
                        column: 6,
                        line: 8,
                        offset: 179,
                    },
                    name: SegmentName::Utf8Literal,
                    start: SourcePosition {
                        column: 1,
                        line: 8,
                        offset: 174,
                    },
                    value: SegmentValue::Text("abc".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 13,
                        line: 8,
                        offset: 186,
                    },
                    name: SegmentName::Utf8Literal,
                    start: SourcePosition {
                        column: 7,
                        line: 8,
                        offset: 180,
                    },
                    value: SegmentValue::Text("'🧙'".to_string()),
                },
                Segment {
                    end: SourcePosition {
                        column: 24,
                        line: 9,
                        offset: 210,
                    },
                    name: SegmentName::Comment,
                    start: SourcePosition {
                        column: 1,
                        line: 9,
                        offset: 187,
                    },
                    value: SegmentValue::Text("a comment at the end".to_string()),
                },
            ]),
        })
    );
}
