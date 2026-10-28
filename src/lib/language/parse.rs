//! CashAssembly parsing (port of `language/parse.ts`).

use std::ops::Range;
use std::rc::Rc;

use super::language_types::{ParseResult, Segment, SegmentName, SegmentValue};
use super::parsimmon::{Language, Parser, Rules, Value, P};
use crate::format::lossy_normalize;
use crate::runtime::regexp::RegExp;
use crate::runtime::string::trim;

type Captures = Option<Vec<Option<Range<usize>>>>;

fn full_match(length: usize) -> Captures {
    Some(vec![Some(0..length)])
}

fn is_digit(unit: u16) -> bool {
    (u16::from(b'0')..=u16::from(b'9')).contains(&unit)
}

fn is_hex_digit(unit: u16) -> bool {
    is_digit(unit) || (u16::from(b'a')..=u16::from(b'f')).contains(&unit) || (u16::from(b'A')..=u16::from(b'F')).contains(&unit)
}

/// `/[^\n]*/u`
fn match_until_newline(input: &[u16]) -> Captures {
    full_match(input.iter().take_while(|unit| **unit != u16::from(b'\n')).count())
}

/// `/[\s\S]*?\*\//u`
fn match_multi_line_comment_end(input: &[u16]) -> Captures {
    let end = input.windows(2).position(|pair| pair == [u16::from(b'*'), u16::from(b'/')])?;
    full_match(end + 2)
}

/// `/[a-zA-Z_][.a-zA-Z0-9_-]*/u`
fn match_identifier(input: &[u16]) -> Captures {
    let is_letter = |unit: u16| u8::try_from(unit).is_ok_and(|byte| byte.is_ascii_alphabetic());
    let first = *input.first()?;
    if !is_letter(first) && first != u16::from(b'_') {
        return None;
    }
    let rest = input[1..]
        .iter()
        .take_while(|unit| {
            is_letter(**unit) || is_digit(**unit) || [b'.', b'_', b'-'].map(u16::from).contains(*unit)
        })
        .count();
    full_match(1 + rest)
}

/// `/[^"]*/u` or `/[^']*/u`
fn match_until(input: &[u16], quote: u8) -> Captures {
    full_match(input.iter().take_while(|unit| **unit != u16::from(quote)).count())
}

/// `/[0-9a-f]_*(?:_*[0-9a-f]_*[0-9a-f]_*)*[0-9a-f]/iu`: the longest prefix of
/// hex digits and underscores which starts and ends with a hex digit and
/// contains an even number (at least two) of hex digits.
fn match_hex(input: &[u16]) -> Captures {
    if !input.first().is_some_and(|unit| is_hex_digit(*unit)) {
        return None;
    }
    let digits: Vec<usize> = input
        .iter()
        .take_while(|unit| is_hex_digit(**unit) || **unit == u16::from(b'_'))
        .enumerate()
        .filter(|(_, unit)| is_hex_digit(**unit))
        .map(|(position, _)| position)
        .collect();
    let even = digits.len() - digits.len() % 2;
    if even < 2 {
        return None;
    }
    full_match(digits[even - 1] + 1)
}

/// `/[01]+(?:[01_]*[01]+)*/iu`
fn match_binary(input: &[u16]) -> Captures {
    let is_binary = |unit: u16| unit == u16::from(b'0') || unit == u16::from(b'1');
    if !input.first().is_some_and(|unit| is_binary(*unit)) {
        return None;
    }
    let candidate = input
        .iter()
        .take_while(|unit| is_binary(**unit) || **unit == u16::from(b'_'))
        .count();
    let last_digit = input[..candidate].iter().rposition(|unit| is_binary(*unit))?;
    full_match(last_digit + 1)
}

/// `/-?[0-9]+(?:[0-9_]*[0-9]+)*/u`
fn match_big_int(input: &[u16]) -> Captures {
    let sign = usize::from(input.first() == Some(&u16::from(b'-')));
    if !input.get(sign).is_some_and(|unit| is_digit(*unit)) {
        return None;
    }
    let candidate = sign
        + input[sign..]
            .iter()
            .take_while(|unit| is_digit(**unit) || **unit == u16::from(b'_'))
            .count();
    let last_digit = input[..candidate].iter().rposition(|unit| is_digit(*unit))?;
    full_match(last_digit + 1)
}

fn regexp(source: &'static str, flags: &'static str, exec: fn(&[u16]) -> Captures) -> Parser {
    P::regexp(&RegExp { source, flags, exec }, None)
}

fn text(value: &Value) -> &str {
    match value {
        Value::String(text) => text,
        _ => unreachable!("expected a string value"),
    }
}

fn nth(values: Vec<Value>, index: usize) -> Value {
    values.into_iter().nth(index).expect("a value at the index")
}

fn rule(parser: impl Fn(&Language) -> Parser + 'static) -> Rc<dyn Fn(&Language) -> Parser> {
    Rc::new(parser)
}

#[rustfmt::skip]
fn rules() -> Rules {
    vec![
        ("script", rule(|r| {
            P::seq_map(
                vec![
                    P::opt_whitespace(),
                    r["expression"].sep_by(&P::opt_whitespace()),
                    P::opt_whitespace(),
                ],
                |values| nth(values, 1),
            )
            .node("Script")
        })),
        ("expression", rule(|r| {
            P::alt(vec![
                r["comment"].clone(),
                r["push"].clone(),
                r["evaluation"].clone(),
                r["utf8"].clone(),
                r["binary"].clone(),
                r["hex"].clone(),
                r["bigint"].clone(),
                r["identifier"].clone(),
            ])
        })),
        ("comment", rule(|r| {
            P::alt(vec![r["singleLineComment"].clone(), r["multiLineComment"].clone()]).node("Comment")
        })),
        ("singleLineComment", rule(|_| {
            P::seq_map(
                vec![
                    P::string("//").desc("the start of a single-line comment ('//')"),
                    regexp(r"[^\n]*", "u", match_until_newline),
                ],
                |values| Value::String(trim(text(&values[1]))),
            )
        })),
        ("multiLineComment", rule(|_| {
            P::seq_map(
                vec![
                    P::string("/*").desc("the start of a multi-line comment ('/*')"),
                    regexp(r"[\s\S]*?\*\/", "u", match_multi_line_comment_end)
                        .desc("the end of this multi-line comment ('*/')"),
                ],
                |values| {
                    let comment = text(&values[1]);
                    Value::String(trim(&comment[..comment.len() - "*/".len()]))
                },
            )
        })),
        ("push", rule(|r| {
            P::seq_map(
                vec![
                    P::string("<").desc("the start of a push statement ('<')"),
                    r["script"].clone(),
                    P::string(">").desc("the end of this push statement ('>')"),
                ],
                |values| nth(values, 1),
            )
            .node("Push")
        })),
        ("evaluation", rule(|r| {
            P::seq_map(
                vec![
                    P::string("$").desc("the start of an evaluation ('$')"),
                    P::string("(").desc("the opening parenthesis of this evaluation ('(')"),
                    r["script"].clone(),
                    P::string(")").desc("the closing parenthesis of this evaluation (')')"),
                ],
                |values| nth(values, 2),
            )
            .node("Evaluation")
        })),
        ("identifier", rule(|_| {
            regexp("[a-zA-Z_][.a-zA-Z0-9_-]*", "u", match_identifier)
                .desc("a valid identifier")
                .node("Identifier")
        })),
        ("utf8", rule(|_| {
            P::alt(vec![
                P::seq_map(
                    vec![
                        P::string("\"").desc("a double quote (\")"),
                        regexp("[^\"]*", "u", |input| match_until(input, b'"')),
                        P::string("\"").desc("a closing double quote (\")"),
                    ],
                    |values| nth(values, 1),
                ),
                P::seq_map(
                    vec![
                        P::string("'").desc("a single quote (')"),
                        regexp("[^']*", "u", |input| match_until(input, b'\'')),
                        P::string("'").desc("a closing single quote (')"),
                    ],
                    |values| nth(values, 1),
                ),
            ])
            .node("UTF8Literal")
        })),
        ("hex", rule(|_| {
            P::seq_map(
                vec![
                    P::string("0x").desc("a hex literal ('0x...')"),
                    regexp("[0-9a-f]_*(?:_*[0-9a-f]_*[0-9a-f]_*)*[0-9a-f]", "iu", match_hex)
                        .desc("a valid hexadecimal string"),
                ],
                |values| nth(values, 1),
            )
            .node("HexLiteral")
        })),
        ("binary", rule(|_| {
            P::seq_map(
                vec![
                    P::string("0b").desc("a binary literal ('0b...')"),
                    regexp("[01]+(?:[01_]*[01]+)*", "iu", match_binary).desc("a string of binary digits"),
                ],
                |values| nth(values, 1),
            )
            .node("BinaryLiteral")
        })),
        ("bigint", rule(|_| {
            regexp("-?[0-9]+(?:[0-9_]*[0-9]+)*", "u", match_big_int)
                .desc("an integer literal")
                .node("BigIntLiteral")
        })),
    ]
}

thread_local! {
    static cashAssemblyParser: Language = P::create_language(rules());
}

/// Convert a parsed `Node` to a [`Segment`] (in libauth, `parseScript` casts
/// the parser's result to `ParseResult`).
fn to_segment(node: Value) -> Segment {
    let Value::Node { end, name, start, value } = node else {
        unreachable!("the parser produces nodes")
    };
    let (name, value) = match (name.as_str(), *value) {
        ("Script", Value::Array(segments)) => (
            SegmentName::Script,
            SegmentValue::Script(segments.into_iter().map(to_segment).collect()),
        ),
        ("Push", script) => (SegmentName::Push, SegmentValue::Push(Box::new(to_segment(script)))),
        ("Evaluation", script) => (
            SegmentName::Evaluation,
            SegmentValue::Evaluation(Box::new(to_segment(script))),
        ),
        (name, Value::String(text)) => (
            match name {
                "Comment" => SegmentName::Comment,
                "Identifier" => SegmentName::Identifier,
                "UTF8Literal" => SegmentName::Utf8Literal,
                "HexLiteral" => SegmentName::HexLiteral,
                "BinaryLiteral" => SegmentName::BinaryLiteral,
                "BigIntLiteral" => SegmentName::BigIntLiteral,
                _ => unreachable!("unknown node: {name}"),
            },
            SegmentValue::Text(text),
        ),
        (name, _) => unreachable!("unexpected value for node: {name}"),
    };
    Segment { end, name, start, value }
}

/// Parse a CashAssembly script.
pub fn parse_script(script: &str) -> ParseResult {
    let result = cashAssemblyParser.with(|parser| parser["script"].parse(&lossy_normalize(script)));
    match result {
        Ok(value) => ParseResult::Success(to_segment(value)),
        Err(failure) => ParseResult::Failure {
            expected: failure.expected,
            index: failure.index,
        },
    }
}
