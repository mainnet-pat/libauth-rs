//! A minimal fork of Parsimmon, the parser combinator library used by the
//! CashAssembly parser (port of `language/parsimmon.ts`).
//!
//! libauth's Parsimmon is dynamically typed: parsers produce untyped
//! JavaScript values. Here, parsers produce [`Value`]s, and inputs are
//! JavaScript strings as UTF-16 code units (so offsets and columns match
//! libauth's).

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::language_types::SourcePosition;
use crate::runtime::regexp::{is_white_space, RegExp};

/// A position in the input (libauth's `Index`).
pub type Index = SourcePosition;

/// A value produced by a parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// A string.
    String(String),
    /// An array of values.
    Array(Vec<Value>),
    /// A position in the input (produced by [`P::index`]).
    Index(Index),
    /// A named value marked with its start and end positions (produced by
    /// [`Parser::node`]; libauth's `Node`).
    Node {
        end: Index,
        name: String,
        start: Index,
        value: Box<Value>,
    },
}

/// The result of applying a parser at a position in the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub expected: Vec<String>,
    pub furthest: isize,
    pub index: isize,
    pub status: bool,
    pub value: Value,
}

/// The result of a failed [`Parser::parse`] (libauth's `Failure`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub expected: Vec<String>,
    pub index: Index,
}

/// A parser: a function from the input and a position to a [`Reply`].
#[derive(Clone)]
pub struct Parser {
    action: Rc<dyn Fn(&[u16], usize) -> Reply>,
}

fn parsimmon(action: impl Fn(&[u16], usize) -> Reply + 'static) -> Parser {
    Parser {
        action: Rc::new(action),
    }
}

fn make_success(index: usize, value: Value) -> Reply {
    Reply {
        expected: Vec::new(),
        furthest: -1,
        index: index as isize,
        status: true,
        value,
    }
}

fn make_failure(index: usize, expected: &str) -> Reply {
    Reply {
        expected: vec![expected.to_string()],
        furthest: index as isize,
        index: -1,
        status: false,
        value: Value::Null,
    }
}

fn merge_replies(result: Reply, last: Option<&Reply>) -> Reply {
    let Some(last) = last else {
        return result;
    };
    if result.furthest > last.furthest {
        return result;
    }
    let expected = if result.furthest == last.furthest {
        union(&result.expected, &last.expected)
    } else {
        last.expected.clone()
    };
    Reply {
        expected,
        furthest: last.furthest,
        index: result.index,
        status: result.status,
        value: result.value,
    }
}

fn make_line_column_index(input: &[u16], i: isize) -> Index {
    // `input.slice(0, i)`
    let end = if i < 0 {
        input.len().saturating_sub(i.unsigned_abs())
    } else {
        (i as usize).min(input.len())
    };
    let lines: Vec<&[u16]> = input[..end].split(|unit| *unit == u16::from(b'\n')).collect();
    let line_we_are_up_to = lines.len();
    let column_we_are_up_to = lines.last().map_or(0, |line| line.len()) + 1;
    Index {
        column: column_we_are_up_to,
        line: line_we_are_up_to,
        offset: i.max(0) as usize,
    }
}

/// The sorted union of two lists of strings (sorted by UTF-16 code units, like
/// `Array.prototype.sort`).
fn union(xs: &[String], ys: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = xs.iter().chain(ys).cloned().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    keys.dedup();
    keys
}

fn seq(parsers: Vec<Parser>) -> Parser {
    parsimmon(move |input, mut i| {
        let mut result: Option<Reply> = None;
        let mut accum = Vec::with_capacity(parsers.len());
        for parser in &parsers {
            let mut reply = merge_replies((parser.action)(input, i), result.as_ref());
            if !reply.status {
                return reply;
            }
            accum.push(std::mem::replace(&mut reply.value, Value::Null));
            i = reply.index as usize;
            result = Some(reply);
        }
        merge_replies(make_success(i, Value::Array(accum)), result.as_ref())
    })
}

fn seq_map(parsers: Vec<Parser>, mapper: impl Fn(Vec<Value>) -> Value + 'static) -> Parser {
    seq(parsers).map(move |results| match results {
        Value::Array(results) => mapper(results),
        _ => unreachable!("seq produces arrays"),
    })
}

/// A set of mutually-referential parsers created by [`P::create_language`];
/// index it by rule name (`language["script"]`).
#[derive(Clone)]
pub struct Language {
    rules: Rc<OnceCell<BTreeMap<&'static str, Parser>>>,
}

impl std::ops::Index<&str> for Language {
    type Output = Parser;
    fn index(&self, rule: &str) -> &Parser {
        self.rules
            .get()
            .expect("the language is created")
            .get(rule)
            .unwrap_or_else(|| panic!("unknown rule: {rule}"))
    }
}

/// The rules of a language: each rule's name and a function returning its
/// parser given the language (libauth's `TypedRule`).
pub type Rules = Vec<(&'static str, Rc<dyn Fn(&Language) -> Parser>)>;

fn create_language(parsers: Rules) -> Language {
    let language = Language {
        rules: Rc::new(OnceCell::new()),
    };
    let rules = parsers
        .into_iter()
        .map(|(rule, func)| {
            let reference = language.clone();
            (rule, lazy(move || func(&reference)))
        })
        .collect();
    language
        .rules
        .set(rules)
        .unwrap_or_else(|_| unreachable!("the language is created once"));
    language
}

fn alt(parsers: Vec<Parser>) -> Parser {
    parsimmon(move |input, i| {
        let mut result: Option<Reply> = None;
        for parser in &parsers {
            let reply = merge_replies((parser.action)(input, i), result.as_ref());
            if reply.status {
                return reply;
            }
            result = Some(reply);
        }
        result.expect("alt requires at least one parser")
    })
}

fn sep_by(parser: &Parser, separator: &Parser) -> Parser {
    sep_by1(parser, separator).or(&succeed(Value::Array(Vec::new())))
}

fn sep_by1(parser: &Parser, separator: &Parser) -> Parser {
    let pairs = separator.then(parser).many();
    seq_map(vec![parser.clone(), pairs], |results| {
        let mut results = results.into_iter();
        let r = results.next().expect("two results");
        let Some(Value::Array(rs)) = results.next() else {
            unreachable!("many produces arrays")
        };
        Value::Array(std::iter::once(r).chain(rs).collect())
    })
}

impl Parser {
    /// Apply the parser at a position in the input.
    fn apply(&self, input: &[u16], i: usize) -> Reply {
        (self.action)(input, i)
    }

    /// Parse the whole `input` (which must be fully consumed).
    pub fn parse(&self, input: &str) -> Result<Value, Failure> {
        let input: Vec<u16> = input.encode_utf16().collect();
        let result = self.skip(&eof()).apply(&input, 0);
        if result.status {
            return Ok(result.value);
        }
        Err(Failure {
            expected: result.expected,
            index: make_line_column_index(&input, result.furthest),
        })
    }

    /// Try this parser, then `alternative`.
    pub fn or(&self, alternative: &Parser) -> Parser {
        alt(vec![self.clone(), alternative.clone()])
    }

    /// Apply this parser, then `next`, keeping the result of `next`.
    pub fn then(&self, next: &Parser) -> Parser {
        seq(vec![self.clone(), next.clone()]).map(|results| match results {
            Value::Array(mut results) => results.swap_remove(1),
            _ => unreachable!("seq produces arrays"),
        })
    }

    /// Apply this parser zero or more times, producing an array of results.
    pub fn many(&self) -> Parser {
        let parser = self.clone();
        parsimmon(move |input, mut i| {
            let mut accum = Vec::new();
            let mut result: Option<Reply> = None;
            loop {
                let mut reply = merge_replies(parser.apply(input, i), result.as_ref());
                if reply.status {
                    if i as isize == reply.index {
                        panic!(
                            "infinite loop detected in .many() parser --- calling .many() on a parser that can accept zero characters is usually the cause"
                        );
                    }
                    i = reply.index as usize;
                    accum.push(std::mem::replace(&mut reply.value, Value::Null));
                    result = Some(reply);
                } else {
                    return merge_replies(make_success(i, Value::Array(accum)), Some(&reply));
                }
            }
        })
    }

    /// Transform the result of this parser.
    pub fn map(&self, fn_: impl Fn(Value) -> Value + 'static) -> Parser {
        let parser = self.clone();
        parsimmon(move |input, i| {
            let mut result = parser.apply(input, i);
            if !result.status {
                return result;
            }
            let index = result.index as usize;
            let value = fn_(std::mem::replace(&mut result.value, Value::Null));
            merge_replies(make_success(index, value), Some(&result))
        })
    }

    /// Apply this parser, then `next`, keeping the result of this parser.
    pub fn skip(&self, next: &Parser) -> Parser {
        seq(vec![self.clone(), next.clone()]).map(|results| match results {
            Value::Array(mut results) => results.swap_remove(0),
            _ => unreachable!("seq produces arrays"),
        })
    }

    /// Mark the result of this parser with `name` and its start and end
    /// positions.
    pub fn node(&self, name: &str) -> Parser {
        let name = name.to_string();
        seq_map(vec![index(), self.clone(), index()], move |results| {
            let [Value::Index(start), value, Value::Index(end)]: [Value; 3] =
                results.try_into().expect("three results")
            else {
                unreachable!("index produces indexes")
            };
            Value::Node {
                end,
                name: name.clone(),
                start,
                value: Box::new(value),
            }
        })
    }

    /// Apply this parser zero or more times, separated by `separator`.
    pub fn sep_by(&self, separator: &Parser) -> Parser {
        sep_by(self, separator)
    }

    /// Describe what this parser expects when it fails.
    pub fn desc(&self, expected: &str) -> Parser {
        let expected = vec![expected.to_string()];
        let parser = self.clone();
        parsimmon(move |input, i| {
            let mut reply = parser.apply(input, i);
            if !reply.status {
                reply.expected = expected.clone();
            }
            reply
        })
    }
}

fn string(str: &str) -> Parser {
    let expected = format!("'{str}'");
    let units: Vec<u16> = str.encode_utf16().collect();
    let value = str.to_string();
    parsimmon(move |input, i| {
        let j = i + units.len();
        let head = &input[i.min(input.len())..j.min(input.len())];
        if head == units.as_slice() {
            return make_success(j, Value::String(value.clone()));
        }
        make_failure(i, &expected)
    })
}

fn regexp(re: &RegExp, group: Option<usize>) -> Parser {
    let group = group.unwrap_or(0);
    let expected = re.to_string();
    let exec = re.exec;
    parsimmon(move |input, i| match exec(&input[i.min(input.len())..]) {
        Some(captures) => {
            let full_match = captures[0].clone().expect("the full match participates");
            let group_match = captures
                .get(group)
                .cloned()
                .flatten()
                .map_or(Value::Null, |range| {
                    Value::String(String::from_utf16_lossy(&input[i + range.start..i + range.end]))
                });
            make_success(i + full_match.len(), group_match)
        }
        None => make_failure(i, &expected),
    })
}

fn succeed(value: Value) -> Parser {
    parsimmon(move |_, i| make_success(i, value.clone()))
}

fn lazy(f: impl Fn() -> Parser + 'static) -> Parser {
    let parser: Rc<OnceCell<Parser>> = Rc::new(OnceCell::new());
    parsimmon(move |input, i| parser.get_or_init(&f).apply(input, i))
}

fn index() -> Parser {
    parsimmon(|input, i| make_success(i, Value::Index(make_line_column_index(input, i as isize))))
}

fn eof() -> Parser {
    parsimmon(|input, i| {
        if i < input.len() {
            return make_failure(i, "EOF");
        }
        make_success(i, Value::Null)
    })
}

fn match_white_space(input: &[u16], minimum: usize) -> Option<Vec<Option<std::ops::Range<usize>>>> {
    let length = input.iter().take_while(|unit| is_white_space(**unit)).count();
    (length >= minimum).then(|| vec![Some(0..length)])
}

fn opt_whitespace() -> Parser {
    regexp(
        &RegExp {
            source: r"\s*",
            flags: "u",
            exec: |input| match_white_space(input, 0),
        },
        None,
    )
    .desc("optional whitespace")
}

fn whitespace() -> Parser {
    regexp(
        &RegExp {
            source: r"\s+",
            flags: "u",
            exec: |input| match_white_space(input, 1),
        },
        None,
    )
    .desc("whitespace")
}

/// The Parsimmon API used by libauth's CashAssembly parser.
pub struct P;

impl P {
    /// Try each parser in order, producing the first success.
    pub fn alt(parsers: Vec<Parser>) -> Parser {
        alt(parsers)
    }

    /// Create a set of mutually-referential parsers.
    pub fn create_language(parsers: Rules) -> Language {
        create_language(parsers)
    }

    /// A parser producing the current position.
    pub fn index() -> Parser {
        index()
    }

    /// A parser which defers creating its implementation until first use.
    pub fn lazy(f: impl Fn() -> Parser + 'static) -> Parser {
        lazy(f)
    }

    /// A failed reply.
    pub fn make_failure(index: usize, expected: &str) -> Reply {
        make_failure(index, expected)
    }

    /// A successful reply.
    pub fn make_success(index: usize, value: Value) -> Reply {
        make_success(index, value)
    }

    /// A parser which always succeeds with `value` (an alias of [`P::succeed`]).
    pub fn of(value: Value) -> Parser {
        succeed(value)
    }

    /// Optional whitespace (`/\s*/u`).
    pub fn opt_whitespace() -> Parser {
        opt_whitespace()
    }

    /// Match a regular expression at the current position, producing the
    /// `group` capture (default `0`, the whole match).
    pub fn regexp(re: &RegExp, group: Option<usize>) -> Parser {
        regexp(re, group)
    }

    /// Zero or more `parser`s separated by `separator`.
    pub fn sep_by(parser: &Parser, separator: &Parser) -> Parser {
        sep_by(parser, separator)
    }

    /// One or more `parser`s separated by `separator`.
    pub fn sep_by1(parser: &Parser, separator: &Parser) -> Parser {
        sep_by1(parser, separator)
    }

    /// Apply each parser in sequence, producing an array of their results.
    pub fn seq(parsers: Vec<Parser>) -> Parser {
        seq(parsers)
    }

    /// Apply each parser in sequence, producing `mapper` applied to their
    /// results.
    pub fn seq_map(parsers: Vec<Parser>, mapper: impl Fn(Vec<Value>) -> Value + 'static) -> Parser {
        seq_map(parsers, mapper)
    }

    /// Match `str` exactly.
    pub fn string(str: &str) -> Parser {
        string(str)
    }

    /// A parser which always succeeds with `value`.
    pub fn succeed(value: Value) -> Parser {
        succeed(value)
    }

    /// Required whitespace (`/\s+/u`).
    pub fn whitespace() -> Parser {
        whitespace()
    }
}
