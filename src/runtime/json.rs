//! A dependency-free JSON reader and writer (the port's `JSON` built-in),
//! used for libauth's JSON imports, VMB fixtures, and golden files.
//!
//! Numbers are preserved as their source text so that 64-bit values are never rounded.

use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// A number, retained in its original textual representation.
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(value) => Some(value),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object()
            .and_then(|entries| entries.iter().find(|(name, _)| name == key).map(|(_, v)| v))
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(text) => text.parse().ok(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Number(text) => text.parse().ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(text) => text.parse().ok(),
            _ => None,
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Json::Null => String::new(),
            Json::Bool(value) => value.to_string(),
            Json::Number(text) => text.clone(),
            Json::String(value) => value.clone(),
            Json::Array(_) | Json::Object(_) => self.to_string(),
        }
    }
}

impl fmt::Display for Json {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", encode_json(self))
    }
}

/// The `JSON.parse` syntax errors which V8 reports with a position, by their
/// message (followed by ` at position P (line L column C)`).
#[derive(Clone, Copy)]
enum SyntaxError {
    UnexpectedTokenNumber,
    UnexpectedTokenString,
    UnterminatedString,
    ExpectedPropNameOrRBrace,
    ExpectedCommaOrRBrack,
    ExpectedCommaOrRBrace,
    UnexpectedNonWhiteSpaceCharacter,
    BadEscapedCharacter,
    BadControlCharacter,
    BadUnicodeEscape,
    NoNumberAfterMinusSign,
    ExponentPartMissingNumber,
    UnterminatedFractionalNumber,
    ExpectedColonAfterPropertyName,
    ExpectedDoubleQuotedPropertyName,
}

impl SyntaxError {
    fn message(self) -> &'static str {
        match self {
            Self::UnexpectedTokenNumber => "Unexpected number in JSON",
            Self::UnexpectedTokenString => "Unexpected string in JSON",
            Self::UnterminatedString => "Unterminated string in JSON",
            Self::ExpectedPropNameOrRBrace => "Expected property name or '}' in JSON",
            Self::ExpectedCommaOrRBrack => "Expected ',' or ']' after array element in JSON",
            Self::ExpectedCommaOrRBrace => "Expected ',' or '}' after property value in JSON",
            Self::UnexpectedNonWhiteSpaceCharacter => {
                "Unexpected non-whitespace character after JSON"
            }
            Self::BadEscapedCharacter => "Bad escaped character in JSON",
            Self::BadControlCharacter => "Bad control character in string literal in JSON",
            Self::BadUnicodeEscape => "Bad Unicode escape in JSON",
            Self::NoNumberAfterMinusSign => "No number after minus sign in JSON",
            Self::ExponentPartMissingNumber => "Exponent part is missing a number in JSON",
            Self::UnterminatedFractionalNumber => "Unterminated fractional number in JSON",
            Self::ExpectedColonAfterPropertyName => "Expected ':' after property name in JSON",
            Self::ExpectedDoubleQuotedPropertyName => {
                "Expected double-quoted property name in JSON"
            }
        }
    }
}

/// V8's message for an unexpected end of the input.
const UNEXPECTED_END: &str = "Unexpected end of JSON input";

/// The number of UTF-16 code units of context V8 quotes on each side of an
/// unexpected token (when the source is longer than twice as many).
const CONTEXT_LENGTH: usize = 10;

/// An array or object being parsed (with the key of the property whose value
/// is being parsed).
enum Container {
    Array(Vec<Json>),
    Object(Vec<(String, Json)>, String),
}

/// A `JSON.parse` implementation following V8's parser (`json-parser.cc`),
/// including the order in which it detects errors. It scans UTF-8 bytes;
/// error positions are converted to the UTF-16 code unit offsets V8 reports.
struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    fn byte(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.byte() {
            self.index += 1;
        }
    }

    /// Skip whitespace, then consume `expected` if it is next.
    fn check(&mut self, expected: u8) -> bool {
        self.skip_whitespace();
        if self.byte() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8, error: SyntaxError) -> Result<(), String> {
        if self.byte() == Some(expected) {
            self.index += 1;
            Ok(())
        } else {
            Err(self.error(error))
        }
    }

    fn expect_next(&mut self, expected: u8, error: SyntaxError) -> Result<(), String> {
        self.skip_whitespace();
        self.expect(expected, error)
    }

    /// The UTF-16 offset of the current position.
    fn position(&self) -> usize {
        self.text[..self.index].encode_utf16().count()
    }

    /// An error at the current position, e.g. `Unterminated string in JSON at
    /// position 4 (line 1 column 5)`. As in V8, `\r\n`, `\r`, and `\n` end
    /// lines, and columns count UTF-16 code units.
    fn error(&self, error: SyntaxError) -> String {
        let mut line = 1;
        let mut line_start = 0;
        let mut cursor = 0;
        while cursor < self.index {
            if self.bytes[cursor] == b'\r'
                && cursor + 1 < self.index
                && self.bytes[cursor + 1] == b'\n'
            {
                cursor += 1;
            }
            if matches!(self.bytes[cursor], b'\r' | b'\n') {
                line += 1;
                line_start = cursor + 1;
            }
            cursor += 1;
        }
        let column = 1 + self.text[line_start..self.index].encode_utf16().count();
        format!(
            "{} at position {} (line {line} column {column})",
            error.message(),
            self.position()
        )
    }

    /// The error for the unexpected character (or end of input) at the
    /// current position (V8's `ReportUnexpectedCharacter`).
    fn unexpected(&self) -> String {
        match self.byte() {
            None => UNEXPECTED_END.to_string(),
            Some(b'"') => self.error(SyntaxError::UnexpectedTokenString),
            Some(b'-' | b'0'..=b'9') => self.error(SyntaxError::UnexpectedTokenNumber),
            Some(_) => self.unexpected_token(),
        }
    }

    /// The error for an unexpected token at the current position, quoting the
    /// token (a UTF-16 code unit: a lone surrogate, here U+FFFD, for
    /// characters beyond the BMP) and the source, or the 10 code units of
    /// context on each side of the token in sources longer than 20.
    fn unexpected_token(&self) -> String {
        if matches!(self.text, "[object Object]" | "undefined" | "Infinity" | "NaN") {
            return format!("\"{}\" is not valid JSON", self.text);
        }
        let units: Vec<u16> = self.text.encode_utf16().collect();
        let position = self.position();
        let token = String::from_utf16_lossy(&units[position..=position]);
        let length = units.len();
        let context = |start: usize, end: usize| String::from_utf16_lossy(&units[start..end]);
        if length <= 2 * CONTEXT_LENGTH {
            format!("Unexpected token '{token}', \"{}\" is not valid JSON", self.text)
        } else if position < CONTEXT_LENGTH {
            format!(
                "Unexpected token '{token}', \"{}\"... is not valid JSON",
                context(0, position + CONTEXT_LENGTH)
            )
        } else if position < length - CONTEXT_LENGTH {
            format!(
                "Unexpected token '{token}', ...\"{}\"... is not valid JSON",
                context(position - CONTEXT_LENGTH, position + CONTEXT_LENGTH)
            )
        } else {
            format!(
                "Unexpected token '{token}', ...\"{}\" is not valid JSON",
                context(position - CONTEXT_LENGTH, length)
            )
        }
    }

    /// Parse a value, using `stack` (rather than recursion) for the arrays and
    /// objects being parsed, so nesting depth is unlimited (as in V8).
    fn parse_value(&mut self, stack: &mut Vec<Container>) -> Result<Json, String> {
        loop {
            // Produce a value (or start an array or object).
            let mut value = loop {
                self.skip_whitespace();
                match self.byte() {
                    Some(b'"') => {
                        self.index += 1;
                        break Json::String(self.scan_string()?);
                    }
                    Some(b'-' | b'0'..=b'9') => break self.parse_number()?,
                    Some(b'{') => {
                        self.index += 1;
                        if self.check(b'}') {
                            break Json::Object(Vec::new());
                        }
                        self.expect_next(b'"', SyntaxError::ExpectedPropNameOrRBrace)?;
                        let key = self.scan_string()?;
                        self.expect_next(b':', SyntaxError::ExpectedColonAfterPropertyName)?;
                        stack.push(Container::Object(Vec::new(), key));
                    }
                    Some(b'[') => {
                        self.index += 1;
                        if self.check(b']') {
                            break Json::Array(Vec::new());
                        }
                        stack.push(Container::Array(Vec::new()));
                    }
                    Some(b't') => {
                        self.scan_literal(b"true")?;
                        break Json::Bool(true);
                    }
                    Some(b'f') => {
                        self.scan_literal(b"false")?;
                        break Json::Bool(false);
                    }
                    Some(b'n') => {
                        self.scan_literal(b"null")?;
                        break Json::Null;
                    }
                    _ => return Err(self.unexpected()),
                }
            };
            // Add the value to its container, completing containers.
            loop {
                match stack.last_mut() {
                    None => return Ok(value),
                    Some(Container::Array(items)) => {
                        items.push(value);
                        if self.check(b',') {
                            break;
                        }
                        self.expect(b']', SyntaxError::ExpectedCommaOrRBrack)?;
                        let Some(Container::Array(items)) = stack.pop() else {
                            unreachable!("the last container is an array")
                        };
                        value = Json::Array(items);
                    }
                    Some(Container::Object(entries, key)) => {
                        entries.push((std::mem::take(key), value));
                        if self.check(b',') {
                            self.expect_next(
                                b'"',
                                SyntaxError::ExpectedDoubleQuotedPropertyName,
                            )?;
                            *key = self.scan_string()?;
                            self.expect_next(b':', SyntaxError::ExpectedColonAfterPropertyName)?;
                            break;
                        }
                        self.expect(b'}', SyntaxError::ExpectedCommaOrRBrace)?;
                        let Some(Container::Object(entries, _)) = stack.pop() else {
                            unreachable!("the last container is an object")
                        };
                        value = Json::Object(entries);
                    }
                }
            }
        }
    }

    /// Consume the rest of `literal` (its first character is current).
    fn scan_literal(&mut self, literal: &[u8]) -> Result<(), String> {
        let remaining = self.bytes.len() - self.index;
        if remaining >= literal.len()
            && self.bytes[self.index + 1..self.index + literal.len()] == literal[1..]
        {
            self.index += literal.len();
            return Ok(());
        }
        self.index += 1;
        for &expected in &literal[1..literal.len().min(remaining)] {
            if self.byte() != Some(expected) {
                return Err(self.unexpected());
            }
            self.index += 1;
        }
        Err(UNEXPECTED_END.to_string())
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.index;
        let negative = self.byte() == Some(b'-');
        if negative {
            self.index += 1;
        }
        let is_digit = |byte: Option<u8>| byte.is_some_and(|byte| byte.is_ascii_digit());
        if self.byte() == Some(b'0') {
            self.index += 1;
            // A leading zero must be the only digit before a fraction or
            // exponent.
            if is_digit(self.byte()) {
                return Err(self.error(SyntaxError::UnexpectedTokenNumber));
            }
        } else {
            let digits = self.index;
            while is_digit(self.byte()) {
                self.index += 1;
            }
            if self.index == digits {
                return Err(self.error(SyntaxError::NoNumberAfterMinusSign));
            }
        }
        if self.byte() == Some(b'.') {
            self.index += 1;
            if !is_digit(self.byte()) {
                return Err(self.error(SyntaxError::UnterminatedFractionalNumber));
            }
            while is_digit(self.byte()) {
                self.index += 1;
            }
        }
        if matches!(self.byte(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.byte(), Some(b'-' | b'+')) {
                self.index += 1;
            }
            if !is_digit(self.byte()) {
                return Err(self.error(SyntaxError::ExponentPartMissingNumber));
            }
            while is_digit(self.byte()) {
                self.index += 1;
            }
        }
        Ok(Json::Number(self.text[start..self.index].to_string()))
    }

    /// Scan a string (the opening quote has been consumed). Escaped surrogate
    /// pairs are combined; escaped lone surrogates, which JavaScript strings
    /// can hold but Rust strings cannot, become U+FFFD.
    fn scan_string(&mut self) -> Result<String, String> {
        let mut result = String::new();
        // An escaped high surrogate, awaiting an escaped low surrogate.
        let mut high_surrogate: Option<u32> = None;
        let flush = |result: &mut String, high_surrogate: &mut Option<u32>| {
            if high_surrogate.take().is_some() {
                result.push('\u{fffd}');
            }
        };
        loop {
            let start = self.index;
            while let Some(byte) = self.byte() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.index += 1;
            }
            if start < self.index {
                flush(&mut result, &mut high_surrogate);
                result.push_str(&self.text[start..self.index]);
            }
            match self.byte() {
                None => return Err(self.error(SyntaxError::UnterminatedString)),
                Some(b'"') => {
                    flush(&mut result, &mut high_surrogate);
                    self.index += 1;
                    return Ok(result);
                }
                Some(b'\\') => {
                    self.index += 1;
                    let escaped = match self.byte() {
                        None => return Err(UNEXPECTED_END.to_string()),
                        // A character beyond U+00FF (a UTF-8 sequence led by
                        // 0xC4 or above) is an unexpected token.
                        Some(byte) if byte >= 0xc4 => return Err(self.unexpected_token()),
                        Some(byte) => byte,
                    };
                    let character = match escaped {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut code = 0;
                            for _ in 0..4 {
                                self.index += 1;
                                let Some(digit) =
                                    self.byte().and_then(|byte| char::from(byte).to_digit(16))
                                else {
                                    return Err(self.error(SyntaxError::BadUnicodeEscape));
                                };
                                code = code * 16 + digit;
                            }
                            match code {
                                0xd800..=0xdbff => {
                                    flush(&mut result, &mut high_surrogate);
                                    high_surrogate = Some(code);
                                    self.index += 1;
                                    continue;
                                }
                                0xdc00..=0xdfff => {
                                    let combined = high_surrogate.take().map(|high| {
                                        0x10000 + ((high - 0xd800) << 10) + (code - 0xdc00)
                                    });
                                    self.index += 1;
                                    result.push(
                                        combined.and_then(char::from_u32).unwrap_or('\u{fffd}'),
                                    );
                                    continue;
                                }
                                _ => char::from_u32(code).expect("a non-surrogate code point"),
                            }
                        }
                        _ => return Err(self.error(SyntaxError::BadEscapedCharacter)),
                    };
                    flush(&mut result, &mut high_surrogate);
                    result.push(character);
                    self.index += 1;
                }
                Some(_) => return Err(self.error(SyntaxError::BadControlCharacter)),
            }
        }
    }
}

/// Drop a (possibly very deeply nested) JSON value without recursion: the
/// derived drop recurses once per level of nesting.
pub(crate) fn dispose_json(value: Json) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Json::Array(items) => pending.extend(items),
            Json::Object(entries) => pending.extend(entries.into_iter().map(|(_, value)| value)),
            _ => {}
        }
    }
}

/// Parse a JSON document: the port's `JSON.parse`.
///
/// The grammar and the errors follow V8's `JSON.parse` (as of Node.js 22): an
/// error is the message of the `SyntaxError` V8 throws, e.g.
/// `Unexpected token 'a', "a string" is not valid JSON` or
/// `Expected ',' or '}' after property value in JSON at position 6 (line 1
/// column 7)`, with positions in UTF-16 code units. Nesting depth is
/// unlimited. Unlike a JavaScript object, the result keeps every property in
/// source order (including repeated keys); numbers keep their source text.
pub fn parse_json(text: &str) -> Result<Json, String> {
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        index: 0,
    };
    let mut stack = Vec::new();
    let result = parser.parse_value(&mut stack).and_then(|value| {
        parser.skip_whitespace();
        if parser.index == parser.bytes.len() {
            Ok(value)
        } else {
            dispose_json(value);
            Err(parser.error(SyntaxError::UnexpectedNonWhiteSpaceCharacter))
        }
    });
    for container in stack {
        match container {
            Container::Array(items) => dispose_json(Json::Array(items)),
            Container::Object(entries, _) => dispose_json(Json::Object(entries)),
        }
    }
    result
}

fn escape_into(result: &mut String, text: &str) {
    result.push('"');
    for character in text.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\u{0008}' => result.push_str("\\b"),
            '\u{000c}' => result.push_str("\\f"),
            c if (c as u32) < 0x20 => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push('"');
}

/// Encode a JSON value as compact text.
pub fn encode_json(value: &Json) -> String {
    let mut result = String::new();
    encode_into(&mut result, value);
    result
}

fn encode_into(result: &mut String, value: &Json) {
    match value {
        Json::Null => result.push_str("null"),
        Json::Bool(inner) => result.push_str(if *inner { "true" } else { "false" }),
        Json::Number(text) => result.push_str(text),
        Json::String(text) => escape_into(result, text),
        Json::Array(items) => {
            result.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    result.push(',');
                }
                encode_into(result, item);
            }
            result.push(']');
        }
        Json::Object(entries) => {
            result.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    result.push(',');
                }
                escape_into(result, key);
                result.push(':');
                encode_into(result, item);
            }
            result.push('}');
        }
    }
}

/// Helpers for typing JSON values: libauth's JSON imports are plain JavaScript
/// objects, which this port converts to and from its typed structs.
pub(crate) mod typed {
    use std::collections::BTreeMap;

    use super::Json;

    /// The properties of a JSON object, rejecting any property not in `known`.
    pub(crate) fn properties<'a>(
        json: &'a Json,
        known: &[&str],
        context: &str,
    ) -> Result<BTreeMap<&'a str, &'a Json>, String> {
        let entries = json
            .as_object()
            .ok_or_else(|| format!("{context}: expected an object, received {json}."))?;
        entries
            .iter()
            .map(|(key, value)| {
                if known.contains(&key.as_str()) {
                    Ok((key.as_str(), value))
                } else {
                    Err(format!("{context}: unknown property \"{key}\"."))
                }
            })
            .collect()
    }

    /// A required property.
    pub(crate) fn required<'a>(
        properties: &BTreeMap<&str, &'a Json>,
        key: &str,
        context: &str,
    ) -> Result<&'a Json, String> {
        properties
            .get(key)
            .copied()
            .ok_or_else(|| format!("{context}: missing property \"{key}\"."))
    }

    /// Convert an optional property with `convert`.
    pub(crate) fn optional<T>(
        properties: &BTreeMap<&str, &Json>,
        key: &str,
        convert: impl Fn(&Json) -> Result<T, String>,
    ) -> Result<Option<T>, String> {
        properties.get(key).map(|value| convert(value)).transpose()
    }

    pub(crate) fn string(json: &Json) -> Result<String, String> {
        json.as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("Expected a string, received {json}."))
    }

    pub(crate) fn boolean(json: &Json) -> Result<bool, String> {
        json.as_bool()
            .ok_or_else(|| format!("Expected a boolean, received {json}."))
    }

    /// A JSON number as a JavaScript number.
    pub(crate) fn number(json: &Json) -> Result<f64, String> {
        json.as_f64()
            .ok_or_else(|| format!("Expected a number, received {json}."))
    }

    pub(crate) fn array<T>(json: &Json, convert: impl Fn(&Json) -> Result<T, String>) -> Result<Vec<T>, String> {
        json.as_array()
            .ok_or_else(|| format!("Expected an array, received {json}."))?
            .iter()
            .map(convert)
            .collect()
    }

    pub(crate) fn strings(json: &Json) -> Result<Vec<String>, String> {
        array(json, string)
    }

    pub(crate) fn map<T>(
        json: &Json,
        convert: impl Fn(&Json) -> Result<T, String>,
    ) -> Result<BTreeMap<String, T>, String> {
        json.as_object()
            .ok_or_else(|| format!("Expected an object, received {json}."))?
            .iter()
            .map(|(key, value)| Ok((key.clone(), convert(value)?)))
            .collect()
    }

    /// An object of the provided entries, omitting those which are `None`
    /// (like `undefined` properties in `JSON.stringify`).
    pub(crate) fn object(entries: Vec<(&str, Option<Json>)>) -> Json {
        Json::Object(
            entries
                .into_iter()
                .filter_map(|(key, value)| value.map(|value| (key.to_string(), value)))
                .collect(),
        )
    }

    pub(crate) fn from_string(value: &str) -> Json {
        Json::String(value.to_string())
    }

    pub(crate) fn from_number(value: impl ToString) -> Json {
        Json::Number(value.to_string())
    }

    /// A JavaScript number as JSON (`JSON.stringify` formats numbers like
    /// `Number#toString`).
    pub(crate) fn from_f64(value: f64) -> Json {
        Json::Number(crate::runtime::number::number_to_string(value))
    }

    pub(crate) fn from_strings(values: &[String]) -> Json {
        Json::Array(values.iter().map(|value| from_string(value)).collect())
    }

    pub(crate) fn from_map<T>(map: &BTreeMap<String, T>, convert: impl Fn(&T) -> Json) -> Json {
        Json::Object(map.iter().map(|(key, value)| (key.clone(), convert(value))).collect())
    }
}
