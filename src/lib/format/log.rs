use crate::runtime::json::{encode_json, parse_json, Json};
use crate::runtime::string::locale_compare;

/// libauth's default `stringify` indentation.
const DEFAULT_STRINGIFY_SPACING: usize = 2;

/// A safe method to `JSON.stringify` a value, useful for debugging and logging
/// purposes.
///
/// @remarks
/// Without modifications, `JSON.stringify` has several shortcomings in
/// debugging and logging usage:
/// - throws when serializing anything containing a `bigint`
/// - `Uint8Array`s are often serialized in base 10 with newlines between each
///   index item
/// - `functions` and `symbols` are not clearly marked
///
/// In this port, values are `Json` documents in which those types have already
/// been encoded using libauth's markers (e.g. `<Uint8Array: 0x...>`).
pub fn stringify(value: &Json, spacing: Option<usize>) -> String {
    let spacing = spacing.unwrap_or(DEFAULT_STRINGIFY_SPACING);
    let compact = encode_json(value);
    let Ok(parsed) = parse_json(&compact) else {
        return compact;
    };
    stringify_with_spacing(&parsed, spacing, 0)
}

fn stringify_with_spacing(value: &Json, spacing: usize, depth: usize) -> String {
    let indent = " ".repeat(spacing * depth);
    let next_indent = " ".repeat(spacing * (depth + 1));
    match value {
        Json::Array(items) if !items.is_empty() => {
            let inner: Vec<String> = items
                .iter()
                .map(|item| format!("{next_indent}{}", stringify_with_spacing(item, spacing, depth + 1)))
                .collect();
            format!("[\n{}\n{indent}]", inner.join(",\n"))
        }
        Json::Object(entries) if !entries.is_empty() => {
            let inner: Vec<String> = entries
                .iter()
                .map(|(key, item)| {
                    format!(
                        "{next_indent}{}: {}",
                        Json::String(key.clone()),
                        stringify_with_spacing(item, spacing, depth + 1)
                    )
                })
                .collect();
            format!("{{\n{}\n{indent}}}", inner.join(",\n"))
        }
        other => encode_json(other),
    }
}

/// Given a value, recursively sort the keys of all objects it references
/// (without sorting arrays).
pub fn sort_object_keys(object_or_array: &Json) -> Json {
    let value = object_or_array;
    match value {
        Json::Array(items) => Json::Array(items.iter().map(sort_object_keys).collect()),
        Json::Object(entries) => {
            let mut sorted = entries.clone();
            sorted.sort_by(|left, right| locale_compare(&left.0, &right.0));
            Json::Object(
                sorted
                    .into_iter()
                    .map(|(key, item)| (key, sort_object_keys(&item)))
                    .collect(),
            )
        }
        other => other.clone(),
    }
}

/// Produce valid JavaScript for use as a test vector (libauth's `stringifyTestVector`).
///
/// The value is stringified with a two-space indent (alphabetizing object keys
/// when `alphabetize` is `true`), then libauth's `Uint8Array` and `bigint`
/// markers are rewritten as `hexToBin('...')` and BigInt literals respectively.
///
/// Note, as in libauth, any string value that matches those markers is
/// converted as well.
pub fn stringify_test_vector(value: &Json, alphabetize: Option<bool>) -> String {
    let stringified = if alphabetize.unwrap_or(true) {
        stringify(&sort_object_keys(value), None)
    } else {
        stringify(value, None)
    };
    replace_test_vector_literals(&stringified)
}

/// Rewrite libauth's `"<Uint8Array: 0x...>"` and `"<bigint: ...n>"` markers.
fn replace_test_vector_literals(text: &str) -> String {
    const UINT8_ARRAY_PREFIX: &str = "\"<Uint8Array: 0x";
    const BIGINT_PREFIX: &str = "\"<bigint: ";
    let mut result = String::with_capacity(text.len());
    let mut index = 0_usize;
    while index < text.len() {
        let rest = &text[index..];
        if let Some(hex) = rest.strip_prefix(UINT8_ARRAY_PREFIX).and_then(|after| {
            marker_contents(after, |byte| {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            })
        }) {
            result.push_str("hexToBin('");
            result.push_str(hex);
            result.push_str("')");
            index += UINT8_ARRAY_PREFIX.len() + hex.len() + 2;
            continue;
        }
        if let Some(digits) = rest.strip_prefix(BIGINT_PREFIX).and_then(|after| {
            let length = after.bytes().take_while(u8::is_ascii_digit).count();
            if after[length..].starts_with("n>\"") {
                Some(&after[..length])
            } else {
                None
            }
        }) {
            result.push_str(digits);
            result.push('n');
            index += BIGINT_PREFIX.len() + digits.len() + 3;
            continue;
        }
        let character = rest.chars().next().expect("non-empty remainder");
        result.push(character);
        index += character.len_utf8();
    }
    result
}

/// Return the leading run of `text` accepted by `predicate` followed by `>"`.
fn marker_contents(text: &str, predicate: impl Fn(u8) -> bool) -> Option<&str> {
    let length = text.bytes().take_while(|byte| predicate(*byte)).count();
    if text[length..].starts_with(">\"") {
        Some(&text[..length])
    } else {
        None
    }
}

/// The number of UTF-16 code units in a string (JavaScript's `string.length`).
fn utf16_length(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// Slice a string by UTF-16 code unit offsets, as JavaScript does.
///
/// Rust strings cannot contain lone surrogates, so a slice that splits a
/// surrogate pair yields U+FFFD in place of the unpaired halves (`String::from_utf16_lossy`).
fn utf16_slice(text: &str, start: usize, end: usize) -> String {
    let units: Vec<u16> = text.encode_utf16().collect();
    let start = start.min(units.len());
    let end = end.clamp(start, units.len());
    String::from_utf16_lossy(&units[start..end])
}

/// JavaScript's `String.prototype.slice(0, end)` for UTF-16 indices.
fn js_slice_to(text: &str, end: i64) -> String {
    let length = utf16_length(text) as i64;
    let end = if end < 0 {
        (length + end).max(0)
    } else {
        end.min(length)
    } as usize;
    utf16_slice(text, 0, end)
}

/// JavaScript's `String.prototype.slice(begin)` for a UTF-16 index.
fn js_slice_from(text: &str, begin: i64) -> String {
    let length = utf16_length(text) as i64;
    let begin = if begin < 0 {
        (length + begin).max(0)
    } else {
        begin.min(length)
    } as usize;
    utf16_slice(text, begin, length as usize)
}

/// JavaScript's `\s` (whitespace) character set.
fn is_javascript_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// Elide words and hex strings in `text` at `max_length` (libauth's
/// `elideWordsAndHexAtLength`).
pub fn elide_words_and_hex_at_length(text: &str, max_length: Option<usize>) -> String {
    let max_length = max_length.unwrap_or(148);
    let mut result = String::with_capacity(text.len());
    let mut word_start: Option<usize> = None;
    for (index, character) in text.char_indices() {
        if is_javascript_whitespace(character) {
            if let Some(start) = word_start.take() {
                elide_word(&mut result, &text[start..index], max_length);
            }
            result.push(character);
        } else if word_start.is_none() {
            word_start = Some(index);
        }
    }
    if let Some(start) = word_start {
        elide_word(&mut result, &text[start..], max_length);
    }
    result
}


fn elide_word(result: &mut String, word: &str, max_length: usize) {
    if utf16_length(word) < max_length {
        result.push_str(word);
        return;
    }
    let hex = hex_word(word);
    let middle = match hex {
        Some(hex) => {
            // `(hex.length - 2) / 2`, formatted as JavaScript formats a number.
            let numerator = hex.len() as i64 - 2;
            // `hex` always contains at least one digit, so `numerator >= 1`.
            let byte_count = if numerator % 2 == 0 {
                (numerator / 2).to_string()
            } else {
                format!("{}.5", numerator / 2)
            };
            format!(" … ({byte_count} total bytes) … ")
        }
        None => "…".to_string(),
    };
    let keep = max_length as i64 - utf16_length(&middle) as i64;
    let front = keep.div_euclid(2);
    let back = keep - front;
    let start = js_slice_to(word, front);
    let end = js_slice_from(word, utf16_length(word) as i64 - back);
    result.push_str(&start);
    result.push_str(&middle);
    result.push_str(&end);
}

/// Match libauth's `^(?:<)?(?<hex>0x[0-9A-Fa-f]+)(?:>)?$`, returning the hex group.
fn hex_word(word: &str) -> Option<&str> {
    let candidate = word.strip_prefix('<').unwrap_or(word);
    let candidate = candidate.strip_suffix('>').unwrap_or(candidate);
    let digits = candidate.strip_prefix("0x")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(candidate)
}

