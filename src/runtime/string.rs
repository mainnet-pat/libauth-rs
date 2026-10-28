//! `String.prototype` behavior that libauth relies on: `normalize('NFKD')`
//! (`key/bip39.ts`), `normalize('NFKC')` (`format/utf8.ts`),
//! `localeCompare(other, 'en')` (`format/log.ts`), and `trim()`
//! (`language/parse.ts`).
//!
//! Normalization implements Unicode Standard Annex #15 with the Unicode 16.0
//! data of the JavaScript engine libauth is tested with (Node.js 22, ICU 77).

use core::cmp::Ordering;

mod unicode_data;

use unicode_data::{CANONICAL_COMBINING_CLASS, CANONICAL_COMPOSITION, COMPATIBILITY_DECOMPOSITION};

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn combining_class(code_point: u32) -> u8 {
    CANONICAL_COMBINING_CLASS
        .binary_search_by_key(&code_point, |(key, _)| *key)
        .map_or(0, |index| CANONICAL_COMBINING_CLASS[index].1)
}

/// The full compatibility decomposition of `input`, in canonical order.
fn decompose_compatibility(input: &str) -> Vec<u32> {
    let mut result = Vec::with_capacity(input.len());
    for character in input.chars() {
        let code_point = u32::from(character);
        if (S_BASE..S_BASE + S_COUNT).contains(&code_point) {
            let index = code_point - S_BASE;
            result.push(L_BASE + index / N_COUNT);
            result.push(V_BASE + (index % N_COUNT) / T_COUNT);
            let trailing = T_BASE + index % T_COUNT;
            if trailing != T_BASE {
                result.push(trailing);
            }
        } else if let Ok(index) = COMPATIBILITY_DECOMPOSITION.binary_search_by_key(&code_point, |(key, _)| *key) {
            result.extend_from_slice(COMPATIBILITY_DECOMPOSITION[index].1);
        } else {
            result.push(code_point);
        }
    }
    // Canonical ordering: stably sort each run of non-starters by class.
    let mut index = 0;
    while index < result.len() {
        if combining_class(result[index]) == 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < result.len() && combining_class(result[index]) != 0 {
            index += 1;
        }
        result[start..index].sort_by_key(|code_point| combining_class(*code_point));
    }
    result
}

fn compose_pair(first: u32, second: u32) -> Option<u32> {
    if (L_BASE..L_BASE + L_COUNT).contains(&first) && (V_BASE..V_BASE + V_COUNT).contains(&second) {
        return Some(S_BASE + ((first - L_BASE) * V_COUNT + (second - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&first)
        && (first - S_BASE) % T_COUNT == 0
        && (T_BASE + 1..T_BASE + T_COUNT).contains(&second)
    {
        return Some(first + (second - T_BASE));
    }
    CANONICAL_COMPOSITION
        .binary_search_by_key(&(first, second), |(pair, _)| *pair)
        .ok()
        .map(|index| CANONICAL_COMPOSITION[index].1)
}

/// The canonical composition of a canonically-ordered decomposition.
fn compose(decomposed: Vec<u32>) -> Vec<u32> {
    let mut result: Vec<u32> = Vec::with_capacity(decomposed.len());
    let mut starter: Option<usize> = None;
    // The class of the last character appended since the starter (`None`
    // before any; a leading non-starter blocks composition).
    let mut last_class: Option<u8> = None;
    for code_point in decomposed {
        let class = combining_class(code_point);
        if let Some(starter_index) = starter {
            let unblocked = match last_class {
                None | Some(0) => true,
                Some(last) => last < class,
            };
            if unblocked {
                if let Some(composite) = compose_pair(result[starter_index], code_point) {
                    result[starter_index] = composite;
                    continue;
                }
            }
        }
        if class == 0 {
            starter = Some(result.len());
            last_class = None;
        } else {
            last_class = Some(if starter.is_none() { u8::MAX } else { class });
        }
        result.push(code_point);
    }
    result
}

fn from_code_points(code_points: Vec<u32>) -> String {
    code_points
        .into_iter()
        .map(|code_point| char::from_u32(code_point).expect("normalization produces scalar values"))
        .collect()
}

/// `String.prototype.normalize('NFKD')`: Unicode Normalization Form KD.
pub fn normalize_nfkd(input: &str) -> String {
    from_code_points(decompose_compatibility(input))
}

/// `String.prototype.normalize('NFKC')`: Unicode Normalization Form KC.
pub fn normalize_nfkc(input: &str) -> String {
    from_code_points(compose(decompose_compatibility(input)))
}

/// The primary collation weights used by `String.prototype.localeCompare` with
/// the `'en'` locale for printable ASCII, in ascending order.
///
/// libauth sorts test-vector object keys with
/// `a.localeCompare(b, 'en')`; ICU orders punctuation, then digits, then
/// letters, and compares letters case-insensitively.
const LOCALE_PRIMARY_ORDER: &str =
    " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789abcdefghijklmnopqrstuvwxyz";

/// A weight for characters outside of `LOCALE_PRIMARY_ORDER` (all equal, so
/// such keys retain their insertion order).
const UNKNOWN_PRIMARY_WEIGHT: usize = 999;

fn primary_weight(character: char) -> usize {
    let folded = if character.is_ascii_uppercase() {
        character.to_ascii_lowercase()
    } else {
        character
    };
    LOCALE_PRIMARY_ORDER
        .find(folded)
        .unwrap_or(UNKNOWN_PRIMARY_WEIGHT)
}

/// `0` for lowercase (and caseless) characters, `1` for uppercase ASCII.
fn tertiary_weight(character: char) -> u8 {
    u8::from(character.is_ascii_uppercase())
}

/// Approximate `String.prototype.localeCompare(other, 'en')` for ASCII strings.
///
/// Characters are compared by their ICU primary weights (case-insensitive,
/// punctuation before digits before letters); strings with equal primary
/// weights are ordered shortest-first, then with lowercase before uppercase.
/// Non-ASCII characters share one primary weight, so keys that differ only in
/// non-ASCII characters keep their insertion order.
pub fn locale_compare(left: &str, right: &str) -> Ordering {
    let left_primary: Vec<usize> = left.chars().map(primary_weight).collect();
    let right_primary: Vec<usize> = right.chars().map(primary_weight).collect();
    for (left_weight, right_weight) in left_primary.iter().zip(right_primary.iter()) {
        match left_weight.cmp(right_weight) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match left_primary.len().cmp(&right_primary.len()) {
        Ordering::Equal => {}
        other => return other,
    }
    for (left_character, right_character) in left.chars().zip(right.chars()) {
        match tertiary_weight(left_character).cmp(&tertiary_weight(right_character)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// `String.prototype.trim`: remove leading and trailing whitespace and line
/// terminators.
pub fn trim(input: &str) -> String {
    input
        .trim_matches(|character: char| {
            u16::try_from(u32::from(character)).is_ok_and(super::regexp::is_white_space)
        })
        .to_string()
}
