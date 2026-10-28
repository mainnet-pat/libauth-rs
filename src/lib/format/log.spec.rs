//! Port of `format/log.spec.ts`.
//!
//! The Rust `stringify`, `sortObjectKeys`, and `stringifyTestVector` take a
//! `libauth::runtime::json::Json` document. JavaScript values with no JSON
//! representation (`bigint`, `Uint8Array`, functions, and symbols) are passed
//! as the marker strings into which libauth's `stringify` encodes them (e.g.
//! `"<Uint8Array: 0x2020>"`).

use libauth::runtime::json::{parse_json, Json};
use libauth::{sort_object_keys, stringify, stringify_test_vector};

fn json(text: &str) -> Json {
    parse_json(text).expect("valid JSON")
}

fn marker(text: &str) -> Json {
    Json::String(text.to_string())
}

#[test]
#[ignore = "MISSING-API: stringify takes a runtime::json::Json, which cannot hold a bigint, Uint8Array, function, or symbol (libauth's stringify encodes these as <bigint: 0n>, <Uint8Array: 0x2020>, ... markers; the Rust caller must pre-encode them)"]
fn stringify_() {
    // Intended:
    // t.deepEqual(stringify(0n), '"<bigint: 0n>"');
    // t.deepEqual(stringify({ a: 0n }), '{\n  "a": "<bigint: 0n>"\n}');
    // t.deepEqual(stringify(Uint8Array.of(32, 32)), '"<Uint8Array: 0x2020>"');
    // t.deepEqual(stringify({ b: Uint8Array.of(32, 32) }), '{\n  "b": "<Uint8Array: 0x2020>"\n}');
    // t.deepEqual(stringify((x: number) => x * 2), '"<function: (x) => x * 2>"');
    // t.deepEqual(stringify({ c: (x: number) => x * 2 }), '{\n  "c": "<function: (x) => x * 2>"\n}');
    // t.deepEqual(stringify(Symbol('A')), '"<symbol: Symbol(A)>"');
    // t.deepEqual(stringify({ d: Symbol('A') }), '{\n  "d": "<symbol: Symbol(A)>"\n}');
    // Closest compiling version (the values pre-encoded as libauth's markers):
    assert_eq!(stringify(&marker("<bigint: 0n>"), None), "\"<bigint: 0n>\"");
    assert_eq!(
        stringify(&json(r#"{ "a": "<bigint: 0n>" }"#), None),
        "{\n  \"a\": \"<bigint: 0n>\"\n}"
    );
    assert_eq!(stringify(&marker("<Uint8Array: 0x2020>"), None), "\"<Uint8Array: 0x2020>\"");
    assert_eq!(
        stringify(&json(r#"{ "b": "<Uint8Array: 0x2020>" }"#), None),
        "{\n  \"b\": \"<Uint8Array: 0x2020>\"\n}"
    );
    assert_eq!(stringify(&marker("<function: (x) => x * 2>"), None), "\"<function: (x) => x * 2>\"");
    assert_eq!(
        stringify(&json(r#"{ "c": "<function: (x) => x * 2>" }"#), None),
        "{\n  \"c\": \"<function: (x) => x * 2>\"\n}"
    );
    assert_eq!(stringify(&marker("<symbol: Symbol(A)>"), None), "\"<symbol: Symbol(A)>\"");
    assert_eq!(
        stringify(&json(r#"{ "d": "<symbol: Symbol(A)>" }"#), None),
        "{\n  \"d\": \"<symbol: Symbol(A)>\"\n}"
    );
}

#[test]
fn sort_object_keys_() {
    // `0n`
    assert_eq!(sort_object_keys(&marker("<bigint: 0n>")), marker("<bigint: 0n>"));
    // `Uint8Array.of(32, 32)`
    assert_eq!(
        sort_object_keys(&marker("<Uint8Array: 0x2020>")),
        marker("<Uint8Array: 0x2020>")
    );
    assert_eq!(
        // { b: { ...{ c: 1 }, a: 2, b: null }, ...{ a: Uint8Array.of(2), c: Uint8Array.of(3) } }
        sort_object_keys(&json(
            r#"{ "b": { "c": 1, "a": 2, "b": null }, "a": "<Uint8Array: 0x02>", "c": "<Uint8Array: 0x03>" }"#
        )),
        // { a: Uint8Array.of(2), b: { a: 2, b: null, c: 1 }, c: Uint8Array.of(3) }
        json(r#"{ "a": "<Uint8Array: 0x02>", "b": { "a": 2, "b": null, "c": 1 }, "c": "<Uint8Array: 0x03>" }"#)
    );
    // const func = (x: number) => x * 2;
    let func = marker("<function: (x) => x * 2>");
    assert_eq!(sort_object_keys(&func), func);
    // const sym = Symbol('A');
    let sym = marker("<symbol: Symbol(A)>");
    assert_eq!(sort_object_keys(&sym), sym);
    assert_eq!(
        // [3, 2, { b: Uint8Array.of(1), ...{ a: Uint8Array.of(2), c: Uint8Array.of(3) } }, 1]
        sort_object_keys(&json(
            r#"[3, 2, { "b": "<Uint8Array: 0x01>", "a": "<Uint8Array: 0x02>", "c": "<Uint8Array: 0x03>" }, 1]"#
        )),
        // [3, 2, { a: Uint8Array.of(2), b: Uint8Array.of(1), c: Uint8Array.of(3) }, 1]
        json(r#"[3, 2, { "a": "<Uint8Array: 0x02>", "b": "<Uint8Array: 0x01>", "c": "<Uint8Array: 0x03>" }, 1]"#)
    );
}

#[test]
fn stringify_test_vector_() {
    let one = stringify_test_vector(
        // { ...{ b: [1, 2, { a: 1, ...{ c: Uint8Array.of(2) }, b: 3 }] }, a: { a: 1, ...{ c: 2n }, b: 3 } }
        &json(r#"{ "b": [1, 2, { "a": 1, "c": "<Uint8Array: 0x02>", "b": 3 }], "a": { "a": 1, "c": "<bigint: 2n>", "b": 3 } }"#),
        None,
    );
    assert_eq!(
        one,
        r#"{
  "a": {
    "a": 1,
    "b": 3,
    "c": 2n
  },
  "b": [
    1,
    2,
    {
      "a": 1,
      "b": 3,
      "c": hexToBin('02')
    }
  ]
}"#,
        "{one}"
    );
}

#[test]
#[ignore = "test.todo: elideWordsAtLength"]
fn elide_words_at_length() {}
