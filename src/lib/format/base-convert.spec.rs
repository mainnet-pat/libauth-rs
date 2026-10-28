//! Port of `format/base-convert.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use std::sync::LazyLock;

use libauth::runtime::json::parse_json;
use libauth::{
    base58_to_bin, bin_to_base58, create_base_converter, hex_to_bin, range, utf8_to_bin,
    BaseConversionError, BaseConverter, BaseConverterCreationError,
};

/// `./fixtures/base58_encode_decode.json`, filtered: `Object.values(base58Json).filter((item) =>
/// Array.isArray(item) && item.every((x) => typeof x === 'string'))`
static BASE58_VECTORS: LazyLock<Vec<Vec<String>>> = LazyLock::new(|| {
    let base58_json = parse_json(include_str!("fixtures/base58_encode_decode.json")).expect("valid JSON");
    base58_json
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|item| {
            item.as_array()?
                .iter()
                .map(|x| x.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
        })
        .collect()
});

/// `const base2 = createBaseConverter('01') as BaseConverter;`
static BASE2: LazyLock<BaseConverter> = LazyLock::new(|| create_base_converter("01").expect("a valid alphabet"));

/// The `base2Vector` macro.
fn base2_vector(string: &str, bin: Vec<u8>) {
    assert_eq!(BASE2.decode(string), Ok(bin.clone()));
    assert_eq!(BASE2.encode(&bin), string);
}

/// `const base16 = createBaseConverter('0123456789abcdef') as BaseConverter;`
static BASE16: LazyLock<BaseConverter> =
    LazyLock::new(|| create_base_converter("0123456789abcdef").expect("a valid alphabet"));

/// The `base16Vector` macro.
fn base16_vector(string: &str, bin: Vec<u8>) {
    assert_eq!(BASE16.decode(string), Ok(bin.clone()));
    assert_eq!(BASE16.encode(&bin), string);
}

/// The `base58Vector` macro.
fn base58_vector(string: &str, bin: Vec<u8>) {
    assert_eq!(base58_to_bin(string), Ok(bin.clone()));
    assert_eq!(bin_to_base58(&bin), string);
}

#[test]
fn create_base_converter_base2() {
    base2_vector("", vec![]);
}

#[test]
fn create_base_converter_base2_0() {
    base2_vector("0", vec![0]);
}

#[test]
fn create_base_converter_base2_00() {
    base2_vector("00", vec![0, 0]);
}

#[test]
fn create_base_converter_base2_001() {
    base2_vector("001", vec![0, 0, 1]);
}

#[test]
fn create_base_converter_base2_0010() {
    base2_vector("0010", vec![0, 0, 2]);
}

#[test]
fn create_base_converter_base2_001111() {
    base2_vector("001111", vec![0, 0, 15]);
}

#[test]
fn create_base_converter_base2_0011111111() {
    base2_vector("0011111111", vec![0, 0, 255]);
}

#[test]
fn create_base_converter_base2_111111111111() {
    base2_vector("111111111111", vec![15, 255]);
}

#[test]
fn create_base_converter_base2_11111111000000001111111100000000() {
    base2_vector("11111111000000001111111100000000", vec![255, 0, 255, 0]);
}

#[test]
fn create_base_converter_base16() {
    base16_vector("", vec![]);
}

#[test]
fn create_base_converter_base16_0() {
    base16_vector("0", vec![0]);
}

#[test]
fn create_base_converter_base16_000f() {
    base16_vector("000f", vec![0, 0, 0, 15]);
}

#[test]
fn create_base_converter_base16_0fff() {
    base16_vector("0fff", vec![0, 15, 255]);
}

#[test]
fn create_base_converter_base16_ffff() {
    base16_vector("ffff", vec![255, 255]);
}

#[test]
fn base58_to_bin_bin_to_base58() {
    base58_vector("", vec![]);
}

#[test]
fn base58_to_bin_bin_to_base58_1() {
    base58_vector("1", vec![0]);
}

#[test]
fn base58_to_bin_bin_to_base58_1111() {
    base58_vector("1111", vec![0, 0, 0, 0]);
}

#[test]
fn base58_to_bin_bin_to_base58_2g() {
    base58_vector("2g", utf8_to_bin("a"));
}

#[test]
fn base58_to_bin_bin_to_base58_a3gv() {
    base58_vector("a3gV", utf8_to_bin("bbb"));
}

#[test]
fn base58_to_bin_bin_to_base58_aper() {
    base58_vector("aPEr", utf8_to_bin("ccc"));
}

#[test]
fn base58_to_bin_bin_to_base58_1ns17iag9jjgthd1vxjvlcenzuq3rjde9l() {
    base58_vector("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", hex_to_bin("00eb15231dfceb60925886b67d065299925915aeb172c06647"));
}

#[test]
fn create_base_converter_alphabet_too_long() {
    assert_eq!(
        create_base_converter(
            &range(255, None)
                .into_iter()
                .map(|i| char::from_u32(i as u32).expect("a character code"))
                .collect::<String>()
        )
        .err(),
        Some(format!(
            "{} Alphabet length: 255",
            BaseConverterCreationError::tooLong
        ))
    );
}

#[test]
fn create_base_converter_ambiguous_character_in_alphabet() {
    assert_eq!(
        create_base_converter("00").err(),
        Some(format!(
            "{} Ambiguous character: 0",
            BaseConverterCreationError::ambiguousCharacter
        ))
    );
}

#[test]
fn base58_to_bin_unknown_character() {
    assert_eq!(
        base58_to_bin("#"),
        Err(format!(
            "{} Unknown character: \"#\".",
            BaseConversionError::unknownCharacter
        ))
    );
}

#[test]
fn fast_check_base2_encode_base2_encode() {
    fc::test_prop(fc::uint8_array(Some(0), Some(100)), |input| {
        assert_eq!(
            BASE2.encode(&BASE2.decode(&BASE2.encode(input)).expect("a Uint8Array")),
            BASE2.encode(input)
        );
    });
}

#[test]
fn fast_check_base16_encode_base16_encode() {
    fc::test_prop(fc::uint8_array(Some(0), Some(100)), |input| {
        assert_eq!(
            BASE16.encode(&BASE16.decode(&BASE16.encode(input)).expect("a Uint8Array")),
            BASE16.encode(input)
        );
    });
}

/// `const base26 = createBaseConverter('abcdefghijklmnopqrstuvwxyz') as BaseConverter;`
static BASE26: LazyLock<BaseConverter> = LazyLock::new(|| {
    // cspell: disable-next-line
    create_base_converter("abcdefghijklmnopqrstuvwxyz").expect("a valid alphabet")
});

#[test]
fn fast_check_base26_encode_base26_encode() {
    fc::test_prop(fc::uint8_array(Some(0), Some(100)), |input| {
        assert_eq!(
            BASE26.encode(&BASE26.decode(&BASE26.encode(input)).expect("a Uint8Array")),
            BASE26.encode(input)
        );
    });
}

/// `const base42 = createBaseConverter('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghi') as BaseConverter;`
static BASE42: LazyLock<BaseConverter> = LazyLock::new(|| {
    create_base_converter("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghi").expect("a valid alphabet")
});

#[test]
fn fast_check_base42_encode_base42_encode() {
    fc::test_prop(fc::uint8_array(Some(0), Some(100)), |input| {
        assert_eq!(
            BASE42.encode(&BASE42.decode(&BASE42.encode(input)).expect("a Uint8Array")),
            BASE42.encode(input)
        );
    });
}

#[test]
fn fast_check_bin_to_base58_base58_to_bin() {
    fc::test_prop(fc::uint8_array(Some(0), Some(100)), |input| {
        assert_eq!(
            bin_to_base58(&base58_to_bin(&bin_to_base58(input)).expect("a Uint8Array")),
            bin_to_base58(input)
        );
    });
}

#[test]
fn base58_test_vectors() {
    // t.truthy(base58Vectors); (an array is always truthy)
    for vector in BASE58_VECTORS.iter() {
        let (bin_hex, base58) = (&vector[0], &vector[1]);
        assert_eq!(base58_to_bin(base58), Ok(hex_to_bin(bin_hex)));
        assert_eq!(bin_to_base58(&hex_to_bin(bin_hex)), *base58);
    }
}
