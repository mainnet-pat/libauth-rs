//! Port of `format/utf8.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use libauth::{bin_to_utf8, hex_to_bin, length, lossy_normalize, segment, utf8_to_bin};

const MAX_UINT8_NUMBER: i64 = 255;
/// `fcUint8Array(minLength, maxLength)`
fn fc_uint8_array(min_length: usize, max_length: usize) -> impl Fn(&mut fc::Random) -> Vec<u8> {
    let array = fc::array(fc::integer(Some(0), Some(MAX_UINT8_NUMBER)), Some(min_length), Some(max_length));
    move |random| array(random).into_iter().map(|value| value as u8).collect()
}

/// `'👍'`
const THUMBS_UP: &str = "\u{1f44d}";

#[test]
fn utf8_to_bin_() {
    assert_eq!(utf8_to_bin(THUMBS_UP), hex_to_bin("f09f918d"));
}

#[test]
fn bin_to_utf8_() {
    assert_eq!(bin_to_utf8(&hex_to_bin("f09f918d")), THUMBS_UP);
}

const TEST_BIN_LENGTH: usize = 100;

#[test]
fn fast_check_utf8_to_bin_bin_to_utf8() {
    fc::test_prop(fc_uint8_array(0, TEST_BIN_LENGTH), |input| {
        assert_eq!(bin_to_utf8(&utf8_to_bin(&bin_to_utf8(input))), bin_to_utf8(input));
    });
}

/// `'ﬁt🚀👫👨‍👩‍👧‍👦'`
const NON_NORMAL: &str = "\u{fb01}t\u{1f680}\u{1f46b}\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}";

#[test]
fn lossy_normalize_() {
    assert_eq!(
        lossy_normalize(NON_NORMAL),
        "fit\u{1f680}\u{1f46b}\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}"
    );
}

#[test]
fn segment_() {
    // [...nonNormal] (iteration by code point)
    assert_eq!(
        NON_NORMAL.chars().map(String::from).collect::<Vec<_>>(),
        vec![
            "\u{fb01}", "t", "\u{1f680}", "\u{1f46b}", "\u{1f468}", "\u{200d}", "\u{1f469}", "\u{200d}",
            "\u{1f467}", "\u{200d}", "\u{1f466}"
        ]
    );
    assert_eq!(
        segment(NON_NORMAL),
        vec![
            "\u{fb01}",
            "t",
            "\u{1f680}",
            "\u{1f46b}",
            "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}"
        ]
    );
}

#[test]
fn length_() {
    // nonNormal.length (UTF-16 code units)
    assert_eq!(NON_NORMAL.encode_utf16().count(), 17);
    assert_eq!(length(NON_NORMAL), 5);
}
