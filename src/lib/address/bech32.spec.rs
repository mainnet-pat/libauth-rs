//! Port of `address/bech32.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use libauth::{
    bech32_padded_to_bin, bin_to_bech32_padded, bin_to_utf8, decode_bech32, encode_bech32,
    extract_non_bech32_characters, is_bech32_character_set, regroup_bits, Bech32DecodingError,
    BitRegroupingError,
};

#[test]
fn regroup_bits_() {
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 1, None),
        Ok(vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    );
    assert_eq!(
        regroup_bits(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 1, 8, None),
        Ok(vec![0b11111111, 0b11111111])
    );
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 2, None),
        Ok(vec![0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11])
    );
    assert_eq!(
        regroup_bits(&[0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11], 2, 8, None),
        Ok(vec![0b11111111, 0b11111111])
    );
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 3, None),
        Ok(vec![0b111, 0b111, 0b111, 0b111, 0b111, 0b100])
    );
    assert_eq!(
        regroup_bits(&[0b111, 0b111, 0b111, 0b111, 0b111, 0b100], 3, 8, None),
        /*
         * The 2 padding bit are now considered significant, so we have to add
         * padding to encode them.
         */
        Ok(vec![0b11111111, 0b11111111, 0b00])
    );
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 4, None),
        Ok(vec![0b1111, 0b1111, 0b1111, 0b1111])
    );
    assert_eq!(
        regroup_bits(&[0b1111, 0b1111, 0b1111, 0b1111], 4, 8, None),
        Ok(vec![0b11111111, 0b11111111])
    );
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 5, None),
        Ok(vec![0b11111, 0b11111, 0b11111, 0b10000])
    );
    assert_eq!(
        regroup_bits(&[0b11111, 0b11111, 0b11111, 0b10000], 5, 8, None),
        Ok(vec![0b11111111, 0b11111111, 0b0000])
    );
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 6, None),
        Ok(vec![0b111111, 0b111111, 0b111100])
    );
    assert_eq!(
        regroup_bits(&[0b111111, 0b111111, 0b111100], 6, 8, None),
        Ok(vec![0b11111111, 0b11111111, 0b00])
    );
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 7, None),
        Ok(vec![0b1111111, 0b1111111, 0b1100000])
    );
    assert_eq!(
        regroup_bits(&[0b1111111, 0b1111111, 0b1100000], 7, 8, None),
        Ok(vec![0b11111111, 0b11111111, 0b00000])
    );
    assert_eq!(
        regroup_bits(&[0b11111111, 0b11111111], 8, 8, None),
        Ok(vec![0b11111111, 0b11111111])
    );
    // `bin: Uint8Array.from([0b11111111, 0b11111111])`
    assert_eq!(
        regroup_bits(&[0b11111111_u8, 0b11111111], 8, 8, None),
        Ok(vec![0b11111111, 0b11111111])
    );
    assert_eq!(
        regroup_bits(&[256], 8, 5, None),
        Err(BitRegroupingError::IntegerOutOfRange.as_str().to_string())
    );
    assert_eq!(
        regroup_bits(&[0b11111, 0b11111, 0b11111, 0b10001], 5, 8, Some(false)),
        Err(BitRegroupingError::RequiresDisallowedPadding.as_str().to_string())
    );
    assert_eq!(
        /*
         * `tf`
         */
        regroup_bits(&[11, 9], 5, 8, Some(false)),
        Err(BitRegroupingError::RequiresDisallowedPadding.as_str().to_string())
    );
    assert_eq!(
        regroup_bits(&[0b00000], 5, 8, Some(false)),
        Err(BitRegroupingError::HasDisallowedPadding.as_str().to_string())
    );
}

#[test]
fn is_bech32_character_set_extract_non_bech32_characters() {
    assert!(is_bech32_character_set(""));
    assert!(is_bech32_character_set("qq"));
    // cspell: disable-next-line
    assert!(is_bech32_character_set("qpzry9x8gf2tvdw0s3jn54khce6mua7l"));
    assert!(!is_bech32_character_set("1u"));
    assert_eq!(extract_non_bech32_characters("1u"), vec!['1']);
    // cspell: disable-next-line
    assert!(!is_bech32_character_set(":qqqsyqc"));
    assert_eq!(extract_non_bech32_characters(":qqqsyqc"), vec![':']);
    assert_eq!(extract_non_bech32_characters("1:qqqsyq*c"), vec!['1', ':', '*']);
}

#[test]
fn decode_bech32_() {
    assert_eq!(decode_bech32(""), Vec::<u8>::new());
    assert_eq!(decode_bech32("qq"), vec![0, 0]);
    assert_eq!(decode_bech32("qqq"), vec![0, 0, 0]);
    assert_eq!(decode_bech32("qqqq"), vec![0, 0, 0, 0]);
    assert_eq!(
        // cspell: disable-next-line
        decode_bech32("qpzry9x8gf2tvdw0s3jn54khce6mua7l"),
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    );
}

#[test]
fn encode_bech32_() {
    assert_eq!(encode_bech32(&[]), "");
    assert_eq!(encode_bech32(&[0, 0]), "qq");
    assert_eq!(encode_bech32(&[0, 0, 0]), "qqq");
    assert_eq!(encode_bech32(&[0, 0, 0, 0]), "qqqq");
    assert_eq!(
        encode_bech32(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
        // cspell: disable-next-line
        "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    );
}

#[test]
fn bin_to_bech32_padded_() {
    assert_eq!(bin_to_bech32_padded(&[0]), "qq");
    assert_eq!(bin_to_bech32_padded(&[255]), "lu");
    // cspell: disable-next-line
    assert_eq!(bin_to_bech32_padded(&[0, 1, 2, 3]), "qqqsyqc");
}

#[test]
fn bech32_padded_to_bin_() {
    assert_eq!(
        bech32_padded_to_bin("qqq"),
        Err(BitRegroupingError::HasDisallowedPadding.as_str().to_string())
    );
    assert_eq!(bech32_padded_to_bin("qq"), Ok(vec![0]));
    assert_eq!(
        bech32_padded_to_bin("tf"),
        Err(BitRegroupingError::RequiresDisallowedPadding.as_str().to_string())
    );
    assert_eq!(bech32_padded_to_bin("lu"), Ok(vec![255]));
    // cspell: disable-next-line
    assert_eq!(bech32_padded_to_bin("qqqsyqc"), Ok(vec![0, 1, 2, 3]));
    assert_eq!(
        bech32_padded_to_bin("qqq1"),
        Err(Bech32DecodingError::NotBech32CharacterSet.as_str().to_string())
    );
}

const MAX_5_BIT_NUMBER: i64 = 31;
const MAX_UINT8_NUMBER: i64 = 255;
/// `fcUint8Array(minLength, maxLength)`
fn fc_uint8_array(min_length: usize, max_length: usize) -> impl Fn(&mut fc::Random) -> Vec<u8> {
    let array = fc::array(fc::integer(Some(0), Some(MAX_UINT8_NUMBER)), Some(min_length), Some(max_length));
    move |random| array(random).into_iter().map(|value| value as u8).collect()
}
const MAX_BIN_LENGTH: usize = 100;

#[test]
fn fast_check_encode_bech32_decode_bech32() {
    fc::test_prop(
        fc::array(fc::integer(Some(0), Some(MAX_5_BIT_NUMBER)), Some(0), Some(MAX_BIN_LENGTH)),
        |input| {
            let input: Vec<u8> = input.iter().map(|value| *value as u8).collect();
            assert_eq!(decode_bech32(&encode_bech32(&input)), input);
        },
    );
}

#[test]
fn fast_check_bech32_padded_to_bin_bin_to_bech32_padded() {
    fc::test_prop(fc_uint8_array(0, MAX_BIN_LENGTH), |input| {
        assert_eq!(
            // `as Uint8Array`
            bin_to_bech32_padded(&bech32_padded_to_bin(&bin_to_bech32_padded(input)).expect("a Uint8Array")),
            bin_to_bech32_padded(input)
        );
    });
}

#[test]
fn fast_check_bin_to_bech32_padded_is_bech32() {
    fc::test_prop(fc_uint8_array(0, MAX_BIN_LENGTH), |input| {
        assert!(is_bech32_character_set(&bin_to_bech32_padded(input)));
    });
}

#[test]
fn fast_check_is_bech32_matches_round_trip_results() {
    fc::test_prop(fc_uint8_array(0, MAX_BIN_LENGTH), |input| {
        let maybe_bech32 = bin_to_utf8(input);
        let try_bin = bech32_padded_to_bin(&maybe_bech32);
        let try_bin = match try_bin {
            Err(_) => {
                // skip
                return;
            }
            Ok(try_bin) => try_bin,
        };
        assert_eq!(bin_to_bech32_padded(&try_bin), maybe_bech32);
    });
}
