//! Port of `key/bip39.spec.ts`.
//!
//! Notes on the port:
//! - The `BIP39 Test Vectors (Trezor) #i: <mnemonic>` and `BIP39 Test Vectors
//!   (Extended) #i: <mnemonic>` tests are named `bip39_test_vectors_trezor_<i>`
//!   and `bip39_test_vectors_extended_<i>` (the mnemonic is omitted from the
//!   name).
//! - The comparisons with the `bip39` npm package use expected values
//!   precomputed with that package in Node.js (see the constants below).

#[path = "../../../tests/fast-check.rs"]
mod fc;

use std::sync::LazyLock;

use libauth::runtime::json::{encode_json, parse_json, Json};
use libauth::{
    assert_success, bin_to_hex, bip39WordListChineseSimplified, bip39WordListChineseTraditional,
    bip39WordListCzech, bip39WordListEnglish, bip39WordListFrench, bip39WordListItalian,
    bip39WordListJapanese, bip39WordListKorean, bip39WordListPortuguese, bip39WordListSpanish,
    decode_bip39_mnemonic, decode_bip39_mnemonic_non_standard, decode_hd_key,
    derive_bip39_checksum_bits, derive_hd_private_node_from_bip39_mnemonic,
    derive_hd_private_node_from_seed, derive_seed_from_bip39_mnemonic, encode_bip39_mnemonic,
    encode_bip39_mnemonic_non_standard, encode_hd_private_key, generate_bip39_mnemonic,
    generate_bip39_mnemonic_non_standard, hex_to_bin, is_valid_bip39_entropy_length,
    is_valid_bip39_word_list, range, Bip39Error, Bip39MnemonicResult, DecodedHdKey, HdKeyNetwork,
    HdNodeValid, HdPrivateNode, HdPrivateNodeValid,
};

const INVALID_WORD_LIST: [&str; 6] = ["word", "list", "must", "have", "2048", "words"];
const ZEROS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SHORT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
const BROKEN: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon banana";
const UNKNOWN_WORD: &str =
    "UNKNOWN abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// `'Å'` (U+00C5)
const ANGSTROM: &str = "\u{00c5}";
static NOT_NFKD_NORMALIZED: LazyLock<String> = LazyLock::new(|| {
    format!("{ANGSTROM} abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
});
const WITH_SPACE: &str =
    "abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const WITH_MIXED_CASE: &str =
    "ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZEROS_20_BYTES: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address";
const ZEROS_24_BYTES: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent";
const ZEROS_28_BYTES: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit";
const ZEROS_32_BYTES: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// `wordListByLanguage`
fn word_list_by_language(language: &str) -> Option<&'static [&'static str]> {
    match language {
        "chinese_simplified" => Some(&bip39WordListChineseSimplified),
        "chinese_traditional" => Some(&bip39WordListChineseTraditional),
        "czech" => Some(&bip39WordListCzech),
        "english" => Some(&bip39WordListEnglish),
        "french" => Some(&bip39WordListFrench),
        "italian" => Some(&bip39WordListItalian),
        "japanese" => Some(&bip39WordListJapanese),
        "korean" => Some(&bip39WordListKorean),
        "portuguese" => Some(&bip39WordListPortuguese),
        "spanish" => Some(&bip39WordListSpanish),
        _ => None,
    }
}

/// `Object.values(wordListByLanguage)`
fn word_lists() -> [&'static [&'static str]; 10] {
    [
        &bip39WordListChineseSimplified,
        &bip39WordListChineseTraditional,
        &bip39WordListCzech,
        &bip39WordListEnglish,
        &bip39WordListFrench,
        &bip39WordListItalian,
        &bip39WordListJapanese,
        &bip39WordListKorean,
        &bip39WordListPortuguese,
        &bip39WordListSpanish,
    ]
}

#[test]
fn all_word_lists_are_exported_and_valid() {
    for list in word_lists() {
        assert!(is_valid_bip39_word_list(list));
    }
}

const VALID_ENTROPY_LENGTH: [usize; 5] = [16, 20, 24, 28, 32];

#[test]
fn is_valid_bip39_entropy_length_() {
    for i in range(40, None) {
        if VALID_ENTROPY_LENGTH.contains(&i) {
            assert!(is_valid_bip39_entropy_length(&vec![0; i]));
        } else {
            assert!(!is_valid_bip39_entropy_length(&vec![0; i]));
        }
    }
}

#[test]
fn derive_bip39_checksum_bits_() {
    let expected_checksums = ["0011", "11011", "100111", "0011101", "01100110"];
    for length in VALID_ENTROPY_LENGTH {
        assert_eq!(
            derive_bip39_checksum_bits(&range(length, None).iter().map(|_| 0).collect::<Vec<u8>>()),
            expected_checksums[VALID_ENTROPY_LENGTH.iter().position(|valid| *valid == length).unwrap()],
            "Failed on {length}"
        );
    }
}

#[test]
fn decode_bip39_mnemonic_works() {
    assert_eq!(
        decode_bip39_mnemonic(ZEROS),
        Ok(hex_to_bin("00000000000000000000000000000000"))
    );
    assert_eq!(
        decode_bip39_mnemonic(SHORT),
        Err(format!("{} Word count: 11.", Bip39Error::invalidMnemonicLength))
    );
    assert_eq!(
        decode_bip39_mnemonic("abandon abandon abandon"),
        Err(format!("{} Word count: 3.", Bip39Error::invalidMnemonicLength))
    );
    assert_eq!(
        decode_bip39_mnemonic(&format!("abandon {ZEROS_32_BYTES}")),
        Err(format!("{} Word count: 25.", Bip39Error::invalidMnemonicLength))
    );
    assert_eq!(
        decode_bip39_mnemonic(UNKNOWN_WORD),
        Err(format!("{} Unknown word(s): UNKNOWN.", Bip39Error::unknownWord))
    );
    assert_eq!(
        decode_bip39_mnemonic(BROKEN),
        Err(format!(
            "{} Encoded: 0001; computed: 1100.",
            Bip39Error::invalidChecksum
        ))
    );
}

#[test]
fn decode_bip39_mnemonic_non_standard_works() {
    assert_eq!(
        decode_bip39_mnemonic_non_standard(ZEROS, &bip39WordListEnglish),
        Ok(hex_to_bin("00000000000000000000000000000000"))
    );
    assert_eq!(
        decode_bip39_mnemonic_non_standard(SHORT, &bip39WordListEnglish),
        Err(format!("{} Word count: 11.", Bip39Error::invalidMnemonicLength))
    );
    assert_eq!(
        decode_bip39_mnemonic_non_standard(BROKEN, &bip39WordListEnglish),
        Err(format!(
            "{} Encoded: 0001; computed: 1100.",
            Bip39Error::invalidChecksum
        ))
    );
    assert_eq!(
        decode_bip39_mnemonic_non_standard(ZEROS, &INVALID_WORD_LIST),
        Err(format!(
            "{} Word list length: 6.",
            Bip39Error::invalidWordListLength
        ))
    );
    assert_eq!(
        decode_bip39_mnemonic_non_standard(UNKNOWN_WORD, &bip39WordListEnglish),
        Err(format!("{} Unknown word(s): UNKNOWN.", Bip39Error::unknownWord))
    );
}

fn phrase(phrase: &str) -> Result<Bip39MnemonicResult, String> {
    Ok(Bip39MnemonicResult {
        phrase: phrase.to_string(),
    })
}

#[test]
fn encode_bip39_mnemonic_works() {
    assert_eq!(
        encode_bip39_mnemonic(&hex_to_bin("000000000000000000000000000000")),
        Err(format!(
            "{} Entropy length: 15.",
            Bip39Error::invalidEntropyLength
        ))
    );
    assert_eq!(
        encode_bip39_mnemonic(&hex_to_bin("00000000000000000000000000000000")),
        phrase(ZEROS)
    );
    assert_eq!(
        encode_bip39_mnemonic(&hex_to_bin("0000000000000000000000000000000000")),
        Err(format!(
            "{} Entropy length: 17.",
            Bip39Error::invalidEntropyLength
        ))
    );
    assert_eq!(
        encode_bip39_mnemonic(&hex_to_bin("0000000000000000000000000000000000000000")),
        phrase(ZEROS_20_BYTES)
    );
    assert_eq!(
        encode_bip39_mnemonic(&hex_to_bin("000000000000000000000000000000000000000000000000")),
        phrase(ZEROS_24_BYTES)
    );
    assert_eq!(
        encode_bip39_mnemonic(&hex_to_bin(
            "00000000000000000000000000000000000000000000000000000000"
        )),
        phrase(ZEROS_28_BYTES)
    );
    assert_eq!(
        encode_bip39_mnemonic(&hex_to_bin(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )),
        phrase(ZEROS_32_BYTES)
    );
}

#[test]
fn encode_bip39_mnemonic_non_standard_works() {
    assert_eq!(
        encode_bip39_mnemonic_non_standard(
            &hex_to_bin("00000000000000000000000000000000"),
            &bip39WordListEnglish
        ),
        phrase(ZEROS)
    );
    assert_eq!(
        encode_bip39_mnemonic_non_standard(
            &hex_to_bin("000000000000000000000000000000"),
            &bip39WordListEnglish
        ),
        Err(format!(
            "{} Entropy length: 15.",
            Bip39Error::invalidEntropyLength
        ))
    );
    assert_eq!(
        encode_bip39_mnemonic_non_standard(
            &hex_to_bin("00000000000000000000000000000000"),
            &INVALID_WORD_LIST
        ),
        Err(format!(
            "{} Word list length: 6.",
            Bip39Error::invalidWordListLength
        ))
    );
}

#[test]
fn fast_check_crypto_encode_bip39_mnemonic_decode_bip39_mnemonic() {
    let arbitrary = {
        let select_length = fc::integer(Some(0), Some(4));
        let entropy_source = fc::uint8_array(Some(32), Some(32));
        move |random: &mut fc::Random| (select_length(random), entropy_source(random))
    };
    fc::test_prop(arbitrary, |(select_length, entropy_source)| {
        let entropy = &entropy_source[..[16, 20, 24, 28, 32][*select_length as usize]];
        let result = match encode_bip39_mnemonic(entropy) {
            Err(result) => panic!("{result}"),
            Ok(result) => result,
        };
        assert_eq!(decode_bip39_mnemonic(&result.phrase), Ok(entropy.to_vec()));
    });
}

#[test]
fn fast_check_crypto_encode_bip39_mnemonic_non_standard_decode_bip39_mnemonic_non_standard() {
    let arbitrary = {
        let select_length = fc::integer(Some(0), Some(4));
        let entropy_source = fc::uint8_array(Some(32), Some(32));
        let select_language = fc::integer(Some(0), Some(word_lists().len() as i64 - 1));
        move |random: &mut fc::Random| {
            (
                select_length(random),
                entropy_source(random),
                select_language(random),
            )
        }
    };
    fc::test_prop(arbitrary, |(select_length, entropy_source, select_language)| {
        let entropy = &entropy_source[..[16, 20, 24, 28, 32][*select_length as usize]];
        let list = word_lists()[*select_language as usize];
        let result = match encode_bip39_mnemonic_non_standard(entropy, list) {
            Err(result) => panic!("{result}"),
            Ok(result) => result,
        };
        assert_eq!(
            decode_bip39_mnemonic_non_standard(&result.phrase, list),
            Ok(entropy.to_vec())
        );
    });
}

#[test]
fn derive_seed_from_bip39_mnemonic_works() {
    assert_eq!(
        derive_seed_from_bip39_mnemonic("", None, None),
        hex_to_bin(
            "4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(ZEROS, None, None),
        hex_to_bin(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(SHORT, None, None),
        hex_to_bin(
            "c010601f44235bce0eac58d966084f7e79a1691c54156578ef7908c10ee66d62f608254c1863b71a3dc8cf7f846cc6e0a746513751f39a4d66ceee3b623348a4"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(BROKEN, None, None),
        hex_to_bin(
            "aeaafed4b67ef003954fbb9a907be3c6e892fe41c2397092ddcd8e01ea65ec3781a5bb9db23b14c3d0d119486929d515c7525549c814bb969a1bb7fc01d30dc7"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(UNKNOWN_WORD, None, None),
        hex_to_bin(
            "5e5827cd9b89e7f7ab20accb162f2cca98cbc199d31c38469600bbc8987c9f71d198328fdbd3cda24cda0d8f56d48cc3c77c635d8207d734f7355e48acd1bcf0"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(WITH_SPACE, None, None),
        hex_to_bin(
            "1525a8d0b3e08e7bc38044293b6c7ce3e82cd344f27f294976c5179bc0505c4230f55dfa9bb326d89f1d7e8931d3c70e2dc2ebe808d8fbb32923a747d0860379"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(WITH_MIXED_CASE, None, None),
        hex_to_bin(
            "ae8ff977c55c498bd3e509b5587772dc6ecb6b65ced45156dbf5342d514172821e252e02cbd656e05244b65371b6bd542c491ec4152968bd9ba962f7e9f77d6a"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(ZEROS_20_BYTES, None, None),
        hex_to_bin(
            "6e9360e8d511f85adcda7bf6078207f0b2d12933845953bc766041cb71ac3bf644ffadd57caac244066657e8ebe01efa0e394d1afa7331379a3c1aebd68f6645"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(ZEROS_24_BYTES, None, None),
        hex_to_bin(
            "4975bb3d1faf5308c86a30893ee903a976296609db223fd717e227da5a813a34dc1428b71c84a787fc51f3b9f9dc28e9459f48c08bd9578e9d1b170f2d7ea506"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(ZEROS_28_BYTES, None, None),
        hex_to_bin(
            "277fe8691c965d8a47439d1ff771d9bad603575b8e8d8cee6cb907a1359992c22ab736b36859f9edcfd33bfef94e0d21ad295ff81194652c6e87bd68289b3522"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(ZEROS_32_BYTES, None, None),
        hex_to_bin(
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
        )
    );
    assert_eq!(
        derive_seed_from_bip39_mnemonic(&NOT_NFKD_NORMALIZED, None, Some(ANGSTROM)),
        hex_to_bin(
            "61d33f77132f19034d761b651c6230d293cfeb1894b8e83abb63baef2e5f9f420b0c9f2256a25cb655c33ee389e4dc7121c48eb8e0921d6b8a4dbe167c7e7421"
        )
    );
}

#[test]
fn derive_hd_private_node_from_bip39_mnemonic_works() {
    assert_eq!(
        derive_hd_private_node_from_bip39_mnemonic("", None, None, None),
        derive_hd_private_node_from_seed(
            &hex_to_bin(
                "4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e"
            ),
            None,
            None,
            None
        )
    );
    assert_eq!(
        derive_hd_private_node_from_bip39_mnemonic(ZEROS, None, None, None),
        derive_hd_private_node_from_seed(
            &hex_to_bin(
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
            ),
            None,
            None,
            None
        )
    );
}

#[test]
fn generate_bip39_mnemonic_and_generate_bip39_mnemonic_non_standard_works() {
    let valid_12_word_mnemonic = assert_success(generate_bip39_mnemonic(), None);
    let decoded = decode_bip39_mnemonic_non_standard(&valid_12_word_mnemonic, &bip39WordListEnglish);
    if let Err(decoded) = decoded {
        panic!("{decoded}");
    }
    assert_eq!(
        valid_12_word_mnemonic.split(' ').count(),
        12,
        "Expected 12 words"
    );
    let valid_24_word_mnemonic = generate_bip39_mnemonic_non_standard(&bip39WordListEnglish, Some(32), None);
    let valid_24_word_mnemonic = match valid_24_word_mnemonic {
        Err(valid_24_word_mnemonic) => panic!("{valid_24_word_mnemonic}"),
        Ok(valid_24_word_mnemonic) => valid_24_word_mnemonic,
    };
    assert_eq!(
        valid_24_word_mnemonic.phrase.split(' ').count(),
        24,
        "Expected 24 words"
    );
    assert_eq!(
        generate_bip39_mnemonic_non_standard(&bip39WordListEnglish, Some(17), None),
        Err(format!(
            "{} Entropy length: 17.",
            Bip39Error::invalidEntropyLength
        ))
    );
    assert_eq!(
        generate_bip39_mnemonic_non_standard(&INVALID_WORD_LIST, None, None),
        Err(format!(
            "{} Word list length: 6.",
            Bip39Error::invalidWordListLength
        ))
    );
}

/// `Bip39TestVector`
#[derive(Clone, Debug, PartialEq, Eq)]
struct Bip39TestVector {
    entropy: String,
    hd_key: Option<String>,
    hd_key_using_passphrase: String,
    mnemonic: String,
    passphrase: String,
    seed: Option<String>,
    seed_using_passphrase: String,
    word_list: String,
}

impl Bip39TestVector {
    /// The vector as a JSON object (with libauth's property names).
    fn to_json(&self) -> Json {
        let string = |value: &str| Json::String(value.to_string());
        let mut entries = vec![("entropy".to_string(), string(&self.entropy))];
        if let Some(hd_key) = &self.hd_key {
            entries.push(("hdKey".to_string(), string(hd_key)));
        }
        entries.push(("hdKeyUsingPassphrase".to_string(), string(&self.hd_key_using_passphrase)));
        entries.push(("mnemonic".to_string(), string(&self.mnemonic)));
        entries.push(("passphrase".to_string(), string(&self.passphrase)));
        if let Some(seed) = &self.seed {
            entries.push(("seed".to_string(), string(seed)));
        }
        entries.push(("seedUsingPassphrase".to_string(), string(&self.seed_using_passphrase)));
        entries.push(("wordList".to_string(), string(&self.word_list)));
        Json::Object(entries)
    }
}

/// The `bip39Vector` macro.
fn bip39_vector(vector: &Bip39TestVector) {
    let word_list = match word_list_by_language(&vector.word_list) {
        None => panic!("Failed to find word list for language {}", vector.word_list),
        Some(word_list) => word_list,
    };
    let mnemonic = encode_bip39_mnemonic_non_standard(&hex_to_bin(&vector.entropy), word_list);
    let mnemonic = match mnemonic {
        Err(mnemonic) => panic!("{mnemonic}"),
        Ok(mnemonic) => mnemonic,
    };
    let entropy = decode_bip39_mnemonic_non_standard(&vector.mnemonic, word_list);
    let seed = derive_seed_from_bip39_mnemonic(&mnemonic.phrase, None, None);
    let hd_key = derive_hd_private_node_from_seed(&seed, None, None, None);
    let seed_using_passphrase = derive_seed_from_bip39_mnemonic(&mnemonic.phrase, None, Some(&vector.passphrase));
    assert_eq!(mnemonic.phrase, vector.mnemonic);
    assert_eq!(seed_using_passphrase, hex_to_bin(&vector.seed_using_passphrase));
    assert_eq!(entropy, Ok(hex_to_bin(&vector.entropy)));
    let hd_key_using_passphrase =
        derive_hd_private_node_from_bip39_mnemonic(&vector.mnemonic, None, None, Some(&vector.passphrase));
    let hd_key_from_seed_using_passphrase = derive_hd_private_node_from_seed(&seed_using_passphrase, None, None, None);
    assert_eq!(hd_key_using_passphrase, hd_key_from_seed_using_passphrase);
    let key_parameters_using_passphrase = match decode_hd_key(&vector.hd_key_using_passphrase, None) {
        Err(key_parameters_using_passphrase) => panic!("{key_parameters_using_passphrase}"),
        Ok(key_parameters_using_passphrase) => key_parameters_using_passphrase,
    };
    // t.deepEqual(hdKeyUsingPassphrase, keyParametersUsingPassphrase.node);
    assert_eq!(
        hd_key_using_passphrase,
        match key_parameters_using_passphrase.node {
            HdNodeValid::Private(node) => HdPrivateNode::Valid(node),
            HdNodeValid::Public(node) => panic!("expected an HD private key: {node:?}"),
        }
    );
    if let Some(vector_seed) = &vector.seed {
        assert_eq!(seed, hex_to_bin(vector_seed));
        let vector_hd_key = match &vector.hd_key {
            None => panic!("Broken test vector"),
            Some(vector_hd_key) => vector_hd_key,
        };
        let hd_key_from_seed = derive_hd_private_node_from_seed(&seed, None, None, None);
        assert_eq!(hd_key, hd_key_from_seed);
        let key_parameters = decode_hd_key(vector_hd_key, None);
        if let Err(key_parameters) = key_parameters {
            panic!("{key_parameters}");
        }
    }
}

fn json_string(value: &Json, key: &str) -> String {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing {key}"))
        .to_string()
}

/// `convertedVectors`: `./fixtures/bip39.trezor.json`, converted.
static CONVERTED_VECTORS: LazyLock<Vec<Bip39TestVector>> = LazyLock::new(|| {
    let bip39_trezor_vectors_raw =
        parse_json(include_str!("fixtures/bip39.trezor.json")).expect("valid JSON");
    bip39_trezor_vectors_raw
        .as_object()
        .expect("an object")
        .iter()
        .flat_map(|(word_list, set)| {
            set.as_array().expect("an array").iter().map(|vector| {
                let item = |index: usize| vector.as_array().expect("an array")[index].as_str().expect("a string").to_string();
                Bip39TestVector {
                    entropy: item(0),
                    hd_key: None,
                    hd_key_using_passphrase: item(3),
                    mnemonic: item(1),
                    passphrase: "TREZOR".to_string(),
                    seed: None,
                    seed_using_passphrase: item(2),
                    word_list: word_list.clone(),
                }
            })
        })
        .collect()
});

/// `./fixtures/bip39.extended-vectors.json`
static BIP39_EXTENDED_VECTORS: LazyLock<Vec<Bip39TestVector>> = LazyLock::new(|| {
    parse_json(include_str!("fixtures/bip39.extended-vectors.json"))
        .expect("valid JSON")
        .as_array()
        .expect("an array")
        .iter()
        .map(|vector| Bip39TestVector {
            entropy: json_string(vector, "entropy"),
            hd_key: vector.get("hdKey").and_then(Json::as_str).map(str::to_string),
            hd_key_using_passphrase: json_string(vector, "hdKeyUsingPassphrase"),
            mnemonic: json_string(vector, "mnemonic"),
            passphrase: json_string(vector, "passphrase"),
            seed: vector.get("seed").and_then(Json::as_str).map(str::to_string),
            seed_using_passphrase: json_string(vector, "seedUsingPassphrase"),
            word_list: json_string(vector, "wordList"),
        })
        .collect()
});

/// One test per vector: `test(\`BIP39 Test Vectors (Trezor) #${i}\`, bip39Vector, vector)`.
macro_rules! bip39_trezor_vector_tests {
    ($($name:ident => $index:expr,)*) => {
        $(
            #[test]
            fn $name() {
                assert_eq!(CONVERTED_VECTORS.len(), VECTOR_COUNT, "the generated test list is out of date");
                bip39_vector(&CONVERTED_VECTORS[$index]);
            }
        )*
    };
}

/// One test per vector: `test(\`BIP39 Test Vectors (Extended) #${i}\`, bip39Vector, vector)`.
macro_rules! bip39_extended_vector_tests {
    ($($name:ident => $index:expr,)*) => {
        $(
            #[test]
            fn $name() {
                assert_eq!(BIP39_EXTENDED_VECTORS.len(), VECTOR_COUNT, "the generated test list is out of date");
                bip39_vector(&BIP39_EXTENDED_VECTORS[$index]);
            }
        )*
    };
}

/// The number of vectors in each fixture (one test is generated per vector).
const VECTOR_COUNT: usize = 240;

bip39_trezor_vector_tests! {
    bip39_test_vectors_trezor_0 => 0,
    bip39_test_vectors_trezor_1 => 1,
    bip39_test_vectors_trezor_2 => 2,
    bip39_test_vectors_trezor_3 => 3,
    bip39_test_vectors_trezor_4 => 4,
    bip39_test_vectors_trezor_5 => 5,
    bip39_test_vectors_trezor_6 => 6,
    bip39_test_vectors_trezor_7 => 7,
    bip39_test_vectors_trezor_8 => 8,
    bip39_test_vectors_trezor_9 => 9,
    bip39_test_vectors_trezor_10 => 10,
    bip39_test_vectors_trezor_11 => 11,
    bip39_test_vectors_trezor_12 => 12,
    bip39_test_vectors_trezor_13 => 13,
    bip39_test_vectors_trezor_14 => 14,
    bip39_test_vectors_trezor_15 => 15,
    bip39_test_vectors_trezor_16 => 16,
    bip39_test_vectors_trezor_17 => 17,
    bip39_test_vectors_trezor_18 => 18,
    bip39_test_vectors_trezor_19 => 19,
    bip39_test_vectors_trezor_20 => 20,
    bip39_test_vectors_trezor_21 => 21,
    bip39_test_vectors_trezor_22 => 22,
    bip39_test_vectors_trezor_23 => 23,
    bip39_test_vectors_trezor_24 => 24,
    bip39_test_vectors_trezor_25 => 25,
    bip39_test_vectors_trezor_26 => 26,
    bip39_test_vectors_trezor_27 => 27,
    bip39_test_vectors_trezor_28 => 28,
    bip39_test_vectors_trezor_29 => 29,
    bip39_test_vectors_trezor_30 => 30,
    bip39_test_vectors_trezor_31 => 31,
    bip39_test_vectors_trezor_32 => 32,
    bip39_test_vectors_trezor_33 => 33,
    bip39_test_vectors_trezor_34 => 34,
    bip39_test_vectors_trezor_35 => 35,
    bip39_test_vectors_trezor_36 => 36,
    bip39_test_vectors_trezor_37 => 37,
    bip39_test_vectors_trezor_38 => 38,
    bip39_test_vectors_trezor_39 => 39,
    bip39_test_vectors_trezor_40 => 40,
    bip39_test_vectors_trezor_41 => 41,
    bip39_test_vectors_trezor_42 => 42,
    bip39_test_vectors_trezor_43 => 43,
    bip39_test_vectors_trezor_44 => 44,
    bip39_test_vectors_trezor_45 => 45,
    bip39_test_vectors_trezor_46 => 46,
    bip39_test_vectors_trezor_47 => 47,
    bip39_test_vectors_trezor_48 => 48,
    bip39_test_vectors_trezor_49 => 49,
    bip39_test_vectors_trezor_50 => 50,
    bip39_test_vectors_trezor_51 => 51,
    bip39_test_vectors_trezor_52 => 52,
    bip39_test_vectors_trezor_53 => 53,
    bip39_test_vectors_trezor_54 => 54,
    bip39_test_vectors_trezor_55 => 55,
    bip39_test_vectors_trezor_56 => 56,
    bip39_test_vectors_trezor_57 => 57,
    bip39_test_vectors_trezor_58 => 58,
    bip39_test_vectors_trezor_59 => 59,
    bip39_test_vectors_trezor_60 => 60,
    bip39_test_vectors_trezor_61 => 61,
    bip39_test_vectors_trezor_62 => 62,
    bip39_test_vectors_trezor_63 => 63,
    bip39_test_vectors_trezor_64 => 64,
    bip39_test_vectors_trezor_65 => 65,
    bip39_test_vectors_trezor_66 => 66,
    bip39_test_vectors_trezor_67 => 67,
    bip39_test_vectors_trezor_68 => 68,
    bip39_test_vectors_trezor_69 => 69,
    bip39_test_vectors_trezor_70 => 70,
    bip39_test_vectors_trezor_71 => 71,
    bip39_test_vectors_trezor_72 => 72,
    bip39_test_vectors_trezor_73 => 73,
    bip39_test_vectors_trezor_74 => 74,
    bip39_test_vectors_trezor_75 => 75,
    bip39_test_vectors_trezor_76 => 76,
    bip39_test_vectors_trezor_77 => 77,
    bip39_test_vectors_trezor_78 => 78,
    bip39_test_vectors_trezor_79 => 79,
    bip39_test_vectors_trezor_80 => 80,
    bip39_test_vectors_trezor_81 => 81,
    bip39_test_vectors_trezor_82 => 82,
    bip39_test_vectors_trezor_83 => 83,
    bip39_test_vectors_trezor_84 => 84,
    bip39_test_vectors_trezor_85 => 85,
    bip39_test_vectors_trezor_86 => 86,
    bip39_test_vectors_trezor_87 => 87,
    bip39_test_vectors_trezor_88 => 88,
    bip39_test_vectors_trezor_89 => 89,
    bip39_test_vectors_trezor_90 => 90,
    bip39_test_vectors_trezor_91 => 91,
    bip39_test_vectors_trezor_92 => 92,
    bip39_test_vectors_trezor_93 => 93,
    bip39_test_vectors_trezor_94 => 94,
    bip39_test_vectors_trezor_95 => 95,
    bip39_test_vectors_trezor_96 => 96,
    bip39_test_vectors_trezor_97 => 97,
    bip39_test_vectors_trezor_98 => 98,
    bip39_test_vectors_trezor_99 => 99,
    bip39_test_vectors_trezor_100 => 100,
    bip39_test_vectors_trezor_101 => 101,
    bip39_test_vectors_trezor_102 => 102,
    bip39_test_vectors_trezor_103 => 103,
    bip39_test_vectors_trezor_104 => 104,
    bip39_test_vectors_trezor_105 => 105,
    bip39_test_vectors_trezor_106 => 106,
    bip39_test_vectors_trezor_107 => 107,
    bip39_test_vectors_trezor_108 => 108,
    bip39_test_vectors_trezor_109 => 109,
    bip39_test_vectors_trezor_110 => 110,
    bip39_test_vectors_trezor_111 => 111,
    bip39_test_vectors_trezor_112 => 112,
    bip39_test_vectors_trezor_113 => 113,
    bip39_test_vectors_trezor_114 => 114,
    bip39_test_vectors_trezor_115 => 115,
    bip39_test_vectors_trezor_116 => 116,
    bip39_test_vectors_trezor_117 => 117,
    bip39_test_vectors_trezor_118 => 118,
    bip39_test_vectors_trezor_119 => 119,
    bip39_test_vectors_trezor_120 => 120,
    bip39_test_vectors_trezor_121 => 121,
    bip39_test_vectors_trezor_122 => 122,
    bip39_test_vectors_trezor_123 => 123,
    bip39_test_vectors_trezor_124 => 124,
    bip39_test_vectors_trezor_125 => 125,
    bip39_test_vectors_trezor_126 => 126,
    bip39_test_vectors_trezor_127 => 127,
    bip39_test_vectors_trezor_128 => 128,
    bip39_test_vectors_trezor_129 => 129,
    bip39_test_vectors_trezor_130 => 130,
    bip39_test_vectors_trezor_131 => 131,
    bip39_test_vectors_trezor_132 => 132,
    bip39_test_vectors_trezor_133 => 133,
    bip39_test_vectors_trezor_134 => 134,
    bip39_test_vectors_trezor_135 => 135,
    bip39_test_vectors_trezor_136 => 136,
    bip39_test_vectors_trezor_137 => 137,
    bip39_test_vectors_trezor_138 => 138,
    bip39_test_vectors_trezor_139 => 139,
    bip39_test_vectors_trezor_140 => 140,
    bip39_test_vectors_trezor_141 => 141,
    bip39_test_vectors_trezor_142 => 142,
    bip39_test_vectors_trezor_143 => 143,
    bip39_test_vectors_trezor_144 => 144,
    bip39_test_vectors_trezor_145 => 145,
    bip39_test_vectors_trezor_146 => 146,
    bip39_test_vectors_trezor_147 => 147,
    bip39_test_vectors_trezor_148 => 148,
    bip39_test_vectors_trezor_149 => 149,
    bip39_test_vectors_trezor_150 => 150,
    bip39_test_vectors_trezor_151 => 151,
    bip39_test_vectors_trezor_152 => 152,
    bip39_test_vectors_trezor_153 => 153,
    bip39_test_vectors_trezor_154 => 154,
    bip39_test_vectors_trezor_155 => 155,
    bip39_test_vectors_trezor_156 => 156,
    bip39_test_vectors_trezor_157 => 157,
    bip39_test_vectors_trezor_158 => 158,
    bip39_test_vectors_trezor_159 => 159,
    bip39_test_vectors_trezor_160 => 160,
    bip39_test_vectors_trezor_161 => 161,
    bip39_test_vectors_trezor_162 => 162,
    bip39_test_vectors_trezor_163 => 163,
    bip39_test_vectors_trezor_164 => 164,
    bip39_test_vectors_trezor_165 => 165,
    bip39_test_vectors_trezor_166 => 166,
    bip39_test_vectors_trezor_167 => 167,
    bip39_test_vectors_trezor_168 => 168,
    bip39_test_vectors_trezor_169 => 169,
    bip39_test_vectors_trezor_170 => 170,
    bip39_test_vectors_trezor_171 => 171,
    bip39_test_vectors_trezor_172 => 172,
    bip39_test_vectors_trezor_173 => 173,
    bip39_test_vectors_trezor_174 => 174,
    bip39_test_vectors_trezor_175 => 175,
    bip39_test_vectors_trezor_176 => 176,
    bip39_test_vectors_trezor_177 => 177,
    bip39_test_vectors_trezor_178 => 178,
    bip39_test_vectors_trezor_179 => 179,
    bip39_test_vectors_trezor_180 => 180,
    bip39_test_vectors_trezor_181 => 181,
    bip39_test_vectors_trezor_182 => 182,
    bip39_test_vectors_trezor_183 => 183,
    bip39_test_vectors_trezor_184 => 184,
    bip39_test_vectors_trezor_185 => 185,
    bip39_test_vectors_trezor_186 => 186,
    bip39_test_vectors_trezor_187 => 187,
    bip39_test_vectors_trezor_188 => 188,
    bip39_test_vectors_trezor_189 => 189,
    bip39_test_vectors_trezor_190 => 190,
    bip39_test_vectors_trezor_191 => 191,
    bip39_test_vectors_trezor_192 => 192,
    bip39_test_vectors_trezor_193 => 193,
    bip39_test_vectors_trezor_194 => 194,
    bip39_test_vectors_trezor_195 => 195,
    bip39_test_vectors_trezor_196 => 196,
    bip39_test_vectors_trezor_197 => 197,
    bip39_test_vectors_trezor_198 => 198,
    bip39_test_vectors_trezor_199 => 199,
    bip39_test_vectors_trezor_200 => 200,
    bip39_test_vectors_trezor_201 => 201,
    bip39_test_vectors_trezor_202 => 202,
    bip39_test_vectors_trezor_203 => 203,
    bip39_test_vectors_trezor_204 => 204,
    bip39_test_vectors_trezor_205 => 205,
    bip39_test_vectors_trezor_206 => 206,
    bip39_test_vectors_trezor_207 => 207,
    bip39_test_vectors_trezor_208 => 208,
    bip39_test_vectors_trezor_209 => 209,
    bip39_test_vectors_trezor_210 => 210,
    bip39_test_vectors_trezor_211 => 211,
    bip39_test_vectors_trezor_212 => 212,
    bip39_test_vectors_trezor_213 => 213,
    bip39_test_vectors_trezor_214 => 214,
    bip39_test_vectors_trezor_215 => 215,
    bip39_test_vectors_trezor_216 => 216,
    bip39_test_vectors_trezor_217 => 217,
    bip39_test_vectors_trezor_218 => 218,
    bip39_test_vectors_trezor_219 => 219,
    bip39_test_vectors_trezor_220 => 220,
    bip39_test_vectors_trezor_221 => 221,
    bip39_test_vectors_trezor_222 => 222,
    bip39_test_vectors_trezor_223 => 223,
    bip39_test_vectors_trezor_224 => 224,
    bip39_test_vectors_trezor_225 => 225,
    bip39_test_vectors_trezor_226 => 226,
    bip39_test_vectors_trezor_227 => 227,
    bip39_test_vectors_trezor_228 => 228,
    bip39_test_vectors_trezor_229 => 229,
    bip39_test_vectors_trezor_230 => 230,
    bip39_test_vectors_trezor_231 => 231,
    bip39_test_vectors_trezor_232 => 232,
    bip39_test_vectors_trezor_233 => 233,
    bip39_test_vectors_trezor_234 => 234,
    bip39_test_vectors_trezor_235 => 235,
    bip39_test_vectors_trezor_236 => 236,
    bip39_test_vectors_trezor_237 => 237,
    bip39_test_vectors_trezor_238 => 238,
    bip39_test_vectors_trezor_239 => 239,
}

bip39_extended_vector_tests! {
    bip39_test_vectors_extended_0 => 0,
    bip39_test_vectors_extended_1 => 1,
    bip39_test_vectors_extended_2 => 2,
    bip39_test_vectors_extended_3 => 3,
    bip39_test_vectors_extended_4 => 4,
    bip39_test_vectors_extended_5 => 5,
    bip39_test_vectors_extended_6 => 6,
    bip39_test_vectors_extended_7 => 7,
    bip39_test_vectors_extended_8 => 8,
    bip39_test_vectors_extended_9 => 9,
    bip39_test_vectors_extended_10 => 10,
    bip39_test_vectors_extended_11 => 11,
    bip39_test_vectors_extended_12 => 12,
    bip39_test_vectors_extended_13 => 13,
    bip39_test_vectors_extended_14 => 14,
    bip39_test_vectors_extended_15 => 15,
    bip39_test_vectors_extended_16 => 16,
    bip39_test_vectors_extended_17 => 17,
    bip39_test_vectors_extended_18 => 18,
    bip39_test_vectors_extended_19 => 19,
    bip39_test_vectors_extended_20 => 20,
    bip39_test_vectors_extended_21 => 21,
    bip39_test_vectors_extended_22 => 22,
    bip39_test_vectors_extended_23 => 23,
    bip39_test_vectors_extended_24 => 24,
    bip39_test_vectors_extended_25 => 25,
    bip39_test_vectors_extended_26 => 26,
    bip39_test_vectors_extended_27 => 27,
    bip39_test_vectors_extended_28 => 28,
    bip39_test_vectors_extended_29 => 29,
    bip39_test_vectors_extended_30 => 30,
    bip39_test_vectors_extended_31 => 31,
    bip39_test_vectors_extended_32 => 32,
    bip39_test_vectors_extended_33 => 33,
    bip39_test_vectors_extended_34 => 34,
    bip39_test_vectors_extended_35 => 35,
    bip39_test_vectors_extended_36 => 36,
    bip39_test_vectors_extended_37 => 37,
    bip39_test_vectors_extended_38 => 38,
    bip39_test_vectors_extended_39 => 39,
    bip39_test_vectors_extended_40 => 40,
    bip39_test_vectors_extended_41 => 41,
    bip39_test_vectors_extended_42 => 42,
    bip39_test_vectors_extended_43 => 43,
    bip39_test_vectors_extended_44 => 44,
    bip39_test_vectors_extended_45 => 45,
    bip39_test_vectors_extended_46 => 46,
    bip39_test_vectors_extended_47 => 47,
    bip39_test_vectors_extended_48 => 48,
    bip39_test_vectors_extended_49 => 49,
    bip39_test_vectors_extended_50 => 50,
    bip39_test_vectors_extended_51 => 51,
    bip39_test_vectors_extended_52 => 52,
    bip39_test_vectors_extended_53 => 53,
    bip39_test_vectors_extended_54 => 54,
    bip39_test_vectors_extended_55 => 55,
    bip39_test_vectors_extended_56 => 56,
    bip39_test_vectors_extended_57 => 57,
    bip39_test_vectors_extended_58 => 58,
    bip39_test_vectors_extended_59 => 59,
    bip39_test_vectors_extended_60 => 60,
    bip39_test_vectors_extended_61 => 61,
    bip39_test_vectors_extended_62 => 62,
    bip39_test_vectors_extended_63 => 63,
    bip39_test_vectors_extended_64 => 64,
    bip39_test_vectors_extended_65 => 65,
    bip39_test_vectors_extended_66 => 66,
    bip39_test_vectors_extended_67 => 67,
    bip39_test_vectors_extended_68 => 68,
    bip39_test_vectors_extended_69 => 69,
    bip39_test_vectors_extended_70 => 70,
    bip39_test_vectors_extended_71 => 71,
    bip39_test_vectors_extended_72 => 72,
    bip39_test_vectors_extended_73 => 73,
    bip39_test_vectors_extended_74 => 74,
    bip39_test_vectors_extended_75 => 75,
    bip39_test_vectors_extended_76 => 76,
    bip39_test_vectors_extended_77 => 77,
    bip39_test_vectors_extended_78 => 78,
    bip39_test_vectors_extended_79 => 79,
    bip39_test_vectors_extended_80 => 80,
    bip39_test_vectors_extended_81 => 81,
    bip39_test_vectors_extended_82 => 82,
    bip39_test_vectors_extended_83 => 83,
    bip39_test_vectors_extended_84 => 84,
    bip39_test_vectors_extended_85 => 85,
    bip39_test_vectors_extended_86 => 86,
    bip39_test_vectors_extended_87 => 87,
    bip39_test_vectors_extended_88 => 88,
    bip39_test_vectors_extended_89 => 89,
    bip39_test_vectors_extended_90 => 90,
    bip39_test_vectors_extended_91 => 91,
    bip39_test_vectors_extended_92 => 92,
    bip39_test_vectors_extended_93 => 93,
    bip39_test_vectors_extended_94 => 94,
    bip39_test_vectors_extended_95 => 95,
    bip39_test_vectors_extended_96 => 96,
    bip39_test_vectors_extended_97 => 97,
    bip39_test_vectors_extended_98 => 98,
    bip39_test_vectors_extended_99 => 99,
    bip39_test_vectors_extended_100 => 100,
    bip39_test_vectors_extended_101 => 101,
    bip39_test_vectors_extended_102 => 102,
    bip39_test_vectors_extended_103 => 103,
    bip39_test_vectors_extended_104 => 104,
    bip39_test_vectors_extended_105 => 105,
    bip39_test_vectors_extended_106 => 106,
    bip39_test_vectors_extended_107 => 107,
    bip39_test_vectors_extended_108 => 108,
    bip39_test_vectors_extended_109 => 109,
    bip39_test_vectors_extended_110 => 110,
    bip39_test_vectors_extended_111 => 111,
    bip39_test_vectors_extended_112 => 112,
    bip39_test_vectors_extended_113 => 113,
    bip39_test_vectors_extended_114 => 114,
    bip39_test_vectors_extended_115 => 115,
    bip39_test_vectors_extended_116 => 116,
    bip39_test_vectors_extended_117 => 117,
    bip39_test_vectors_extended_118 => 118,
    bip39_test_vectors_extended_119 => 119,
    bip39_test_vectors_extended_120 => 120,
    bip39_test_vectors_extended_121 => 121,
    bip39_test_vectors_extended_122 => 122,
    bip39_test_vectors_extended_123 => 123,
    bip39_test_vectors_extended_124 => 124,
    bip39_test_vectors_extended_125 => 125,
    bip39_test_vectors_extended_126 => 126,
    bip39_test_vectors_extended_127 => 127,
    bip39_test_vectors_extended_128 => 128,
    bip39_test_vectors_extended_129 => 129,
    bip39_test_vectors_extended_130 => 130,
    bip39_test_vectors_extended_131 => 131,
    bip39_test_vectors_extended_132 => 132,
    bip39_test_vectors_extended_133 => 133,
    bip39_test_vectors_extended_134 => 134,
    bip39_test_vectors_extended_135 => 135,
    bip39_test_vectors_extended_136 => 136,
    bip39_test_vectors_extended_137 => 137,
    bip39_test_vectors_extended_138 => 138,
    bip39_test_vectors_extended_139 => 139,
    bip39_test_vectors_extended_140 => 140,
    bip39_test_vectors_extended_141 => 141,
    bip39_test_vectors_extended_142 => 142,
    bip39_test_vectors_extended_143 => 143,
    bip39_test_vectors_extended_144 => 144,
    bip39_test_vectors_extended_145 => 145,
    bip39_test_vectors_extended_146 => 146,
    bip39_test_vectors_extended_147 => 147,
    bip39_test_vectors_extended_148 => 148,
    bip39_test_vectors_extended_149 => 149,
    bip39_test_vectors_extended_150 => 150,
    bip39_test_vectors_extended_151 => 151,
    bip39_test_vectors_extended_152 => 152,
    bip39_test_vectors_extended_153 => 153,
    bip39_test_vectors_extended_154 => 154,
    bip39_test_vectors_extended_155 => 155,
    bip39_test_vectors_extended_156 => 156,
    bip39_test_vectors_extended_157 => 157,
    bip39_test_vectors_extended_158 => 158,
    bip39_test_vectors_extended_159 => 159,
    bip39_test_vectors_extended_160 => 160,
    bip39_test_vectors_extended_161 => 161,
    bip39_test_vectors_extended_162 => 162,
    bip39_test_vectors_extended_163 => 163,
    bip39_test_vectors_extended_164 => 164,
    bip39_test_vectors_extended_165 => 165,
    bip39_test_vectors_extended_166 => 166,
    bip39_test_vectors_extended_167 => 167,
    bip39_test_vectors_extended_168 => 168,
    bip39_test_vectors_extended_169 => 169,
    bip39_test_vectors_extended_170 => 170,
    bip39_test_vectors_extended_171 => 171,
    bip39_test_vectors_extended_172 => 172,
    bip39_test_vectors_extended_173 => 173,
    bip39_test_vectors_extended_174 => 174,
    bip39_test_vectors_extended_175 => 175,
    bip39_test_vectors_extended_176 => 176,
    bip39_test_vectors_extended_177 => 177,
    bip39_test_vectors_extended_178 => 178,
    bip39_test_vectors_extended_179 => 179,
    bip39_test_vectors_extended_180 => 180,
    bip39_test_vectors_extended_181 => 181,
    bip39_test_vectors_extended_182 => 182,
    bip39_test_vectors_extended_183 => 183,
    bip39_test_vectors_extended_184 => 184,
    bip39_test_vectors_extended_185 => 185,
    bip39_test_vectors_extended_186 => 186,
    bip39_test_vectors_extended_187 => 187,
    bip39_test_vectors_extended_188 => 188,
    bip39_test_vectors_extended_189 => 189,
    bip39_test_vectors_extended_190 => 190,
    bip39_test_vectors_extended_191 => 191,
    bip39_test_vectors_extended_192 => 192,
    bip39_test_vectors_extended_193 => 193,
    bip39_test_vectors_extended_194 => 194,
    bip39_test_vectors_extended_195 => 195,
    bip39_test_vectors_extended_196 => 196,
    bip39_test_vectors_extended_197 => 197,
    bip39_test_vectors_extended_198 => 198,
    bip39_test_vectors_extended_199 => 199,
    bip39_test_vectors_extended_200 => 200,
    bip39_test_vectors_extended_201 => 201,
    bip39_test_vectors_extended_202 => 202,
    bip39_test_vectors_extended_203 => 203,
    bip39_test_vectors_extended_204 => 204,
    bip39_test_vectors_extended_205 => 205,
    bip39_test_vectors_extended_206 => 206,
    bip39_test_vectors_extended_207 => 207,
    bip39_test_vectors_extended_208 => 208,
    bip39_test_vectors_extended_209 => 209,
    bip39_test_vectors_extended_210 => 210,
    bip39_test_vectors_extended_211 => 211,
    bip39_test_vectors_extended_212 => 212,
    bip39_test_vectors_extended_213 => 213,
    bip39_test_vectors_extended_214 => 214,
    bip39_test_vectors_extended_215 => 215,
    bip39_test_vectors_extended_216 => 216,
    bip39_test_vectors_extended_217 => 217,
    bip39_test_vectors_extended_218 => 218,
    bip39_test_vectors_extended_219 => 219,
    bip39_test_vectors_extended_220 => 220,
    bip39_test_vectors_extended_221 => 221,
    bip39_test_vectors_extended_222 => 222,
    bip39_test_vectors_extended_223 => 223,
    bip39_test_vectors_extended_224 => 224,
    bip39_test_vectors_extended_225 => 225,
    bip39_test_vectors_extended_226 => 226,
    bip39_test_vectors_extended_227 => 227,
    bip39_test_vectors_extended_228 => 228,
    bip39_test_vectors_extended_229 => 229,
    bip39_test_vectors_extended_230 => 230,
    bip39_test_vectors_extended_231 => 231,
    bip39_test_vectors_extended_232 => 232,
    bip39_test_vectors_extended_233 => 233,
    bip39_test_vectors_extended_234 => 234,
    bip39_test_vectors_extended_235 => 235,
    bip39_test_vectors_extended_236 => 236,
    bip39_test_vectors_extended_237 => 237,
    bip39_test_vectors_extended_238 => 238,
    bip39_test_vectors_extended_239 => 239,
}

/// Mixed case (`Libauth`) to verify case-sensitivity.
const OUR_PASSPHRASE: &str = "Libauth";

/// `extendedVectors`
fn extended_vectors() -> Vec<Bip39TestVector> {
    CONVERTED_VECTORS
        .iter()
        .map(|vector| {
            let seed = derive_seed_from_bip39_mnemonic(&vector.mnemonic, None, None);
            let seed_using_passphrase = derive_seed_from_bip39_mnemonic(&vector.mnemonic, None, Some(OUR_PASSPHRASE));
            let node = derive_hd_private_node_from_seed(&seed, None, None, None);
            let node_with_passphrase = derive_hd_private_node_from_seed(&seed_using_passphrase, None, None, None);
            let valid = |node: HdPrivateNode| -> HdPrivateNodeValid {
                match node {
                    HdPrivateNode::Valid(node) => node,
                    HdPrivateNode::Invalid(node) => panic!("invalid node: {node:?}"),
                }
            };
            let hd_key = assert_success(
                encode_hd_private_key(
                    &DecodedHdKey {
                        network: HdKeyNetwork::Mainnet,
                        node: valid(node),
                    },
                    None,
                ),
                None,
            )
            .hd_private_key;
            let hd_key_using_passphrase = assert_success(
                encode_hd_private_key(
                    &DecodedHdKey {
                        network: HdKeyNetwork::Mainnet,
                        node: valid(node_with_passphrase),
                    },
                    None,
                ),
                None,
            )
            .hd_private_key;
            Bip39TestVector {
                entropy: vector.entropy.clone(),
                hd_key: Some(hd_key),
                hd_key_using_passphrase,
                mnemonic: vector.mnemonic.clone(),
                passphrase: OUR_PASSPHRASE.to_string(),
                seed: Some(bin_to_hex(&seed)),
                seed_using_passphrase: bin_to_hex(&seed_using_passphrase),
                word_list: vector.word_list.clone(),
            }
        })
        .collect()
}

#[test]
fn bip39_test_vectors_extended_are_up_to_date() {
    let extended_vectors = extended_vectors();
    // if (process.env['GENERATE_TEST_VECTORS'] === '1') { test.after(`Write BIP39
    // Test Vectors (Extended) to: ${path}`, () => { writeFileSync(path,
    // JSON.stringify(extendedVectors)); }); }
    if std::env::var("GENERATE_TEST_VECTORS").as_deref() == Ok("1") {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib/key/fixtures/bip39.extended-vectors.json");
        let json = Json::Array(extended_vectors.iter().map(Bip39TestVector::to_json).collect());
        std::fs::write(path, encode_json(&json)).expect("the fixture is writable");
    }
    let solution = "Run \"export GENERATE_TEST_VECTORS=1; yarn test:fast src/lib/key/bip39.spec.ts\" to correct this issue. (Note: watch tasks don't always update cached JSON imports when the source file changes. You may need to restart tsc.)";
    assert_eq!(*BIP39_EXTENDED_VECTORS, extended_vectors, "{solution}");
}

/// Substitution for the `bip39` npm package (JavaScript-only): 32 inputs
/// sampled from this test's fast-check arbitraries (`fc.sample(..., { seed: 1,
/// numRuns: 32 })`) – `[selectLength, entropySource (hex), selectLanguage]` –
/// and the result of `entropyToMnemonic(Buffer.from(entropy), list)` for each,
/// computed with the `bip39` package in Node.js.
const NPM_BIP39_ENTROPY_TO_MNEMONIC: [(usize, &str, usize, &str); 32] = [
    (0, "fae0b185c80386d7ff02a2042efd97fbe6012dac0102751cfcc14507a6055a00", 4, "vilain admirer extraire lithium correct franchir viseur engin acquérir habitude février vedette"),
    (3, "f8a7c5d0a836f9fcfcfcff06faf9046e06b002fc3dd70719fe04fb01951aea04", 0, "萄 首 威 考 肉 溜 卢 冰 定 扣 含 扶 沉 大 昂 壳 行 叛 寨 仇 与"),
    (2, "9ff92be48d04074806fffb0300fcfcfd0107a800f8700207fd133b00e7fd019f", 2, "pomlka stehno zima cvik jednatel potrava demokrat zvesela atol bicykl jantar zlato bydlet toaleta badatel brzda arogance hygiena"),
    (0, "26fa510200f806055001927607f901582e142601a702efc4bd5cff000267f25b", 0, "切 拒 神 国 脑 来 推 近 顾 女 谈 袋"),
    (2, "6b8eb59c25fe001b0304d4025ff9f86a0300f805fd02c5010559cf14a3bc360a", 1, "答 鄉 剛 堅 崗 還 點 耳 要 矮 菌 硝 低 伊 料 黎 柳 把"),
    (3, "030305a4b1080002fce3d500eafe02040405f9f906ce0604fbcb68aefabc0402", 2, "atol citace mikrofon louh obsluha anekdota zalepit nominace alkohol kulomet obvinit bidlo jedle zplodit vidina ubytovna barva epopej zahynout tekutina vylekat"),
    (1, "081c27b8586a851faa020e33050205040401000605760207fffd039f05fd700e", 1, "三 曹 債 鬼 虛 壁 鋒 項 技 身 敢 三 推 熟 設"),
    (3, "051a5605ba15f70402fcab0703050163fde802076f01db450207040305f50729", 8, "acusador rimar incolor gestor europeu inerente alface macaco adubo assoalho coruja radial sincero abotoar bacia soletrar segmento borbulha indutor afivelar cogumelo"),
    (3, "c2041bfdd9e789f2f9f801000392fba102690501c7a3ecfca3fa04315b7d06f3", 7, "조선 기술 희곡 장르 시리즈 홈페이지 편지 가끔 가격 극히 정장 물가 내일 아시아 개성 햄버거 하순 특수 흐름 건설 광주"),
    (4, "05c3ce0307a00702538b067905d1fdb20281af7301050006ffc3fa60fa03d9ad", 7, "강원도 금메달 심부름 고통 가능 심정 벌금 산책 시선 답장 실장 새벽 노력 최선 직원 기숙사 가격 만세 한문 행동 골목 가정 서쪽 작품"),
    (4, "b18c2d00fbcb04fc996978ecfbfa82ff0750c7b679812245ec2e5c822ffd04fb", 7, "작용 삼국 무릎 형사 자원 신화 서른 당장 하순 큰절 위협 훨씬 술병 상품 출입 대문 긴장 대단히 경영 전달 깍두기 흐름 관련 생물"),
    (0, "900623ccbdbaa9fda606f5012ef8f642b603d87b01c1189af82800ff8a069f12", 8, "letivo caracol turma hiato nutrir xeretar manhoso singular abranger grego concha inspetor"),
    (1, "8dfeb8802f4cfd9049ae5600f9f1956de5fa66c103be052482cff40220958034", 6, "たらす　よろしい　おおい　さめる　ひるま　はんとし　おんけい　ひさしぶり　あける　ひりつ　しねま　ほうほう　さんいん　きぞん　あらすじ"),
    (1, "68eea28301f132c0abf8fc27355c59f884fbe8bf03f5aefd80030205c0b15b27", 1, "貴 孫 逃 分 氣 貨 縫 先 白 描 想 墊 昇 諮 暢"),
    (3, "3fff8f01ebb401b0abe110f94806fe0ae80200ebfa3ff8d8527ff0d702fcf947", 1, "黃 沫 吊 罵 推 霧 伍 熱 糞 顯 簽 情 蟲 在 縫 章 瘋 偶 冰 厲 抓"),
    (4, "4d02260513b4e107050533b2fe02cefd037e1a2fa62e6404430003ff02d10100", 2, "kohout cedr ocel empatie komando odkaz chlad pracovat rostlina vzdor roup zlato hostina brepta skladba soused magistr doslov slabika bicykl vzduch mezera bageta ananas"),
    (2, "7e0171b4e84dcbf3ffe63d04010100690078c5f1f8fc0502fdfeb12000cab107", 3, "lawn argue honey spatial syrup wheat zebra sibling advice amount divorce spirit always glass side buzz agree behave"),
    (1, "f872dd049fb642a489ff0435ee04aa03e026052980feb1220bda01254ed8ba03", 1, "霞 盛 企 死 願 簡 場 滲 除 揚 八 經 他 時 稍"),
    (0, "3085f5c8fcbe03a06f01c8f9b8fe070007b005e5050001e96befab9334ca0f02", 8, "capotar canoa gazela verniz soletrar resfriar pincel ciranda vertente radial indutor absoluto"),
    (0, "ca85f9fb519a3a05a6037b52c1e4a86a6607f95ee30035010b021a02f7fb06a7", 1, "玩 影 符 售 泡 用 嘴 翻 盡 社 報 挺"),
    (4, "fa6e7339011666a804450254c83d0187fd0371c007fa06e706fd2e06f804938a", 9, "vigor instante rueda acento gratis fachada árbol oculto fallo desnudo delfín apoyo sacar portal ábaco zapato aire copa queja fogón humilde aceptar entrar dejar"),
    (4, "93f8c867f96ff8afc5d2dd06f98800a806a406aa07b9ff025106fa00c74be900", 6, "ちしき　はろうぃん　うんてん　ようい　わじまし　こんわく　うぶげ　ざつがく　いいだす　ひつじゅひん　あいさつ　こすう　しゃれい　あてはまる　とさか　られつ　わかめ　うおざ　げきげん　よくぼう　いっそう　とおい　てんとう　うどん"),
    (2, "00b8cc0494a1e6dd38f8b7f85279067aa6031379453407cf0383d2e21d010602", 8, "abelha quebrar abranger briga baixista fuligem sulfato arrumar vencedor lorde cravo vadiar evoluir judeu surpresa navio afetivo guincho"),
    (1, "03a761fb161566cdb0e70000b8f3610690073d3b589c9efbca06a1de03fafd8f", 7, "갈증 며느리 실례 단맛 부정 서클 종소리 클럽 가르침 중부 추억 계속 가능 원고 하느님"),
    (3, "2afaf9cddfd653dd76a420053a9e203fdded1f1ff872e0050e016db9e3330f5a", 0, "名 扣 抓 闹 孩 醇 刷 塔 工 碗 抽 幅 疾 词 竟 前 岗 真 泽 漫 柬"),
    (4, "8fd302b4c2cafb24004a8400fef8adfffcfbf05d6a001706e5d7a5a60402073c", 9, "minuto natal pausa madera pensar momento abuelo esquí abrazo venir cariño zurdo sábado ver jaula defensa atún cómodo jefe embudo gafas abrir batería maíz"),
    (2, "0efe78a90747250304fa01ab0266c9b9fe0705ad01fc1e025ccc1db702d50cdd", 0, "日 丛 完 天 编 虑 变 显 膜 气 弧 娘 盗 湿 寒 讲 几 并"),
    (2, "ab2b96d8f9040002fc6a04aecd9401fc1803d40c916a020003dc2c016e076a98", 9, "parcela forro pleito umbral defensa acabar tutor delgado peldaño historia abierto ver lindo toldo cine cebolla acelga acción"),
    (0, "99927ae0d3032b016765e69e5302da04eb057775fbccf8037087fb003409fa34", 5, "pargolo ortica ripresa portata cortese mitezza periodo rotondo pervaso palesare rinascita alunno"),
    (0, "e435dae6a304370201fa02567b4c2ffac104622ec0ea2c076d02d69b86f4428a", 1, "鼻 袖 礙 案 輪 側 十 談 載 薯 使 刮"),
    (0, "fba252fc2e7906e1f907338e4804f7b6008be001fd300ca7f901ffde0003065c", 0, "酱 利 妻 烧 闻 秋 坑 尸 碎 显 价 烟"),
    (2, "f80001b49daa0407d0940505f707f904c7b8011229cedcb424a62b04bb00f8a4", 1, "捅 的 免 廠 黎 分 英 碳 說 桌 玄 水 懷 不 服 格 腔 登"),
];

#[test]
fn fast_check_crypto_encode_bip39_mnemonic_non_standard_and_bip39_npm_produce_equivalent_results() {
    for (select_length, entropy_source, select_language, npm_bip39) in NPM_BIP39_ENTROPY_TO_MNEMONIC {
        let entropy_source = hex_to_bin(entropy_source);
        let entropy = &entropy_source[..[16, 20, 24, 28, 32][select_length]];
        let list = word_lists()[select_language];
        let result = match encode_bip39_mnemonic_non_standard(entropy, list) {
            Err(result) => panic!("{result}"),
            Ok(result) => result,
        };
        // const npmBip39 = entropyToMnemonic(Buffer.from(entropy), list);
        assert_eq!(result.phrase, npm_bip39);
    }
}

/// Substitution for the `bip39` npm package (JavaScript-only): 32 inputs
/// sampled from this test's fast-check arbitraries (`fc.sample(..., { seed: 1,
/// numRuns: 32 })`) – `[mnemonic, passphrase]` – and the results of
/// `mnemonicToSeedSync(mnemonic)` and `mnemonicToSeedSync(mnemonic,
/// passphrase)` (hex) for each, computed with the `bip39` package in Node.js.
const NPM_BIP39_MNEMONIC_TO_SEED: [(&str, &str, &str, &str); 32] = [
    (
        "TVb~o\"nP",
        "Q3~b)Vl",
        "cc06a34f9d3176c2e74d7cd1cbf8f42e8ca930cb2454f60929e04a5830d1737a715c0ef20d76e6c8590913b3fa523a408b920b517472e3faaa9c11b4ba94d223",
        "ea23fa7b4febf2acc5102edee5b8d4ebdb646a99717dd2360c55de3048f93ff287baf4fb2b321fe7cfa4af5504210f69605f544f0097130b2fd5a5b054537e12",
    ),
    (
        "ref",
        "Z#f~{zzz\"",
        "674b73a5c052894f068254a7f51a2f3be42f8470992321c3e61ce23670a95e70900893d72932a62dd5686eca7087268127ad4ab206b147cb17f20723307da5f9",
        "3c0711468f928dcbe8d36e1705333f8a2c57f2c7f129e079312c31b8ae5819d7c671f2c15526dfb1e5fd5a61c2cfa3d296dbe2d9956d5da31fe9e7377e5902f8",
    ),
    (
        "",
        "valueOf",
        "4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "8de4b4d136fd018fe52b0d2342825cc3ee854c4a11e1d6d213e13672d17d3c45e66c61808fbf75c4c02562eac176eb056ed60332f6991377cddda1776ab06321",
    ),
    (
        "k",
        "y=",
        "4f57e014a0871ff9e05f218b5fd5ef93d44a3fccbd38d1ecf36a4b0c270e2339c7150969f3094e03227c604afbe5c26155e0d9f0ca1a6bdc7a86767c0ba7455e",
        "1bfdb09cd735cfd6d1bc2fc794b8d656ff7ce514caaad1d54a33e5a4dd96ea8d96e38ee7495ac1f68fe734d1b1320f2cb660b84198707d9fe5812d259639926a",
    ),
    (
        "2vn",
        "IUjx",
        "14fa39d87ae658f097183efb35975057a9c51ca91e109a2c2a903cd24a6b125ccf88e0239364dc5d5641f2a225b1a669c4730b53c2f28fab2b5c8f9e1d631632",
        "b29b90cbbbfc04ded56065df9d525496707630f31522647f4846713c5dd8f18ca9ddf0e233357eb61aa97a1b5feed6cbb72391158c0f738b35d395fdf6ba0f5a",
    ),
    (
        "yvF*+s)%%=",
        "pE>",
        "5530c5e11b6a2da675bd86119a7347726890c3e822d495d168019209519876d5492c9176ca4ead0c3707c02dd5a1c9645d43054badf5324f8aa3fffe7bc61ec4",
        "5fd12396bf4e04d9b7675ea6889b66b96819dc499cedf8a72adb313f2b7fc175f80d650b914a64c97e61e5e5e20d7e53fe2ae18562d2aae287f8b43a2304bb74",
    ),
    (
        "m6Rc",
        "@geVp%Mj",
        "f6d2c68a0075c84cf9e6d071765429abdb6971a0695f9af37c21eeb7140cdd4ae19b70b9e2e20e309d65c347d4e7797f6a7614bb64ccb428cf96f569e08f2243",
        "eaaf60043d63e36718869fb192212c0d9dd95176695a65051302cc0fc7236f8bf2a56f9aae426e61a333e30ed0f4365f6eb6120dbb61bb27cffc926fdac7f17a",
    ),
    (
        "__proto__",
        "Qm>s~dv3I",
        "b74b4e554ef705aaed03010a741b85ba6cee9845d8ec9b9a69564f97468795093ae0624bb43a1871babd5e9fd9875aa41823a2503e1bee6d5928c03a6b4fdcf7",
        "f89225c2dce0f80394990dc6ea7b83f3fda12e46426add04cdfd8d5058e089088685a8734ab4f0827e8d9001748bdcbee3046b4c0469cd6b9cb7d45e7a77f7bd",
    ),
    (
        "apply",
        "ek]r&",
        "948668ab40c935f8fc2a9bb1672b108c7ea653bac0ad017677378620b34e1deec562eea5830a2b4eac4da3b670a6265c3f5726556d627eeb77b92327bba1054f",
        "273c26439872ec5d5e482b07e380c868aade901a76f1e6a67ba40c3ae368a3b59e3808e28e748e855cdb8d35a6456810150183e76c11c507bfc84cb07a193118",
    ),
    (
        "j^.>5]ei#5",
        "]mcX>",
        "b3a9fa61c913c9feaa23c19b418f3c9d8b421bedbf38de0889e224d2b6155840a15b7e8e6eda59fc0dacbf41dd055d98a1e518f08642bc40dc11e44b59580a69",
        "391382e25a967ae2fb9341431a11e944740d51bc00546439322fc7785309fdea3e73e0e10123e6beda391e4a8d230aa6a1e8a726469d838f031e08988365c16c",
    ),
    (
        "?YH4>Kw",
        "",
        "363d8c32b4cb48f9df4af9331f7132aa7ce35717a999b41655714fbba76c144acd3d4a90b8b22e82cef9548febf8f915b6b8d8d17dd66aa781d536effde07619",
        "363d8c32b4cb48f9df4af9331f7132aa7ce35717a999b41655714fbba76c144acd3d4a90b8b22e82cef9548febf8f915b6b8d8d17dd66aa781d536effde07619",
    ),
    (
        "I2@",
        "eSzD",
        "4856bdf1c2e4bfc2e292ced434c4115cd428df98081cadf390eed4ebbcd9db87eb528a60e93ce5792afd4018e3335dbc3711fc7329b93c0e8f78cae84d109619",
        "1675cf5c293e78bf0aee3368cef3fbdc939a1b3a613b7889bad5332a038cb8e494f8d9da9bca8d4feb2a11d9edab29e8fdf2ac53134a6b70b4296f7989528b3a",
    ),
    (
        "+rJ7AYdEM",
        ">?}",
        "40cfc08da6ce83c491d6c71a3b40ae40c11ea979c21927c8784c67faca3d433ceaf09fd30c3d56c332b0a3e5f4ada78d80da8283fae09c8ff32b6aecc56fc199",
        "d467ad7e108f7a1daaf4330603ab497538e0c707e1f589235419e9bc66db083450403017c19f0ce3cb7ffb94d740f1cac1ef9ee25d954158c8c3f33b9e7f7210",
    ),
    (
        "ope",
        "..p\\/",
        "5d1e46f6692afd873b5c68e0823fd26f58b8d781d9f4f687029f45a2c70ea70783223af6bc2186dc6fde9a002fb951126efe0f241b353c84a2f8425b3cff6ecd",
        "6f211333a21987439cb236f37b4084618922e96073ad3fa7ba2ba2a5727972d56955a448c2cb9c176f433070fe3c9c1d88f4439b75dcf76d96d7f2b495fffac2",
    ),
    (
        "KX",
        "K+$D\\d.d9",
        "36187fcf1e6ad4ddfd03d504d4a58228f03140a7070abed7ad0a3b7b81e9962f3d3402e1e446209fabb71c338f5f96c37ef9937a83a9c84c394e02362a7e834c",
        "2defe36e65e0fa2dfa283e6517e239deea2e925b5cdff04050b7639111559ec20feee80c90730c4a34a70d4a63376a825931d2ea0e8274b10e86a79bf2e20628",
    ),
    (
        "",
        "&/o'4)sO_",
        "4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "bd3d1e994459735b7e6cfc2256153c3ee2ff2548ebedf029268b893f9c0f817cf84169e18e6466f7ae8cb831bc521b93bf2aa42d2103b0c62c28de32fb2507a1",
    ),
    (
        "3m,d",
        "PK4na",
        "d2aa41330f2627f25adbe86ba0c91dff68c57f6bf121e3bee3f78055c111ec47cf2599b6b73df6ef8992285dd6faf4262a3f554dd9b5870c0e34dd4e8a507bad",
        "2b2f48e50b6f6fa66c9e212725fc512d8e6ed4adc9693a066aef400d7af984be2c5c570f1a9a3c26621480d1456200e75ba89840be559add11833d6845252362",
    ),
    (
        "l",
        "5~@uJ*",
        "05ed102fb70ae98349466073e8806f6fc8f060bbe8ce0f5acba943e284bcf7434523f3533391e7d8a10800855a39149b5d4ee379f9eb8c29acfef8cc8e5939b6",
        "bbebf7d960e3c7c0c5f0a4be1249fa8c8ba3fabc0d8df4ba3424cba66c22a4e334836b9e7e550cf9cc8c250899c1422126f59645ff0a83fe190fe9b294322b2e",
    ),
    (
        "D_@6~X,",
        "mT`f",
        "3f75a9056e00551d514ced31c9ebe2478af32280a36dd6704459c942d1e854181f77aecfc363f1b42fb37c6f6b505a09200a29f4cfa149d0af195e6800fb028a",
        "9620e12a9bef54cf653a0872a04d0b48d25721ce83ff4f11309427607f5398ee5789983b0a3f0e1dfa06d08027c726b4b20d1029709ebcb548efb6d036a9a6b5",
    ),
    (
        "lc+",
        "y3y5h%521",
        "3074b96e2ef04ec11908a084302feb11216897aac00f89f424c18f641f4fc732690929682cdf62535c10d7cc9d660edf935c762612794ab72008df1359ce635e",
        "f01794da2f0d7fe07ac09abf94c2c37908389739d547d5a7dfce9021ba2b58354b5cbc6e253a95932e0bd664060a75b3abc700681b3ead18d3b2dfeba8c59cc5",
    ),
    (
        "zn9>\"H7!",
        "#z.d$D|",
        "5fea14de62b8aed4f0347a56400670fe5b2ce127d40a84e1f8505fa770233825dab0337d720a040555defa8017fb13e9ca841a56b116ac09b83915f3ae300d5f",
        "998d4b01c78eaa82b8e0bf1ad8ddf2265f813008c029132cd588ad6500aaab8d5499fec6660ccee7e467b2c1439e1c49dc5b7df680981ee7cb52619a07f49468",
    ),
    (
        ">]*v]9I9",
        "#3Qp<",
        "1dfa323c012540a5f11644b583a834aa9db19aef9ed0ca8c5e2f30bdc23c18699707ae1e70f78ec344dbeecddc967888379cb51ece5c953262ceec5dab126eaf",
        "1681e11b7feb05f693475df0c5b27818c2918869ce5fd2f8645ac5adfce7c3051db1967f5d9e71d4aef023c7e5c769cfb614358b59a80ad2fa19538d08244920",
    ),
    (
        "GWW",
        "G",
        "c3da739264914fd23cf79b921bb2f952a4855dd58ecbaa4c10273b8ce16b3bc83855edd325b1a40be7e6814788b7b79d8b8a6c193ac142cc24b511d058552047",
        "7035cfe3b7543ea3808b6be250163580bb3dc59eab0584aaa16b491e703541a3633f23c117b3344e21e9f919ccc8c35e4cff66631a575d168e6c262adda5d84a",
    ),
    (
        "",
        "YtDSY#|",
        "4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "cbfd31ba43c58ee2123763ca56a161d2a1eee82d92f6116c05eac82648dfd6c7d01d71ddb045cdea316e87dc1e2c65f822233fce723f25da1cbe2c67e81d1efc",
    ),
    (
        "(prototy",
        "4U?R'sdu",
        "bbdd53c4151fbdc8e01ca35a3cbd8709ec865154be30d439cc73f8fdbb9b5dba29786d6a994124204c73b9c0fe43363835bc348c5d7ebbcd2f5c1175617a0c0f",
        "ac97bb5be20ab9145b0d4dbff09316a534b2155ffc1a8cb0cc3c7cd73330db17604d3a74ab9ea2f3e083a41baf6ab8c7f316d8e42dcb3d0c2cde5ba344f4da10",
    ),
    (
        "F5yZ",
        "M{^^",
        "8085286a3b86d3b4f015e0523773f9a7f1fd0fd1caa9c0213fbad9bd89c0a5d2e477718584664b3118f61922a94477f017063dcf17003793888cfe13145ea0e3",
        "8ea8ea17deaff47f19f3508288a33033b3a7f9598884d191214ee54090abf018dbe5e8009a3ebdee12151a0f917f02e62a7a82cb25f2536223ac61b25b96c649",
    ),
    (
        "",
        "%#\\$ett",
        "4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "d47c4ded1c17af33a89259031321acb0ded2104c6c13ef0354423d0a71c43db5d473597f976c313019fad9938f47ebe637edd18fb4f9fce35a05fe7639fde30d",
    ),
    (
        "nt2",
        "f",
        "c95e7590c6147381350dda5ea1cc5c30491d9249dd451cdb2d3d34f6c21fc10ec50fcf9fdf0df7bf955b5a3fc56aba0ccfb7ef906766d5c5aef1a4732fef6b71",
        "74c0b930d7719be89f2bd7f0a4629b67e2c5ba8fc21119f65a3b670fa0913d4c9dbb626aade2e8d5ba12432bb3905cc3e6a392a921e4c75563e2d1f9e8b0eb4a",
    ),
    (
        ")-<j)+",
        "qyF\\cK<|$;",
        "bd94327f9d7d0b4f4e9b60ca8ad89320daf3928eb367829bc5bf70047c88117734673a6616c16a55131aa3aff12869bd7c50c22f707088cec1e0e59e0a19cf9a",
        "3a37f7f236afd738977d61f6aa1f02cf8d6a45f4400210c37940daa5f217726827b2b873d40c950e0e4fba0c3ca28f069aa854666610842431ba73e037ab177a",
    ),
    (
        "?Z",
        "&G",
        "1ef438798fc948c9e14c079f70b70d0202a059be1e6ce8ac175054fe73e1d0805f3d5b38ee404e51cbcdfde237d2248b6a1437a49098a49d50737e8de9c0d6e5",
        "74b041c8652f1eb22557385303e826383df630a2a115e82982da17aa1a881ed69b2c6d97e948bfc4a4ab36cd4d3e7a6bac0b72a9407b3f76ca366fc1e71ba52b",
    ),
    (
        "}",
        "9rq\"2\"0",
        "80ddf7d0652fe00cd8e4e9e3404243883fa9915fce14950941684edd126bcc41958f240a5e0282d5ba9bf368e96410e49b7920b6c054c1a3c94f59af53155c7a",
        "5808d26650e1516922a302e4cd6c2294fd581ec7634d34e21e1f261a2c011d5af8db07d9d3d0f073bb9b044da12255f6fa6705620c0cb59e3b21e72d83a9b839",
    ),
    (
        "valueOf",
        "\"oW",
        "6cf89e1097837286d0f0fb8d0d7e193505a1bc46b8f2a46982db5533338d20e3ae6f49527cc0010ff3155d3d06e72626952283c91ebbe9d3d974c5a0a46d73a4",
        "b3a9de43cab91a1a3ca3c290cf7a906fbf6f0dfe72a9b8842fdc6516c9987bcc09458fd85d9d0aab8837ba0d9bf8445d2716539e616df0fb7daf25baf4b7cbc0",
    ),
];

#[test]
fn fast_check_crypto_derive_seed_from_bip39_mnemonic_and_bip39_npm_produce_equivalent_results() {
    for (mnemonic, passphrase, npm_bip39, npm_bip39_pass) in NPM_BIP39_MNEMONIC_TO_SEED {
        let libauth = derive_seed_from_bip39_mnemonic(mnemonic, None, None);
        assert_eq!(libauth, hex_to_bin(npm_bip39));
        let libauth_pass = derive_seed_from_bip39_mnemonic(mnemonic, None, Some(passphrase));
        assert_eq!(libauth_pass, hex_to_bin(npm_bip39_pass));
    }
}

#[test]
#[ignore = "test.todo: attemptBip39MnemonicErrorCorrection: works"]
fn attempt_bip39_mnemonic_error_correction_works() {}

#[test]
#[ignore = "test.todo: [fast-check] attemptBip39MnemonicErrorCorrection"]
fn fast_check_attempt_bip39_mnemonic_error_correction() {}
