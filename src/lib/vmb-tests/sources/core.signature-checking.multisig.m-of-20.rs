//! Port of `vmb-tests/sources/core.signature-checking.multisig.m-of-20.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, PossibleTestValue, VmbTestDefinitionGroup, generate_test_cases,
    set_expected_results,
};

/// Build a `setExpectedResults` result dictionary (test description → test
/// set override labels).
fn results(entries: &[(&str, &[&str])]) -> ExpectedResultsDictionary {
    entries
        .iter()
        .map(|(description, labels)| {
            (description.to_string(), labels.iter().map(|label| label.to_string()).collect())
        })
        .collect()
}

static signatureAlgorithms: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| vec![
    ("ECDSA".to_string(), "ecdsa".to_string()),
    ("Schnorr".to_string(), "schnorr".to_string()),
]);

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Signature checking".to_string(),
            [
                set_expected_results(
                    generate_test_cases(
                        [
                            "<$0> <$2.$1_signature.all_outputs> <$3.$1_signature.all_outputs>",
                            "<2> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <key16.public_key> <key17.public_key> <key18.public_key> <key19.public_key> <key20.public_key> <20> OP_CHECKMULTISIG",
                            "2-of-20 multisig with $0 ($1, $2 and $3)",
                        ],
                        &[
                            vec![
                                ("checkBits of zero".to_string(), "0".to_string()),
                                ("checkBits of keys 1 and 13".to_string(), "0b00000001 0b00010000 0b00000000".to_string()),
                                ("checkBits of keys 1 and 20".to_string(), "0b00000001 0b00000000 0b00001000".to_string()),
                                ("checkBits of keys 13 and 20".to_string(), "0b00000000 0b00010000 0b00001000".to_string()),
                            ],
                            signatureAlgorithms.clone(),
                            vec![
                                ("key 1".to_string(), "key1".to_string()),
                                ("key 13".to_string(), "key13".to_string()),
                                ("key 20".to_string(), "key20".to_string()),
                            ],
                            vec![
                                ("key 1".to_string(), "key1".to_string()),
                                ("key 13".to_string(), "key13".to_string()),
                                ("key 20".to_string(), "key20".to_string()),
                            ],
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 1 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 1 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 13 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (ECDSA, key 20 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 1 and key 13)", &["p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 1 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 13 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 13 (Schnorr, key 20 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 1 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 1 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 13 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (ECDSA, key 20 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 1 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 1 and key 20)", &["p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 13 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 1 and 20 (Schnorr, key 20 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 1 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 1 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 13 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (ECDSA, key 20 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 1 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 1 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 13 and key 20)", &["p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of keys 13 and 20 (Schnorr, key 20 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 1 and key 13)", &["p2s_invalid", "2023_p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 1 and key 20)", &["p2s_invalid", "2023_p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 13 and key 20)", &["p2s_invalid", "2023_p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (ECDSA, key 20 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 1 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 1 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 1 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 13 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 13 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 13 and key 20)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 20 and key 1)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 20 and key 13)", &["invalid"]),
                        ("2-of-20 multisig with checkBits of zero (Schnorr, key 20 and key 20)", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
                set_expected_results(
                    generate_test_cases(
                        [
                            "<$0> <key1.$1_signature.all_outputs> <key2.$1_signature.all_outputs> <key3.$1_signature.all_outputs> <key4.$1_signature.all_outputs> <key5.$1_signature.all_outputs> <key6.$1_signature.all_outputs> <key7.$1_signature.all_outputs> <key8.$1_signature.all_outputs>",
                            "<8> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <key16.public_key> <key17.public_key> <key18.public_key> <key19.public_key> <key20.public_key> <20> OP_CHECKMULTISIG",
                            "8-of-20 $1 multisig with $0 (keys 1 to 8)",
                        ],
                        &[
                            vec![
                                ("checkBits of zero".to_string(), "0".to_string()),
                                ("one-byte checkBits of keys 1 to 8".to_string(), "0b11111111".to_string()),
                                ("checkBits of keys 1 to 8".to_string(), "0b11111111 0b00000000 0b00000000".to_string()),
                            ],
                            signatureAlgorithms.clone(),
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("8-of-20 ECDSA multisig with checkBits of keys 1 to 8 (keys 1 to 8)", &["invalid"]),
                        
                        ("8-of-20 ECDSA multisig with checkBits of zero (keys 1 to 8)", &["p2s_invalid", "2023_p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("8-of-20 ECDSA multisig with one-byte checkBits of keys 1 to 8 (keys 1 to 8)", &["invalid"]),
                        ("8-of-20 Schnorr multisig with checkBits of keys 1 to 8 (keys 1 to 8)", &["p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("8-of-20 Schnorr multisig with checkBits of zero (keys 1 to 8)", &["invalid"]),
                        ("8-of-20 Schnorr multisig with one-byte checkBits of keys 1 to 8 (keys 1 to 8)", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
                set_expected_results(
                    generate_test_cases(
                        [
                            "<$0> <key1.$1_signature.all_outputs> <key2.$1_signature.all_outputs> <key3.$1_signature.all_outputs> <key4.$1_signature.all_outputs> <key5.$1_signature.all_outputs> <key6.$1_signature.all_outputs> <key7.$1_signature.all_outputs> <key8.$1_signature.all_outputs> <key9.$1_signature.all_outputs>",
                            "<9> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <key16.public_key> <key17.public_key> <key18.public_key> <key19.public_key> <key20.public_key> <20> OP_CHECKMULTISIG",
                            "9-of-20 $1 multisig with $0 (keys 1 to 9)",
                        ],
                        &[
                            vec![
                                ("checkBits of zero".to_string(), "0".to_string()),
                                ("checkBits of keys 1 to 9".to_string(), "0b11111111 0b00000001 0b00000000".to_string()),
                            ],
                            signatureAlgorithms.clone(),
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("9-of-20 ECDSA multisig with checkBits of keys 1 to 9 (keys 1 to 9)", &["invalid"]),
                        ("9-of-20 ECDSA multisig with checkBits of zero (keys 1 to 9)", &["p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("9-of-20 Schnorr multisig with checkBits of keys 1 to 9 (keys 1 to 9)", &["p2s_nonstandard", "2023_p2sh_invalid"]),
                        ("9-of-20 Schnorr multisig with checkBits of zero (keys 1 to 9)", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
                set_expected_results(
                    generate_test_cases(
                        ["<$0> <$2.$1_signature.all_outputs> <key3.$1_signature.all_outputs>", "<2> <$3> OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP OP_DUP <key2.public_key> OP_OVER OP_DUP OP_DUP OP_DUP <key3.public_key> <20> OP_CHECKMULTISIG", "2-of-20 $1 multisig with $0, signatures $2 and 20, and $3"],
                        &[
                            vec![
                                ("checkBits of zero".to_string(), "0".to_string()),
                                ("checkBits of keys 15 and 20".to_string(), "0b00000000 0b01000000 0b00001000".to_string()),
                                ("checkBits of keys 19 and 20".to_string(), "0b00000000 0b00000000 0b00001100".to_string()),
                            ],
                            signatureAlgorithms.clone(),
                            vec![
                                ("15".to_string(), "key2".to_string()),
                                ("19".to_string(), "key1".to_string()),
                            ],
                            vec![
                                ("valid public key 19".to_string(), "key1.public_key".to_string()),
                                ("invalid public key 19".to_string(), "0".to_string()),
                            ],
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("2-of-20 ECDSA multisig with checkBits of keys 15 and 20, signatures 15 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of keys 15 and 20, signatures 15 and 20, and valid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of keys 15 and 20, signatures 19 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of keys 15 and 20, signatures 19 and 20, and valid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of keys 19 and 20, signatures 15 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of keys 19 and 20, signatures 15 and 20, and valid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of keys 19 and 20, signatures 19 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of keys 19 and 20, signatures 19 and 20, and valid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of zero, signatures 15 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of zero, signatures 15 and 20, and valid public key 19", &["invalid", "2023_nonstandard"]),
                        ("2-of-20 ECDSA multisig with checkBits of zero, signatures 19 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 ECDSA multisig with checkBits of zero, signatures 19 and 20, and valid public key 19", &["invalid", "2023_nonstandard"]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 15 and 20, signatures 15 and 20, and invalid public key 19", &[]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 15 and 20, signatures 15 and 20, and valid public key 19", &[]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 15 and 20, signatures 19 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 15 and 20, signatures 19 and 20, and valid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 19 and 20, signatures 15 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 19 and 20, signatures 15 and 20, and valid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 19 and 20, signatures 19 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of keys 19 and 20, signatures 19 and 20, and valid public key 19", &[]),
                        ("2-of-20 Schnorr multisig with checkBits of zero, signatures 15 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of zero, signatures 15 and 20, and valid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of zero, signatures 19 and 20, and invalid public key 19", &["invalid"]),
                        ("2-of-20 Schnorr multisig with checkBits of zero, signatures 19 and 20, and valid public key 19", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
            ]
            .concat(),
        ),
    ]
});
