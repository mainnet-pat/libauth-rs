//! Port of `vmb-tests/sources/core.signature-checking.multisig.pubkey-validation.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, VmbTestDefinitionGroup, generate_test_cases, set_expected_results,
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

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Signature checking".to_string(),
            set_expected_results(
                generate_test_cases(
                    ["<$0> <$1.$2_signature.all_outputs>", "OP_1 <$3> <key1.public_key> OP_2 OP_CHECKMULTISIG", "1-of-2 $2 multisig with $0, $1 ($3)"],
                    &[
                        vec![
                            ("checkBits of zero".to_string(), "0".to_string()),
                            ("checkBits of key 1".to_string(), "0b10".to_string()),
                            ("checkBits of key 2".to_string(), "0b1".to_string()),
                        ],
                        vec![
                            ("key 1 signature".to_string(), "key1".to_string()),
                            ("key 2 signature".to_string(), "key2".to_string()),
                        ],
                        vec![
                            ("ECDSA".to_string(), "ecdsa".to_string()),
                            ("Schnorr".to_string(), "schnorr".to_string()),
                        ],
                        vec![
                            ("second public key: valid compressed key2".to_string(), "key2.public_key".to_string()),
                            ("second public key: short arbitrary data".to_string(), "0x0000000000".to_string()),
                            ("second public key: excessive length".to_string(), "0x040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string()),
                            ("second public key: valid legacy hybrid format".to_string(), "0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8".to_string()),
                            ("second public key: valid uncompressed key2".to_string(), "0x04c23083dccdc50247ebc5725c88d6d550cc49c9cb94e4bd4c485a1c6715a5dbfd4e56a5f51b754c2f35f95353ff5fd44855e6b28b39ab794d6b354dc2d3629e53".to_string()),
                        ],
                    ],
                    None,
                    None,
                ),
                &results(&[
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 1 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 1 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 1 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 1 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 1 signature (second public key: valid uncompressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 2 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 2 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 2 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 2 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 1, key 2 signature (second public key: valid uncompressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 1 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 1 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 1 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 1 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 1 signature (second public key: valid uncompressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 2 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 2 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 2 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 2 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of key 2, key 2 signature (second public key: valid uncompressed key2)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 1 signature (second public key: excessive length)", &[]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 1 signature (second public key: short arbitrary data)", &[]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 1 signature (second public key: valid compressed key2)", &["p2s_standard"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 1 signature (second public key: valid legacy hybrid format)", &["p2s_standard"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 1 signature (second public key: valid uncompressed key2)", &["p2s_standard"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 2 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 2 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 2 signature (second public key: valid compressed key2)", &["p2s_standard"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 2 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 ECDSA multisig with checkBits of zero, key 2 signature (second public key: valid uncompressed key2)", &["p2s_standard"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 1 signature (second public key: excessive length)", &[]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 1 signature (second public key: short arbitrary data)", &[]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 1 signature (second public key: valid compressed key2)", &["p2s_standard"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 1 signature (second public key: valid legacy hybrid format)", &["p2s_standard"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 1 signature (second public key: valid uncompressed key2)", &["p2s_standard"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 2 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 2 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 2 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 2 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 1, key 2 signature (second public key: valid uncompressed key2)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 1 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 1 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 1 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 1 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 1 signature (second public key: valid uncompressed key2)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 2 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 2 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 2 signature (second public key: valid compressed key2)", &["p2s_standard"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 2 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of key 2, key 2 signature (second public key: valid uncompressed key2)", &["p2s_standard"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 1 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 1 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 1 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 1 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 1 signature (second public key: valid uncompressed key2)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 2 signature (second public key: excessive length)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 2 signature (second public key: short arbitrary data)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 2 signature (second public key: valid compressed key2)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 2 signature (second public key: valid legacy hybrid format)", &["invalid"]),
                    ("1-of-2 Schnorr multisig with checkBits of zero, key 2 signature (second public key: valid uncompressed key2)", &["invalid"]),
                ]),
                None,
            ).expect("setExpectedResults"),
        ),
    ]
});
