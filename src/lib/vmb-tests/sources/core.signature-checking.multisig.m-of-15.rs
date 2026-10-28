//! Port of `vmb-tests/sources/core.signature-checking.multisig.m-of-15.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, PossibleTestValue, VmbTestDefinition, VmbTestDefinitionGroup,
    generate_test_cases, set_expected_results,
};

/// Build a [`VmbTestDefinition`] from the elements of libauth's
/// `VmbTestDefinition` tuple: `[unlockingScript, redeemOrLockingScript,
/// testDescription, testSetOverrideLabels?, scenario?, additionalScripts?]`.
fn definition(
    unlocking_script: &str,
    redeem_or_locking_script: &str,
    test_description: &str,
    test_set_override_labels: &[&str],
    scenario: Option<WalletTemplateScenario>,
    additional_scripts: Option<BTreeMap<String, WalletTemplateScriptDefinition>>,
) -> VmbTestDefinition {
    VmbTestDefinition {
        unlocking_script: unlocking_script.to_string(),
        redeem_or_locking_script: redeem_or_locking_script.to_string(),
        test_description: test_description.to_string(),
        test_set_override_labels: test_set_override_labels.iter().map(|label| label.to_string()).collect(),
        scenario,
        additional_scripts,
    }
}

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
                        ["<$0> <$1.$2_signature.all_outputs>", "<1> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <15> OP_CHECKMULTISIG", "1-of-15 multisig with $0 ($2 $1)"],
                        &[
                            vec![
                                ("checkBits of zero".to_string(), "0".to_string()),
                                ("checkBits of padded zero".to_string(), "0x0000".to_string()),
                                ("checkBits of key 1".to_string(), "0b00000001 0x00".to_string()),
                                ("checkBits of key 7".to_string(), "0b1000000 0x00".to_string()),
                                ("checkBits of key 15".to_string(), "0x00 0b1000000".to_string()),
                            ],
                            vec![
                                ("key 1".to_string(), "key1".to_string()),
                                ("key 7".to_string(), "key7".to_string()),
                                ("key 15".to_string(), "key15".to_string()),
                            ],
                            signatureAlgorithms.clone(),
                        ],
                        None,
                        None,
                    ),
                    &results(&[
                        ("1-of-15 multisig with checkBits of key 1 (ECDSA key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 1 (ECDSA key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 1 (ECDSA key 7)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 1 (Schnorr key 1)", &["p2s_standard"]),
                        ("1-of-15 multisig with checkBits of key 1 (Schnorr key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 1 (Schnorr key 7)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 15 (ECDSA key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 15 (ECDSA key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 15 (ECDSA key 7)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 15 (Schnorr key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 15 (Schnorr key 15)", &["p2s_standard"]),
                        ("1-of-15 multisig with checkBits of key 15 (Schnorr key 7)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 7 (ECDSA key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 7 (ECDSA key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 7 (ECDSA key 7)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 7 (Schnorr key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 7 (Schnorr key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of key 7 (Schnorr key 7)", &["p2s_standard"]),
                        ("1-of-15 multisig with checkBits of padded zero (ECDSA key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of padded zero (ECDSA key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of padded zero (ECDSA key 7)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of padded zero (Schnorr key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of padded zero (Schnorr key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of padded zero (Schnorr key 7)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of zero (ECDSA key 1)", &["p2s_invalid", "2023_p2s_nonstandard"]),
                        ("1-of-15 multisig with checkBits of zero (ECDSA key 15)", &["p2s_invalid", "2023_p2s_nonstandard"]),
                        ("1-of-15 multisig with checkBits of zero (ECDSA key 7)", &["p2s_invalid", "2023_p2s_nonstandard"]),
                        ("1-of-15 multisig with checkBits of zero (Schnorr key 1)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of zero (Schnorr key 15)", &["invalid"]),
                        ("1-of-15 multisig with checkBits of zero (Schnorr key 7)", &["invalid"]),
                    ]),
                    None,
                ).expect("setExpectedResults"),
                vec![
                    definition(
                        "<0> <key1.ecdsa_signature.all_outputs> <key2.ecdsa_signature.all_outputs>",
                        "<2> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <15> OP_CHECKMULTISIG",
                        "2-of-15 ECDSA multisig (keys 1 and 2)",
                        &["p2s_invalid", "2023_p2s_nonstandard"],
                        None,
                        None,
                    ),
                    definition("<0> <0> <0>", "<2> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <15> OP_CHECKMULTISIG OP_NOT", "2-of-15 ECDSA multisig (null signatures)", &["p2s_nonstandard"], None, None),
                    definition(
                        "<0b11 0x00> <key1.schnorr_signature.all_outputs> <key2.schnorr_signature.all_outputs>",
                        "<2> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <15> OP_CHECKMULTISIG",
                        "2-of-15 Schnorr multisig (keys 1 and 2)",
                        &["p2s_standard"],
                        None,
                        None,
                    ),
                    definition(
                        "<0b11 0x00> <0> <0>",
                        "<2> <key1.public_key> <key2.public_key> <key3.public_key> <key4.public_key> <key5.public_key> <key6.public_key> <key7.public_key> <key8.public_key> <key9.public_key> <key10.public_key> <key11.public_key> <key12.public_key> <key13.public_key> <key14.public_key> <key15.public_key> <15> OP_CHECKMULTISIG OP_NOT",
                        "2-of-15 Schnorr multisig (null signatures)",
                        &["invalid"],
                        None,
                        None,
                    ),
                ],
            ]
            .concat(),
        ),
    ]
});
