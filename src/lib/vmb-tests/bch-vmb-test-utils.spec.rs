//! Port of `vmb-tests/bch-vmb-test-utils.spec.ts`.

use libauth::{vmb_test_group_to_vmb_tests, VmbTestDefinition, VmbTestMasterBch};

#[allow(clippy::too_many_arguments)]
fn master(
    short_id: &str,
    test_description: &str,
    unlocking_script_asm: &str,
    redeem_or_locking_script_asm: &str,
    test_transaction_hex: &str,
    source_outputs_hex: &str,
    test_sets: &[&str],
    input_index: usize,
) -> VmbTestMasterBch {
    VmbTestMasterBch {
        short_id: short_id.to_string(),
        test_description: test_description.to_string(),
        unlocking_script_asm: unlocking_script_asm.to_string(),
        redeem_or_locking_script_asm: redeem_or_locking_script_asm.to_string(),
        test_transaction_hex: test_transaction_hex.to_string(),
        source_outputs_hex: source_outputs_hex.to_string(),
        test_sets: test_sets.iter().map(ToString::to_string).collect(),
        input_index: Some(input_index),
    }
}

/* spell-checker: disable */
#[test]
fn vmb_test_group_to_vmb_tests_() {
    let result = vmb_test_group_to_vmb_tests(&(
        "Test set".to_string(),
        vec![
            VmbTestDefinition {
                unlocking_script: "OP_0".to_string(),
                redeem_or_locking_script: "OP_SIZE <0> OP_EQUAL".to_string(),
                test_description:
                    "OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item"
                        .to_string(),
                ..VmbTestDefinition::default()
            },
            VmbTestDefinition {
                unlocking_script: "OP_PUSHBYTES_1".to_string(),
                redeem_or_locking_script: "OP_SIZE <1> OP_EQUAL".to_string(),
                test_description: "OP_PUSHBYTES_1 with missing bytes".to_string(),
                test_set_override_labels: vec!["invalid".to_string(), "p2sh_ignore".to_string()],
                ..VmbTestDefinition::default()
            },
        ],
    ));
    // libauth's assertion message is `stringifyTestVector(result)`; the Rust
    // `stringify_test_vector` accepts only `Json`, so the debug representation
    // is used instead.
    assert_eq!(
        result,
        Ok(vec![
            vec![
                master(
                    "lqhcne",
                    "Test set: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (P2S)",
                    "OP_0",
                    "OP_SIZE <0> OP_EQUAL",
                    "020000000201000000000000000000000000000000000000000000000000000000000000000000000064417dfb529d352908ee0a88a0074c216b09793d6aa8c94c7640bb4ced51eaefc75d0aef61f7685d0307491e2628da3d4f91e86329265a4a58ca27a41ec0b8910779c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e785000000000100000000000000000000000000000000000000000000000000000000000000010000000100000000000100000000000000000a6a08766d625f7465737400000000",
                    "0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000003820087",
                    &["2023_nonstandard", "2025_nonstandard", "2026_standard"],
                    1,
                ),
                master(
                    "y0ql2w",
                    "Test set: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (P2SH20)",
                    "OP_0",
                    "OP_SIZE <0> OP_EQUAL",
                    "020000000201000000000000000000000000000000000000000000000000000000000000000000000064417dfb529d352908ee0a88a0074c216b09793d6aa8c94c7640bb4ced51eaefc75d0aef61f7685d0307491e2628da3d4f91e86329265a4a58ca27a41ec0b8910779c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000001000000050003820087000000000100000000000000000a6a08766d625f7465737400000000",
                    "0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000017a9146b14122b4b3cb280c9ec66f8e2827cf3384010a387",
                    &["2023_standard", "2025_standard", "2026_standard"],
                    1,
                ),
                master(
                    "zdclze",
                    "Test set: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (P2SH32)",
                    "OP_0",
                    "OP_SIZE <0> OP_EQUAL",
                    "020000000201000000000000000000000000000000000000000000000000000000000000000000000064417dfb529d352908ee0a88a0074c216b09793d6aa8c94c7640bb4ced51eaefc75d0aef61f7685d0307491e2628da3d4f91e86329265a4a58ca27a41ec0b8910779c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000001000000050003820087000000000100000000000000000a6a08766d625f7465737400000000",
                    "0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000023aa2058f29d1d690dc5a8e34ade0a6a3a18356b09b491d3d7e8bc7b2ea3ee2f471ce387",
                    &["2023_standard", "2025_standard", "2026_standard"],
                    1,
                ),
            ],
            vec![master(
                "7j2u2h",
                "Test set: OP_PUSHBYTES_1 with missing bytes (P2S)",
                "OP_PUSHBYTES_1",
                "OP_SIZE <1> OP_EQUAL",
                "020000000201000000000000000000000000000000000000000000000000000000000000000000000064417dfb529d352908ee0a88a0074c216b09793d6aa8c94c7640bb4ced51eaefc75d0aef61f7685d0307491e2628da3d4f91e86329265a4a58ca27a41ec0b8910779c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e785000000000100000000000000000000000000000000000000000000000000000000000000010000000101000000000100000000000000000a6a08766d625f7465737400000000",
                "0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000003825187",
                &["2023_invalid", "2025_invalid", "2026_invalid"],
                1,
            )],
        ]),
        "Stringified test vector:\n{result:#?}"
    );
}
