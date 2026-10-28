//! Port of `compiler/compiler-bch/compiler-bch.e2e.hd-key.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use libauth::{
    hex_to_bin, BytecodeGenerationResult, CompilationData, CompilationDataHdKeys, CompilationError,
    CompilationErrorType, CompilationResultError, CompilerConfiguration, Range, WalletTemplateHdKey,
    WalletTemplateVariable, WalletTemplateVariableType,
};

use compiler_bch_e2e_spec_helper::{expect_compilation_result, hdPrivateKey, hdPrivateKeyM0H, hdPublicKey};

// `m/0` public key push
static m0PublicPush: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5"));

// `m/0/0` public key push
static m00PublicPush: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("2102df61d0e0ca2d1f02670cd94941d1f3299e10a01f0cc008b695e73006e4b28bfc"));

// `m/0'` HD public key
const m0HardenedHdPublicKeyTestnet: &str =
    "tpubD8j9goBmftKU5otNLACVivEM1gEn41NQ4ikvEAH6nnuXdz4s3apUauUNsL6rFhPKXV2Ft2EDBNjRio1Y5BAnJJpq3GtRp3vVzWH9mDRF7ac";

// `m/0'/1` public key push
static m0H1PublicPush: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("21034f4d20bf3a18f6deb0109c20e0ab7328b22ff0d5a29ce85595344012ebca41e6"));

// `m/1` public key push
static m1PublicPush: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("21034002efc4f44014b116a986faa63b741b0b894a45ccf3f30c671e4146fb1c1954"));

// [BCH compiler] HdKey - errors on deprecated "signature" operation
#[test]
fn bch_compiler_hd_key_errors_on_deprecated_signature_operation() {
    expect_compilation_result(
        "<owner.signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "The \"signature\" compiler operation was renamed to \"ecdsa_signature\". Consider fixing this error by changing \"owner.signature.all_outputs\" to \"owner.schnorr_signature.all_outputs\" (schnorr signatures reduce transaction sizes and enable multi-party signature aggregation).".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 29,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - ECDSA: use an HD private key, addressIndex (`0`)
#[test]
fn bch_compiler_hd_key_ecdsa_use_an_hd_private_key_address_index_0() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "473044022023aafaded9a737022375e895d752466760c98fdd40841dc0b1c9dff6eb884469022035672abd7d7402d9b9791805d78581fa1e23cea7f1887ee80ea346ca75ee3f1f41",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - schnorr: use an HD private key
#[test]
fn bch_compiler_hd_key_schnorr_use_an_hd_private_key() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "41dc748427ac03d7436efeed4a8a2deef63522dd60f2b401302e7120b6117b440e858571c17d5a4b66646c52093100f9242569767cc1a510c522ccfc36019eea8641",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - schnorr: use a non-zero-depth HD private key
#[test]
fn bch_compiler_hd_key_schnorr_use_a_non_zero_depth_hd_private_key() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKeyM0H.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "413c7374fe79a973794b81bba52c139e087217c8fb66a7ca650f3c6e7edd0d173d4b402f0d37dd27b01c62b133b77e9ebb4290fc5fe58823c1636e600b332c136f41",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - schnorr: use a private key (no address index)
#[test]
fn bch_compiler_hd_key_schnorr_use_a_private_key_no_address_index() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: None,
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.schnorr_signature.all_outputs\" refers to an HdKey, but \"hdKeys.addressIndex\" was not provided in the compilation data.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - derive a public key from an HD private key
#[test]
fn bch_compiler_hd_key_derive_a_public_key_from_an_hd_private_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m0PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - derive a public key from a non-zero HD private key
#[test]
fn bch_compiler_hd_key_derive_a_public_key_from_a_non_zero_hd_private_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKeyM0H.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m0H1PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - derive a public key from an HD public key
#[test]
fn bch_compiler_hd_key_derive_a_public_key_from_an_hd_public_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPublicKey.to_string())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m0PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - derive m/1 from an HD public key with addressIndex of 0, addressOffset of 1
#[test]
fn bch_compiler_hd_key_derive_m_1_from_an_hd_public_key_with_address_index_of_0_address_offset_of_1() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPublicKey.to_string())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m1PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: Some(1.0),
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: None,
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - derive a public key from an HD private key (no address index)
#[test]
fn bch_compiler_hd_key_derive_a_public_key_from_an_hd_private_key_no_address_index() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: None,
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.public_key\" refers to an HdKey, but \"hdKeys.addressIndex\" was not provided in the compilation data.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - derive a public key: no secp256k1
#[test]
fn bch_compiler_hd_key_derive_a_public_key_no_secp256k1() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.public_key\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - use a provided derived public key
#[test]
fn bch_compiler_hd_key_use_a_provided_derived_public_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.public_key".to_string(),
                hex_to_bin("0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5"),
            )])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m0PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - fail if a provided derived public key is invalid
#[test]
fn bch_compiler_hd_key_fail_if_a_provided_derived_public_key_is_invalid() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.public_key".to_string(),
                hex_to_bin("020000000000000000000000000000000000000000000000000000000000000007"),
            )])),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "Invalid compilation data detected: the public key provided for \"owner.public_key\" is not a valid Secp256k1 public key.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 0,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - ECDSA: use a provided signature
#[test]
fn bch_compiler_hd_key_ecdsa_use_a_provided_signature() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.ecdsa_signature.all_outputs".to_string(),
                hex_to_bin(
                    "3044022059e9ad8fabd511fa2ef6935dae6395d5d3ce93b929436c835c9c8372b353bd3d0220527c17e2e4ec12f7b8969a9bb80e58ab1a24e44c2e5512916d1bcb3fc4dc2f2241",
                ),
            )])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "473044022059e9ad8fabd511fa2ef6935dae6395d5d3ce93b929436c835c9c8372b353bd3d0220527c17e2e4ec12f7b8969a9bb80e58ab1a24e44c2e5512916d1bcb3fc4dc2f2241",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - schnorr: use a provided signature
#[test]
fn bch_compiler_hd_key_schnorr_use_a_provided_signature() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            bytecode: Some(BTreeMap::from([(
                "owner.schnorr_signature.all_outputs".to_string(),
                hex_to_bin(
                    "313d8a853bd82f5fe251d6b04581333800001ee7680c5e4775db3afabf4873360b3481802d8d656cc608e4625d6568bf1a8801bb1efff19a8306267681177aed41",
                ),
            )])),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(
                "41313d8a853bd82f5fe251d6b04581333800001ee7680c5e4775db3afabf4873360b3481802d8d656cc608e4625d6568bf1a8801bb1efff19a8306267681177aed41",
            ),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - malformed identifier
#[test]
fn bch_compiler_hd_key_malformed_identifier() {
    expect_compilation_result(
        "<owner.ecdsa_signature>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Invalid signature identifier. Signatures must be of the form: \"[variable_id].ecdsa_signature.[signing_serialization_type]\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 23,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - ECDSA: wrong private key
#[test]
fn bch_compiler_hd_key_ecdsa_wrong_private_key() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("wrong".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.ecdsa_signature.all_outputs\" refers to an HdKey owned by \"ownerEntityId\", but an HD private key for this entity (or an existing signature) was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.ecdsa_signature.all_outputs".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - schnorr: wrong private key
#[test]
fn bch_compiler_hd_key_schnorr_wrong_private_key() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("wrong".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.schnorr_signature.all_outputs\" refers to an HdKey owned by \"ownerEntityId\", but an HD private key for this entity (or an existing signature) was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.schnorr_signature.all_outputs".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - schnorr: no "hdPrivateKeys"
#[test]
fn bch_compiler_hd_key_schnorr_no_hd_private_keys() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: None,
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.schnorr_signature.all_outputs\" refers to an HdKey owned by \"ownerEntityId\", but an HD private key for this entity (or an existing signature) was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.schnorr_signature.all_outputs".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - ECDSA: unknown signing serialization algorithm
#[test]
fn bch_compiler_hd_key_ecdsa_unknown_signing_serialization_algorithm() {
    expect_compilation_result(
        "<owner.ecdsa_signature.another>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown signing serialization algorithm, \"another\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 31,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - schnorr: unknown signing serialization algorithm
#[test]
fn bch_compiler_hd_key_schnorr_unknown_signing_serialization_algorithm() {
    expect_compilation_result(
        "<owner.schnorr_signature.another>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Unknown signing serialization algorithm, \"another\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 33,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - ECDSA: no secp256k1
#[test]
fn bch_compiler_hd_key_ecdsa_no_secp256k1() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_signature.all_outputs\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - schnorr: no secp256k1
#[test]
fn bch_compiler_hd_key_schnorr_no_secp256k1() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.schnorr_signature.all_outputs\" - the \"secp256k1\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            secp256k1: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - ECDSA: no sha256
#[test]
fn bch_compiler_hd_key_ecdsa_no_sha256() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_signature.all_outputs\" - the \"sha256\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            sha256: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - schnorr: no sha256
#[test]
fn bch_compiler_hd_key_schnorr_no_sha256() {
    expect_compilation_result(
        "<owner.schnorr_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.schnorr_signature.all_outputs\" - the \"sha256\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 37,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            sha256: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - m/0 via addressIndex of 1, addressOffset of -1
#[test]
fn bch_compiler_hd_key_m_0_via_address_index_of_1_address_offset_of_1() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m0PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: Some(-1.0),
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: None,
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - m/1 via addressIndex of 1, default addressOffset (0)
#[test]
fn bch_compiler_hd_key_m_1_via_address_index_of_1_default_address_offset_0() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m1PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - m/1 via addressIndex of 0, addressOffset of 1
#[test]
fn bch_compiler_hd_key_m_1_via_address_index_of_0_address_offset_of_1() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m1PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: Some(1.0),
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: None,
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - m/1 via addressIndex of 2, addressOffset of -1
#[test]
fn bch_compiler_hd_key_m_1_via_address_index_of_2_address_offset_of_1() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(2.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m1PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: Some(-1.0),
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: None,
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - invalid HD private key
#[test]
fn bch_compiler_hd_key_invalid_hd_private_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(2.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), "xprivkey1bad".to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "Invalid compilation data detected: the HD private key provided for the \"ownerEntityId\" entity is not a valid HD private key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 9.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 0,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - bad privateDerivationPath
#[test]
fn bch_compiler_hd_key_bad_private_derivation_path() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Could not generate \"owner.public_key\" - the path \"-1\" could not be derived for entity \"ownerEntityId\": HD node derivation error: invalid relative derivation path; path must contain only positive child index numbers, separated by forward slashes (\"/\"), with zero or one apostrophe (\"'\") after each child index number. Invalid path: \"-1\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: Some(-1.0),
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: None,
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - error in coveredBytecode compilation
#[test]
fn bch_compiler_hd_key_error_in_covered_bytecode_compilation() {
    expect_compilation_result(
        "",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Compilation error in resolved script \"lock\": [1, 1] Unknown identifier \"invalid\"."
                    .to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            scripts: BTreeMap::from([
                ("lock".to_string(), "invalid".to_string()),
                ("test".to_string(), "<owner.ecdsa_signature.all_outputs>".to_string()),
            ]),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - signature no "entityOwnership"
#[test]
fn bch_compiler_hd_key_signature_no_entity_ownership() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.ecdsa_signature.all_outputs\" - the \"entityOwnership\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            entity_ownership: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - signature unknown entity
#[test]
fn bch_compiler_hd_key_signature_unknown_entity() {
    expect_compilation_result(
        "<owner.ecdsa_signature.all_outputs>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("unknown".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.ecdsa_signature.all_outputs\" refers to an HdKey, but the \"entityOwnership\" for \"owner\" is not available in this compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 35,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            entity_ownership: Some(BTreeMap::new()),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - public_key no "entityOwnership"
#[test]
fn bch_compiler_hd_key_public_key_no_entity_ownership() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Cannot resolve \"owner.public_key\" - the \"entityOwnership\" property was not provided in the compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            entity_ownership: None,
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - HD key not included in "entityOwnership"
#[test]
fn bch_compiler_hd_key_hd_key_not_included_in_entity_ownership() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.public_key\" refers to an HdKey, but the \"entityOwnership\" for \"owner\" is not available in this compiler configuration.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            entity_ownership: Some(BTreeMap::new()),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - no "hdPrivateKeys"
#[test]
fn bch_compiler_hd_key_no_hd_private_keys() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: None,
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Identifier \"owner.public_key\" refers to an HdKey owned by \"ownerEntityId\", but an HD private key or HD public key for this entity was not provided in the compilation data.".to_string(),
                missing_identifier: Some("owner.public_key".to_string()),
                owning_entity: Some("ownerEntityId".to_string()),
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - invalid HD public key
#[test]
fn bch_compiler_hd_key_invalid_hd_public_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(2.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), "xprivkey1bad".to_string())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Parse,
            errors: vec![CompilationError {
                error: "Invalid compilation data detected: the HD public key provided for the \"ownerEntityId\" entity is not a valid HD public key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 9.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 0,
                    end_line_number: 0,
                    start_column: 0,
                    start_line_number: 0,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        None,
    );
}

// [BCH compiler] HdKey - public_key at m/0/0 using HD public key
#[test]
fn bch_compiler_hd_key_public_key_at_m_0_0_using_hd_public_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPublicKey.to_string())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m00PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: Some("m".to_string()),
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/0/i".to_string()),
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - attempt public_key at m/0'/1 using HD public key
#[test]
fn bch_compiler_hd_key_attempt_public_key_at_m_0_1_using_hd_public_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPublicKey.to_string())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Could not generate \"owner.public_key\" - the path \"0'/0\" could not be derived for entity \"ownerEntityId\": HD node derivation error: derivation for hardened child indexes (indexes greater than or equal to 2147483648) requires an HD private node. Requested index: 2147483648.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: Some("m".to_string()),
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/0'/i".to_string()),
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - public_key derivation failure using HD public key
#[test]
fn bch_compiler_hd_key_public_key_derivation_failure_using_hd_public_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPublicKey.to_string())])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Could not generate \"owner.public_key\" - the path \"2147483649/0\" could not be derived for entity \"ownerEntityId\": HD node derivation error: derivation for hardened child indexes (indexes greater than or equal to 2147483648) requires an HD private node. Requested index: 2147483649.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: Some("m".to_string()),
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/2147483649/i".to_string()),
                    public_derivation_path: Some("2147483649/i".to_string()),
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - attempt public_key at invalid path using HD private key
#[test]
fn bch_compiler_hd_key_attempt_public_key_at_invalid_path_using_hd_private_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(0.0),
                hd_private_keys: Some(BTreeMap::from([("ownerEntityId".to_string(), hdPrivateKey.to_string())])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Could not generate \"owner.public_key\" - the path \"bad/i\" is not a valid \"privateDerivationPath\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("bad/i".to_string()),
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - public_key at m/0'/1 using HD private key
#[test]
fn bch_compiler_hd_key_public_key_at_m_0_1_using_hd_private_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    hdPrivateKey.to_string(),
                )])),
                hd_public_keys: None,
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m0H1PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: None,
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/0'/i".to_string()),
                    public_derivation_path: None,
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - public_key at m/0'/1 using custom publicDerivationPath (and testnet HD public key)
#[test]
fn bch_compiler_hd_key_public_key_at_m_0_1_using_custom_public_derivation_path_and_testnet_hd_public_key() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    m0HardenedHdPublicKeyTestnet.to_string(),
                )])),
            }),
            ..data
        },
        BytecodeGenerationResult::Success {
            bytecode: m0H1PublicPush.clone(),
        },
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: Some("m/0'".to_string()),
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/0'/i".to_string()),
                    public_derivation_path: Some("i".to_string()),
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - public_key using HD public key with unexpected depth
#[test]
fn bch_compiler_hd_key_public_key_using_hd_public_key_with_unexpected_depth() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    m0HardenedHdPublicKeyTestnet.to_string(),
                )])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Could not generate \"owner.public_key\" - the HD public key derivation path (\"m/0'/1'\") indicates an expected depth of 2, but the provided HD public key has a depth of 1.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: Some("m/0'/1'".to_string()),
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/0'/1'/i".to_string()),
                    public_derivation_path: Some("i".to_string()),
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - public_key at m/0'/1'/1, mismatching privateDerivationPath
#[test]
fn bch_compiler_hd_key_public_key_at_m_0_1_1_mismatching_private_derivation_path() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    m0HardenedHdPublicKeyTestnet.to_string(),
                )])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Could not generate \"owner.public_key\" - \"privateDerivationPath\" (\"i\") is expected to be the combination of \"hdPublicKeyDerivationPath\" and \"publicDerivationPath\": \"m/0'/1'/i\".".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: Some("m/0'/1'".to_string()),
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: None,
                    public_derivation_path: Some("i".to_string()),
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}

// [BCH compiler] HdKey - hdPublicKeyDerivationPath must be fixed
#[test]
fn bch_compiler_hd_key_hd_public_key_derivation_path_must_be_fixed() {
    expect_compilation_result(
        "<owner.public_key>",
        |data| CompilationData {
            hd_keys: Some(CompilationDataHdKeys {
                address_index: Some(1.0),
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([(
                    "ownerEntityId".to_string(),
                    m0HardenedHdPublicKeyTestnet.to_string(),
                )])),
            }),
            ..data
        },
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Could not generate \"owner.public_key\" - \"hdPublicKeyDerivationPath\" (\"m/i\") must be a fixed (no \"i\" characters), valid absolute derivation path.".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 18,
                    end_line_number: 1,
                    start_column: 2,
                    start_line_number: 1,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: None,
                hd_public_key_derivation_path: None,
                name: None,
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        Some(|configuration| CompilerConfiguration {
            variables: Some(BTreeMap::from([(
                "owner".to_string(),
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: None,
                    description: None,
                    hd_public_key_derivation_path: Some("m/i".to_string()),
                    name: None,
                    never_sign_twice: None,
                    private_derivation_path: Some("m/i".to_string()),
                    public_derivation_path: Some("i".to_string()),
                    r#type: WalletTemplateVariableType::HdKey,
                }),
            )])),
            ..configuration
        }),
    );
}
