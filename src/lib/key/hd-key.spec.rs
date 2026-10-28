//! Port of `key/hd-key.spec.ts`.
//!
//! Notes on the port:
//! - `throwErrors` is not ported: each libauth call is the non-throwing
//!   variant, so `t.throws(() => f(x), { message })` and
//!   `t.deepEqual(f(x, { throwErrors: false }), message)` both become
//!   `assert_eq!(f(x), Err(message))`.
//! - libauth's `{ crypto }` (`{ ripemd160, secp256k1, sha256, sha512 }`) passes
//!   the default instances explicitly; in Rust each function takes the subset
//!   of instances it uses (see [`crypto`]).
//! - libauth narrows `deriveHdPath`/`deriveHdPathRelative` return types by the
//!   type of the provided node; in Rust both functions take and return an
//!   `HdNodeValid`, so the `AssertTypesEqual` checks assert that type.
//! - Mocked `secp256k1` implementations (`{ ...secp256k1, addTweakPrivateKey:
//!   () => 'mock failure' }`) cannot be constructed in Rust (`Secp256k1` is a
//!   concrete type); the assertions which use them are kept in separate,
//!   ignored `*_mock_crypto` tests.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use libauth::{
    assert_success, crack_hd_private_node_from_hd_public_node_and_child_private_node,
    decode_hd_key, decode_hd_key_unchecked, decode_hd_private_key, decode_hd_public_key,
    derive_hd_path, derive_hd_path_relative, derive_hd_private_node_child,
    derive_hd_private_node_from_seed, derive_hd_private_node_identifier, derive_hd_public_key,
    derive_hd_public_node, derive_hd_public_node_child, derive_hd_public_node_identifier,
    encode_hd_private_key, encode_hd_public_key, hd_key_version_is_private_key,
    hd_key_version_is_public_key, hd_private_key_to_identifier, hd_public_key_to_identifier,
    hex_to_bin, ripemd160, secp256k1, sha256, sha512, validate_secp256k1_private_key,
    BaseConversionError, DecodedHdKey, DecodedHdKeyUnchecked, HdKeyDecodingError,
    HdKeyEncodingError, HdKeyNetwork, HdKeyVersion, HdNode, HdNodeCrackingError,
    HdNodeDerivationError, HdNodeValid, HdPrivateKeyEncodeResult, HdPrivateNode,
    HdPrivateNodeInvalid, HdPrivateNodeValid, HdPublicKeyEncodeResult, HdPublicNode,
    HdPublicNodeInvalid, HdPublicNodeValid, Ripemd160, Secp256k1, Secp256k1Error, Sha256, Sha512,
};

const SEED: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

const XPRV: &str =
    "xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta";
const TPRV: &str =
    "tprv8ZgxMBicQKsPd7qLuJ7yJhzbwSrNfh9MF5qR4tJRPCs63xksUdTAF79dUHADNygu5kLTsXC6jtq4Cibsy6QCVBEboRzAH48vw5zoLkJTuso";
const XPUB: &str =
    "xpub661MyMwAqRbcEngHLkoUWCKMBMGeqdqCGkqtzrHaTZub9ALw2oRfHA6fQP5n5X9VHStaNTBYomkSb8BFhUGavwD3RG1qvMkEKceTavTp2Tm";
const TPUB: &str =
    "tpubD6NzVbkrYhZ4Was8nwnZi7eiWUNJq2LFpPSCMQLioUfUtT1e72GkRbmVeRAZc26j5MRUz2hRLsaVHJfs6L7ppNfLUrm9btQTuaEsLrT7D87";

const MAXIMUM_DEPTH: i64 = 255;
const MAXIMUM_CHILD_INDEX: i64 = 0xffff_ffff;
const FINGERPRINT_LENGTH: usize = 4;
const CHAIN_CODE_LENGTH: usize = 32;
const PRIVATE_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 33;
const HARDENED_INDEX_OFFSET: i64 = 0x8000_0000;
const MAXIMUM_NON_HARDENED_INDEX: i64 = HARDENED_INDEX_OFFSET - 1;

/// libauth's `const crypto = { ripemd160, secp256k1, sha256, sha512 };`.
fn crypto() -> (&'static Ripemd160, &'static Secp256k1, &'static Sha256, &'static Sha512) {
    (&ripemd160, &secp256k1, &sha256, &sha512)
}

/// libauth's `AssertTypesEqual<typeof value, T>`: compiles only if `value`
/// has type `T`.
fn assert_type<T>(_value: &T) -> bool {
    true
}

/// `{ network: 'mainnet', node }`
fn mainnet<NodeType>(node: NodeType) -> DecodedHdKey<NodeType> {
    DecodedHdKey {
        network: HdKeyNetwork::Mainnet,
        node,
    }
}

/// `{ network: 'testnet', node }`
fn testnet<NodeType>(node: NodeType) -> DecodedHdKey<NodeType> {
    DecodedHdKey {
        network: HdKeyNetwork::Testnet,
        node,
    }
}

/// libauth's `deriveHdPrivateNodeChild(...) as HdPrivateNodeValid` (and the
/// throwing default of `deriveHdPrivateNodeFromSeed`).
fn as_private_node_valid(result: Result<HdPrivateNode, String>) -> HdPrivateNodeValid {
    match result {
        Ok(HdPrivateNode::Valid(node)) => node,
        other => panic!("expected an HdPrivateNodeValid, received: {other:?}"),
    }
}

/// libauth's `deriveHdPublicNodeChild(...) as HdPublicNodeValid`.
fn as_public_node_valid(result: Result<HdPublicNode, String>) -> HdPublicNodeValid {
    match result {
        Ok(HdPublicNode::Valid(node)) => node,
        other => panic!("expected an HdPublicNodeValid, received: {other:?}"),
    }
}

/// The private node returned by `deriveHdPath`/`deriveHdPathRelative` for a
/// private node.
fn private_node_of(node: HdNodeValid) -> HdPrivateNodeValid {
    match node {
        HdNodeValid::Private(node) => node,
        HdNodeValid::Public(node) => panic!("expected a private node, received: {node:?}"),
    }
}

/// A child derivation result in the type returned by `deriveHdPathRelative`.
fn private_child(result: Result<HdPrivateNode, String>) -> Result<HdNodeValid, String> {
    result.map(|node| HdNodeValid::Private(as_private_node_valid(Ok(node))))
}

/// A child derivation result in the type returned by `deriveHdPathRelative`.
fn public_child(result: Result<HdPublicNode, String>) -> Result<HdNodeValid, String> {
    result.map(|node| HdNodeValid::Public(as_public_node_valid(Ok(node))))
}

#[test]
fn libauth_exposes_expected_types() {
    // type TypeTests =
    //   | AssertTypesEqual<HdKeyNetwork, 'mainnet' | 'testnet'>
    //   | AssertTypesEqual<HdPrivateNode, HdPrivateNodeInvalid | HdPrivateNodeValid>
    //   | AssertTypesEqual<HdPublicNode, HdPublicNodeInvalid | HdPublicNodeValid>;
    // (checked by these exhaustive matches compiling)
    fn type_tests(network: HdKeyNetwork, private_node: HdPrivateNode, public_node: HdPublicNode) -> bool {
        let network = match network {
            HdKeyNetwork::Mainnet | HdKeyNetwork::Testnet => true,
        };
        let private_node = match private_node {
            HdPrivateNode::Invalid(HdPrivateNodeInvalid { .. }) | HdPrivateNode::Valid(HdPrivateNodeValid { .. }) => true,
        };
        let public_node = match public_node {
            HdPublicNode::Invalid(HdPublicNodeInvalid { .. }) | HdPublicNode::Valid(HdPublicNodeValid { .. }) => true,
        };
        network && private_node && public_node
    }
    let _ = type_tests;
    let test_types = true;
    assert!(test_types);
}

#[test]
fn crypto_derive_hd_private_node_from_seed() {
    let valid = HdPrivateNode::Valid(HdPrivateNodeValid {
        chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
        child_index: 0,
        depth: 0,
        parent_fingerprint: hex_to_bin("00000000"),
        parent_identifier: None,
        private_key: hex_to_bin("330fd355e141910d33bbe84c369b87a209dd18b81095912be766b2b5a9d72bc4"),
    });
    let invalid = HdPrivateNode::Invalid(HdPrivateNodeInvalid {
        chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
        child_index: 0,
        depth: 0,
        invalid_material: hex_to_bin("330fd355e141910d33bbe84c369b87a209dd18b81095912be766b2b5a9d72bc4"),
        parent_fingerprint: hex_to_bin("00000000"),
        parent_identifier: None,
    });
    let either = derive_hd_private_node_from_seed(&SEED, None, None, None);
    let custom_crypto = derive_hd_private_node_from_seed(&SEED, None, Some(&sha512), None);
    let valid_node = derive_hd_private_node_from_seed(&SEED, Some(true), None, None);
    let invalid_node = derive_hd_private_node_from_seed(&SEED, Some(false), None, None);
    assert_eq!(either, valid);
    assert_eq!(custom_crypto, valid);
    assert_eq!(valid_node, valid);
    assert_eq!(invalid_node, invalid);
    // t.throws(() => { deriveHdPrivateNodeFromSeed(seed, { assumeValidity: false }); });
    // (`throwErrors` is not ported: the non-throwing result is the invalid node
    // for which libauth throws `HdNodeDerivationError.invalidDerivedKey`.)
    assert!(matches!(
        derive_hd_private_node_from_seed(&SEED, Some(false), None, None),
        HdPrivateNode::Invalid(_)
    ));
}

#[test]
fn crypto_derive_hd_private_node_identifier() {
    let node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    assert_eq!(
        derive_hd_private_node_identifier(&node, None),
        Ok(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111"))
    );
    assert_eq!(
        derive_hd_private_node_identifier(&node, Some((&ripemd160, &secp256k1, &sha256))),
        Ok(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111"))
    );
    assert_eq!(
        derive_hd_private_node_identifier(
            &HdPrivateNodeValid {
                private_key: vec![],
                ..node.clone()
            },
            None
        ),
        Err(Secp256k1Error::derivePublicKeyFromInvalidPrivateKey.to_string())
    );
}

#[test]
fn crypto_derive_hd_public_node_identifier() {
    let node = assert_success(decode_hd_public_key(XPUB, None), None).node;
    assert_eq!(
        derive_hd_public_node_identifier(&node, None),
        hex_to_bin("15c918d389673c6cd0660050f268a843361e1111")
    );
    assert_eq!(
        derive_hd_public_node_identifier(&node, Some((&ripemd160, &sha256))),
        hex_to_bin("15c918d389673c6cd0660050f268a843361e1111")
    );
}

#[test]
fn crypto_hd_private_key_to_identifier() {
    assert_eq!(
        hd_private_key_to_identifier(XPRV, None),
        Ok(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111"))
    );
    assert_eq!(
        hd_private_key_to_identifier(XPRV, Some((&secp256k1, &sha256))),
        Ok(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111"))
    );
    assert_eq!(
        hd_private_key_to_identifier(&XPRV[1..], None),
        Err(format!("{} Length: 81.", HdKeyDecodingError::incorrectLength))
    );
}

#[test]
fn crypto_hd_public_key_to_identifier() {
    assert_eq!(
        hd_public_key_to_identifier(XPUB, None),
        Ok(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111"))
    );
    assert_eq!(
        hd_public_key_to_identifier(XPUB, Some((&secp256k1, &sha256))),
        Ok(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111"))
    );
    assert_eq!(
        hd_public_key_to_identifier(&XPUB[1..], Some((&secp256k1, &sha256))),
        Err(format!("{} Length: 81.", HdKeyDecodingError::incorrectLength))
    );
}

#[test]
fn hd_key_version_is_private_key_() {
    assert!(hd_key_version_is_private_key(HdKeyVersion::mainnetPrivateKey));
    assert!(!hd_key_version_is_private_key(HdKeyVersion::mainnetPublicKey));
    assert!(hd_key_version_is_private_key(HdKeyVersion::testnetPrivateKey));
    assert!(!hd_key_version_is_private_key(HdKeyVersion::testnetPublicKey));
}

#[test]
fn hd_key_version_is_public_key_() {
    assert!(!hd_key_version_is_public_key(HdKeyVersion::mainnetPrivateKey));
    assert!(hd_key_version_is_public_key(HdKeyVersion::mainnetPublicKey));
    assert!(!hd_key_version_is_public_key(HdKeyVersion::testnetPrivateKey));
    assert!(hd_key_version_is_public_key(HdKeyVersion::testnetPublicKey));
}

#[test]
fn crypto_decode_hd_key() {
    assert_eq!(
        decode_hd_key(XPRV, None),
        Ok(DecodedHdKey {
            network: HdKeyNetwork::Mainnet,
            node: HdNodeValid::Private(HdPrivateNodeValid {
                chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
                child_index: 0,
                depth: 0,
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
                private_key: hex_to_bin("330fd355e141910d33bbe84c369b87a209dd18b81095912be766b2b5a9d72bc4"),
            }),
        })
    );
    assert_eq!(
        decode_hd_key(XPUB, Some((&secp256k1, &sha256))),
        Ok(DecodedHdKey {
            network: HdKeyNetwork::Mainnet,
            node: HdNodeValid::Public(HdPublicNodeValid {
                chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
                child_index: 0,
                depth: 0,
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
                public_key: hex_to_bin("02be99138b48b430a8ee40bf8b56c8ebc584c363774010a9bfe549a87126e61746"),
            }),
        })
    );
}

#[test]
fn crypto_decode_hd_key_errors() {
    assert_eq!(
        decode_hd_key("#badKey", None),
        Err(format!(
            "{} {} Unknown character: \"#\".",
            HdKeyDecodingError::unknownCharacter,
            BaseConversionError::unknownCharacter
        ))
    );
    assert_eq!(
        decode_hd_key("xprv1234", None),
        Err(format!("{} Length: 6.", HdKeyDecodingError::incorrectLength))
    );
    assert_eq!(
        decode_hd_key(
            "xpub661MyMwAqRbcEngHLkoUWCKMBMGeqdqCGkqtzrHaTZub9ALw2oRfHA6fQP5n5X9VHStaNTBYomkSb8BFhUGavwD3RG1qvMkEKceTavTp2Ta",
            Some((&secp256k1, &sha256))
        ),
        Err(format!(
            "{} Encoded: c695e081; computed: c695e08c.",
            HdKeyDecodingError::invalidChecksum
        ))
    );
}

#[test]
fn crypto_decode_hd_private_key() {
    assert_eq!(
        decode_hd_private_key(XPRV, None),
        Ok(mainnet(HdPrivateNodeValid {
            chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
            child_index: 0,
            depth: 0,
            parent_fingerprint: hex_to_bin("00000000"),
            parent_identifier: None,
            private_key: hex_to_bin("330fd355e141910d33bbe84c369b87a209dd18b81095912be766b2b5a9d72bc4"),
        }))
    );
    assert_eq!(
        decode_hd_private_key(TPRV, Some((&secp256k1, &sha256))),
        Ok(testnet(HdPrivateNodeValid {
            chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
            child_index: 0,
            depth: 0,
            parent_fingerprint: hex_to_bin("00000000"),
            parent_identifier: None,
            private_key: hex_to_bin("330fd355e141910d33bbe84c369b87a209dd18b81095912be766b2b5a9d72bc4"),
        }))
    );
}

#[test]
fn crypto_decode_hd_private_key_errors() {
    assert_eq!(
        decode_hd_private_key(XPUB, None),
        Err(HdKeyDecodingError::privateKeyExpected.to_string())
    );
    assert_eq!(
        decode_hd_private_key(
            "1111111111111FF9QeH94hg7KAjgjUqkHUqbrw5wWQLoRNfRhB4cHUDCJxx2HfNb5qDiAjpbKjXeLJSknuzDmja42174H9Es1XbY24sZts9",
            None
        ),
        Err(format!("{} Version: 0", HdKeyDecodingError::unknownVersion))
    );
    let xprv_with_0_filled_key =
        "xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBZ6c54tCKNErugtr5mi7oyGaDVrYe4SE5u1GnzYHmjDKuKg4vuNm";
    assert_eq!(
        decode_hd_private_key(xprv_with_0_filled_key, None),
        Err(HdKeyDecodingError::invalidPrivateKey.to_string())
    );
    let xprv_with_255_filled_key =
        "xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBZ8YpF7eMDfY8piRngHjovbAzQyAMi94xgeLuEgyfisLHpC7G5ST";

    assert_eq!(
        decode_hd_private_key(xprv_with_255_filled_key, None),
        Err(HdKeyDecodingError::invalidPrivateKey.to_string())
    );
    assert_eq!(
        decode_hd_private_key(
            "xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBhegPMjkj1oGSFcmBkMX3xdwcMy6NSgrHvmqJptpUW5xGjg7kifZ",
            None
        ),
        Err(HdKeyDecodingError::missingPrivateKeyPaddingByte.to_string())
    );
}

#[test]
fn crypto_decode_hd_public_key() {
    assert_eq!(
        decode_hd_public_key(XPUB, None),
        Ok(mainnet(HdPublicNodeValid {
            chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
            child_index: 0,
            depth: 0,
            parent_fingerprint: hex_to_bin("00000000"),
            parent_identifier: None,
            public_key: hex_to_bin("02be99138b48b430a8ee40bf8b56c8ebc584c363774010a9bfe549a87126e61746"),
        }))
    );
    assert_eq!(
        decode_hd_public_key(TPUB, Some((&secp256k1, &sha256))),
        Ok(testnet(HdPublicNodeValid {
            chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
            child_index: 0,
            depth: 0,
            parent_fingerprint: hex_to_bin("00000000"),
            parent_identifier: None,
            public_key: hex_to_bin("02be99138b48b430a8ee40bf8b56c8ebc584c363774010a9bfe549a87126e61746"),
        }))
    );
}

#[test]
fn crypto_decode_hd_public_key_errors() {
    assert_eq!(
        decode_hd_public_key(XPRV, None),
        Err(HdKeyDecodingError::publicKeyExpected.to_string())
    );
    assert_eq!(
        decode_hd_public_key(
            "1111111111111FF9QeH94hg7KAjgjUqkHUqbrw5wWQLoRNfRhB4cHUDCJxx2HfNb5qDiAjpbKjXeLJSknuzDmja42174H9Es1XbY24sZts9",
            None
        ),
        Err(format!("{} Version: 0", HdKeyDecodingError::unknownVersion))
    );
}

#[test]
fn crypto_encode_hd_private_key() {
    let node = HdPrivateNodeValid {
        chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
        child_index: 0,
        depth: 0,
        parent_fingerprint: hex_to_bin("00000000"),
        parent_identifier: None,
        private_key: hex_to_bin("330fd355e141910d33bbe84c369b87a209dd18b81095912be766b2b5a9d72bc4"),
    };
    assert_eq!(
        encode_hd_private_key(&mainnet(node.clone()), None),
        Ok(HdPrivateKeyEncodeResult {
            hd_private_key: XPRV.to_string()
        })
    );

    assert_eq!(
        encode_hd_private_key(&testnet(node.clone()), Some(&sha256)),
        Ok(HdPrivateKeyEncodeResult {
            hd_private_key: TPRV.to_string()
        })
    );

    // { throwErrors: false }
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                private_key: hex_to_bin("01"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Private key length: 1.",
            HdKeyEncodingError::invalidPrivateKeyLength
        ))
    );
    // t.throws(...)
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                private_key: hex_to_bin("01"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Private key length: 1.",
            HdKeyEncodingError::invalidPrivateKeyLength
        ))
    );
    // t.throws(..., { throwErrors: true })
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                private_key: hex_to_bin("01"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Private key length: 1.",
            HdKeyEncodingError::invalidPrivateKeyLength
        ))
    );

    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                chain_code: hex_to_bin("18aab7"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Chain code length: 3.",
            HdKeyEncodingError::invalidChainCodeLength
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                chain_code: hex_to_bin("18"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Chain code length: 1.",
            HdKeyEncodingError::invalidChainCodeLength
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                chain_code: hex_to_bin("18"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Chain code length: 1.",
            HdKeyEncodingError::invalidChainCodeLength
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 1,
                parent_fingerprint: hex_to_bin(""),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint length: 0.",
            HdKeyEncodingError::invalidParentFingerprintLength
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 1,
                parent_fingerprint: hex_to_bin("00"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint length: 1.",
            HdKeyEncodingError::invalidParentFingerprintLength
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 1,
                parent_fingerprint: hex_to_bin("0000"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint length: 2.",
            HdKeyEncodingError::invalidParentFingerprintLength
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: -1,
                ..node.clone()
            }),
            None
        ),
        Err(format!("{} Depth: -1.", HdKeyEncodingError::invalidChildDepth))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 256,
                ..node.clone()
            }),
            None
        ),
        Err(format!("{} Depth: 256.", HdKeyEncodingError::invalidChildDepth))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 256,
                ..node.clone()
            }),
            None
        ),
        Err(format!("{} Depth: 256.", HdKeyEncodingError::invalidChildDepth))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                child_index: -1,
                depth: 1,
                ..node.clone()
            }),
            None
        ),
        Err(format!("{} Child index: -1.", HdKeyEncodingError::invalidChildIndex))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                child_index: 4_294_967_296,
                depth: 1,
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Child index: 4294967296.",
            HdKeyEncodingError::invalidChildIndex
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                child_index: 4_294_967_296,
                depth: 1,
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Child index: 4294967296.",
            HdKeyEncodingError::invalidChildIndex
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                child_index: 1,
                depth: 0,
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Child index: 1.",
            HdKeyEncodingError::zeroDepthWithNonZeroChildIndex
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                child_index: 1,
                depth: 0,
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Child index: 1.",
            HdKeyEncodingError::zeroDepthWithNonZeroChildIndex
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                child_index: 1,
                depth: 0,
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Child index: 1.",
            HdKeyEncodingError::zeroDepthWithNonZeroChildIndex
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 0,
                parent_fingerprint: hex_to_bin("01020304"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint: 1,2,3,4.",
            HdKeyEncodingError::zeroDepthWithNonZeroParentFingerprint
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 0,
                parent_fingerprint: hex_to_bin("01020304"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint: 1,2,3,4.",
            HdKeyEncodingError::zeroDepthWithNonZeroParentFingerprint
        ))
    );
    assert_eq!(
        encode_hd_private_key(
            &mainnet(HdPrivateNodeValid {
                depth: 0,
                parent_fingerprint: hex_to_bin("01020304"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint: 1,2,3,4.",
            HdKeyEncodingError::zeroDepthWithNonZeroParentFingerprint
        ))
    );
}

#[test]
fn crypto_encode_hd_public_key() {
    let node = HdPublicNodeValid {
        chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
        child_index: 0,
        depth: 0,
        parent_fingerprint: hex_to_bin("00000000"),
        parent_identifier: None,
        public_key: hex_to_bin("02be99138b48b430a8ee40bf8b56c8ebc584c363774010a9bfe549a87126e61746"),
    };

    assert_eq!(
        encode_hd_public_key(&mainnet(node.clone()), None),
        Ok(HdPublicKeyEncodeResult {
            hd_public_key: XPUB.to_string()
        })
    );
    assert_eq!(
        encode_hd_public_key(&testnet(node.clone()), Some((&secp256k1, &sha256))),
        Ok(HdPublicKeyEncodeResult {
            hd_public_key: TPUB.to_string()
        })
    );

    for _ in 0..3 {
        // { throwErrors: false }, t.throws(...), and t.throws(..., { throwErrors: true })
        assert_eq!(
            encode_hd_public_key(
                &mainnet(HdPublicNodeValid {
                    public_key: hex_to_bin("00"),
                    ..node.clone()
                }),
                None
            ),
            Err(format!(
                "{} Invalid public key: \"00\".",
                HdKeyEncodingError::invalidPublicKey
            ))
        );
    }

    for _ in 0..3 {
        // { throwErrors: false }, t.throws(...), and t.throws(..., { throwErrors: true })
        assert_eq!(
            encode_hd_public_key(
                &mainnet(HdPublicNodeValid {
                    public_key: hex_to_bin(
                        "0476ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c56dd53b07c7a983bb2ddd71551f0633194a2fe330f90aaf675dde25b137efd285"
                    ),
                    ..node.clone()
                }),
                None
            ),
            Err(format!(
                "{} Public key length: 65.",
                HdKeyEncodingError::invalidPublicKeyLength
            ))
        );
    }

    assert_eq!(
        encode_hd_public_key(
            &mainnet(HdPublicNodeValid {
                chain_code: hex_to_bin("18aab7"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Chain code length: 3.",
            HdKeyEncodingError::invalidChainCodeLength
        ))
    );
    for _ in 0..2 {
        // t.throws(...) and t.throws(..., { throwErrors: true })
        assert_eq!(
            encode_hd_public_key(
                &mainnet(HdPublicNodeValid {
                    chain_code: hex_to_bin("18"),
                    ..node.clone()
                }),
                None
            ),
            Err(format!(
                "{} Chain code length: 1.",
                HdKeyEncodingError::invalidChainCodeLength
            ))
        );
    }
    assert_eq!(
        encode_hd_public_key(
            &mainnet(HdPublicNodeValid {
                depth: 1,
                parent_fingerprint: hex_to_bin(""),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint length: 0.",
            HdKeyEncodingError::invalidParentFingerprintLength
        ))
    );
    assert_eq!(
        encode_hd_public_key(
            &mainnet(HdPublicNodeValid {
                depth: 1,
                parent_fingerprint: hex_to_bin("00"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint length: 1.",
            HdKeyEncodingError::invalidParentFingerprintLength
        ))
    );
    assert_eq!(
        encode_hd_public_key(
            &mainnet(HdPublicNodeValid {
                depth: 1,
                parent_fingerprint: hex_to_bin("0000"),
                ..node.clone()
            }),
            None
        ),
        Err(format!(
            "{} Parent fingerprint length: 2.",
            HdKeyEncodingError::invalidParentFingerprintLength
        ))
    );
    assert_eq!(
        encode_hd_public_key(
            &mainnet(HdPublicNodeValid {
                depth: -1,
                ..node.clone()
            }),
            None
        ),
        Err(format!("{} Depth: -1.", HdKeyEncodingError::invalidChildDepth))
    );
    for _ in 0..2 {
        // t.throws(...) and t.throws(..., { throwErrors: true })
        assert_eq!(
            encode_hd_public_key(
                &mainnet(HdPublicNodeValid {
                    depth: 256,
                    ..node.clone()
                }),
                None
            ),
            Err(format!("{} Depth: 256.", HdKeyEncodingError::invalidChildDepth))
        );
    }
    assert_eq!(
        encode_hd_public_key(
            &mainnet(HdPublicNodeValid {
                child_index: -1,
                depth: 1,
                ..node.clone()
            }),
            None
        ),
        Err(format!("{} Child index: -1.", HdKeyEncodingError::invalidChildIndex))
    );
    for _ in 0..2 {
        // t.throws(...) and t.throws(..., { throwErrors: true })
        assert_eq!(
            encode_hd_public_key(
                &mainnet(HdPublicNodeValid {
                    child_index: 4_294_967_296,
                    depth: 1,
                    ..node.clone()
                }),
                None
            ),
            Err(format!(
                "{} Child index: 4294967296.",
                HdKeyEncodingError::invalidChildIndex
            ))
        );
    }
    for _ in 0..3 {
        // { throwErrors: false }, t.throws(...), and t.throws(..., { throwErrors: true })
        assert_eq!(
            encode_hd_public_key(
                &mainnet(HdPublicNodeValid {
                    child_index: 1,
                    depth: 0,
                    ..node.clone()
                }),
                None
            ),
            Err(format!(
                "{} Child index: 1.",
                HdKeyEncodingError::zeroDepthWithNonZeroChildIndex
            ))
        );
    }
    for _ in 0..3 {
        // { throwErrors: false }, t.throws(...), and t.throws(..., { throwErrors: true })
        assert_eq!(
            encode_hd_public_key(
                &mainnet(HdPublicNodeValid {
                    depth: 0,
                    parent_fingerprint: hex_to_bin("01020304"),
                    ..node.clone()
                }),
                None
            ),
            Err(format!(
                "{} Parent fingerprint: 1,2,3,4.",
                HdKeyEncodingError::zeroDepthWithNonZeroParentFingerprint
            ))
        );
    }
}

#[test]
fn crypto_derive_hd_public_node() {
    let private_params = decode_hd_private_key(XPRV, None);
    let private_params = match private_params {
        Err(error) => panic!("{error}"),
        Ok(private_params) => private_params,
    };
    assert_eq!(
        derive_hd_public_node(&private_params.node, None),
        Ok(HdPublicNodeValid {
            chain_code: hex_to_bin("18aab7e9ef169f3029d93651d0c85303cbcc2ac559ccd04c324a2e678ef26dc9"),
            child_index: 0,
            depth: 0,
            parent_fingerprint: hex_to_bin("00000000"),
            parent_identifier: None,
            public_key: hex_to_bin("02be99138b48b430a8ee40bf8b56c8ebc584c363774010a9bfe549a87126e61746"),
        })
    );
}

#[test]
fn crypto_derive_hd_public_key() {
    assert_eq!(
        derive_hd_public_key(XPRV, None),
        Ok(HdPublicKeyEncodeResult {
            hd_public_key: XPUB.to_string()
        })
    );
    assert_eq!(
        derive_hd_public_key(TPRV, None),
        Ok(HdPublicKeyEncodeResult {
            hd_public_key: TPUB.to_string()
        })
    );
    let error = format!("{} Length: 81.", HdKeyDecodingError::incorrectLength);
    assert_eq!(derive_hd_public_key(&XPRV[1..], None), Err(error.clone()));
    assert_eq!(derive_hd_public_key(&XPRV[1..], None), Err(error.clone()));
    assert_eq!(derive_hd_public_key(&XPRV[1..], None), Err(error));
}

#[test]
fn crypto_derive_hd_private_node_child() {
    let master = assert_success(decode_hd_private_key(XPRV, None), None);
    let hardened_index_0_child = assert_success(
        decode_hd_private_key(
            "xprv9u4S6TaiPQaF7FS24QFpRP6hjff4jXNwwYTkVNC6f6YzHj2a6G28aRN1D6Az82SxMeBivpVS3gDDXyQiu3RANTqWy34Zxi9JN76zSwkjqPF",
            None,
        ),
        None,
    );
    let index_1_grand_child = assert_success(
        decode_hd_private_key(
            "xprv9w8PdihBAeR4xgGYWWqBnmDTrpWEW1QjuYAUkR7A6X48q1iQVgN433aSFxQGgtureVz7cCyi5zfuMTtBF3AkanjtvNs9m8u2JobxNfphSi3",
            None,
        ),
        None,
    );

    let hardened_index_0: i64 = 0x8000_0000;
    let result0 = as_private_node_valid(derive_hd_private_node_child(&master.node, hardened_index_0, None, None));

    let result1 = as_private_node_valid(derive_hd_private_node_child(&result0, 1, Some(crypto()), None));
    assert_eq!(
        result0,
        HdPrivateNodeValid {
            parent_identifier: Some(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111")),
            ..hardened_index_0_child.node.clone()
        }
    );
    assert_eq!(
        result1,
        HdPrivateNodeValid {
            parent_identifier: Some(hex_to_bin("2f2bc501c943dd7f17904b612c090dd88270cc59")),
            ..index_1_grand_child.node.clone()
        }
    );
    // The remaining (mock crypto) assertions of this test are in
    // `crypto_derive_hd_private_node_child_mock_crypto`.
}

/// The mock crypto assertions of `[crypto] deriveHdPrivateNodeChild`.
#[test]
#[ignore = "MISSING-API: Secp256k1 cannot be mocked (libauth's mockCrypto replaces secp256k1.addTweakPrivateKey with () => 'mock failure')"]
fn crypto_derive_hd_private_node_child_mock_crypto() {
    let master = assert_success(decode_hd_private_key(XPRV, None), None);
    let hardened_index_0_child = assert_success(
        decode_hd_private_key(
            "xprv9u4S6TaiPQaF7FS24QFpRP6hjff4jXNwwYTkVNC6f6YzHj2a6G28aRN1D6Az82SxMeBivpVS3gDDXyQiu3RANTqWy34Zxi9JN76zSwkjqPF",
            None,
        ),
        None,
    );
    let hardened_index_0: i64 = 0x8000_0000;

    // Intended:
    // const mockCrypto = {
    //   ripemd160,
    //   secp256k1: { ...secp256k1, addTweakPrivateKey: () => 'mock failure' },
    //   sha256,
    //   sha512,
    // };
    // Closest compiling version (the unmodified instances):
    let mock_crypto = crypto();
    assert_eq!(
        derive_hd_private_node_child(&master.node, hardened_index_0, Some(mock_crypto), Some(true)),
        Ok(HdPrivateNode::Invalid(HdPrivateNodeInvalid {
            chain_code: hardened_index_0_child.node.chain_code.clone(),
            child_index: hardened_index_0_child.node.child_index,
            depth: hardened_index_0_child.node.depth,
            invalid_material: hex_to_bin("df936db251b869552fbed141a01dc3d5680dbba8846b000e58685fe6be409fa4"),
            parent_fingerprint: hardened_index_0_child.node.parent_fingerprint.clone(),
            parent_identifier: Some(hex_to_bin("15c918d389673c6cd0660050f268a843361e1111")),
        }))
    );
    // t.throws(() => deriveHdPrivateNodeChild(master.node, hardenedIndex0, {
    //   crypto: mockCrypto, returnInvalidNodes: true }), { message: ... });
    // (`returnInvalidNodes: true` with the default `throwErrors: true` has no
    // Rust counterpart: with `throwErrors` dropped, it is the call above.)
    assert_eq!(
        derive_hd_private_node_child(&master.node, hardened_index_0, Some(mock_crypto), Some(false)),
        Err(format!(
            "{} Invalid child index: 2147483648.",
            HdNodeDerivationError::invalidDerivedKey
        ))
    );
    assert_eq!(
        derive_hd_private_node_child(&master.node, hardened_index_0, Some(mock_crypto), None),
        Err(format!(
            "{} Invalid child index: 2147483648.",
            HdNodeDerivationError::invalidDerivedKey
        ))
    );
    assert_eq!(
        derive_hd_private_node_child(&master.node, hardened_index_0, Some(mock_crypto), None),
        Err(format!(
            "{} Invalid child index: 2147483648.",
            HdNodeDerivationError::invalidDerivedKey
        ))
    );
}

#[test]
fn crypto_derive_hd_private_node_child_errors() {
    let node = assert_success(decode_hd_private_key(XPRV, None), None).node;

    let max: i64 = 0xffff_ffff;
    assert_eq!(
        derive_hd_private_node_child(&node, max + 1, None, None),
        Err(format!(
            "{} Child index: 4294967296.",
            HdNodeDerivationError::childIndexExceedsMaximum
        ))
    );
    assert_eq!(
        derive_hd_private_node_child(&node, max + 1, None, None),
        Err(format!(
            "{} Child index: 4294967296.",
            HdNodeDerivationError::childIndexExceedsMaximum
        ))
    );
}

#[test]
fn crypto_derive_hd_public_node_child() {
    let node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    let parent_public = assert_success(derive_hd_public_node(&node, None), None);
    let derivation_index = 0;
    let child = as_private_node_valid(derive_hd_private_node_child(&node, derivation_index, None, None));
    let expected_public = assert_success(derive_hd_public_node(&child, None), None);

    assert_eq!(
        derive_hd_public_node_child(&parent_public, derivation_index, None, None),
        Ok(HdPublicNode::Valid(expected_public.clone()))
    );

    assert_eq!(
        derive_hd_public_node_child(&parent_public, derivation_index, Some(crypto()), None),
        Ok(HdPublicNode::Valid(expected_public))
    );
    // The remaining (mock crypto) assertions of this test are in
    // `crypto_derive_hd_public_node_child_mock_crypto`.
}

/// The mock crypto assertions of `[crypto] deriveHdPublicNodeChild`.
#[test]
#[ignore = "MISSING-API: Secp256k1 cannot be mocked (libauth's mockCrypto replaces secp256k1.addTweakPrivateKey/addTweakPublicKeyCompressed with () => 'mock failure')"]
fn crypto_derive_hd_public_node_child_mock_crypto() {
    let node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    let parent_public = assert_success(derive_hd_public_node(&node, None), None);
    let derivation_index = 0;
    let child = as_private_node_valid(derive_hd_private_node_child(&node, derivation_index, None, None));
    let expected_public = assert_success(derive_hd_public_node(&child, None), None);

    // Intended:
    // const mockCrypto = {
    //   ripemd160,
    //   secp256k1: { addTweakPublicKeyCompressed: () => 'mock failure' },
    //   sha256,
    //   sha512,
    // };
    // Closest compiling version (the unmodified instances):
    let mock_crypto = crypto();

    // Intended: `crypto: { ripemd160, secp256k1: { ...secp256k1,
    // addTweakPrivateKey: () => 'mock failure' }, sha256, sha512 }`.
    let private_invalid = derive_hd_private_node_child(&node, derivation_index, Some(crypto()), Some(true));
    let private_invalid = match private_invalid {
        Ok(HdPrivateNode::Invalid(private_invalid)) => private_invalid,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        private_invalid.invalid_material,
        hex_to_bin("e0a47856471d353842d4a660069d8fa49b7ed4e17caa1137605ed9adfbd70950")
    );
    assert_eq!(
        derive_hd_public_node_child(&parent_public, derivation_index, Some(mock_crypto), Some(true)),
        Ok(HdPublicNode::Invalid(HdPublicNodeInvalid {
            chain_code: expected_public.chain_code.clone(),
            child_index: expected_public.child_index,
            depth: expected_public.depth,
            invalid_material: private_invalid.invalid_material.clone(),
            parent_fingerprint: expected_public.parent_fingerprint.clone(),
            parent_identifier: expected_public.parent_identifier.clone(),
        }))
    );
    // t.throws(() => deriveHdPublicNodeChild(parentPublic, derivationIndex, {
    //   crypto: mockCrypto, returnInvalidNodes: true }), { message: ... });
    // (`returnInvalidNodes: true` with the default `throwErrors: true` has no
    // Rust counterpart: with `throwErrors` dropped, it is the call above.)
    assert_eq!(
        derive_hd_public_node_child(&parent_public, derivation_index, Some(mock_crypto), Some(false)),
        Err(format!(
            "{} Invalid child index: 0.",
            HdNodeDerivationError::invalidDerivedKey
        ))
    );
    assert_eq!(
        derive_hd_public_node_child(&parent_public, derivation_index, Some(mock_crypto), None),
        Err(format!(
            "{} Invalid child index: 0.",
            HdNodeDerivationError::invalidDerivedKey
        ))
    );
    assert_eq!(
        derive_hd_public_node_child(&parent_public, derivation_index, Some(mock_crypto), None),
        Err(format!(
            "{} Invalid child index: 0.",
            HdNodeDerivationError::invalidDerivedKey
        ))
    );
}

#[test]
fn crypto_derive_hd_public_node_child_errors() {
    let node = assert_success(decode_hd_public_key(XPUB, None), None).node;
    let hardened0: i64 = 0x8000_0000;
    assert_eq!(
        derive_hd_public_node_child(&node, hardened0, None, None),
        Err(format!(
            "{} Requested index: 2147483648.",
            HdNodeDerivationError::hardenedDerivationRequiresPrivateNode
        ))
    );
    assert_eq!(
        derive_hd_public_node_child(&node, hardened0, None, None),
        Err(format!(
            "{} Requested index: 2147483648.",
            HdNodeDerivationError::hardenedDerivationRequiresPrivateNode
        ))
    );
}

#[test]
fn crypto_derive_hd_path_derive_hd_path_return_types() {
    let private_node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    let public_node = assert_success(derive_hd_public_node(&private_node, None), None);
    let private = HdNodeValid::Private(private_node.clone());
    let public = HdNodeValid::Public(public_node.clone());
    let no_op = derive_hd_path(&private, "m", None);
    assert_eq!(no_op, Ok(private.clone()));
    let no_op_with_errors = derive_hd_path(&private, "m", None);
    // AssertTypesEqual<typeof noOpWithErrors, HdPrivateNodeValid | string>
    assert!(assert_type::<Result<HdNodeValid, String>>(&no_op_with_errors));
    assert_eq!(no_op_with_errors, Ok(private.clone()));
    let attempted_inverse = derive_hd_path(&public, "m", None);
    // AssertTypesEqual<typeof attemptedInverse, string>
    assert!(assert_type::<Result<HdNodeValid, String>>(&attempted_inverse));
    assert_eq!(
        attempted_inverse,
        Err(format!(
            "{} Invalid path: \"m\".",
            HdNodeDerivationError::invalidPublicDerivationPrefix
        ))
    );
    let no_op_public = derive_hd_path(&public, "M", Some(crypto()));
    // AssertTypesEqual<typeof noOpPublic, HdPublicNodeValid>
    assert!(assert_type::<Result<HdNodeValid, String>>(&no_op_public));
    assert_eq!(no_op_public, Ok(public.clone()));
    let no_op_public_with_errors = derive_hd_path(&public, "M", Some(crypto()));
    // AssertTypesEqual<typeof noOpPublicWithErrors, HdPublicNodeValid | string>
    assert!(assert_type::<Result<HdNodeValid, String>>(&no_op_public_with_errors));
    assert_eq!(no_op_public_with_errors, Ok(public.clone()));
    let known_parent = derive_hd_path(&private, "m/0'/1", None);
    // AssertTypesEqual<typeof knownParent, HdPrivateNodeKnownParent | HdPrivateNodeValid>
    assert!(assert_type::<Result<HdNodeValid, String>>(&known_parent));
    // t.truthy(deriveHdPath(privateNode as HdPrivateNode, "m/0'/1")) with
    // `@ts-expect-error`: in Rust, an `HdPrivateNode` is likewise rejected by the
    // type checker (`derive_hd_path` takes an `&HdNodeValid`).
    assert!(derive_hd_path(&private, "m/0'/1", None).is_ok());
    let known_parent_public = derive_hd_path(&public, "M/0", None);
    // AssertTypesEqual<typeof knownParentPublic, HdPublicNodeKnownParent | HdPublicNodeValid>
    assert!(assert_type::<Result<HdNodeValid, String>>(&known_parent_public));
    // t.truthy(deriveHdPath(publicNode as HdPublicNode, 'M/0')) with
    // `@ts-expect-error` (see above).
    assert!(derive_hd_path(&public, "M/0", None).is_ok());
    assert_eq!(
        known_parent,
        Ok(HdNodeValid::Private(HdPrivateNodeValid {
            parent_identifier: Some(hex_to_bin("2f2bc501c943dd7f17904b612c090dd88270cc59")),
            ..assert_success(
                decode_hd_private_key(
                    "xprv9w8PdihBAeR4xgGYWWqBnmDTrpWEW1QjuYAUkR7A6X48q1iQVgN433aSFxQGgtureVz7cCyi5zfuMTtBF3AkanjtvNs9m8u2JobxNfphSi3",
                    None,
                ),
                None,
            )
            .node
        }))
    );
    // t.throws(() => { const alsoKnownParent = deriveHdPath(
    //   assertSuccess(knownParent) as HdPrivateNodeKnownParent, 'm');
    //   unknownValue(alsoKnownParent); }, { message: ... });
    let also_known_parent = derive_hd_path(&assert_success(known_parent.clone(), None), "m", None);
    assert_eq!(
        also_known_parent,
        Err(format!(
            "{} Depth of provided HD node: 2.",
            HdNodeDerivationError::requiresZeroDepthNode
        ))
    );
    assert_eq!(
        derive_hd_path(&public, "M/0/1/2/3", None),
        Ok(HdNodeValid::Public(assert_success(
            derive_hd_public_node(
                &private_node_of(assert_success(derive_hd_path(&private, "m/0/1/2/3", None), None)),
                None
            ),
            None
        )))
    );
    assert_eq!(
        derive_hd_path(&private, "m/0'/1'/2'/3'", None),
        derive_hd_path(&private, "m/2147483648/2147483649/2147483650/2147483651", None)
    );
}

#[test]
fn crypto_derive_hd_path_errors() {
    let private_node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    let public_node = assert_success(derive_hd_public_node(&private_node, None), None);
    let private = HdNodeValid::Private(private_node.clone());
    let public = HdNodeValid::Public(public_node);
    let depth_1 = HdNodeValid::Private(HdPrivateNodeValid {
        depth: 1,
        ..private_node.clone()
    });
    for _ in 0..2 {
        // { throwErrors: false } and t.throws(...)
        assert_eq!(
            derive_hd_path(&depth_1, "m/0'/1", None),
            Err(format!(
                "{} Depth of provided HD node: 1.",
                HdNodeDerivationError::requiresZeroDepthNode
            ))
        );
    }
    for _ in 0..2 {
        assert_eq!(
            derive_hd_path(&private, "m/bad/1", None),
            Err(format!(
                "{} Invalid path: \"m/bad/1\".",
                HdNodeDerivationError::invalidAbsoluteDerivationPath
            ))
        );
    }
    for _ in 0..2 {
        assert_eq!(
            derive_hd_path(&private, "M", None),
            Err(format!(
                "{} Invalid path: \"M\".",
                HdNodeDerivationError::invalidPrivateDerivationPrefix
            ))
        );
    }
    for _ in 0..2 {
        assert_eq!(
            derive_hd_path(&public, "m", None),
            Err(format!(
                "{} Invalid path: \"m\".",
                HdNodeDerivationError::invalidPublicDerivationPrefix
            ))
        );
    }
    for _ in 0..2 {
        assert_eq!(
            derive_hd_path(&private, "m/0/4294967296/0", None),
            Err(format!(
                "{} Child index: 4294967296.",
                HdNodeDerivationError::childIndexExceedsMaximum
            ))
        );
    }
    for _ in 0..2 {
        assert_eq!(
            derive_hd_path(&public, "M/0/0'/0", None),
            Err(format!(
                "{} Requested index: 2147483648.",
                HdNodeDerivationError::hardenedDerivationRequiresPrivateNode
            ))
        );
    }
    for _ in 0..2 {
        assert_eq!(
            derive_hd_path(&public, "M/0/2147483648/0", None),
            Err(format!(
                "{} Requested index: 2147483648.",
                HdNodeDerivationError::hardenedDerivationRequiresPrivateNode
            ))
        );
    }
}

#[test]
fn crypto_derive_hd_path_relative() {
    let private_node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    let public_node = assert_success(derive_hd_public_node(&private_node, None), None);
    let private = HdNodeValid::Private(private_node.clone());
    let public = HdNodeValid::Public(public_node.clone());
    let basic_private = derive_hd_path_relative(&private, "0", None);
    assert_eq!(
        basic_private,
        private_child(derive_hd_private_node_child(&private_node, 0, None, None))
    );
    // AssertTypesEqual<typeof basicPrivate, HdPrivateNodeKnownParent>
    assert!(assert_type::<Result<HdNodeValid, String>>(&basic_private));
    let basic_public = derive_hd_path_relative(&public, "0", None);
    assert_eq!(
        basic_public,
        public_child(derive_hd_public_node_child(&public_node, 0, None, None))
    );
    // AssertTypesEqual<typeof basicPublic, HdPublicNodeKnownParent>
    assert!(assert_type::<Result<HdNodeValid, String>>(&basic_public));
    let no_op_private = derive_hd_path_relative(&private, "", None);
    assert_eq!(no_op_private, Ok(private.clone()));
    // AssertTypesEqual<typeof noOpPrivate, HdPrivateNodeValid>
    assert!(assert_type::<Result<HdNodeValid, String>>(&no_op_private));
    let no_op_public = derive_hd_path_relative(&public, "", None);
    assert_eq!(no_op_public, Ok(public.clone()));
    // AssertTypesEqual<typeof noOpPublic, HdPublicNodeValid>
    assert!(assert_type::<Result<HdNodeValid, String>>(&no_op_public));
    let public_child_0 = as_public_node_valid(derive_hd_public_node_child(&public_node, 0, None, None));
    assert_eq!(
        derive_hd_path_relative(&HdNodeValid::Public(public_child_0.clone()), "0", None),
        public_child(derive_hd_public_node_child(&public_child_0, 0, None, None))
    );
    assert_eq!(
        derive_hd_path_relative(&private, "0'/1", None),
        Ok(HdNodeValid::Private(HdPrivateNodeValid {
            parent_identifier: Some(hex_to_bin("2f2bc501c943dd7f17904b612c090dd88270cc59")),
            ..assert_success(
                decode_hd_private_key(
                    "xprv9w8PdihBAeR4xgGYWWqBnmDTrpWEW1QjuYAUkR7A6X48q1iQVgN433aSFxQGgtureVz7cCyi5zfuMTtBF3AkanjtvNs9m8u2JobxNfphSi3",
                    None,
                ),
                None,
            )
            .node
        }))
    );
    assert_eq!(
        derive_hd_path_relative(&public, "0/1/2/3", None),
        Ok(HdNodeValid::Public(assert_success(
            derive_hd_public_node(
                // `as HdPrivateNodeKnownParent`
                &private_node_of(assert_success(derive_hd_path_relative(&private, "0/1/2/3", None), None)),
                None
            ),
            None
        )))
    );
    assert_eq!(
        derive_hd_path_relative(&private, "0'/1'/2'/3'", None),
        derive_hd_path_relative(&private, "2147483648/2147483649/2147483650/2147483651", None)
    );
    // `assertSuccess(privateNode)`
    let known_parent = derive_hd_path_relative(&private, "0", None);
    let also_known_parent = derive_hd_path_relative(&assert_success(known_parent.clone(), None), "", None);
    assert_eq!(known_parent, also_known_parent);
}

#[test]
fn crypto_derive_hd_path_relative_errors() {
    let private_node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    let private = HdNodeValid::Private(private_node);
    assert_eq!(derive_hd_path_relative(&private, "", None), Ok(private.clone()));
    for _ in 0..2 {
        // { throwErrors: false } and t.throws(...)
        assert_eq!(
            derive_hd_path_relative(&private, "bad/1", None),
            Err(format!(
                "{} Invalid path: \"bad/1\".",
                HdNodeDerivationError::invalidRelativeDerivationPath
            ))
        );
    }
}

#[test]
fn crypto_crack_hd_private_node_from_hd_public_node_and_child_private_node() {
    let parent_private_node = assert_success(decode_hd_private_key(XPRV, None), None).node;
    let parent_public_node = assert_success(derive_hd_public_node(&parent_private_node, None), None);
    let private = HdNodeValid::Private(parent_private_node.clone());
    let non_hardened_child_node = match derive_hd_path(&private, "m/1234", None) {
        Err(error) => panic!("hardenedChildNode: {error:?}"),
        Ok(node) => private_node_of(node),
    };
    let hardened_child_node = match derive_hd_path(&private, "m/1234'", None) {
        Err(error) => panic!("hardenedChildNode: {error:?}"),
        Ok(node) => private_node_of(node),
    };
    let hardened_child_public_node = match derive_hd_public_node(&hardened_child_node, None) {
        Err(error) => panic!("hardenedChildPublicNode: {error:?}"),
        Ok(node) => node,
    };
    let non_hardened_grandchild_node =
        match derive_hd_path_relative(&HdNodeValid::Private(hardened_child_node.clone()), "1234", None) {
            Err(error) => panic!("nonHardenedGrandchildNode: {error:?}"),
            Ok(node) => private_node_of(node),
        };
    assert_eq!(
        crack_hd_private_node_from_hd_public_node_and_child_private_node(
            &parent_public_node,
            &non_hardened_child_node,
            None
        ),
        Ok(parent_private_node.clone())
    );

    assert_eq!(
        crack_hd_private_node_from_hd_public_node_and_child_private_node(
            &hardened_child_public_node,
            &non_hardened_grandchild_node,
            Some(&sha512)
        ),
        Ok(hardened_child_node.clone())
    );

    assert_eq!(
        crack_hd_private_node_from_hd_public_node_and_child_private_node(
            &parent_public_node,
            &hardened_child_node,
            None
        ),
        Err(HdNodeCrackingError::cannotCrackHardenedDerivation.to_string())
    );
}

/// The `bip32Vector` macro.
fn bip32_vector(seed_hex: &str, path: &str, hd_private_key: &str, hd_public_key: &str) {
    let master = as_private_node_valid(Ok(derive_hd_private_node_from_seed(
        &hex_to_bin(seed_hex),
        None,
        None,
        None,
    )));
    let child_node = private_node_of(assert_success(
        derive_hd_path(&HdNodeValid::Private(master), path, None),
        None,
    ));
    let vector_xprv = assert_success(encode_hd_private_key(&mainnet(child_node.clone()), None), None).hd_private_key;
    assert_eq!(vector_xprv, hd_private_key, "vectorXprv === hdPrivateKey");
    let decoded_private = assert_success(decode_hd_private_key(hd_private_key, None), Some("decodedPrivate:"));
    assert_eq!(
        child_node
            .parent_identifier
            .as_ref()
            .map(|identifier| identifier[..FINGERPRINT_LENGTH].to_vec()),
        if path == "m" {
            None
        } else {
            Some(decoded_private.node.parent_fingerprint.clone())
        },
        "parentFingerprint (private)"
    );
    assert_eq!(
        child_node,
        HdPrivateNodeValid {
            parent_identifier: if path == "m" {
                decoded_private.node.parent_identifier.clone()
            } else {
                child_node.parent_identifier.clone()
            },
            ..decoded_private.node.clone()
        },
        "childNode contents"
    );
    let decoded_public = assert_success(decode_hd_public_key(hd_public_key, None), Some("decodedPublic:"));
    let public_node = assert_success(derive_hd_public_node(&child_node, None), None);
    assert_eq!(
        public_node
            .parent_identifier
            .as_ref()
            .map(|identifier| identifier[..FINGERPRINT_LENGTH].to_vec()),
        if path == "m" {
            None
        } else {
            Some(decoded_public.node.parent_fingerprint.clone())
        },
        "parentFingerprint (public)"
    );
    assert_eq!(
        public_node,
        HdPublicNodeValid {
            parent_identifier: if path == "m" {
                decoded_public.node.parent_identifier.clone()
            } else {
                public_node.parent_identifier.clone()
            },
            ..decoded_public.node.clone()
        },
        "publicNode contents"
    );
    let vector_xpub = assert_success(encode_hd_public_key(&mainnet(public_node), None), None).hd_public_key;
    assert_eq!(vector_xpub, hd_public_key, "vectorXpub === hdPublicKey");
}

#[test]
fn crypto_bip32_vector_1_1_m() {
    bip32_vector(
        "000102030405060708090a0b0c0d0e0f",
        "m",
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    );
}

#[test]
fn crypto_bip32_vector_1_2_m_0() {
    bip32_vector(
        "000102030405060708090a0b0c0d0e0f",
        "m/0'",
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    );
}

#[test]
fn crypto_bip32_vector_1_3_m_0_1() {
    bip32_vector(
        "000102030405060708090a0b0c0d0e0f",
        "m/0'/1",
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    );
}

#[test]
fn crypto_bip32_vector_1_4_m_0_1_2() {
    bip32_vector(
        "000102030405060708090a0b0c0d0e0f",
        "m/0'/1/2'",
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
    );
}

#[test]
fn crypto_bip32_vector_1_5_m_0_1_2_2() {
    bip32_vector(
        "000102030405060708090a0b0c0d0e0f",
        "m/0'/1/2'/2",
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
    );
}

#[test]
fn crypto_bip32_vector_1_6_m_0_1_2_2_1000000000() {
    bip32_vector(
        "000102030405060708090a0b0c0d0e0f",
        "m/0'/1/2'/2/1000000000",
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
    );
}

#[test]
fn crypto_bip32_vector_2_1_m() {
    bip32_vector(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m",
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
    );
}

#[test]
fn crypto_bip32_vector_2_2_m_0() {
    bip32_vector(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0",
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
    );
}

#[test]
fn crypto_bip32_vector_2_3_m_0_2147483647() {
    bip32_vector(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0/2147483647'",
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
    );
}

#[test]
fn crypto_bip32_vector_2_4_m_0_2147483647_1() {
    bip32_vector(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0/2147483647'/1",
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
    );
}

#[test]
fn crypto_bip32_vector_2_5_m_0_2147483647_1_2147483646() {
    bip32_vector(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0/2147483647'/1/2147483646'",
        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
    );
}

#[test]
fn crypto_bip32_vector_2_6_m_0_2147483647_1_2147483646_2() {
    bip32_vector(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0/2147483647'/1/2147483646'/2",
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
    );
}

#[test]
fn crypto_bip32_vector_3_1_m() {
    bip32_vector(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        "m",
        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
    );
}

#[test]
fn crypto_bip32_vector_3_2_m_0() {
    bip32_vector(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        "m/0'",
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
    );
}

#[test]
fn crypto_bip32_vector_4_1_m() {
    bip32_vector(
        "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
        "m",
        "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
        "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
    );
}

#[test]
fn crypto_bip32_vector_4_2_m_0() {
    bip32_vector(
        "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
        "m/0'",
        "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
        "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
    );
}

#[test]
fn crypto_bip32_vector_4_3_m_0_1() {
    bip32_vector(
        "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
        "m/0'/1'",
        "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
        "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
    );
}

/// The `bip32InvalidVector` macro.
fn bip32_invalid_vector(
    hd_key: &str,
    expected_unchecked_result: Result<DecodedHdKeyUnchecked, String>,
    expected_strict_result: &str,
) {
    let unchecked = decode_hd_key_unchecked(hd_key, None);
    assert_eq!(
        unchecked, expected_unchecked_result,
        "decodeHdKeyUnchecked produced an unexpected result: {unchecked:?}"
    );
    let strict = decode_hd_key(hd_key, None);
    assert_eq!(
        strict,
        Err(expected_strict_result.to_string()),
        "decodeHdKey produced an unexpected result: {strict:?}"
    );
}

fn zero_chain_code() -> Vec<u8> {
    hex_to_bin("0000000000000000000000000000000000000000000000000000000000000000")
}

#[test]
fn crypto_bip32_invalid_vector_5_0_pubkey_version_prv_key_mismatch() {
    bip32_invalid_vector(
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Public(HdPublicNode::Invalid(HdPublicNodeInvalid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                invalid_material: hex_to_bin("00000000000000000000000000000000000000000000000000000000000000000c"),
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
            })),
            version: HdKeyVersion::mainnetPublicKey,
        }),
        &format!(
            "{} Invalid public key: 00000000000000000000000000000000000000000000000000000000000000000c.",
            HdKeyDecodingError::invalidPublicKey
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_1_pubkey_version_prv_key_mismatch() {
    bip32_invalid_vector(
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        Err(HdKeyDecodingError::missingPrivateKeyPaddingByte.to_string()),
        HdKeyDecodingError::missingPrivateKeyPaddingByte,
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_2_invalid_pubkey_prefix_04() {
    bip32_invalid_vector(
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Public(HdPublicNode::Invalid(HdPublicNodeInvalid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                invalid_material: hex_to_bin("04000000000000000000000000000000000000000000000000000000000000000c"),
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
            })),
            version: HdKeyVersion::mainnetPublicKey,
        }),
        &format!(
            "{} Invalid public key: 04000000000000000000000000000000000000000000000000000000000000000c.",
            HdKeyDecodingError::invalidPublicKey
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_3_invalid_pubkey_prefix_04() {
    bip32_invalid_vector(
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        Err(HdKeyDecodingError::missingPrivateKeyPaddingByte.to_string()),
        HdKeyDecodingError::missingPrivateKeyPaddingByte,
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_4_invalid_pubkey_prefix_01() {
    bip32_invalid_vector(
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Public(HdPublicNode::Invalid(HdPublicNodeInvalid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                invalid_material: hex_to_bin("01000000000000000000000000000000000000000000000000000000000000000c"),
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
            })),
            version: HdKeyVersion::mainnetPublicKey,
        }),
        &format!(
            "{} Invalid public key: 01000000000000000000000000000000000000000000000000000000000000000c.",
            HdKeyDecodingError::invalidPublicKey
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_5_invalid_pubkey_prefix_01() {
    bip32_invalid_vector(
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        Err(HdKeyDecodingError::missingPrivateKeyPaddingByte.to_string()),
        HdKeyDecodingError::missingPrivateKeyPaddingByte,
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_6_zero_depth_with_non_zero_parent_fingerprint() {
    bip32_invalid_vector(
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Private(HdPrivateNode::Valid(HdPrivateNodeValid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                parent_fingerprint: hex_to_bin("01010101"),
                parent_identifier: None,
                private_key: hex_to_bin("000000000000000000000000000000000000000000000000000000000000000c"),
            })),
            version: HdKeyVersion::mainnetPrivateKey,
        }),
        &format!(
            "{} Parent fingerprint: 1,1,1,1.",
            HdKeyDecodingError::zeroDepthWithNonZeroParentFingerprint
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_7_zero_depth_with_non_zero_parent_fingerprint() {
    bip32_invalid_vector(
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Public(HdPublicNode::Valid(HdPublicNodeValid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                parent_fingerprint: hex_to_bin("01010101"),
                parent_identifier: None,
                public_key: hex_to_bin("03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"),
            })),
            version: HdKeyVersion::mainnetPublicKey,
        }),
        &format!(
            "{} Parent fingerprint: 1,1,1,1.",
            HdKeyDecodingError::zeroDepthWithNonZeroParentFingerprint
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_8_zero_depth_with_non_zero_index() {
    bip32_invalid_vector(
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Private(HdPrivateNode::Valid(HdPrivateNodeValid {
                chain_code: zero_chain_code(),
                child_index: 16_843_009,
                depth: 0,
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
                private_key: hex_to_bin("000000000000000000000000000000000000000000000000000000000000000c"),
            })),
            version: HdKeyVersion::mainnetPrivateKey,
        }),
        &format!(
            "{} Child index: 16843009.",
            HdKeyDecodingError::zeroDepthWithNonZeroChildIndex
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_9_zero_depth_with_non_zero_index() {
    bip32_invalid_vector(
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Public(HdPublicNode::Valid(HdPublicNodeValid {
                chain_code: zero_chain_code(),
                child_index: 16_843_009,
                depth: 0,
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
                public_key: hex_to_bin("03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"),
            })),
            version: HdKeyVersion::mainnetPublicKey,
        }),
        &format!(
            "{} Child index: 16843009.",
            HdKeyDecodingError::zeroDepthWithNonZeroChildIndex
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_10_unknown_extended_key_version() {
    bip32_invalid_vector(
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        Err(format!("{} Version: 16843009", HdKeyDecodingError::unknownVersion)),
        &format!("{} Version: 16843009", HdKeyDecodingError::unknownVersion),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_11_unknown_extended_key_version() {
    bip32_invalid_vector(
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        Err(format!("{} Version: 16843009", HdKeyDecodingError::unknownVersion)),
        &format!("{} Version: 16843009", HdKeyDecodingError::unknownVersion),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_12_private_key_0_not_in_1_n_1() {
    bip32_invalid_vector(
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Private(HdPrivateNode::Invalid(HdPrivateNodeInvalid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                invalid_material: hex_to_bin("0000000000000000000000000000000000000000000000000000000000000000"),
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
            })),
            version: HdKeyVersion::mainnetPrivateKey,
        }),
        HdKeyDecodingError::invalidPrivateKey,
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_13_private_key_n_not_in_1_n_1() {
    bip32_invalid_vector(
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Private(HdPrivateNode::Invalid(HdPrivateNodeInvalid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                invalid_material: hex_to_bin("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
            })),
            version: HdKeyVersion::mainnetPrivateKey,
        }),
        HdKeyDecodingError::invalidPrivateKey,
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_14_invalid_pubkey_020000000000000000000000000000000000000000000000000000000000000007() {
    bip32_invalid_vector(
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
        Ok(DecodedHdKeyUnchecked {
            node: HdNode::Public(HdPublicNode::Invalid(HdPublicNodeInvalid {
                chain_code: zero_chain_code(),
                child_index: 0,
                depth: 0,
                invalid_material: hex_to_bin("020000000000000000000000000000000000000000000000000000000000000007"),
                parent_fingerprint: hex_to_bin("00000000"),
                parent_identifier: None,
            })),
            version: HdKeyVersion::mainnetPublicKey,
        }),
        &format!(
            "{} Invalid public key: 020000000000000000000000000000000000000000000000000000000000000007.",
            HdKeyDecodingError::invalidPublicKey
        ),
    );
}

#[test]
fn crypto_bip32_invalid_vector_5_15_invalid_checksum() {
    bip32_invalid_vector(
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        Err(format!(
            "{} Encoded: e77e9d5b; computed: e77e9d71.",
            HdKeyDecodingError::invalidChecksum
        )),
        &format!(
            "{} Encoded: e77e9d5b; computed: e77e9d71.",
            HdKeyDecodingError::invalidChecksum
        ),
    );
}

/// Substitution for `bitcore-lib-cash` (a JavaScript-only library): for 10
/// paths sampled from libauth's `fcBip32Path()` arbitrary (`fc.sample(...,
/// { numRuns: 10, seed: 1 })`, matching the test's `numRuns: 10`), the
/// results of `bitcoreLibCash.HDPrivateKey(xprv).deriveChild(path)`
/// (`[path, xprivkey, xpubkey]`), computed with bitcore-lib-cash in Node.js.
const BITCORE_LIB_CASH_DERIVATIONS: [(&str, &str, &str); 10] = [
    (
        "m/136423089'/2080322404/1650234236/1952407034/1906876559/1298244064'/1960851565'/1185627313/1612734911/1539900037'/1349867681'",
        "xprvAEyCw4hJXBSEhu3LHrgvCkgZ2xGkZNeaMNgGRHDNg5hSwt7WwpVUR89k9pF4azanArkYZE21sbKSn2UeQoKQjQL6SHJTj8pdpDogt4DsjPX",
        "xpub6TxZLaECMYzXvP7oPtDvZtdHaz7ExqNRibbsDfczERERpgSfVMoixvUE17KqTV1nhssAtSEnMuvXMZ7o63pBjFJ44MKYmgMagXTi1UtCnB3",
    ),
    (
        "m/2147483631'/2147483623'/455969477/1645190608'",
        "xprvA1chWRxgavThkbF5eGkVzFEqbc7Ra6wYGo1pcaMj8ztA5RL371ySfceumJkUCLxis2wCZyQv3T4Voo7PqxXtaMKUJNbuXk6e9nxB5g2w6xG",
        "xpub6Ec3uwVaRJ1zy5KYkJHWMPBa9dwuyZfPe1wRQxmLhLR8xDfBeZHhDQyPcc56KgcuKEELTns6G2ZBhiraNT2CHUDvzce5QzkzGNJSL8rczDe",
    ),
    (
        "m/54450308/774554357/779268255/309647422/1029021578",
        "xprvA2hqaPY1ZmJEvQatVeyXZcabkxcUSMghJ6a4CUpTkQqvcznHSiwxFCRj8CSbiCXwAvK6XoH9a5wievvCEgT8aQHB8h6RFJ6gX3vwZrookPq",
        "xpub6FhByu4uQ8rY8tfMbgWXvkXLJzSxqpQYfKVezsE5JkNuVo7RzGGCnzkCyWNZZp6fW2iZQvHUF1LdqmReDcPJtAm7LqV6ZN8j6U6xfcC9j17",
    ),
    (
        "m/334260992'/1847528059/913998118'",
        "xprv9yZ36MDCSWKvNXs4KziLXomsQMgy8hRB5LeHi5oKHMx9FAsMB7GSbWtNPdjZjtty6Au8Bh9P5QnrmaVhNKiJ44ABGUjLv53nKjY7Y4R8TKy",
        "xpub6CYPVrk6GstDb1wXS2FLtwibxPXTYA92SZZtWUCvqhV87yCVieah9KCrEuHFxALUjyJY2mi46d4xfRgCMpxxgGAc9hwaBtAHDdcWkKktiXh",
    ),
    (
        "m/924270310'/1387202623'/744289643/1058705421'/1375159438/552794303'",
        "xprvA4zg3Y3v8AUk5ZWw5atLuPuFmfT1X9YgUkgpShsWDGMLnnK2pDLHJpS7qdQmnS9VpnLUvoi7dA5Vc2S72Zj9evJRTVUGvU6aRsWRmwv7rxC",
        "xpub6Hz2T3aoxY33J3bQBcRMGXqzKhHVvcGXqycRF6H7mbtKfaeBMkeXrckbgv4ytzRuFey2T7dVZZ174m7mSamLY81v9WYP4dZYudeQq7QMbwq",
    ),
    (
        "m/1549893831'/1954505858'/1798841853/1691775875/699997916/117991603/1357120419/774676552'",
        "xprvA9uXnj3WkhG5jR6jd4N6xTky9Q1o1WgXpwRLePxFCBNbdVAgrajd3kodDEaZpQoXxkyoLYx91M5qfSPGoz5EtXvcn6kie4wH71FKUQKcGYT",
        "xpub6NttCEaQb4pNwuBCj5u7KbhhhRrHQyQPCALwSnMrkWuaWHVqQ83sbZ874ZEFinCpEXyaJqY7mahuinThzVvmJnyXfKMVt9cPqQHE9rm13td",
    ),
    (
        "m/1308776223'/28/1134455847'/823175352/1758527832'/156222058'/88012421'/1559787807'/1634413226'/10/2086363918'",
        "xprvAFDNfebBQewK1wa2XWHfySpf7gopWnhLFCTTnTznxLbpVEdiw9FL3KeQu5cxo5J8u8S3vPZUce5Wy4YrGfYbQ1KsTZgdowPLuHbV1A3kiCQ",
        "xpub6UCj5A85F2VcEReVdXpgLamPfieJvFRBcRP4arQQWg8oN2xsUgZab7xtkKc9pEkMqyhhB28iYgTifkoQMp4VnCXVqtaunXwswnmH7UqdjmD",
    ),
    (
        "m/2147483625'/1380261045",
        "xprv9x1SKSimUrsBe64Y9tvTyccbz6YQpnmq5FwdwQt9R6E1gngi3pELiRsRScBQETm7uJSAYRBkadFm3idse8WRpzzoQF1wqZTnRgUFQyPxzxq",
        "xpub6AznixFfKERUra91FvTULkZLY8NuEFVgSUsEjoHkyRkzZb1rbMYbGEBuHrubbg5vmwYXZaHipSmk88zidtYaXpMn7qvxDXL7aMSNN6HnX4K",
    ),
    (
        "m/2147483618'/12",
        "xprv9xQkHxVubdKmBXP1z7pNkXzXPMxAx81P3BQrEPqyf8of4gJ21FscNhwfkWoKJpLoxG9sYiaoD4USjqYvqUq9kzLJeU1uqHBhyJSUTtceeoK",
        "xpub6BQ6hU2oRzt4Q1TV69MP7fwFwPnfMajEQQLT2nFbDULdwUdAYoBrvWG9boM8mAuSU38vTrsPbdQSeYDHnHQCjQUHkYoMPgnd964UEHxhBeB",
    ),
    (
        "m/1100130094/1288357572/1748810839/374412317'/1774039043'",
        "xprvA2ZyvAz6Gy7VSvuTZemYH3B7pKhjRJdbQghpqVMWpLGNiD371iwvsFwhDE4z3JGStbK5osqn1mLLrrN4SbU9iBCTuZtUnyzCdaB3EUBmJK9",
        "xpub6FZLKgWz7LfnfQyvfgJYeB7rNMYDpmMSmudRdsm8NfoMb1NFZGGBR4GB4Uc2porG24w8jgxi1ET7TJUmpD6b7omLvbB8uwcEn74eh3r81fX",
    ),
];

#[test]
fn fast_check_crypto_hd_node_derivation_is_equivalent_to_bitcore_lib_cash() {
    for (path, bitcore_prv, bitcore_pub) in BITCORE_LIB_CASH_DERIVATIONS {
        let private_node = assert_success(decode_hd_private_key(XPRV, None), None).node;
        // `deriveHdPath(privateNode, path) as HdPrivateNodeValid`
        let node = private_node_of(assert_success(
            derive_hd_path(&HdNodeValid::Private(private_node), path, None),
            None,
        ));
        let public_node = assert_success(derive_hd_public_node(&node, None), None);

        let result_prv = assert_success(encode_hd_private_key(&mainnet(node), None), None).hd_private_key;
        let result_pub = assert_success(encode_hd_public_key(&mainnet(public_node), None), None).hd_public_key;
        // const bitcoreResult = bitcoreLibCash.HDPrivateKey(xprv).deriveChild(path);
        // (precomputed: see BITCORE_LIB_CASH_DERIVATIONS)

        assert_eq!(result_prv, bitcore_prv, "path: {path}");
        assert_eq!(result_pub, bitcore_pub, "path: {path}");
    }
}

#[test]
fn fast_check_crypto_encode_hd_private_key_with_without_throw_errors_decode_hd_private_key() {
    let arbitrary = {
        let mainnet = fc::boolean();
        let depth = fc::integer(Some(0), Some(MAXIMUM_DEPTH));
        let child_index = fc::integer(Some(0), Some(MAXIMUM_CHILD_INDEX));
        let parent_fingerprint = fc::uint8_array(Some(FINGERPRINT_LENGTH), Some(FINGERPRINT_LENGTH));
        let chain_code = fc::uint8_array(Some(CHAIN_CODE_LENGTH), Some(CHAIN_CODE_LENGTH));
        let private_key = fc::uint8_array(Some(PRIVATE_KEY_LENGTH), Some(PRIVATE_KEY_LENGTH));
        move |random: &mut fc::Random| {
            (
                mainnet(random),
                depth(random),
                child_index(random),
                parent_fingerprint(random),
                chain_code(random),
                private_key(random),
            )
        }
    };
    fc::test_prop(
        arbitrary,
        |(mainnet, depth, child_index, parent_fingerprint, chain_code, private_key)| {
            if !validate_secp256k1_private_key(private_key) {
                // t.pass();
                return;
            }
            let parameters = DecodedHdKey {
                network: if *mainnet {
                    HdKeyNetwork::Mainnet
                } else {
                    HdKeyNetwork::Testnet
                },
                node: HdPrivateNodeValid {
                    chain_code: chain_code.clone(),
                    child_index: *child_index,
                    depth: *depth,
                    parent_fingerprint: parent_fingerprint.clone(),
                    parent_identifier: None,
                    private_key: private_key.clone(),
                },
            };
            let encoded = match encode_hd_private_key(&parameters, None) {
                Err(encoded) => {
                    // t.throws(() => encodeHdPrivateKey(parameters), { message: encoded })
                    assert_eq!(
                        encode_hd_private_key(&parameters, None),
                        Err(encoded),
                        "parameters: {parameters:?}"
                    );
                    return;
                }
                Ok(encoded) => encoded,
            };
            let decoded = match decode_hd_private_key(&encoded.hd_private_key, None) {
                Err(decoded) => panic!("{decoded}"),
                Ok(decoded) => decoded,
            };
            assert_eq!(
                encoded.hd_private_key,
                assert_success(encode_hd_private_key(&decoded, None), None).hd_private_key
            );
        },
    );
}

#[test]
fn fast_check_crypto_encode_hd_public_key_with_without_throw_errors_decode_hd_public_key() {
    let arbitrary = {
        let mainnet = fc::boolean();
        let depth = fc::integer(Some(0), Some(MAXIMUM_DEPTH));
        let child_index = fc::integer(Some(0), Some(MAXIMUM_CHILD_INDEX));
        let parent_fingerprint = fc::uint8_array(Some(FINGERPRINT_LENGTH), Some(FINGERPRINT_LENGTH));
        let chain_code = fc::uint8_array(Some(CHAIN_CODE_LENGTH), Some(CHAIN_CODE_LENGTH));
        let public_key = fc::uint8_array(Some(PUBLIC_KEY_LENGTH), Some(PUBLIC_KEY_LENGTH));
        move |random: &mut fc::Random| {
            (
                mainnet(random),
                depth(random),
                child_index(random),
                parent_fingerprint(random),
                chain_code(random),
                public_key(random),
            )
        }
    };
    fc::test_prop(
        arbitrary,
        |(mainnet, depth, child_index, parent_fingerprint, chain_code, public_key)| {
            let parameters = DecodedHdKey {
                network: if *mainnet {
                    HdKeyNetwork::Mainnet
                } else {
                    HdKeyNetwork::Testnet
                },
                node: HdPublicNodeValid {
                    chain_code: chain_code.clone(),
                    child_index: *child_index,
                    depth: *depth,
                    parent_fingerprint: parent_fingerprint.clone(),
                    parent_identifier: None,
                    public_key: public_key.clone(),
                },
            };
            let encoded = match encode_hd_public_key(&parameters, None) {
                Err(encoded) => {
                    // t.throws(() => encodeHdPublicKey(parameters), { message: encoded })
                    assert_eq!(
                        encode_hd_public_key(&parameters, None),
                        Err(encoded),
                        "parameters: {parameters:?}"
                    );
                    return;
                }
                Ok(encoded) => encoded,
            };
            let decoded = match decode_hd_public_key(&encoded.hd_public_key, None) {
                Err(decoded) => panic!("decoded: {decoded:?}"),
                Ok(decoded) => decoded,
            };
            assert_eq!(
                encoded.hd_public_key,
                assert_success(encode_hd_public_key(&decoded, None), None).hd_public_key
            );
        },
    );
}

#[test]
fn fast_check_crypto_derive_non_hardened_hd_node_crack_hd_node() {
    let arbitrary = {
        let depth = fc::integer(Some(0), Some(MAXIMUM_DEPTH));
        let child_indexes = fc::integer(Some(0), Some(MAXIMUM_NON_HARDENED_INDEX));
        let parent_fingerprint = fc::uint8_array(Some(FINGERPRINT_LENGTH), Some(FINGERPRINT_LENGTH));
        let chain_code = fc::uint8_array(Some(CHAIN_CODE_LENGTH), Some(CHAIN_CODE_LENGTH));
        let private_key = fc::uint8_array(Some(PRIVATE_KEY_LENGTH), Some(PRIVATE_KEY_LENGTH));
        move |random: &mut fc::Random| {
            (
                depth(random),
                child_indexes(random),
                parent_fingerprint(random),
                chain_code(random),
                private_key(random),
            )
        }
    };
    fc::test_prop(
        arbitrary,
        |(depth, child_indexes, parent_fingerprint, chain_code, private_key)| {
            if !validate_secp256k1_private_key(private_key) {
                // t.pass();
                return;
            }
            let parameters = mainnet(HdPrivateNodeValid {
                chain_code: chain_code.clone(),
                child_index: *child_indexes,
                depth: *depth,
                parent_fingerprint: parent_fingerprint.clone(),
                parent_identifier: None,
                private_key: private_key.clone(),
            });
            let encoded = match encode_hd_private_key(&parameters, None) {
                Err(_) => {
                    // t.pass();
                    return;
                }
                Ok(encoded) => encoded,
            };
            let parent_xprv = encoded.hd_private_key;
            let decoded = match decode_hd_private_key(&parent_xprv, None) {
                Err(decoded) => panic!(
                    "parameters: {parameters:?}\n\n parentXprv: {parent_xprv}\n\n decoded: {decoded}"
                ),
                Ok(decoded) => decoded,
            };
            let parent_private_node = decoded.node;
            let parent_public_node = assert_success(derive_hd_public_node(&parent_private_node, None), None);

            let non_hardened_child_node =
                as_private_node_valid(derive_hd_private_node_child(&parent_private_node, *child_indexes, None, None));

            // `as HdPrivateNodeValid`
            let cracked_parent_node = assert_success(
                crack_hd_private_node_from_hd_public_node_and_child_private_node(
                    &parent_public_node,
                    &non_hardened_child_node,
                    None,
                ),
                None,
            );
            let cracked_xprv =
                assert_success(encode_hd_private_key(&mainnet(cracked_parent_node), None), None).hd_private_key;

            assert_eq!(parent_xprv, cracked_xprv);
        },
    );
}
