//! Port of `compiler/p2pkh-utils.spec.ts`.
#![allow(non_upper_case_globals, non_snake_case)]

use std::sync::LazyLock;

use libauth::{
    assert_success, decode_hd_private_key, decode_private_key_wif, derive_hd_path, derive_hd_public_node,
    encode_hd_public_key, hd_private_key_to_p2pkh_cash_address, hd_private_key_to_p2pkh_locking_bytecode,
    hd_public_key_to_p2pkh_cash_address, hd_public_key_to_p2pkh_locking_bytecode, hex_to_bin,
    private_key_to_p2pkh_cash_address, private_key_to_p2pkh_locking_bytecode, public_key_to_p2pkh_cash_address,
    public_key_to_p2pkh_locking_bytecode, DecodedHdKey, HdKeyNetwork, HdNodeValid, HdPrivateNodeValid,
    HdPublicNodeValid, P2pkhUtilityError,
};

const hdPrivateKey: &str =
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
const hdPublicKey: &str =
    "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";
const m0Wif: &str = "L3UYuE3vUJ9DXZ6fyiJL4b991cZGFpawcbF7YZiw94QcKKtQ4C8g";
static m0PublicKey: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("0376bf533d4b15510fa9f4124b6e48616f07debcf2ef0cfb185cdc4a576450b475"));
static m0PrivateKey: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("baa89a8bdd61c5e22b9f10601d8791c9f8fc4b2fa6df9d68d336f0eb03b06eb6"));
static m0LockingBytecode: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("76a9145525def68633f742eb828a3eb27419ea9815f73588ac"));
static node: LazyLock<HdPrivateNodeValid> =
    LazyLock::new(|| assert_success(decode_hd_private_key(hdPrivateKey, None), None).node);
static publicNode: LazyLock<HdPublicNodeValid> =
    LazyLock::new(|| assert_success(derive_hd_public_node(&node, None), None));
static M: LazyLock<String> = LazyLock::new(|| {
    assert_success(
        encode_hd_public_key(
            &DecodedHdKey {
                network: HdKeyNetwork::Mainnet,
                node: publicNode.clone(),
            },
            None,
        ),
        None,
    )
    .hd_public_key
});
static publicKey: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let M0 = assert_success(
        derive_hd_path(&HdNodeValid::Public(publicNode.clone()), "M/0", None),
        None,
    );
    let HdNodeValid::Public(M0) = M0 else {
        unreachable!("public derivation")
    };
    M0.public_key
});
static privateKey: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let m0 = assert_success(derive_hd_path(&HdNodeValid::Private(node.clone()), "m/0", None), None);
    let HdNodeValid::Private(m0) = m0 else {
        unreachable!("private derivation")
    };
    m0.private_key
});
const m0Mainnet: &str = "bitcoincash:qp2jthhkscelwshts29ravn5r84fs90hx5td9vqu73";
const m0Testnet: &str = "bchtest:qp2jthhkscelwshts29ravn5r84fs90hx50lptzted";
const m0Regtest: &str = "bchreg:qp2jthhkscelwshts29ravn5r84fs90hx54rh2pc6t";
const m0Tokens: &str = "bitcoincash:zp2jthhkscelwshts29ravn5r84fs90hx5v8kjw6pz";
const m0TestnetTokens: &str = "bchtest:zp2jthhkscelwshts29ravn5r84fs90hx5g4j4vdx7";

#[test]
fn p2pkh_utility_test_vectors() {
    assert_eq!(
        assert_success(decode_private_key_wif(m0Wif, None), None).private_key,
        *m0PrivateKey
    );
    assert_eq!(*m0PrivateKey, *privateKey);
    assert_eq!(*m0PublicKey, *publicKey);
    assert_eq!(hdPublicKey, *M);
}

#[test]
fn private_key_to_p2pkh_locking_bytecode_() {
    assert_eq!(
        private_key_to_p2pkh_locking_bytecode(&privateKey),
        Ok(m0LockingBytecode.clone())
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the private key provided for the \"key\" variable is not a valid Secp256k1 private key.",
        P2pkhUtilityError::privateKeyToP2pkhLockingBytecodeCompilation
    );
    // `t.throws` (default `throwErrors`)
    assert_eq!(private_key_to_p2pkh_locking_bytecode(&[0; 32]), Err(message.clone()));
    // `throwErrors: false`
    assert_eq!(private_key_to_p2pkh_locking_bytecode(&[0; 32]), Err(message.clone()));
    let too_short = [1, 2, 3];
    assert_eq!(private_key_to_p2pkh_locking_bytecode(&too_short), Err(message.clone()));
    assert_eq!(private_key_to_p2pkh_locking_bytecode(&too_short), Err(message.clone()));
    let exceeds_max = hex_to_bin("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    assert_eq!(
        private_key_to_p2pkh_locking_bytecode(&exceeds_max),
        Err(message.clone())
    );
    assert_eq!(private_key_to_p2pkh_locking_bytecode(&exceeds_max), Err(message));
}

#[test]
fn public_key_to_p2pkh_locking_bytecode_() {
    assert_eq!(
        public_key_to_p2pkh_locking_bytecode(&publicKey),
        Ok(m0LockingBytecode.clone())
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the public key provided for \"key.public_key\" is not a valid Secp256k1 public key.",
        P2pkhUtilityError::publicKeyToP2pkhLockingBytecodeCompilation
    );
    assert_eq!(public_key_to_p2pkh_locking_bytecode(&[1]), Err(message.clone()));
    assert_eq!(public_key_to_p2pkh_locking_bytecode(&[0; 33]), Err(message.clone()));
    // `t.throws`
    assert_eq!(public_key_to_p2pkh_locking_bytecode(&[0; 33]), Err(message.clone()));
    assert_eq!(
        public_key_to_p2pkh_locking_bytecode(&hex_to_bin(
            "020000000000000000000000000000000000000000000000000000000000000007"
        )),
        Err(message.clone())
    );
    // `t.throws`
    assert_eq!(
        public_key_to_p2pkh_locking_bytecode(&hex_to_bin(
            "020000000000000000000000000000000000000000000000000000000000000007"
        )),
        Err(message.clone())
    );
    // `t.throws` (`throwErrors: true`)
    assert_eq!(
        public_key_to_p2pkh_locking_bytecode(&hex_to_bin(
            "020000000000000000000000000000000000000000000000000000000000000007"
        )),
        Err(message)
    );
}

#[test]
fn hd_private_key_to_p2pkh_locking_bytecode_() {
    assert_eq!(
        hd_private_key_to_p2pkh_locking_bytecode(0.0, hdPrivateKey, None),
        Ok(m0LockingBytecode.clone())
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the HD private key provided for the \"owner\" entity is not a valid HD private key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 0.",
        P2pkhUtilityError::hdPrivateKeyToP2pkhLockingBytecodeCompilation
    );
    assert_eq!(
        hd_private_key_to_p2pkh_locking_bytecode(0.0, "", None),
        Err(message.clone())
    );
    assert_eq!(
        hd_private_key_to_p2pkh_locking_bytecode(
            0.0,
            "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
            None
        ),
        Err(format!(
            "{} [0, 0] Invalid compilation data detected: the HD private key provided for the \"owner\" entity is not a valid HD private key. HD key decoding error: key encodes a depth of zero with a non-zero parent fingerprint. Parent fingerprint: 1,1,1,1.",
            P2pkhUtilityError::hdPrivateKeyToP2pkhLockingBytecodeCompilation
        ))
    );
    assert_eq!(
        hd_private_key_to_p2pkh_locking_bytecode(-1.0, hdPrivateKey, None),
        Err(format!("{} [2, 16] Could not generate \"key.public_key\" - the path \"-1\" could not be derived for entity \"owner\": HD node derivation error: invalid relative derivation path; path must contain only positive child index numbers, separated by forward slashes (\"/\"), with zero or one apostrophe (\"'\") after each child index number. Invalid path: \"-1\".", P2pkhUtilityError::hdPrivateKeyToP2pkhLockingBytecodeCompilation))
    );
    assert_eq!(
        hd_private_key_to_p2pkh_locking_bytecode(1.1, hdPrivateKey, None),
        Err(format!("{} [2, 16] Could not generate \"key.public_key\" - the path \"1.1\" could not be derived for entity \"owner\": HD node derivation error: invalid relative derivation path; path must contain only positive child index numbers, separated by forward slashes (\"/\"), with zero or one apostrophe (\"'\") after each child index number. Invalid path: \"1.1\".", P2pkhUtilityError::hdPrivateKeyToP2pkhLockingBytecodeCompilation))
    );
    // `t.throws`
    assert_eq!(
        hd_private_key_to_p2pkh_locking_bytecode(0.0, "", None),
        Err(message.clone())
    );
    // `t.throws` (`throwErrors: true`)
    assert_eq!(hd_private_key_to_p2pkh_locking_bytecode(0.0, "", None), Err(message));
}

#[test]
fn hd_public_key_to_p2pkh_locking_bytecode_() {
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(0.0, hdPublicKey, None, None),
        Ok(m0LockingBytecode.clone())
    );
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(0.0, hdPublicKey, None, Some("i")),
        Ok(m0LockingBytecode.clone())
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the HD public key provided for the \"owner\" entity is not a valid HD public key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 0.",
        P2pkhUtilityError::hdPublicKeyToP2pkhLockingBytecodeCompilation
    );
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(0.0, "", None, None),
        Err(message.clone())
    );
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(
            0.0,
            "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
            None,
            None
        ),
        Err(format!(
            "{} [0, 0] Invalid compilation data detected: the HD public key provided for the \"owner\" entity is not a valid HD public key. HD key decoding error: key encodes a depth of zero with a non-zero parent fingerprint. Parent fingerprint: 1,1,1,1.",
            P2pkhUtilityError::hdPublicKeyToP2pkhLockingBytecodeCompilation
        ))
    );
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(
            0.0,
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
            None,
            None
        ),
        Err(format!(
            "{} [0, 0] Invalid compilation data detected: the HD public key provided for the \"owner\" entity is not a valid HD public key. HD key decoding error: the public key for this HD public node is not a valid Secp256k1 public key. Invalid public key: 020000000000000000000000000000000000000000000000000000000000000007.",
            P2pkhUtilityError::hdPublicKeyToP2pkhLockingBytecodeCompilation
        ))
    );
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(-1.0, hdPublicKey, None, None),
        Err(format!("{} [2, 16] Could not generate \"key.public_key\" - the path \"-1\" could not be derived for entity \"owner\": HD node derivation error: invalid relative derivation path; path must contain only positive child index numbers, separated by forward slashes (\"/\"), with zero or one apostrophe (\"'\") after each child index number. Invalid path: \"-1\".", P2pkhUtilityError::hdPublicKeyToP2pkhLockingBytecodeCompilation))
    );
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(1.1, hdPublicKey, None, None),
        Err(format!("{} [2, 16] Could not generate \"key.public_key\" - the path \"1.1\" could not be derived for entity \"owner\": HD node derivation error: invalid relative derivation path; path must contain only positive child index numbers, separated by forward slashes (\"/\"), with zero or one apostrophe (\"'\") after each child index number. Invalid path: \"1.1\".", P2pkhUtilityError::hdPublicKeyToP2pkhLockingBytecodeCompilation))
    );
    // `t.throws`
    assert_eq!(
        hd_public_key_to_p2pkh_locking_bytecode(0.0, "", None, None),
        Err(message.clone())
    );
    // `t.throws` (`throwErrors: true`)
    assert_eq!(hd_public_key_to_p2pkh_locking_bytecode(0.0, "", None, None), Err(message));
}

#[test]
fn private_key_to_p2pkh_cash_address_() {
    assert_eq!(
        private_key_to_p2pkh_cash_address(&privateKey, None, None)
            .unwrap()
            .address,
        m0Mainnet
    );
    assert_eq!(
        private_key_to_p2pkh_cash_address(&privateKey, Some("bchtest"), None)
            .unwrap()
            .address,
        m0Testnet
    );
    assert_eq!(
        private_key_to_p2pkh_cash_address(&privateKey, Some("bchreg"), None)
            .unwrap()
            .address,
        m0Regtest
    );
    assert_eq!(
        private_key_to_p2pkh_cash_address(&privateKey, None, Some(true))
            .unwrap()
            .address,
        m0Tokens
    );
    assert_eq!(
        private_key_to_p2pkh_cash_address(&privateKey, Some("bchtest"), Some(true))
            .unwrap()
            .address,
        m0TestnetTokens
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the private key provided for the \"key\" variable is not a valid Secp256k1 private key.",
        P2pkhUtilityError::privateKeyToP2pkhLockingBytecodeCompilation
    );
    assert_eq!(
        private_key_to_p2pkh_cash_address(&hex_to_bin(""), None, None),
        Err(message.clone())
    );
    // `t.throws`
    assert_eq!(
        private_key_to_p2pkh_cash_address(&hex_to_bin(""), None, None),
        Err(message.clone())
    );
    // `t.throws` (`throwErrors: true`)
    assert_eq!(
        private_key_to_p2pkh_cash_address(&hex_to_bin(""), None, None),
        Err(message)
    );
}

#[test]
fn public_key_to_p2pkh_cash_address_() {
    assert_eq!(
        public_key_to_p2pkh_cash_address(&publicKey, None, None)
            .unwrap()
            .address,
        m0Mainnet
    );
    assert_eq!(
        public_key_to_p2pkh_cash_address(&publicKey, Some("bchtest"), None)
            .unwrap()
            .address,
        m0Testnet
    );
    assert_eq!(
        public_key_to_p2pkh_cash_address(&publicKey, Some("bchreg"), None)
            .unwrap()
            .address,
        m0Regtest
    );
    assert_eq!(
        public_key_to_p2pkh_cash_address(&publicKey, None, Some(true))
            .unwrap()
            .address,
        m0Tokens
    );
    assert_eq!(
        public_key_to_p2pkh_cash_address(&publicKey, Some("bchtest"), Some(true))
            .unwrap()
            .address,
        m0TestnetTokens
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the public key provided for \"key.public_key\" is not a valid Secp256k1 public key.",
        P2pkhUtilityError::publicKeyToP2pkhLockingBytecodeCompilation
    );
    assert_eq!(
        public_key_to_p2pkh_cash_address(&hex_to_bin(""), None, None),
        Err(message.clone())
    );
    // `t.throws`
    assert_eq!(
        public_key_to_p2pkh_cash_address(&hex_to_bin(""), None, None),
        Err(message.clone())
    );
    // `t.throws` (`throwErrors: true`)
    assert_eq!(
        public_key_to_p2pkh_cash_address(&hex_to_bin(""), None, None),
        Err(message)
    );
}

#[test]
fn hd_private_key_to_p2pkh_cash_address_() {
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, hdPrivateKey, None, None, None)
            .unwrap()
            .address,
        m0Mainnet
    );
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, hdPrivateKey, Some("bchtest"), None, None)
            .unwrap()
            .address,
        m0Testnet
    );
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, hdPrivateKey, Some("bchreg"), None, None)
            .unwrap()
            .address,
        m0Regtest
    );
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, hdPrivateKey, None, None, Some(true))
            .unwrap()
            .address,
        m0Tokens
    );
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, hdPrivateKey, Some("bchtest"), None, Some(true))
            .unwrap()
            .address,
        m0TestnetTokens
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the HD private key provided for the \"owner\" entity is not a valid HD private key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 0.",
        P2pkhUtilityError::hdPrivateKeyToP2pkhLockingBytecodeCompilation
    );
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, "", None, None, None),
        Err(message.clone())
    );
    // `t.throws`
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, "", None, None, None),
        Err(message.clone())
    );
    // `t.throws` (`throwErrors: true`)
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(0.0, "", None, None, None),
        Err(message)
    );
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(2147483648.0, &hdPrivateKey[1..], None, None, None),
        Err("P2PKH utility error: could not derive P2PKH locking bytecode from the provided HD private key. [0, 0] Invalid compilation data detected: the HD private key provided for the \"owner\" entity is not a valid HD private key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 81.".to_string())
    );
    assert_eq!(
        hd_private_key_to_p2pkh_cash_address(4294967296.0, hdPrivateKey, None, None, None),
        Err("P2PKH utility error: could not derive P2PKH locking bytecode from the provided HD private key. [2, 16] Could not generate \"key.public_key\" - the path \"4294967296\" could not be derived for entity \"owner\": HD node derivation error: child index exceeds maximum (4294967295). Child index: 4294967296.".to_string())
    );
}

#[test]
fn hd_public_key_to_p2pkh_cash_address_() {
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, hdPublicKey, None, None, None, None)
            .unwrap()
            .address,
        m0Mainnet
    );
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, hdPublicKey, None, Some("bchtest"), None, None)
            .unwrap()
            .address,
        m0Testnet
    );
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, hdPublicKey, None, Some("bchreg"), None, None)
            .unwrap()
            .address,
        m0Regtest
    );
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, hdPublicKey, None, None, None, Some(true))
            .unwrap()
            .address,
        m0Tokens
    );
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, hdPublicKey, None, Some("bchtest"), None, Some(true))
            .unwrap()
            .address,
        m0TestnetTokens
    );
    let message = format!(
        "{} [0, 0] Invalid compilation data detected: the HD public key provided for the \"owner\" entity is not a valid HD public key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 0.",
        P2pkhUtilityError::hdPublicKeyToP2pkhLockingBytecodeCompilation
    );
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, "", None, None, None, None),
        Err(message.clone())
    );
    // `t.throws`
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, "", None, None, None, None),
        Err(message.clone())
    );
    // `t.throws` (`throwErrors: true`)
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(0.0, "", None, None, None, None),
        Err(message)
    );
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(2147483648.0, &hdPublicKey[1..], None, None, None, None),
        Err("P2PKH utility error: could not derive P2PKH locking bytecode from the provided HD public key. [0, 0] Invalid compilation data detected: the HD public key provided for the \"owner\" entity is not a valid HD public key. HD key decoding error: length is incorrect (must encode 82 bytes). Length: 81.".to_string())
    );
    assert_eq!(
        hd_public_key_to_p2pkh_cash_address(2147483648.0, hdPublicKey, None, None, None, None),
        Err("P2PKH utility error: could not derive P2PKH locking bytecode from the provided HD public key. [2, 16] Could not generate \"key.public_key\" - the path \"2147483648\" could not be derived for entity \"owner\": HD node derivation error: derivation for hardened child indexes (indexes greater than or equal to 2147483648) requires an HD private node. Requested index: 2147483648.".to_string())
    );
}
