//! Port of `key/wallet-import-format.spec.ts`.

use libauth::{
    decode_private_key_wif, encode_private_key_wif, hex_to_bin, sha256 as internal_sha256,
    Base58AddressError, BaseConversionError, DecodedPrivateKeyWif, WalletImportFormatType,
};

#[test]
fn decode_private_key_wif_pass_through_errors() {
    assert_eq!(
        decode_private_key_wif("not a key", None),
        Err(format!(
            "{} {} Unknown character: \" \".",
            Base58AddressError::UnknownCharacter.as_str(),
            BaseConversionError::unknownCharacter
        ))
    );
}

/// The `wifVectors` macro.
fn wif_vectors(r#type: WalletImportFormatType, wif: &str, key: &str) {
    assert_eq!(encode_private_key_wif(&hex_to_bin(key), r#type, None), wif);
    assert_eq!(
        decode_private_key_wif(wif, None),
        Ok(DecodedPrivateKeyWif {
            private_key: hex_to_bin(key),
            key_type: r#type,
        })
    );
    assert_eq!(
        encode_private_key_wif(&hex_to_bin(key), r#type, Some(&internal_sha256)),
        wif
    );
    assert_eq!(
        decode_private_key_wif(wif, Some(&internal_sha256)),
        Ok(DecodedPrivateKeyWif {
            private_key: hex_to_bin(key),
            key_type: r#type,
        })
    );
}

#[test]
fn encode_private_key_wif_decode_private_key_wif_mainnet_l1rrrn() {
    wif_vectors(
        WalletImportFormatType::Mainnet,
        "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi",
        "7d998b45c219a1e38e99e7cbd312ef67f77a455a9b50c730c27f02c6f730dfb4",
    );
}

#[test]
fn encode_private_key_wif_decode_private_key_wif_mainnet_kwv9ka() {
    wif_vectors(
        WalletImportFormatType::Mainnet,
        "KwV9KAfwbwt51veZWNscRTeZs9CKpojyu1MsPnaKTF5kz69H1UN2",
        "07f0803fc5399e773555ab1e8939907e9badacc17ca129e67a2f5f2ff84351dd",
    );
}

#[test]
fn encode_private_key_wif_decode_private_key_wif_testnet_ctpb4y() {
    wif_vectors(
        WalletImportFormatType::Testnet,
        "cTpB4YiyKiBcPxnefsDpbnDxFDffjqJob8wGCEDXxgQ7zQoMXJdH",
        "b9f4892c9e8282028fea1d2667c4dc5213564d41fc5783896a0d843fc15089f3",
    );
}

#[test]
fn encode_private_key_wif_decode_private_key_wif_mainnet_uncompressed_5kd3nb() {
    wif_vectors(
        WalletImportFormatType::MainnetUncompressed,
        "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr",
        "eddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19",
    );
}

#[test]
fn encode_private_key_wif_decode_private_key_wif_testnet_uncompressed_9213qj() {
    wif_vectors(
        WalletImportFormatType::TestnetUncompressed,
        "9213qJab2HNEpMpYNBa7wHGFKKbkDn24jpANDs2huN3yi4J11ko",
        "36cb93b9ab1bdabf7fb9f2c04f1b9cc879933530ae7842398eef5a63a56800c2",
    );
}
