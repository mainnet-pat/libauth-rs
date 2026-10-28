//! Port of `address/locking-bytecode.spec.ts`.
//!
//! libauth's `AddressContents` (`{ payload, type }`) is the Rust enum
//! `AddressContents` (`Known { type, payload }` or `Unknown { payload }`);
//! `type: 'P2PK'` and `type: LockingBytecodeType.p2pk` are both
//! `LockingBytecodeType::P2pk`.

use libauth::{
    address_contents_to_locking_bytecode, base58_address_to_locking_bytecode,
    cash_address_to_locking_bytecode, hex_to_bin, locking_bytecode_to_address_contents,
    locking_bytecode_to_base58_address, locking_bytecode_to_cash_address, sha256, AddressContents,
    Base58AddressEncodingResult, Base58AddressError, Base58AddressFormatVersion, Base58AddressNetwork,
    BaseConversionError, CashAddressDecodingError, CashAddressEncodingError, CashAddressNetworkPrefix,
    CashAddressResult, DecodedBase58AddressLockingBytecode, DecodedCashAddressLockingBytecode,
    LockingBytecodeType,
};

fn known(payload: Vec<u8>, r#type: LockingBytecodeType) -> AddressContents {
    AddressContents::Known { r#type, payload }
}

fn address(address: &str) -> Result<CashAddressResult, String> {
    Ok(CashAddressResult {
        address: address.to_string(),
    })
}

#[test]
fn locking_bytecode_address_contents_p2pk() {
    let genesis_coinbase = hex_to_bin(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );
    let genesis_public_key = hex_to_bin(
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
    );

    assert_eq!(
        locking_bytecode_to_address_contents(&genesis_coinbase),
        known(genesis_public_key.clone(), LockingBytecodeType::P2pk)
    );

    // `type: 'P2PK'`
    assert_eq!(
        address_contents_to_locking_bytecode(&known(genesis_public_key.clone(), LockingBytecodeType::P2pk)),
        Ok(genesis_coinbase.clone())
    );
    assert_eq!(
        address_contents_to_locking_bytecode(&known(genesis_public_key, LockingBytecodeType::P2pk)),
        Ok(genesis_coinbase)
    );

    let genesis_coinbase_compressed =
        hex_to_bin("2103678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6ac");
    let compressed_public_key =
        hex_to_bin("03678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6");
    assert_eq!(
        locking_bytecode_to_address_contents(&genesis_coinbase_compressed),
        known(compressed_public_key.clone(), LockingBytecodeType::P2pk)
    );

    assert_eq!(
        address_contents_to_locking_bytecode(&known(compressed_public_key, LockingBytecodeType::P2pk)),
        Ok(genesis_coinbase_compressed)
    );
}

#[test]
fn locking_bytecode_address_contents_p2pkh() {
    let p2pkh = hex_to_bin("76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac");
    let expected_payload = hex_to_bin("65a16059864a2fdbc7c99a4723a8395bc6f188eb");
    assert_eq!(
        locking_bytecode_to_address_contents(&p2pkh),
        known(expected_payload.clone(), LockingBytecodeType::P2pkh)
    );
    // `type: 'P2PKH'`
    assert_eq!(
        address_contents_to_locking_bytecode(&known(expected_payload.clone(), LockingBytecodeType::P2pkh)),
        Ok(p2pkh.clone())
    );
    assert_eq!(
        address_contents_to_locking_bytecode(&known(expected_payload, LockingBytecodeType::P2pkh)),
        Ok(p2pkh)
    );
}

#[test]
fn locking_bytecode_address_contents_p2sh20() {
    let p2sh20 = hex_to_bin("a91474f209f6ea907e2ea48f74fae05782ae8a66525787");
    let expected_payload = hex_to_bin("74f209f6ea907e2ea48f74fae05782ae8a665257");
    assert_eq!(
        locking_bytecode_to_address_contents(&p2sh20),
        known(expected_payload.clone(), LockingBytecodeType::P2sh20)
    );
    // `type: 'P2SH20'`
    assert_eq!(
        address_contents_to_locking_bytecode(&known(expected_payload.clone(), LockingBytecodeType::P2sh20)),
        Ok(p2sh20.clone())
    );
    assert_eq!(
        address_contents_to_locking_bytecode(&known(expected_payload, LockingBytecodeType::P2sh20)),
        Ok(p2sh20)
    );
}

#[test]
fn locking_bytecode_address_contents_unknown() {
    let simple_math = hex_to_bin("52935387");
    assert_eq!(
        locking_bytecode_to_address_contents(&simple_math),
        AddressContents::Unknown {
            payload: simple_math.clone()
        }
    );
    // t.throws(() => addressContentsToLockingBytecode({ payload: simpleMath, type: 'unknown' as 'P2PK' }),
    //   { message: 'Unrecognized addressContents type: unknown' });
    assert_eq!(
        address_contents_to_locking_bytecode(&AddressContents::Unknown {
            payload: simple_math.clone()
        }),
        Err("Unrecognized addressContents type: unknown".to_string())
    );

    let almost_p2pk = hex_to_bin("0100ac");
    let almost_p2pkh = hex_to_bin("76a9010088ac");
    let almost_p2sh20 = hex_to_bin("a9010087");
    let almost_p2sh32 = hex_to_bin("aa010087");

    assert_eq!(
        locking_bytecode_to_address_contents(&almost_p2pk),
        AddressContents::Unknown {
            payload: almost_p2pk.clone()
        }
    );

    assert_eq!(
        locking_bytecode_to_address_contents(&almost_p2pkh),
        AddressContents::Unknown {
            payload: almost_p2pkh.clone()
        }
    );

    assert_eq!(
        locking_bytecode_to_address_contents(&almost_p2sh20),
        AddressContents::Unknown {
            payload: almost_p2sh20.clone()
        }
    );

    assert_eq!(
        locking_bytecode_to_address_contents(&almost_p2sh32),
        AddressContents::Unknown {
            payload: almost_p2sh32.clone()
        }
    );
}

#[test]
fn locking_bytecode_to_address_contents_improperly_sized_scripts_return_address_type_unknown() {
    let almost_p2pk = hex_to_bin("0100ac");
    let almost_p2pkh = hex_to_bin("76a9010088ac");
    let almost_p2sh20 = hex_to_bin("a9010087");

    assert_eq!(
        locking_bytecode_to_address_contents(&almost_p2pk),
        AddressContents::Unknown {
            payload: almost_p2pk.clone()
        }
    );

    assert_eq!(
        locking_bytecode_to_address_contents(&almost_p2pkh),
        AddressContents::Unknown {
            payload: almost_p2pkh.clone()
        }
    );

    assert_eq!(
        locking_bytecode_to_address_contents(&almost_p2sh20),
        AddressContents::Unknown {
            payload: almost_p2sh20.clone()
        }
    );
}

/// The `cashVectors` macro.
fn cash_vectors(address_: &str, bytecode: &str) {
    assert_eq!(
        cash_address_to_locking_bytecode(address_),
        Ok(DecodedCashAddressLockingBytecode {
            bytecode: hex_to_bin(bytecode),
            prefix: "bitcoincash".to_string(),
            token_support: false,
        }),
        "cashAddressToLockingBytecode"
    );
    assert_eq!(
        locking_bytecode_to_cash_address(Some("bitcoincash"), &hex_to_bin(bytecode), None),
        address(address_),
        "lockingBytecodeToCashAddress"
    );
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_bitcoincash_qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a() {
    cash_vectors(
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
        "76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac",
    );
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_bitcoincash_qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy() {
    cash_vectors(
        "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
        "76a914cb481232299cd5743151ac4b2d63ae198e7bb0a988ac",
    );
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_bitcoincash_qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r() {
    cash_vectors(
        "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
        "76a914011f28e473c95f4013d7d53ec5fbc3b42df8ed1088ac",
    );
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_bitcoincash_ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq() {
    cash_vectors(
        "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
        "a91476a04053bda0a88bda5177b86a15c3b29f55987387",
    );
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_bitcoincash_pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e() {
    cash_vectors(
        "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
        "a914cb481232299cd5743151ac4b2d63ae198e7bb0a987",
    );
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_bitcoincash_pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37() {
    cash_vectors(
        "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37",
        "a914011f28e473c95f4013d7d53ec5fbc3b42df8ed1087",
    );
}

#[test]
fn locking_bytecode_to_cash_address_p2pk() {
    let genesis_coinbase = hex_to_bin(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );

    assert_eq!(
        locking_bytecode_to_cash_address(Some("bitcoincash"), &genesis_coinbase, None),
        Err(CashAddressEncodingError::NoTypeBitsValueStandardizedForP2pk.as_str().to_string())
    );

    let genesis_coinbase_compressed =
        hex_to_bin("2103678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6ac");
    assert_eq!(
        locking_bytecode_to_cash_address(
            Some(CashAddressNetworkPrefix::Mainnet.as_str()),
            &genesis_coinbase_compressed,
            None
        ),
        Err(CashAddressEncodingError::NoTypeBitsValueStandardizedForP2pk.as_str().to_string())
    );
}

/// The body shared by the P2PKH, P2SH20, and P2SH32 tests.
fn round_trip(bytecode: &[u8], address_: &str, token_address: &str) {
    assert_eq!(
        locking_bytecode_to_cash_address(Some("bitcoincash"), bytecode, None),
        address(address_)
    );
    assert_eq!(
        locking_bytecode_to_cash_address(Some("bitcoincash"), bytecode, Some(true)),
        address(token_address)
    );
    assert_eq!(
        cash_address_to_locking_bytecode(address_),
        Ok(DecodedCashAddressLockingBytecode {
            bytecode: bytecode.to_vec(),
            prefix: "bitcoincash".to_string(),
            token_support: false,
        })
    );
    assert_eq!(
        cash_address_to_locking_bytecode(token_address),
        Ok(DecodedCashAddressLockingBytecode {
            bytecode: bytecode.to_vec(),
            prefix: "bitcoincash".to_string(),
            token_support: true,
        })
    );
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_p2pkh() {
    let p2pkh = hex_to_bin("76a914fc916f213a3d7f1369313d5fa30f6168f9446a2d88ac");
    let address_ = "bitcoincash:qr7fzmep8g7h7ymfxy74lgc0v950j3r2959lhtxxsl";
    let token_address = "bitcoincash:zr7fzmep8g7h7ymfxy74lgc0v950j3r295z4y4gq0v";
    round_trip(&p2pkh, address_, token_address);
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_p2sh20() {
    let p2sh20 = hex_to_bin("a91474f209f6ea907e2ea48f74fae05782ae8a66525787");
    let address_ = "bitcoincash:pp60yz0ka2g8ut4y3a604czhs2hg5ejj2ugn82jfsr";
    let token_address = "bitcoincash:rp60yz0ka2g8ut4y3a604czhs2hg5ejj2u0e55u00s";
    round_trip(&p2sh20, address_, token_address);
}

#[test]
fn cash_address_to_locking_bytecode_locking_bytecode_to_cash_address_p2sh32() {
    let p2sh32 = hex_to_bin("aa20000000000000000000000000000012345678900000000000000000000000000087");
    let address_ = "bitcoincash:pvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqpkp7fqn0";
    let token_address = "bitcoincash:rvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqn9alsp2y";
    round_trip(&p2sh32, address_, token_address);
}

#[test]
fn locking_bytecode_to_cash_address_error() {
    let simple_math = hex_to_bin("52935387");

    assert_eq!(
        locking_bytecode_to_cash_address(Some("bitcoincash"), &simple_math, None),
        Err(CashAddressEncodingError::UnknownLockingBytecodeType.as_str().to_string())
    );
    let genesis_coinbase = hex_to_bin(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );
    assert_eq!(
        locking_bytecode_to_cash_address(Some("bitcoincash"), &genesis_coinbase, None),
        Err(CashAddressEncodingError::NoTypeBitsValueStandardizedForP2pk.as_str().to_string())
    );
}

#[test]
fn cash_address_to_locking_bytecode_error() {
    assert_eq!(
        cash_address_to_locking_bytecode("bad:address"),
        Err(CashAddressDecodingError::InvalidChecksum.as_str().to_string())
    );
    assert_eq!(
        cash_address_to_locking_bytecode("bitcoincash:dp60yz0ka2g8ut4y3a604czhs2hg5ejj2u6xkulaqj"),
        Err(format!(
            "{} Type bit value: 13.",
            CashAddressDecodingError::UnknownAddressType.as_str()
        ))
    );
}

#[test]
fn locking_bytecode_to_base58_address_p2pk() {
    let genesis_coinbase = hex_to_bin(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );
    let genesis_public_key = hex_to_bin(
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
    );

    assert_eq!(
        locking_bytecode_to_base58_address(&genesis_coinbase, Some(Base58AddressNetwork::Mainnet), Some(&*sha256)),
        Base58AddressEncodingResult::Contents(known(genesis_public_key, LockingBytecodeType::P2pk))
    );

    let genesis_coinbase_compressed =
        hex_to_bin("2103678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6ac");
    let compressed_public_key =
        hex_to_bin("03678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6");
    assert_eq!(
        locking_bytecode_to_base58_address(
            &genesis_coinbase_compressed,
            Some(Base58AddressNetwork::Testnet),
            Some(&*sha256)
        ),
        Base58AddressEncodingResult::Contents(known(compressed_public_key, LockingBytecodeType::P2pk))
    );
}

fn base58(address: &str) -> Base58AddressEncodingResult {
    Base58AddressEncodingResult::Address(address.to_string())
}

#[test]
fn base58_address_to_locking_bytecode_locking_bytecode_to_base58_address_p2pkh() {
    let p2pkh = hex_to_bin("76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac");
    // cspell: disable-next-line
    let address = "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu";
    // cspell: disable-next-line
    let address_testnet = "mrLC19Je2BuWQDkWSTriGYPyQJXKkkBmCx";
    // cspell: disable-next-line
    let address_copay = "CTH8H8Zj6DSnXFBKQeDG28ogAS92iS16Bp";
    assert_eq!(
        locking_bytecode_to_base58_address(&p2pkh, Some(Base58AddressNetwork::Mainnet), None),
        base58(address)
    );
    assert_eq!(
        locking_bytecode_to_base58_address(&p2pkh, Some(Base58AddressNetwork::Testnet), Some(&*sha256)),
        base58(address_testnet)
    );
    assert_eq!(
        locking_bytecode_to_base58_address(&p2pkh, Some(Base58AddressNetwork::CopayBch), None),
        base58(address_copay)
    );

    assert_eq!(
        base58_address_to_locking_bytecode(address, None),
        Ok(DecodedBase58AddressLockingBytecode {
            bytecode: p2pkh.clone(),
            version: Base58AddressFormatVersion::P2pkh,
        })
    );
    assert_eq!(
        base58_address_to_locking_bytecode(address_testnet, None),
        Ok(DecodedBase58AddressLockingBytecode {
            bytecode: p2pkh.clone(),
            version: Base58AddressFormatVersion::P2pkhTestnet,
        })
    );
    assert_eq!(
        base58_address_to_locking_bytecode(address_copay, Some(&*sha256)),
        Ok(DecodedBase58AddressLockingBytecode {
            bytecode: p2pkh,
            version: Base58AddressFormatVersion::P2pkhCopayBch,
        })
    );
}

#[test]
fn base58_address_to_locking_bytecode_locking_bytecode_to_base58_address_p2sh20() {
    let p2sh20 = hex_to_bin("a91476a04053bda0a88bda5177b86a15c3b29f55987387");
    // cspell: disable-next-line
    let address = "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC";
    // cspell: disable-next-line
    let address_testnet = "2N44ThNe8NXHyv4bsX8AoVCXquBRW94Ls7W";
    // cspell: disable-next-line
    let address_copay = "HHLN6S9BcP1JLSrMhgD5qe57iVEMFMLCBT";
    assert_eq!(
        locking_bytecode_to_base58_address(&p2sh20, Some(Base58AddressNetwork::Mainnet), None),
        base58(address)
    );
    assert_eq!(
        locking_bytecode_to_base58_address(&p2sh20, Some(Base58AddressNetwork::Testnet), Some(&*sha256)),
        base58(address_testnet)
    );
    assert_eq!(
        locking_bytecode_to_base58_address(&p2sh20, Some(Base58AddressNetwork::CopayBch), None),
        base58(address_copay)
    );

    assert_eq!(
        base58_address_to_locking_bytecode(address, None),
        Ok(DecodedBase58AddressLockingBytecode {
            bytecode: p2sh20.clone(),
            version: Base58AddressFormatVersion::P2sh20,
        })
    );
    assert_eq!(
        base58_address_to_locking_bytecode(address_testnet, None),
        Ok(DecodedBase58AddressLockingBytecode {
            bytecode: p2sh20.clone(),
            version: Base58AddressFormatVersion::P2sh20Testnet,
        })
    );
    assert_eq!(
        base58_address_to_locking_bytecode(address_copay, Some(&*sha256)),
        Ok(DecodedBase58AddressLockingBytecode {
            bytecode: p2sh20,
            version: Base58AddressFormatVersion::P2sh20CopayBch,
        })
    );
}

#[test]
fn base58_address_to_locking_bytecode_error() {
    assert_eq!(
        base58_address_to_locking_bytecode("bad:address", None),
        Err(format!(
            "{} {} Unknown character: \":\".",
            Base58AddressError::UnknownCharacter.as_str(),
            BaseConversionError::unknownCharacter
        ))
    );
}
