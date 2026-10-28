//! Port of `address/base58-address.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use std::sync::LazyLock;

use libauth::runtime::json::{parse_json, Json};
use libauth::{
    decode_base58_address, decode_base58_address_format, decode_private_key_wif,
    encode_base58_address, encode_base58_address_format, hex_to_bin,
    locking_bytecode_to_base58_address, sha256, Base58AddressEncodingResult, Base58AddressError,
    Base58AddressFormatVersion, Base58AddressNetwork, BaseConversionError, DecodedBase58Address,
    DecodedBase58AddressFormat, DecodedPrivateKeyWif, WalletImportFormatType,
};

/// `./fixtures/key_io_invalid.json`, filtered: `Object.values(keyIoInvalid).filter((item) =>
/// Array.isArray(item) && item.every((x) => typeof x === 'string'))`
static INVALID_VECTORS: LazyLock<Vec<Vec<String>>> = LazyLock::new(|| {
    let key_io_invalid = parse_json(include_str!("fixtures/key_io_invalid.json")).expect("valid JSON");
    key_io_invalid
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|item| {
            let items = item.as_array()?;
            items
                .iter()
                .map(|x| x.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
        })
        .collect()
});

/// `./fixtures/key_io_valid.json`, filtered: `Object.values(keyIoValid).filter((item) =>
/// item.every((x) => !Array.isArray(x)))`
static VALID_VECTORS: LazyLock<Vec<Vec<Json>>> = LazyLock::new(|| {
    let key_io_valid = parse_json(include_str!("fixtures/key_io_valid.json")).expect("valid JSON");
    key_io_valid
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item.as_array().expect("an array").to_vec())
        .filter(|item| item.iter().all(|x| x.as_array().is_none()))
        .collect()
});

#[test]
fn encode_base58_address_format_() {
    let payload = hex_to_bin("65a16059864a2fdbc7c99a4723a8395bc6f188eb");
    assert_eq!(
        encode_base58_address_format(Base58AddressFormatVersion::P2pkh.to_u8(), &payload, None),
        // cspell: disable-next-line
        "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i"
    );
    assert_eq!(
        encode_base58_address_format(Base58AddressFormatVersion::P2pkh.to_u8(), &payload, Some(&sha256)),
        // cspell: disable-next-line
        "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i"
    );
}

#[test]
fn encode_base58_address_() {
    let payload = hex_to_bin("76a04053bda0a88bda5177b86a15c3b29f559873");
    // `'p2pkh'`, `'p2pkhTestnet'`, ... are `Base58AddressFormatVersion` variants in Rust.
    assert_eq!(
        encode_base58_address(Base58AddressFormatVersion::P2pkh, &payload, Some(&sha256)),
        // cspell: disable-next-line
        "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
    );
    assert_eq!(
        encode_base58_address(Base58AddressFormatVersion::P2pkhTestnet, &payload, Some(&sha256)),
        // cspell: disable-next-line
        "mrLC19Je2BuWQDkWSTriGYPyQJXKkkBmCx"
    );
    assert_eq!(
        encode_base58_address(Base58AddressFormatVersion::P2pkhCopayBch, &payload, None),
        // cspell: disable-next-line
        "CTH8H8Zj6DSnXFBKQeDG28ogAS92iS16Bp"
    );
    assert_eq!(
        encode_base58_address(Base58AddressFormatVersion::P2sh20, &payload, Some(&sha256)),
        // cspell: disable-next-line
        "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
    );
    assert_eq!(
        encode_base58_address(Base58AddressFormatVersion::P2sh20Testnet, &payload, None),
        // cspell: disable-next-line
        "2N44ThNe8NXHyv4bsX8AoVCXquBRW94Ls7W"
    );
    assert_eq!(
        encode_base58_address(Base58AddressFormatVersion::P2sh20CopayBch, &payload, Some(&sha256)),
        // cspell: disable-next-line
        "HHLN6S9BcP1JLSrMhgD5qe57iVEMFMLCBT"
    );
}

#[test]
fn decode_base58_address_format_() {
    let payload = hex_to_bin("65a16059864a2fdbc7c99a4723a8395bc6f188eb");
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address_format("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", None),
        Ok(DecodedBase58AddressFormat {
            payload: payload.clone(),
            version: Base58AddressFormatVersion::P2pkh.to_u8(),
        })
    );
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address_format("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", Some(&sha256)),
        Ok(DecodedBase58AddressFormat {
            payload,
            version: Base58AddressFormatVersion::P2pkh.to_u8(),
        })
    );
}

#[test]
fn decode_base58_address_() {
    let payload = hex_to_bin("65a16059864a2fdbc7c99a4723a8395bc6f188eb");
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", None),
        Ok(DecodedBase58Address {
            payload: payload.clone(),
            version: Base58AddressFormatVersion::P2pkh,
        })
    );
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", Some(&sha256)),
        Ok(DecodedBase58Address {
            payload,
            version: Base58AddressFormatVersion::P2pkh,
        })
    );
}

const MAX_UINT8_NUMBER: i64 = 255;
const MAX_BIN_LENGTH: usize = 100;

#[test]
fn fast_check_encode_base58_address_decode_base58_address() {
    let arbitrary = {
        let version = fc::integer(Some(0), Some(MAX_UINT8_NUMBER));
        let payload = fc::uint8_array(Some(0), Some(MAX_BIN_LENGTH));
        move |random: &mut fc::Random| (version(random), payload(random))
    };
    fc::test_prop(arbitrary, |(version, payload)| {
        let version = *version as u8;
        let address = encode_base58_address_format(version, payload, None);
        let decoded = match decode_base58_address_format(&address, None) {
            Err(decoded) => panic!("{decoded}"),
            Ok(decoded) => decoded,
        };
        assert_eq!(
            decoded,
            DecodedBase58AddressFormat {
                payload: payload.clone(),
                version,
            }
        );
    });
}

#[test]
fn decode_base58_address_format_errors() {
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address_format("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62a", None),
        Err(Base58AddressError::InvalidChecksum.as_str().to_string())
    );
    assert_eq!(
        decode_base58_address_format("1234", None),
        Err(Base58AddressError::TooShort.as_str().to_string())
    );
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address_format("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62I", None),
        Err(format!(
            "{} {} Unknown character: \"I\".",
            Base58AddressError::UnknownCharacter.as_str(),
            BaseConversionError::unknownCharacter
        ))
    );
}

#[test]
fn decode_base58_address_errors() {
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address("6PfDNQxJdsBx7K4r9kMrRBZSa2NZKVNUZn", None),
        Err(Base58AddressError::UnknownAddressVersion.as_str().to_string())
    );
    assert_eq!(
        // cspell: disable-next-line
        decode_base58_address("2DqXtydYdu9pq6uXcy3Tbw3pUscCiPC6F", None),
        // Base58AddressError.incorrectLength
        Err(Base58AddressError::UnknownAddressVersion.as_str().to_string())
    );
}

#[test]
fn base58_address_invalid_vectors() {
    for vector in INVALID_VECTORS.iter() {
        let invalid = &vector[0];
        let result = decode_base58_address(invalid, None);
        let has_error = result.is_err();
        if !has_error {
            /*
             * cspell: disable-next-line
             * HPhFUhUAh8ZQQisH8QQWafAxtQYju3SFTX
             */
            assert_eq!(
                result,
                Ok(DecodedBase58Address {
                    payload: hex_to_bin("bc6437e3089918c9cb7e3d3ddd7ca83969b1e0bc"),
                    version: Base58AddressFormatVersion::P2sh20CopayBch,
                })
            );
            continue;
        }
        assert!(has_error);
    }
}

#[test]
fn base58_address_valid_vectors_from_c_implementation_includes_wif_vectors() {
    for vectors in VALID_VECTORS.iter() {
        let base58_address = vectors[0].as_str().expect("a string");
        let data = vectors[1].as_str().expect("a string");
        let meta = &vectors[2];
        let chain = meta.get("chain").and_then(Json::as_str).expect("a chain");
        let is_privkey = meta.get("isPrivkey").and_then(Json::as_bool).expect("isPrivkey");
        let is_compressed = meta.get("isCompressed").and_then(Json::as_bool);

        let testnet = chain != "main";
        if is_privkey {
            let wif_key = base58_address;
            let compressed = is_compressed.unwrap_or(false);
            let private_key = hex_to_bin(data);
            let r#type = if testnet {
                if compressed {
                    WalletImportFormatType::Testnet
                } else {
                    WalletImportFormatType::TestnetUncompressed
                }
            } else if compressed {
                WalletImportFormatType::Mainnet
            } else {
                WalletImportFormatType::MainnetUncompressed
            };
            assert_eq!(
                decode_private_key_wif(wif_key, None),
                Ok(DecodedPrivateKeyWif {
                    private_key,
                    key_type: r#type,
                })
            );
        } else {
            let locking_bytecode = data;
            assert_eq!(
                locking_bytecode_to_base58_address(
                    &hex_to_bin(locking_bytecode),
                    Some(if testnet {
                        Base58AddressNetwork::Testnet
                    } else {
                        Base58AddressNetwork::Mainnet
                    }),
                    Some(&sha256)
                ),
                Base58AddressEncodingResult::Address(base58_address.to_string())
            );
        }
    }
}
