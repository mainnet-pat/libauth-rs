//! Port of `address/cash-address.spec.ts`.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use libauth::runtime::json::{parse_json, Json};
use libauth::{
    attempt_cash_address_format_error_correction, decode_base58_address_format,
    decode_cash_address, decode_cash_address_format, decode_cash_address_format_without_prefix,
    decode_cash_address_non_standard, decode_cash_address_version_byte,
    encode_cash_address, encode_cash_address_format, encode_cash_address_non_standard,
    encode_cash_address_version_byte, hex_to_bin, mask_cash_address_prefix, split_every,
    CashAddressDecodingError, CashAddressEncodingError, CashAddressFormatCorrection,
    CashAddressFormatCorrectionError, CashAddressFormatEncodingError, CashAddressNetworkPrefix,
    CashAddressResult, CashAddressType, CashAddressTypeBits, CashAddressVersionByte,
    CashAddressVersionByteDecodingError, CashAddressVersionByteInfo, DecodedCashAddress,
    DecodedCashAddressFormat, DecodedCashAddressNonStandard,
};

/// `const lowercaseLetter = () => fc.integer({ max: 122, min: 97 }).map((i) => String.fromCharCode(i));`
fn lowercase_letter() -> impl Fn(&mut fc::Random) -> char {
    let integer = fc::integer(Some(97), Some(122));
    move |random| char::from(integer(random) as u8)
}

/// `fc.array(lowercaseLetter(), { maxLength: 50, minLength: 1 }).map((arr) => arr.join(''))`
fn fc_prefix() -> impl Fn(&mut fc::Random) -> String {
    let array = fc::array(lowercase_letter(), Some(1), Some(50));
    move |random| array(random).into_iter().collect()
}

/// `encodeCashAddressVersionByte(typeBits, length)`
fn version_byte(type_bits: u8, length: usize) -> u8 {
    encode_cash_address_version_byte(type_bits, length)
}

fn address(address: &str) -> Result<CashAddressResult, String> {
    Ok(CashAddressResult {
        address: address.to_string(),
    })
}

#[test]
fn mask_cash_address_prefix_() {
    #[rustfmt::skip]
    let payload_prefix = vec![2, 9, 20, 3, 15, 9, 14, 3, 1, 19, 8];
    assert_eq!(mask_cash_address_prefix("bitcoincash"), payload_prefix);
}

#[test]
fn encode_cash_address_version_byte_() {
    assert_eq!(
        encode_cash_address_version_byte(CashAddressTypeBits::P2pkh as u8, 20),
        CashAddressVersionByte::P2pkh as u8
    );
    assert_eq!(
        encode_cash_address_version_byte(0, 20),
        CashAddressVersionByte::P2pkh as u8
    );
    assert_eq!(
        encode_cash_address_version_byte(CashAddressTypeBits::P2sh as u8, 20),
        CashAddressVersionByte::P2sh20 as u8
    );
    assert_eq!(
        encode_cash_address_version_byte(1, 20),
        CashAddressVersionByte::P2sh20 as u8
    );
    assert_eq!(
        encode_cash_address_version_byte(CashAddressTypeBits::P2sh as u8, 32),
        CashAddressVersionByte::P2sh32 as u8
    );
    assert_eq!(
        encode_cash_address_version_byte(CashAddressTypeBits::P2pkhWithTokens as u8, 20),
        CashAddressVersionByte::P2pkhWithTokens as u8
    );
    assert_eq!(
        encode_cash_address_version_byte(CashAddressTypeBits::P2shWithTokens as u8, 20),
        CashAddressVersionByte::P2sh20WithTokens as u8
    );
    assert_eq!(
        encode_cash_address_version_byte(CashAddressTypeBits::P2shWithTokens as u8, 32),
        CashAddressVersionByte::P2sh32WithTokens as u8
    );
}

#[test]
fn decode_cash_address_version_byte_() {
    assert_eq!(
        decode_cash_address_version_byte(CashAddressVersionByte::P2pkh as u8),
        Ok(CashAddressVersionByteInfo {
            length: 20,
            type_bits: 0
        })
    );
    assert_eq!(
        decode_cash_address_version_byte(CashAddressVersionByte::P2sh20 as u8),
        Ok(CashAddressVersionByteInfo {
            length: 20,
            type_bits: 1
        })
    );
    assert_eq!(
        decode_cash_address_version_byte(CashAddressVersionByte::P2sh32 as u8),
        Ok(CashAddressVersionByteInfo {
            length: 32,
            type_bits: 1
        })
    );
    assert_eq!(
        decode_cash_address_version_byte(0b10000000),
        Err(CashAddressVersionByteDecodingError::ReservedBitSet)
    );
    assert_eq!(
        decode_cash_address_version_byte(CashAddressVersionByte::P2pkhWithTokens as u8),
        Ok(CashAddressVersionByteInfo {
            length: 20,
            type_bits: 2
        })
    );
    assert_eq!(
        decode_cash_address_version_byte(CashAddressVersionByte::P2sh20WithTokens as u8),
        Ok(CashAddressVersionByteInfo {
            length: 20,
            type_bits: 3
        })
    );
    assert_eq!(
        decode_cash_address_version_byte(CashAddressVersionByte::P2sh32WithTokens as u8),
        Ok(CashAddressVersionByteInfo {
            length: 32,
            type_bits: 3
        })
    );
    assert_eq!(
        decode_cash_address_version_byte(0b01000011),
        Ok(CashAddressVersionByteInfo {
            length: 32,
            type_bits: 8
        })
    );

    assert_eq!(
        decode_cash_address_version_byte(0b01111111),
        Ok(CashAddressVersionByteInfo {
            length: 64,
            type_bits: 15
        })
    );
}

#[test]
fn encode_cash_address_format_works() {
    assert_eq!(
        encode_cash_address_format(
            &hex_to_bin("978306aa4e02fd06e251b38d2e961f78f4af2ea6524a3e4531126776276a6af1"),
            "bitauth",
            u16::from(version_byte(0, 32))
        ),
        address("bitauth:qwtcxp42fcp06phz2xec6t5krau0ftew5efy50j9xyfxwa38df40zp58z6t5w")
    );
    // { throwErrors: false }
    assert_eq!(
        encode_cash_address_format(
            &hex_to_bin("978306aa4e02fd06e251b38d2e961f78f4af2ea6524a3e4531126776276a6af1"),
            "bitauth",
            u16::from(version_byte(0, 32))
        ),
        address("bitauth:qwtcxp42fcp06phz2xec6t5krau0ftew5efy50j9xyfxwa38df40zp58z6t5w")
    );
    let invalid1 = (
        hex_to_bin("978306aa4e02fd06e251b38d2e961f78f4af2ea6524a3e4531126776276a6af1"),
        "bitcoincash",
        256,
    );
    let version_error = format!(
        "{} Version: 256.",
        CashAddressFormatEncodingError::ExcessiveVersion.as_str()
    );
    // { ...invalid1, throwErrors: false }
    assert_eq!(
        encode_cash_address_format(&invalid1.0, invalid1.1, invalid1.2),
        Err(version_error.clone())
    );
    // t.throws(() => encodeCashAddressFormat(invalid1), { message: versionError });
    assert_eq!(
        encode_cash_address_format(&invalid1.0, invalid1.1, invalid1.2),
        Err(version_error)
    );
}

#[test]
fn encode_cash_address_works() {
    /*
     * From `f85d4bd8a03ca106c9deb47b791803dac7f0333809e3f1dd04d182e0aba6e553`
     */
    let payload = hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d");
    assert_eq!(
        encode_cash_address(&payload, Some(CashAddressNetworkPrefix::Testnet.as_str()), CashAddressType::P2pkh),
        address("bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x")
    );
    // `type: 'p2pkh'`
    assert_eq!(
        encode_cash_address(&payload, Some("bchtest"), CashAddressType::P2pkh),
        address("bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x")
    );
    // { throwErrors: false }
    assert_eq!(
        encode_cash_address(&payload, Some("bchtest"), CashAddressType::P2pkh),
        address("bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x")
    );
    assert_eq!(
        encode_cash_address(&payload, Some(CashAddressNetworkPrefix::Mainnet.as_str()), CashAddressType::P2pkh),
        address("bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6")
    );
    assert_eq!(
        encode_cash_address(&payload, Some("bitcoincash"), CashAddressType::P2pkh),
        address("bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6")
    );
    assert_eq!(
        encode_cash_address(
            &payload,
            Some(CashAddressNetworkPrefix::Mainnet.as_str()),
            CashAddressType::P2pkhWithTokens
        ),
        address("bitcoincash:zq2azmyyv6dtgczexyalqar70q036yund5j2mspghf")
    );
    // `type: 'p2pkhWithTokens'`
    assert_eq!(
        encode_cash_address(&payload, Some("bitcoincash"), CashAddressType::P2pkhWithTokens),
        address("bitcoincash:zq2azmyyv6dtgczexyalqar70q036yund5j2mspghf")
    );
    assert_eq!(
        encode_cash_address(&payload, Some(CashAddressNetworkPrefix::Regtest.as_str()), CashAddressType::P2pkh),
        address("bchreg:qq2azmyyv6dtgczexyalqar70q036yund5tw6gw2vq")
    );
    assert_eq!(
        encode_cash_address(&payload, Some("bchreg"), CashAddressType::P2pkh),
        address("bchreg:qq2azmyyv6dtgczexyalqar70q036yund5tw6gw2vq")
    );
    // const invalid = { payload: hexToBin('97'), prefix: 'bitcoincash', type: 'p2sh' } as const;
    let invalid_payload = hex_to_bin("97");
    let message = format!(
        "{} Payload length: 1.",
        CashAddressEncodingError::UnsupportedPayloadLength.as_str()
    );
    // { ...invalid, throwErrors: false }, t.throws(...), and t.throws(..., { throwErrors: true })
    for _ in 0..3 {
        assert_eq!(
            encode_cash_address(&invalid_payload, Some("bitcoincash"), CashAddressType::P2sh),
            Err(message.clone())
        );
    }
}

#[test]
fn encode_cash_address_non_standard_works() {
    let payload = hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d");
    assert_eq!(
        encode_cash_address_non_standard(
            &payload,
            CashAddressNetworkPrefix::Testnet.as_str(),
            CashAddressTypeBits::P2pkh as u8
        ),
        address("bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x")
    );
    assert_eq!(
        encode_cash_address_non_standard(&payload, "bchtest", 0),
        address("bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x")
    );
    // const invalid = { payload: hexToBin('97'), prefix: 'bchtest', typeBits: 1 } as const;
    let invalid_payload = hex_to_bin("97");
    let message = format!(
        "{} Payload length: 1.",
        CashAddressEncodingError::UnsupportedPayloadLength.as_str()
    );
    // { ...invalid, throwErrors: false } and t.throws(...)
    for _ in 0..2 {
        assert_eq!(
            encode_cash_address_non_standard(&invalid_payload, "bchtest", 1),
            Err(message.clone())
        );
    }
}

#[test]
fn decode_cash_address_decode_cash_address_format_works() {
    let payload = hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d");
    let result = decode_cash_address("bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x");
    let result = match result {
        Err(result) => {
            println!("{result}");
            panic!();
        }
        Ok(result) => result,
    };
    assert_eq!(
        result,
        DecodedCashAddress {
            payload: payload.clone(),
            prefix: "bchtest".to_string(),
            address_type: CashAddressType::P2pkh,
        }
    );
    assert_eq!(
        decode_cash_address("bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x"),
        Ok(DecodedCashAddress {
            payload: payload.clone(),
            prefix: CashAddressNetworkPrefix::Testnet.as_str().to_string(),
            address_type: CashAddressType::P2pkh,
        })
    );

    assert_eq!(
        decode_cash_address("bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6"),
        Ok(DecodedCashAddress {
            payload: payload.clone(),
            prefix: CashAddressNetworkPrefix::Mainnet.as_str().to_string(),
            address_type: CashAddressType::P2pkh,
        })
    );
    assert_eq!(
        decode_cash_address("bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6"),
        Ok(DecodedCashAddress {
            payload: payload.clone(),
            prefix: "bitcoincash".to_string(),
            address_type: CashAddressType::P2pkh,
        })
    );

    assert_eq!(
        decode_cash_address("bchreg:qq2azmyyv6dtgczexyalqar70q036yund5tw6gw2vq"),
        Ok(DecodedCashAddress {
            payload: payload.clone(),
            prefix: CashAddressNetworkPrefix::Regtest.as_str().to_string(),
            address_type: CashAddressType::P2pkh,
        })
    );
    assert_eq!(
        decode_cash_address("bchreg:qq2azmyyv6dtgczexyalqar70q036yund5tw6gw2vq"),
        Ok(DecodedCashAddress {
            payload,
            prefix: "bchreg".to_string(),
            address_type: CashAddressType::P2pkh,
        })
    );

    assert_eq!(
        decode_cash_address_format("bitauth:qwtcxp42fcp06phz2xec6t5krau0ftew5efy50j9xyfxwa38df40zp58z6t5w"),
        Ok(DecodedCashAddressFormat {
            payload: hex_to_bin("978306aa4e02fd06e251b38d2e961f78f4af2ea6524a3e4531126776276a6af1"),
            prefix: "bitauth".to_string(),
            version: version_byte(0, 32),
        })
    );

    assert_eq!(
        decode_cash_address_format(":qwtcxp42fcp06phz2xec6t5krau0ftew5efy50j9xyfxwa38df40zp58z6t5w"),
        Err(format!(
            "{} Provided address: \":qwtcxp42fcp06phz2xec6t5krau0ftew5efy50j9xyfxwa38df40zp58z6t5w\".",
            CashAddressDecodingError::InvalidFormat.as_str()
        ))
    );

    assert_eq!(
        decode_cash_address("prefix:broken"),
        Err(format!(
            "{} Invalid characters: b, o.",
            CashAddressDecodingError::InvalidCharacters.as_str()
        ))
    );

    assert_eq!(
        decode_cash_address_format("prefix:broken"),
        Err(format!(
            "{} Invalid characters: b, o.",
            CashAddressDecodingError::InvalidCharacters.as_str()
        ))
    );

    assert_eq!(
        // cspell: disable-next-line
        decode_cash_address_format("verybroken:lll30n6j98m5"),
        Err(format!(
            "{} Encoding requires padding while padding is disallowed.",
            CashAddressDecodingError::ImproperPadding.as_str()
        ))
    );

    assert_eq!(
        // cspell: disable-next-line
        decode_cash_address_format("bchtest:testnetaddress4d6njnut"),
        Err(format!(
            "{} Encountered padding when padding was disallowed.",
            CashAddressDecodingError::ImproperPadding.as_str()
        ))
    );
    assert_eq!(
        decode_cash_address("bchreg:555555555555555555555555555555555555555555555udxmlmrz"),
        Err(CashAddressDecodingError::ReservedBit.as_str().to_string())
    );
    assert_eq!(
        decode_cash_address("bitcoincash:qu2azmyyv6dtgczexyalqar70q036yund53an46hf6"),
        Err(format!(
            "{} Version byte indicated a byte length of 64, but the payload is 20 bytes.",
            CashAddressDecodingError::MismatchedPayloadLength.as_str()
        ))
    );
}

#[test]
fn cash_address_test_vectors() {
    let cash_addr_json = parse_json(include_str!("fixtures/cashaddr.json")).expect("valid JSON");
    // Object.values(cashAddrJson).filter((item) => !Array.isArray(item))
    for vector in cash_addr_json
        .as_array()
        .expect("an array")
        .iter()
        .filter(|item| item.as_array().is_none())
    {
        let cashaddr = vector.get("cashaddr").and_then(Json::as_str).expect("cashaddr");
        let prefix = cashaddr.split(':').next().expect("a prefix");
        let payload = hex_to_bin(vector.get("payload").and_then(Json::as_str).expect("payload"));
        let type_bits = vector.get("type").and_then(Json::as_u64).expect("type") as u8;
        let version = version_byte(type_bits, payload.len());
        let address = encode_cash_address_format(&payload, prefix, u16::from(version))
            .expect("a valid version")
            .address;
        if cashaddr != address {
            println!("expected vector {cashaddr}");
            println!("typeBits {type_bits}");
            println!("prefix {prefix}");
            println!("payload {payload:?}");
            println!("encodeResult {address}");
        }
        assert_eq!(cashaddr, address);

        let decode_result = decode_cash_address_non_standard(cashaddr);
        if let Err(decode_result) = &decode_result {
            println!("{decode_result}");
        }
        assert_eq!(
            decode_result,
            Ok(DecodedCashAddressNonStandard {
                payload,
                prefix: prefix.to_string(),
                type_bits,
            })
        );
    }
}

#[test]
fn decode_cash_address_without_prefix() {
    let payload = hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d");
    assert_eq!(
        decode_cash_address_format_without_prefix("qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x", None),
        Ok(DecodedCashAddressFormat {
            payload: payload.clone(),
            prefix: "bchtest".to_string(),
            version: 0,
        })
    );

    assert_eq!(
        decode_cash_address_format_without_prefix("qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6", None),
        Ok(DecodedCashAddressFormat {
            payload: payload.clone(),
            prefix: "bitcoincash".to_string(),
            version: 0,
        })
    );

    assert_eq!(
        decode_cash_address_format_without_prefix("qq2azmyyv6dtgczexyalqar70q036yund5tw6gw2vq", None),
        Ok(DecodedCashAddressFormat {
            payload,
            prefix: "bchreg".to_string(),
            version: 0,
        })
    );

    assert_eq!(
        decode_cash_address_format_without_prefix(
            "qwtcxp42fcp06phz2xec6t5krau0ftew5efy50j9xyfxwa38df40zp58z6t5w",
            Some(&["bitauth"])
        ),
        Ok(DecodedCashAddressFormat {
            payload: hex_to_bin("978306aa4e02fd06e251b38d2e961f78f4af2ea6524a3e4531126776276a6af1"),
            prefix: "bitauth".to_string(),
            version: version_byte(0, 32),
        })
    );

    assert_eq!(
        // cspell: disable-next-line
        decode_cash_address_format_without_prefix("qwtcxp42fcp06phz", Some(&["bitauth"])),
        Err(CashAddressDecodingError::InvalidChecksum.as_str().to_string())
    );
}

/// `CashAddressSupportedLength` values, in the order used by the tests.
const SUPPORTED_LENGTHS: [usize; 8] = [20, 24, 28, 32, 40, 48, 56, 64];

#[test]
fn fast_check_encode_cash_address_format_decode_cash_address_format() {
    let round_trip_with_payload_length = |length: usize| {
        fc::property(
            {
                let prefix = fc_prefix();
                let version = fc::nat(Some(0xff));
                let payload = fc::uint8_array(Some(length), Some(length));
                move |random: &mut fc::Random| (prefix(random), version(random), payload(random))
            },
            |(prefix, version, payload)| {
                let version = *version as u8;
                assert_eq!(
                    decode_cash_address_format(
                        &encode_cash_address_format(payload, prefix, u16::from(version))
                            .expect("a valid version")
                            .address
                    ),
                    Ok(DecodedCashAddressFormat {
                        payload: payload.clone(),
                        prefix: prefix.clone(),
                        version,
                    })
                );
                true
            },
        )
    };
    // t.notThrows(() => { fc.assert(roundTripWithPayloadLength(20)); ... });
    for length in SUPPORTED_LENGTHS {
        fc::assert(round_trip_with_payload_length(length), None);
    }
}

#[test]
fn fast_check_encode_cash_address_non_standard_decode_cash_address_non_standard() {
    let round_trip_with_payload_length = |length: usize| {
        fc::property(
            {
                let prefix = fc_prefix();
                let type_bits = fc::nat(Some(15));
                let payload = fc::uint8_array(Some(length), Some(length));
                move |random: &mut fc::Random| (prefix(random), type_bits(random), payload(random))
            },
            |(prefix, type_bits, payload)| {
                let type_bits = *type_bits as u8;
                assert_eq!(
                    decode_cash_address_non_standard(
                        &encode_cash_address_non_standard(payload, prefix, type_bits)
                            .expect("a supported length")
                            .address
                    ),
                    Ok(DecodedCashAddressNonStandard {
                        payload: payload.clone(),
                        prefix: prefix.clone(),
                        type_bits,
                    })
                );
                true
            },
        )
    };
    for length in SUPPORTED_LENGTHS {
        fc::assert(round_trip_with_payload_length(length), None);
    }
}

#[test]
fn fast_check_encode_cash_address_decode_cash_address() {
    // `Object.keys(CashAddressNetworkPrefix)`: the enum's keys (not its values).
    let prefixes = ["mainnet", "testnet", "regtest"];
    // `Object.keys(CashAddressType)`
    let types = [
        CashAddressType::P2pkh,
        CashAddressType::P2sh,
        CashAddressType::P2pkhWithTokens,
        CashAddressType::P2shWithTokens,
    ];
    let round_trip_with_payload_length = |length: usize| {
        fc::property(
            {
                let prefix_index = fc::nat(Some(prefixes.len() as u64 - 1));
                let type_index = fc::nat(Some(types.len() as u64 - 1));
                let payload = fc::uint8_array(Some(length), Some(length));
                move |random: &mut fc::Random| (prefix_index(random), type_index(random), payload(random))
            },
            move |(prefix_index, type_index, payload)| {
                let prefix = prefixes[*prefix_index as usize];
                let r#type = types[*type_index as usize];
                assert_eq!(
                    decode_cash_address(
                        &encode_cash_address(payload, Some(prefix), r#type)
                            .expect("a supported length")
                            .address
                    ),
                    Ok(DecodedCashAddress {
                        payload: payload.clone(),
                        prefix: prefix.to_string(),
                        address_type: r#type,
                    })
                );
                true
            },
        )
    };
    for length in SUPPORTED_LENGTHS {
        fc::assert(round_trip_with_payload_length(length), None);
    }
}

#[test]
fn attempt_cash_address_error_correction() {
    assert_eq!(
        attempt_cash_address_format_error_correction(":qq2azmyyv6dtgczexyalqar70q036yund53jvfde0c"),
        Err(CashAddressDecodingError::InvalidFormat.as_str().to_string())
    );

    assert_eq!(
        attempt_cash_address_format_error_correction("broken:broken"),
        Err(format!(
            "{} Invalid characters: b, o.",
            CashAddressDecodingError::InvalidCharacters.as_str()
        ))
    );

    assert_eq!(
        attempt_cash_address_format_error_correction(
            // cspell: disable-next-line
            "achtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0c"
        ),
        Ok(CashAddressFormatCorrection {
            address: "bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x".to_string(),
            corrections: vec![0, 49],
        })
    );
    assert_eq!(
        attempt_cash_address_format_error_correction(
            // cspell: disable-next-line
            "btcbest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x"
        ),
        Err(CashAddressFormatCorrectionError::TooManyErrors.as_str().to_string())
    );
}

#[test]
fn fast_check_attempt_cash_address_error_correction() {
    let corrects_up_to_two_errors = |payload_length: usize| {
        fc::property(
            {
                let prefix = fc_prefix();
                let type_bits = fc::nat(Some(15));
                let payload = fc::uint8_array(Some(payload_length), Some(payload_length));
                let random_errors = fc::array(fc::nat(Some(payload_length as u64)), Some(0), Some(2));
                move |random: &mut fc::Random| {
                    (
                        prefix(random),
                        type_bits(random),
                        payload(random),
                        random_errors(random),
                    )
                }
            },
            |(prefix, type_bits, payload, random_errors)| {
                let address = encode_cash_address_non_standard(payload, prefix, *type_bits as u8)
                    .expect("a supported length")
                    .address;
                let address_chars = split_every(&address, 1);
                let mut errors: Vec<usize> = random_errors
                    .iter()
                    .map(|error| *error as usize)
                    .filter(|error| *error != prefix.len())
                    .collect();
                errors.sort_unstable();
                errors.dedup();
                let broken: String = address_chars
                    .iter()
                    .enumerate()
                    .map(|(i, char)| {
                        if errors.contains(&i) {
                            if *char == "q" {
                                "p"
                            } else {
                                "q"
                            }
                        } else {
                            char
                        }
                    })
                    .collect();

                assert_eq!(
                    attempt_cash_address_format_error_correction(&broken),
                    Ok(CashAddressFormatCorrection {
                        address: address.clone(),
                        corrections: errors,
                    })
                );
                true
            },
        )
    };
    for length in SUPPORTED_LENGTHS {
        fc::assert(corrects_up_to_two_errors(length), None);
    }
}

/// The `legacyVectors` macro.
fn legacy_vectors(base58_address: &str, cash_address: &str) {
    let decoded_base58_address = decode_base58_address_format(base58_address, None);
    let decoded_cash_address = decode_cash_address(cash_address);
    let decoded_cash_address = match decoded_cash_address {
        Err(decoded_cash_address) => panic!("{decoded_cash_address}"),
        Ok(decoded_cash_address) => decoded_cash_address,
    };
    let decoded_base58_address = match decoded_base58_address {
        Err(decoded_base58_address) => panic!("{decoded_base58_address}"),
        Ok(decoded_base58_address) => decoded_base58_address,
    };
    assert_eq!(decoded_base58_address.payload, decoded_cash_address.payload);
}

#[test]
fn cash_address_legacy_base58_vectors_1bpei6dfdaufd7gtittlsdbeyjvcoavggu() {
    legacy_vectors(
        // cspell: disable-next-line
        "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    );
}

#[test]
fn cash_address_legacy_base58_vectors_1kxrwxcirdzupqwqmum1dbwskdlyaysvlr() {
    legacy_vectors(
        // cspell: disable-next-line
        "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR",
        "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
    );
}

#[test]
fn cash_address_legacy_base58_vectors_16w1d5wrvkjuzussrzdlp9w3ygcgoxdxb() {
    legacy_vectors(
        // cspell: disable-next-line
        "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb",
        "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
    );
}

#[test]
fn cash_address_legacy_base58_vectors_3cwfddi6m4ndigykqzyvsfyagqdlpvmtzc() {
    legacy_vectors(
        // cspell: disable-next-line
        "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC",
        "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    );
}

#[test]
fn cash_address_legacy_base58_vectors_3ldss579y7sruadqu11beejotjdfifcdx4() {
    legacy_vectors(
        // cspell: disable-next-line
        "3LDsS579y7sruadqu11beEJoTjdFiFCdX4",
        "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
    );
}

#[test]
fn cash_address_legacy_base58_vectors_31nwvkzwypdgzjbjzxfdmswsc4zlkpyyuw() {
    legacy_vectors(
        // cspell: disable-next-line
        "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw",
        "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37",
    );
}

#[test]
fn cash_address_legacy_base58_vectors_1q2twhe3gmdb6bzkafqwxxtwawgft5jvm3() {
    legacy_vectors(
        // cspell: disable-next-line
        "1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3",
        "bitcoincash:qr7fzmep8g7h7ymfxy74lgc0v950j3r2959lhtxxsl",
    );
}
