//! CashAddress encoding and decoding (the CashAddress format used on Bitcoin Cash).

use std::collections::BTreeMap;
use std::sync::LazyLock;
use super::bech32::{
    decode_bech32, encode_bech32, extract_non_bech32_characters, is_bech32_character_set,
    regroup_bits,
};
use crate::format::format_error;

/// The network prefixes standardized by the CashAddress specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CashAddressNetworkPrefix {
    Mainnet,
    Testnet,
    Regtest,
}

impl CashAddressNetworkPrefix {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "bitcoincash",
            Self::Testnet => "bchtest",
            Self::Regtest => "bchreg",
        }
    }

    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "bitcoincash" => Some(Self::Mainnet),
            "bchtest" => Some(Self::Testnet),
            "bchreg" => Some(Self::Regtest),
            _ => None,
        }
    }
}

impl core::fmt::Display for CashAddressNetworkPrefix {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The CashAddress version bytes currently defined by the specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CashAddressVersionByte {
    P2pkh = 0b0000_0000,
    P2sh20 = 0b0000_1000,
    P2sh32 = 0b0000_1011,
    P2pkhWithTokens = 0b0001_0000,
    P2sh20WithTokens = 0b0001_1000,
    P2sh32WithTokens = 0b0001_1011,
}

/// The address types currently defined in the CashAddress specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CashAddressType {
    P2pkh,
    P2sh,
    P2pkhWithTokens,
    P2shWithTokens,
}

impl CashAddressType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P2pkh => "p2pkh",
            Self::P2sh => "p2sh",
            Self::P2pkhWithTokens => "p2pkhWithTokens",
            Self::P2shWithTokens => "p2shWithTokens",
        }
    }
}

impl core::fmt::Display for CashAddressType {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The address type bits currently defined in the CashAddress specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CashAddressTypeBits {
    P2pkh = 0,
    P2sh = 1,
    P2pkhWithTokens = 2,
    P2shWithTokens = 3,
}

/// The type bits of each [`CashAddressType`].
pub static cashAddressTypeToTypeBits: LazyLock<BTreeMap<CashAddressType, CashAddressTypeBits>> =
    LazyLock::new(|| {
        BTreeMap::from([
            (CashAddressType::P2pkh, CashAddressTypeBits::P2pkh),
            (CashAddressType::P2sh, CashAddressTypeBits::P2sh),
            (CashAddressType::P2pkhWithTokens, CashAddressTypeBits::P2pkhWithTokens),
            (CashAddressType::P2shWithTokens, CashAddressTypeBits::P2shWithTokens),
        ])
    });

/// The [`CashAddressType`] of each standardized type bits value.
pub static cashAddressTypeBitsToType: LazyLock<BTreeMap<u8, CashAddressType>> = LazyLock::new(|| {
    BTreeMap::from([
        (CashAddressTypeBits::P2pkh as u8, CashAddressType::P2pkh),
        (CashAddressTypeBits::P2sh as u8, CashAddressType::P2sh),
        (CashAddressTypeBits::P2pkhWithTokens as u8, CashAddressType::P2pkhWithTokens),
        (CashAddressTypeBits::P2shWithTokens as u8, CashAddressType::P2shWithTokens),
    ])
});

/// The payload length encoded by each value of the CashAddress length bits.
pub static cashAddressLengthBitsToLength: LazyLock<BTreeMap<u8, usize>> = LazyLock::new(|| {
    BTreeMap::from([(0, 20), (1, 24), (2, 28), (3, 32), (4, 40), (5, 48), (6, 56), (7, 64)])
});

/// The CashAddress length bits of each supported payload length.
pub static cashAddressLengthToLengthBits: LazyLock<BTreeMap<usize, u8>> = LazyLock::new(|| {
    BTreeMap::from([(20, 0), (24, 1), (28, 2), (32, 3), (40, 4), (48, 5), (56, 6), (64, 7)])
});

/// Returns true if a payload length can be encoded in a CashAddress version byte.
pub fn is_valid_cash_address_payload_length(length: usize) -> bool {
    cashAddressLengthToLengthBits.contains_key(&length)
}

/// Errors returned while encoding a CashAddress format string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CashAddressFormatEncodingError {
    ExcessiveVersion,
}

impl CashAddressFormatEncodingError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExcessiveVersion => {
                "CashAddress format encoding error: version must be 255 or less."
            }
        }
    }
}

impl core::fmt::Display for CashAddressFormatEncodingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors returned while encoding a standard CashAddress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CashAddressEncodingError {
    NoTypeBitsValueStandardizedForP2pk,
    UnsupportedPayloadLength,
    UnknownLockingBytecodeType,
}

impl CashAddressEncodingError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoTypeBitsValueStandardizedForP2pk => {
                "CashAddress encoding error: no CashAddress type bit has been standardized for P2PK locking bytecode."
            }
            Self::UnsupportedPayloadLength => {
                "CashAddress encoding error: a payload of this length can not be encoded as a valid CashAddress."
            }
            Self::UnknownLockingBytecodeType => {
                "CashAddress encoding error: unknown locking bytecode type."
            }
        }
    }
}

impl core::fmt::Display for CashAddressEncodingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors returned while decoding a CashAddress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CashAddressDecodingError {
    ImproperPadding,
    InvalidCharacters,
    InvalidChecksum,
    InvalidFormat,
    MismatchedPayloadLength,
    ReservedBit,
    UnknownAddressType,
}

impl CashAddressDecodingError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImproperPadding => {
                "CashAddress decoding error: the payload is improperly padded."
            }
            Self::InvalidCharacters => {
                "CashAddress decoding error: the payload contains unexpected characters."
            }
            Self::InvalidChecksum => {
                "CashAddress decoding error: invalid checksum - please review the address for errors."
            }
            Self::InvalidFormat => {
                "CashAddress decoding error: CashAddresses should be of the form \"prefix:payload\"."
            }
            Self::MismatchedPayloadLength => {
                "CashAddress decoding error: mismatched payload length for specified address version."
            }
            Self::ReservedBit => {
                "CashAddress decoding error: unknown CashAddress version, reserved bit set."
            }
            Self::UnknownAddressType => "CashAddress decoding error: unknown CashAddress type.",
        }
    }
}

impl core::fmt::Display for CashAddressDecodingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors returned while decoding a CashAddress version byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CashAddressVersionByteDecodingError {
    ReservedBitSet,
}

impl CashAddressVersionByteDecodingError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservedBitSet => "Reserved bit is set.",
        }
    }
}

impl core::fmt::Display for CashAddressVersionByteDecodingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors returned while correcting errors in a CashAddress format string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CashAddressFormatCorrectionError {
    TooManyErrors,
}

impl CashAddressFormatCorrectionError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooManyErrors => {
                "CashAddress format correction error: this address cannot be corrected as it contains more than 2 errors."
            }
        }
    }
}

impl core::fmt::Display for CashAddressFormatCorrectionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The successfully encoded CashAddress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashAddressResult {
    pub address: String,
}

/// A decoded CashAddress format string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedCashAddressFormat {
    /// The payload of the CashAddress-formatted string.
    pub payload: Vec<u8>,
    /// The prefix before the colon, e.g. a [`CashAddressNetworkPrefix`].
    pub prefix: String,
    /// The version byte of the CashAddress-formatted string.
    pub version: u8,
}

/// A decoded, non-standard CashAddress (any prefix and type bits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedCashAddressNonStandard {
    pub payload: Vec<u8>,
    pub prefix: String,
    pub type_bits: u8,
}

/// A decoded, standard CashAddress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedCashAddress {
    pub payload: Vec<u8>,
    pub prefix: String,
    pub address_type: CashAddressType,
}

/// A decoded CashAddress version byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CashAddressVersionByteInfo {
    pub length: usize,
    pub type_bits: u8,
}

/// A successful CashAddress format correction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashAddressFormatCorrection {
    pub address: String,
    /// The indexes of the corrected characters, in ascending order.
    pub corrections: Vec<usize>,
}

/// Encode a CashAddress version byte for the given address type bits and payload length.
pub fn encode_cash_address_version_byte(type_bits: u8, length: usize) -> u8 {
    // `length` must be a supported length (`CashAddressSupportedLength`);
    // otherwise libauth's `| undefined` is `| 0`.
    (type_bits << 3) | cashAddressLengthToLengthBits.get(&length).copied().unwrap_or(0)
}

/// Decode a CashAddress version byte.
pub fn decode_cash_address_version_byte(
    version: u8,
) -> Result<CashAddressVersionByteInfo, CashAddressVersionByteDecodingError> {
    if version & 0b1000_0000 != 0 {
        return Err(CashAddressVersionByteDecodingError::ReservedBitSet);
    }
    Ok(CashAddressVersionByteInfo {
        length: cashAddressLengthBitsToLength[&(version & 0b111)],
        type_bits: (version >> 3) & 0b1111,
    })
}

/// Convert a prefix into 5-bit, case-insensitive values.
pub fn mask_cash_address_prefix(prefix: &str) -> Vec<u8> {
    prefix
        .chars()
        .map(|character| ((character as u32) & 0b11111) as u8)
        .collect()
}

const BECH32_GENERATOR_MOST_SIGNIFICANT_BYTE: [u32; 5] = [0x98, 0x79, 0xf3, 0xae, 0x1e];
const BECH32_GENERATOR_REMAINING_BYTES: [u32; 5] =
    [0xf2bc8e61, 0xb76d99e2, 0x3e5fb3c4, 0x2eabe2a8, 0x4f43e470];

/// The CashAddress polynomial modulo operation (a 40-bit Bech32-style checksum).
pub fn cash_address_polynomial_modulo(v: &[u8]) -> u64 {
    let mut most_significant_byte: u32 = 0;
    let mut lower_bytes: u32 = 1;
    for &value in v {
        let remaining = most_significant_byte >> 3;
        most_significant_byte = (most_significant_byte & 0x07) << 5;
        most_significant_byte |= lower_bytes >> 27;
        lower_bytes = (lower_bytes & 0x07ff_ffff) << 5;
        lower_bytes ^= u32::from(value);
        for index in 0..BECH32_GENERATOR_MOST_SIGNIFICANT_BYTE.len() {
            if remaining & (1 << index) != 0 {
                most_significant_byte ^= BECH32_GENERATOR_MOST_SIGNIFICANT_BYTE[index];
                lower_bytes ^= BECH32_GENERATOR_REMAINING_BYTES[index];
            }
        }
    }
    lower_bytes ^= 1;
    u64::from(most_significant_byte) * (1_u64 << 32) + u64::from(lower_bytes)
}

/// Convert a 40-bit checksum into eight 5-bit integers, most significant first.
pub fn cash_address_checksum_to_uint5_array(checksum: u64) -> Vec<u8> {
    let mut checksum = checksum;
    let mut result = Vec::with_capacity(8);
    for _ in 0..8 {
        result.push((checksum & 31) as u8);
        checksum /= 32;
    }
    result.reverse();
    result
}

/// Encode a payload as a CashAddress-like string using the CashAddress format.
pub fn encode_cash_address_format(
    payload: &[u8],
    prefix: &str,
    version: u16,
) -> Result<CashAddressResult, String> {
    if version > 255 {
        return Err(format_error(
            CashAddressFormatEncodingError::ExcessiveVersion.as_str(),
            Some(&format!("Version: {version}.")),
        ));
    }
    let mut content = Vec::with_capacity(payload.len() + 1);
    content.push(version as u8);
    content.extend_from_slice(payload);
    let payload_contents = regroup_bits(&content, 8, 5, Some(true))?;

    let mut checksum_contents = mask_cash_address_prefix(prefix);
    checksum_contents.push(0);
    checksum_contents.extend_from_slice(&payload_contents);
    checksum_contents.extend_from_slice(&[0_u8; 8]);
    let checksum = cash_address_polynomial_modulo(&checksum_contents);

    let mut encoded = payload_contents;
    encoded.extend_from_slice(&cash_address_checksum_to_uint5_array(checksum));
    Ok(CashAddressResult {
        address: format!("{prefix}:{}", encode_bech32(&encoded)),
    })
}

/// Encode a payload as a CashAddress supporting non-standard prefixes and type bits.
pub fn encode_cash_address_non_standard(
    payload: &[u8],
    prefix: &str,
    type_bits: u8,
) -> Result<CashAddressResult, String> {
    if !is_valid_cash_address_payload_length(payload.len()) {
        return Err(format_error(
            CashAddressEncodingError::UnsupportedPayloadLength.as_str(),
            Some(&format!("Payload length: {}.", payload.len())),
        ));
    }
    let version = encode_cash_address_version_byte(type_bits, payload.len());
    encode_cash_address_format(payload, prefix, u16::from(version))
}

/// Encode a payload as a standard CashAddress.
pub fn encode_cash_address(
    payload: &[u8],
    prefix: Option<&str>,
    address_type: CashAddressType,
) -> Result<CashAddressResult, String> {
    let prefix = prefix.unwrap_or("bitcoincash");
    encode_cash_address_non_standard(payload, prefix, cashAddressTypeToTypeBits[&address_type] as u8)
}

/// Decode and validate a string using the CashAddress format.
pub fn decode_cash_address_format(address: &str) -> Result<DecodedCashAddressFormat, String> {
    let lowercase = address.to_lowercase();
    let parts: Vec<&str> = lowercase.split(':').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format_error(
            CashAddressDecodingError::InvalidFormat.as_str(),
            Some(&format!("Provided address: \"{address}\".")),
        ));
    }
    let prefix = parts[0];
    let payload = parts[1];
    if !is_bech32_character_set(payload) {
        let invalid_characters = extract_non_bech32_characters(payload)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ");
        return Err(format_error(
            CashAddressDecodingError::InvalidCharacters.as_str(),
            Some(&format!("Invalid characters: {invalid_characters}.")),
        ));
    }
    let decoded_payload = decode_bech32(payload);

    let mut polynomial = mask_cash_address_prefix(prefix);
    polynomial.push(0);
    polynomial.extend_from_slice(&decoded_payload);
    if cash_address_polynomial_modulo(&polynomial) != 0 {
        return Err(CashAddressDecodingError::InvalidChecksum
            .as_str()
            .to_string());
    }

    let checksum_length = 8;
    let contents_end = decoded_payload.len().saturating_sub(checksum_length);
    let payload_contents =
        regroup_bits(&decoded_payload[..contents_end], 5, 8, Some(false)).map_err(|error| {
            format_error(
                CashAddressDecodingError::ImproperPadding.as_str(),
                Some(&error),
            )
        })?;

    // libauth destructures the version from this array; a checksum-valid string
    // too short to contain a version has an empty payload and no version.
    let version = payload_contents.first().copied().unwrap_or(0);
    let contents = payload_contents
        .get(1..)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    Ok(DecodedCashAddressFormat {
        payload: contents,
        prefix: prefix.to_string(),
        version,
    })
}

/// Decode and validate a CashAddress, supporting non-standard type bits.
pub fn decode_cash_address_non_standard(
    address: &str,
) -> Result<DecodedCashAddressNonStandard, String> {
    let decoded = decode_cash_address_format(address)?;
    let info = decode_cash_address_version_byte(decoded.version)
        .map_err(|_| CashAddressDecodingError::ReservedBit.as_str().to_string())?;
    if decoded.payload.len() != info.length {
        return Err(format_error(
            CashAddressDecodingError::MismatchedPayloadLength.as_str(),
            Some(&format!(
                "Version byte indicated a byte length of {}, but the payload is {} bytes.",
                info.length,
                decoded.payload.len()
            )),
        ));
    }
    Ok(DecodedCashAddressNonStandard {
        payload: decoded.payload,
        prefix: decoded.prefix,
        type_bits: info.type_bits,
    })
}

/// Decode and validate a standard CashAddress.
pub fn decode_cash_address(address: &str) -> Result<DecodedCashAddress, String> {
    let decoded = decode_cash_address_non_standard(address)?;
    let address_type = cashAddressTypeBitsToType.get(&decoded.type_bits).copied().ok_or_else(|| {
        format_error(
            CashAddressDecodingError::UnknownAddressType.as_str(),
            Some(&format!("Type bit value: {}.", decoded.type_bits)),
        )
    })?;
    Ok(DecodedCashAddress {
        payload: decoded.payload,
        prefix: decoded.prefix,
        address_type,
    })
}

/// Attempt to decode a CashAddress without a prefix, trying each of
/// `possible_prefixes` (default: the mainnet, testnet, and regtest prefixes).
pub fn decode_cash_address_format_without_prefix(
    address: &str,
    possible_prefixes: Option<&[&str]>,
) -> Result<DecodedCashAddressFormat, String> {
    let default_prefixes = [
        CashAddressNetworkPrefix::Mainnet.as_str(),
        CashAddressNetworkPrefix::Testnet.as_str(),
        CashAddressNetworkPrefix::Regtest.as_str(),
    ];
    for prefix in possible_prefixes.unwrap_or(&default_prefixes) {
        let attempt = decode_cash_address_format(&format!("{prefix}:{address}"));
        match attempt {
            Ok(decoded) => return Ok(decoded),
            Err(error) if error == CashAddressDecodingError::InvalidChecksum.as_str() => {}
            Err(error) => return Err(error),
        }
    }
    Err(CashAddressDecodingError::InvalidChecksum
        .as_str()
        .to_string())
}

/// Convert a CashAddress polynomial to CashAddress string format.
pub fn cash_address_polynomial_to_cash_address(polynomial: &[u8]) -> String {
    let separator_position = polynomial
        .iter()
        .position(|&value| value == 0)
        .unwrap_or_else(|| polynomial.len().saturating_sub(1));
    let prefix: String = polynomial[..separator_position]
        .iter()
        .map(|&value| char::from(96 + (value & 0b11111)))
        .collect();
    let contents_start = (separator_position + 1).min(polynomial.len());
    let contents = encode_bech32(&polynomial[contents_start..]);
    format!("{prefix}:{contents}")
}

/// Attempt to correct up to 2 errors in a CashAddress-formatted string.
///
/// The string must include the prefix and only contain Bech32 characters.
pub fn attempt_cash_address_format_error_correction(
    address: &str,
) -> Result<CashAddressFormatCorrection, String> {
    let lowercase = address.to_lowercase();
    let parts: Vec<&str> = lowercase.split(':').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(CashAddressDecodingError::InvalidFormat.as_str().to_string());
    }
    let prefix = parts[0];
    let payload = parts[1];
    if !is_bech32_character_set(payload) {
        let invalid_characters = extract_non_bech32_characters(payload)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ");
        return Err(format_error(
            CashAddressDecodingError::InvalidCharacters.as_str(),
            Some(&format!("Invalid characters: {invalid_characters}.")),
        ));
    }
    let decoded_payload = decode_bech32(payload);

    let mut polynomial = mask_cash_address_prefix(prefix);
    polynomial.push(0);
    polynomial.extend_from_slice(&decoded_payload);

    let original_checksum = cash_address_polynomial_modulo(&polynomial);
    if original_checksum == 0 {
        return Ok(CashAddressFormatCorrection {
            address: cash_address_polynomial_to_cash_address(&polynomial),
            corrections: Vec::new(),
        });
    }

    // Preserve first-insertion order for duplicate syndrome keys.
    let mut syndromes: Vec<(u64, usize)> = Vec::new();
    for term in 0..polynomial.len() {
        for error_vector in 1..32_u8 {
            polynomial[term] ^= error_vector;
            let correct = cash_address_polynomial_modulo(&polynomial);
            if correct == 0 {
                return Ok(CashAddressFormatCorrection {
                    address: cash_address_polynomial_to_cash_address(&polynomial),
                    corrections: vec![term],
                });
            }
            let syndrome = correct ^ original_checksum;
            let location = term * 32 + usize::from(error_vector);
            match syndromes.iter_mut().find(|(key, _)| *key == syndrome) {
                Some(entry) => entry.1 = location,
                None => syndromes.push((syndrome, location)),
            }
            polynomial[term] ^= error_vector;
        }
    }

    for (syndrome, location) in javascript_object_order(&syndromes) {
        let target = syndrome ^ original_checksum;
        if let Some((_, second_location)) = syndromes.iter().find(|(key, _)| *key == target) {
            let first_index = location / 32;
            let second_index = second_location / 32;
            polynomial[first_index] ^= (location % 32) as u8;
            polynomial[second_index] ^= (second_location % 32) as u8;
            let mut corrections = vec![first_index, second_index];
            corrections.sort_unstable();
            return Ok(CashAddressFormatCorrection {
                address: cash_address_polynomial_to_cash_address(&polynomial),
                corrections,
            });
        }
    }

    Err(CashAddressFormatCorrectionError::TooManyErrors
        .as_str()
        .to_string())
}

/// Reproduce JavaScript's object key enumeration: array-index keys are visited in
/// ascending numeric order, followed by remaining keys in insertion order.
fn javascript_object_order(entries: &[(u64, usize)]) -> Vec<(u64, usize)> {
    const MAX_ARRAY_INDEX: u64 = 4_294_967_294;
    let mut result: Vec<(u64, usize)> = entries
        .iter()
        .copied()
        .filter(|(key, _)| *key <= MAX_ARRAY_INDEX)
        .collect();
    result.sort_by_key(|(key, _)| *key);
    result.extend(
        entries
            .iter()
            .copied()
            .filter(|(key, _)| *key > MAX_ARRAY_INDEX),
    );
    result
}

/// libauth's `CashAddressAvailableTypeBits`: the standardized type bits.
pub type CashAddressAvailableTypeBits = u8;

/// libauth's `CashAddressLengthBits`: the CashAddress length bits.
pub type CashAddressLengthBits = u8;

/// libauth's `CashAddressSupportedLength`: a supported payload length.
pub type CashAddressSupportedLength = usize;
