//! Base58 and Base58Address (A.K.A. "Base58Check") encoding and decoding.

use crate::format::format_error;
use crate::crypto::{hash256, Sha256};
use crate::format::{base58_to_bin, bin_to_base58};

/// Base58 version byte values for common Base58Address format versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Base58AddressFormatVersion {
    /// Pay to Public Key Hash (P2PKH), `0x00`.
    P2pkh = 0,
    /// 20-byte Pay to Script Hash (P2SH20), `0x05`.
    P2sh20 = 5,
    /// Wallet Import Format private key, `0x80`.
    Wif = 128,
    /// Testnet P2PKH, `0x6f`.
    P2pkhTestnet = 111,
    /// Testnet P2SH20, `0xc4`.
    P2sh20Testnet = 196,
    /// Testnet Wallet Import Format private key, `0xef`.
    WifTestnet = 239,
    /// Copay-project P2PKH for Bitcoin Cash, `0x1c`.
    P2pkhCopayBch = 28,
    /// Copay-project P2SH20 for Bitcoin Cash, `0x28`.
    P2sh20CopayBch = 40,
}

impl Base58AddressFormatVersion {
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(version: u8) -> Option<Self> {
        match version {
            0 => Some(Self::P2pkh),
            5 => Some(Self::P2sh20),
            128 => Some(Self::Wif),
            111 => Some(Self::P2pkhTestnet),
            196 => Some(Self::P2sh20Testnet),
            239 => Some(Self::WifTestnet),
            28 => Some(Self::P2pkhCopayBch),
            40 => Some(Self::P2sh20CopayBch),
            _ => None,
        }
    }

    /// Returns true for the six versions standardized as Base58Addresses (not WIF keys).
    pub(crate) const fn is_address_version(self) -> bool {
        matches!(
            self,
            Self::P2pkh
                | Self::P2sh20
                | Self::P2pkhTestnet
                | Self::P2sh20Testnet
                | Self::P2pkhCopayBch
                | Self::P2sh20CopayBch
        )
    }

    pub(crate) const fn is_p2pkh(self) -> bool {
        matches!(self, Self::P2pkh | Self::P2pkhTestnet | Self::P2pkhCopayBch)
    }
}

/// The available networks for common Base58Address versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base58AddressNetwork {
    CopayBch,
    Mainnet,
    Testnet,
}

impl Base58AddressNetwork {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CopayBch => "copayBCH",
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    pub fn from_network(network: &str) -> Option<Self> {
        match network {
            "copayBCH" => Some(Self::CopayBch),
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            _ => None,
        }
    }
}

impl core::fmt::Display for Base58AddressNetwork {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors returned while decoding Base58Addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base58AddressError {
    UnknownCharacter,
    TooShort,
    InvalidChecksum,
    UnknownAddressVersion,
    IncorrectLength,
}

impl Base58AddressError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCharacter => {
                "Base58Address error: address may only contain valid base58 characters."
            }
            Self::TooShort => "Base58Address error: address is too short to be valid.",
            Self::InvalidChecksum => "Base58Address error: address has an invalid checksum.",
            Self::UnknownAddressVersion => {
                "Base58Address error: address uses an unknown address version."
            }
            Self::IncorrectLength => {
                "Base58Address error: the encoded payload is not the correct length (20 bytes)."
            }
        }
    }
}

impl core::fmt::Display for Base58AddressError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A decoded Base58Address-like string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBase58AddressFormat {
    pub payload: Vec<u8>,
    pub version: u8,
}

/// A decoded, validated Base58Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBase58Address {
    pub payload: Vec<u8>,
    pub version: Base58AddressFormatVersion,
}

/// Encode a payload using the Base58Address format.
///
/// The returned string is only a valid Base58Address if `payload` is exactly 20
/// bytes; this matches libauth, which does not validate the payload length here.
pub fn encode_base58_address_format(version: u8, payload: &[u8], sha256: Option<&Sha256>) -> String {
    let mut content = Vec::with_capacity(payload.len() + 1);
    content.push(version);
    content.extend_from_slice(payload);
    let checksum = hash256(&content, sha256);
    content.extend_from_slice(&checksum[..4]);
    bin_to_base58(&content)
}

/// Encode a payload as a Base58Address with the given version.
pub fn encode_base58_address(
    r#type: Base58AddressFormatVersion,
    payload: &[u8],
    sha256: Option<&Sha256>,
) -> String {
    encode_base58_address_format(r#type.to_u8(), payload, sha256)
}

/// Attempt to decode a Base58Address-formatted string without validating its version.
pub fn decode_base58_address_format(
    address: &str,
    sha256: Option<&Sha256>,
) -> Result<DecodedBase58AddressFormat, String> {
    let bin = base58_to_bin(address).map_err(|error| {
        format_error(Base58AddressError::UnknownCharacter.as_str(), Some(&error))
    })?;
    if bin.len() < 5 {
        return Err(Base58AddressError::TooShort.as_str().to_string());
    }
    let (content, checksum) = bin.split_at(bin.len() - 4);
    let expected_checksum = hash256(content, sha256);
    if checksum != &expected_checksum[..4] {
        return Err(Base58AddressError::InvalidChecksum.as_str().to_string());
    }
    Ok(DecodedBase58AddressFormat {
        payload: content[1..].to_vec(),
        version: content[0],
    })
}

/// Decode and validate a Base58Address, strictly checking the version and payload length.
pub fn decode_base58_address(
    address: &str,
    sha256: Option<&Sha256>,
) -> Result<DecodedBase58Address, String> {
    let decoded = decode_base58_address_format(address, sha256)?;
    let version = Base58AddressFormatVersion::from_u8(decoded.version)
        .filter(|version| version.is_address_version())
        .ok_or_else(|| {
            Base58AddressError::UnknownAddressVersion
                .as_str()
                .to_string()
        })?;
    if decoded.payload.len() != 20 {
        return Err(Base58AddressError::IncorrectLength.as_str().to_string());
    }
    Ok(DecodedBase58Address {
        payload: decoded.payload,
        version,
    })
}
