use crate::address::{
    decode_base58_address_format, encode_base58_address_format, Base58AddressFormatVersion,
};
use crate::crypto::Sha256;

/// Errors produced while decoding Wallet Import Format (WIF) private keys.
pub struct WalletImportFormatError;

impl WalletImportFormatError {
    pub const incorrectLength: &'static str =
        "The WIF private key payload is not the correct length.";
}

/// The network and address format in which a WIF-encoded private key is
/// expected to be used.
///
/// WIF-encoding is generally used to serialize private keys for Pay to Public
/// Key (P2PKH) addresses – each WIF-encoded private key specifies the
/// compression of the public key to use in the P2PKH address:
/// - The values `mainnet` and `testnet` indicate that the address should use
/// the compressed form of the derived public key (33 bytes, beginning with `0x02`
/// or `0x03`) on the respective network.
/// - The less common `mainnetUncompressed` and `testnetUncompressed` values
/// indicate that the address should use the uncompressed form of the public key
/// (65 bytes beginning with `0x04`) on the specified network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletImportFormatType {
    /// `'mainnet'`
    Mainnet,
    /// `'mainnetUncompressed'`
    MainnetUncompressed,
    /// `'testnet'`
    Testnet,
    /// `'testnetUncompressed'`
    TestnetUncompressed,
}

/// A decoded WIF private key: the private key and its
/// {@link WalletImportFormatType}.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPrivateKeyWif {
    /// The 32-byte Secp256k1 private key.
    pub private_key: Vec<u8>,
    /// The intended network and public key compression (libauth's `type`).
    pub key_type: WalletImportFormatType,
}

/// Encode a private key using Wallet Import Format (WIF).
///
/// WIF encodes the 32-byte private key, a 4-byte checksum, and a `type`
/// indicating the intended usage for the private key. See
/// {@link WalletImportFormatType} for details.
///
/// @param privateKey - a 32-byte Secp256k1 ECDSA private key
/// @param type - the intended usage of the private key (e.g. `mainnet` or
/// `testnet`)
/// @param sha256 - an implementation of sha256
pub fn encode_private_key_wif(
    private_key: &[u8],
    key_type: WalletImportFormatType,
    sha256: Option<&Sha256>,
) -> String {
    const COMPRESSED_BYTE: u8 = 0x01;
    let mainnet = matches!(
        key_type,
        WalletImportFormatType::Mainnet | WalletImportFormatType::MainnetUncompressed
    );
    let compressed = matches!(
        key_type,
        WalletImportFormatType::Mainnet | WalletImportFormatType::Testnet
    );
    let payload = if compressed {
        [private_key, &[COMPRESSED_BYTE]].concat()
    } else {
        private_key.to_vec()
    };
    encode_base58_address_format(
        if mainnet {
            Base58AddressFormatVersion::Wif
        } else {
            Base58AddressFormatVersion::WifTestnet
        }
        .to_u8(),
        &payload,
        sha256,
    )
}

/// Decode a private key using Wallet Import Format (WIF). See
/// {@link encodePrivateKeyWif} for details.
///
/// @param wifKey - the private key to decode (in Wallet Import Format)
/// @param sha256 - an implementation of sha256
pub fn decode_private_key_wif(
    wif_key: &str,
    sha256: Option<&Sha256>,
) -> Result<DecodedPrivateKeyWif, String> {
    const COMPRESSED_PAYLOAD_LENGTH: usize = 33;
    let decoded = decode_base58_address_format(wif_key, sha256)?;
    let mainnet = decoded.version == Base58AddressFormatVersion::Wif.to_u8();
    let compressed = decoded.payload.len() == COMPRESSED_PAYLOAD_LENGTH;
    let private_key = if compressed {
        decoded.payload[..decoded.payload.len() - 1].to_vec()
    } else {
        decoded.payload
    };
    let key_type = match (mainnet, compressed) {
        (true, true) => WalletImportFormatType::Mainnet,
        (true, false) => WalletImportFormatType::MainnetUncompressed,
        (false, true) => WalletImportFormatType::Testnet,
        (false, false) => WalletImportFormatType::TestnetUncompressed,
    };
    Ok(DecodedPrivateKeyWif {
        private_key,
        key_type,
    })
}
