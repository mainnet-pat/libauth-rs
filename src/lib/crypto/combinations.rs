use super::default_crypto_instances::{ripemd160 as internal_ripemd160, sha256 as internal_sha256};
use super::ripemd160::Ripemd160;
use super::sha256::Sha256;

/// Hash the given payload with sha256, then hash the 32-byte result with
/// ripemd160, returning a 20-byte hash.
///
/// This hash is used in both {@link AddressType.p2pkh} and
/// {@link AddressType.p2sh20} addresses.
///
/// @param payload - the payload to hash
/// @param crypto - the `ripemd160` and `sha256` implementations to use
/// (defaults to the internal WASM implementations)
pub fn hash160(payload: &[u8], crypto: Option<(&Ripemd160, &Sha256)>) -> Vec<u8> {
    let (ripemd160, sha256) = crypto.unwrap_or((&internal_ripemd160, &internal_sha256));
    ripemd160.hash(&sha256.hash(payload))
}

/// Hash the given payload with sha256, then hash the 32-byte result with
/// sha256, returning a 32-byte hash.
///
/// This hash is used to create {@link TransactionCommon} identifiers,
/// {@link AddressType.p2sh32} addresses, and checksums in WIF and BIP32 keys.
///
/// @param payload - the payload to hash
/// @param sha256 - an implementation of sha256 (defaults to the internal WASM
/// implementation)
pub fn hash256(payload: &[u8], sha256: Option<&Sha256>) -> Vec<u8> {
    let sha256 = sha256.unwrap_or(&internal_sha256);
    sha256.hash(&sha256.hash(payload))
}
