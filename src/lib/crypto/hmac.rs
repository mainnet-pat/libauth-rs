use super::default_crypto_instances::{sha256 as internal_sha256, sha512 as internal_sha512};
use super::sha256::Sha256;
use super::sha512::Sha512;
use crate::format::flatten_bin_array;

/// An HMAC function: `(secret, message) => hmac`.
pub trait HmacFunction: Fn(&[u8], &[u8]) -> Vec<u8> {}

impl<F: Fn(&[u8], &[u8]) -> Vec<u8>> HmacFunction for F {}

/// Instantiate a hash-based message authentication code (HMAC) function as
/// specified by RFC 2104.
///
/// @param hashFunction - a cryptographic hash function that iterates a basic
/// compression function over blocks of data
/// @param blockByteLength - the byte-length of blocks used in `hashFunction`
pub fn instantiate_hmac_function(
    hash_function: impl Fn(&[u8]) -> Vec<u8>,
    block_byte_length: usize,
) -> impl HmacFunction {
    move |secret: &[u8], message: &[u8]| {
        let mut key = vec![0_u8; block_byte_length];
        let secret = if secret.len() > block_byte_length {
            hash_function(secret)
        } else {
            secret.to_vec()
        };
        key[..secret.len()].copy_from_slice(&secret);
        const INNER_PADDING_FILL: u8 = 0x36;
        let inner_prefix: Vec<u8> = key.iter().map(|byte| INNER_PADDING_FILL ^ byte).collect();
        let inner_content = flatten_bin_array(&[inner_prefix, message.to_vec()]);
        let inner_result = hash_function(&inner_content);
        const OUTER_PADDING_FILL: u8 = 0x5c;
        let outer_prefix: Vec<u8> = key.iter().map(|byte| OUTER_PADDING_FILL ^ byte).collect();
        hash_function(&flatten_bin_array(&[outer_prefix, inner_result]))
    }
}

const SHA256_BLOCK_BYTE_LENGTH: usize = 64;

/// Create a hash-based message authentication code using HMAC-SHA256 as
/// specified in `RFC 4231`. Returns a 32-byte Uint8Array.
///
/// Secrets longer than the block byte-length (64 bytes) are hashed before use,
/// shortening their length to the minimum recommended length (32 bytes). See
/// `RFC 2104` for details.
///
/// @param secret - the secret key (recommended length: 32-64 bytes)
/// @param message - the message to authenticate
/// @param sha256 - an implementation of Sha256 (defaults to the internal
/// implementation)
pub fn hmac_sha256(secret: &[u8], message: &[u8], sha256: Option<&Sha256>) -> Vec<u8> {
    let sha256 = sha256.unwrap_or(&internal_sha256);
    instantiate_hmac_function(|input| sha256.hash(input), SHA256_BLOCK_BYTE_LENGTH)(secret, message)
}

const SHA512_BLOCK_BYTE_LENGTH: usize = 128;

/// Create a hash-based message authentication code using HMAC-SHA512 as
/// specified in `RFC 4231`. Returns a 64-byte Uint8Array.
///
/// Secrets longer than the block byte-length (128 bytes) are hashed before use,
/// shortening their length to the minimum recommended length (64 bytes). See
/// `RFC 2104` for details.
///
/// @param secret - the secret key (recommended length: 64-128 bytes)
/// @param message - the message to authenticate
/// @param sha512 - an implementation of Sha512 (defaults to the internal
/// implementation)
pub fn hmac_sha512(secret: &[u8], message: &[u8], sha512: Option<&Sha512>) -> Vec<u8> {
    let sha512 = sha512.unwrap_or(&internal_sha512);
    instantiate_hmac_function(|input| sha512.hash(input), SHA512_BLOCK_BYTE_LENGTH)(secret, message)
}
