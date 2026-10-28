use super::hmac::{hmac_sha256, hmac_sha512, HmacFunction};
use crate::format::{format_error, number_to_bin_uint32_be};

/// Errors produced by {@link instantiatePbkdf2Function}.
pub struct Pbkdf2Error;

impl Pbkdf2Error {
    pub const invalidIterations: &'static str =
        "Invalid PBKDF2 parameters: iterations must be a positive integer.";
    pub const invalidDerivedKeyLength: &'static str =
        "Invalid PBKDF2 parameters: derived key length must be a positive integer.";
    pub const invalidHmacLength: &'static str =
        "Invalid HMAC length: HMAC length must be a positive integer.";
}

/// The parameters of a PBKDF2 derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pbkdf2Parameters {
    /// The length of the derived key in bytes.
    pub derived_key_length: usize,
    /// The password from which to derive the key.
    pub password: Vec<u8>,
    /// The number of iterations to perform.
    pub iterations: u32,
    /// The salt to use.
    pub salt: Vec<u8>,
}

/// Instantiate a PBKDF2 function as specified by RFC 2898.
///
/// @param hmacFunction - the HMAC function to use
/// @param hmacByteLength - the byte-length of the HMAC function
pub fn instantiate_pbkdf2_function(
    hmac_function: impl HmacFunction,
    hmac_byte_length: usize,
) -> impl Fn(&Pbkdf2Parameters) -> Result<Vec<u8>, String> {
    move |parameters: &Pbkdf2Parameters| {
        let Pbkdf2Parameters {
            password,
            salt,
            iterations,
            derived_key_length,
        } = parameters;
        if *iterations == 0 {
            return Err(format_error(
                Pbkdf2Error::invalidIterations,
                Some(&format!("Iterations parameter: {iterations}.")),
            ));
        }
        if *derived_key_length == 0 {
            return Err(format_error(
                Pbkdf2Error::invalidDerivedKeyLength,
                Some(&format!("Derived key length: {derived_key_length}.")),
            ));
        }
        if hmac_byte_length == 0 {
            return Err(format_error(
                Pbkdf2Error::invalidHmacLength,
                Some(&format!("HMAC length: {hmac_byte_length}.")),
            ));
        }
        const ITERATION_COUNT_BYTE_LENGTH: usize = 4;
        let mut derived_key = vec![0_u8; *derived_key_length];
        let mut block = vec![0_u8; salt.len() + ITERATION_COUNT_BYTE_LENGTH];
        block[..salt.len()].copy_from_slice(salt);
        let mut write_position = 0;
        let length = derived_key_length.div_ceil(hmac_byte_length);
        for i in 1..=length {
            block[salt.len()..].copy_from_slice(&number_to_bin_uint32_be(i as u32));
            let mut accumulated_mac = hmac_function(password, &block);
            let mut intermediate_mac = accumulated_mac.clone();
            for _ in 1..*iterations {
                intermediate_mac = hmac_function(password, &intermediate_mac);
                for k in 0..hmac_byte_length {
                    accumulated_mac[k] ^= intermediate_mac[k];
                }
            }
            let truncated_result = &accumulated_mac[..hmac_byte_length.min(*derived_key_length)];
            if write_position + truncated_result.len() > *derived_key_length {
                // As in libauth, `derivedKey.set(truncatedResult, writePosition)`
                // throws for derived key lengths which exceed, but are not a
                // multiple of, the HMAC length.
                panic!("RangeError: offset is out of bounds");
            }
            derived_key[write_position..write_position + truncated_result.len()].copy_from_slice(truncated_result);
            write_position += hmac_byte_length;
        }
        Ok(derived_key)
    }
}

const HMAC_SHA256_BYTE_LENGTH: usize = 32;

/// Derive a key using PBKDF2 and the HMAC SHA256 function as specified in RFC
/// 2898.
///
/// If the provided parameters are invalid, a string error message is returned.
///
/// @param parameters - the PBKDF2 parameters to use
/// @param sha256Hmac - a SHA256 HMAC implementation (defaults to
/// `hmacSha256`)
pub fn pbkdf2_hmac_sha256(
    parameters: &Pbkdf2Parameters,
    sha256_hmac: Option<&dyn HmacFunction>,
) -> Result<Vec<u8>, String> {
    match sha256_hmac {
        Some(hmac) => instantiate_pbkdf2_function(hmac, HMAC_SHA256_BYTE_LENGTH)(parameters),
        None => instantiate_pbkdf2_function(
            |secret: &[u8], message: &[u8]| hmac_sha256(secret, message, None),
            HMAC_SHA256_BYTE_LENGTH,
        )(parameters),
    }
}

const HMAC_SHA512_BYTE_LENGTH: usize = 64;

/// Derive a key using PBKDF2 and the HMAC SHA512 function as specified in RFC
/// 2898.
///
/// If the provided parameters are invalid, a string error message is returned.
///
/// @param parameters - the PBKDF2 parameters to use
/// @param sha512Hmac - a SHA512 HMAC implementation (defaults to
/// `hmacSha512`)
pub fn pbkdf2_hmac_sha512(
    parameters: &Pbkdf2Parameters,
    sha512_hmac: Option<&dyn HmacFunction>,
) -> Result<Vec<u8>, String> {
    match sha512_hmac {
        Some(hmac) => instantiate_pbkdf2_function(hmac, HMAC_SHA512_BYTE_LENGTH)(parameters),
        None => instantiate_pbkdf2_function(
            |secret: &[u8], message: &[u8]| hmac_sha512(secret, message, None),
            HMAC_SHA512_BYTE_LENGTH,
        )(parameters),
    }
}
