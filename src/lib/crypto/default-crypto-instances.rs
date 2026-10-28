use super::ripemd160::{instantiate_ripemd160, Ripemd160};
use super::secp256k1::instantiate_secp256k1;
use super::secp256k1_types::Secp256k1;
use super::sha1::{instantiate_sha1, Sha1};
use super::sha256::{instantiate_sha256, Sha256};
use super::sha512::{instantiate_sha512, Sha512};

/// The default sha1 instance.
pub static sha1: Sha1 = instantiate_sha1();

/// The default sha256 instance.
pub static sha256: Sha256 = instantiate_sha256();

/// The default sha512 instance.
pub static sha512: Sha512 = instantiate_sha512();

/// The default ripemd160 instance.
pub static ripemd160: Ripemd160 = instantiate_ripemd160();

/// The default secp256k1 instance.
pub static secp256k1: Secp256k1 = instantiate_secp256k1(None);
