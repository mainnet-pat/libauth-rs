use std::sync::LazyLock;

use super::ripemd160::{instantiate_ripemd160, Ripemd160};
use super::secp256k1::instantiate_secp256k1;
use super::secp256k1_types::Secp256k1;
use super::sha1::{instantiate_sha1, Sha1};
use super::sha256::{instantiate_sha256, Sha256};
use super::sha512::{instantiate_sha512, Sha512};

/// The default sha1 instance (instantiated from the embedded binary).
pub static sha1: LazyLock<Sha1> =
    LazyLock::new(|| instantiate_sha1().expect("the embedded sha1 module instantiates"));

/// The default sha256 instance (instantiated from the embedded binary).
pub static sha256: LazyLock<Sha256> =
    LazyLock::new(|| instantiate_sha256().expect("the embedded sha256 module instantiates"));

/// The default sha512 instance (instantiated from the embedded binary).
pub static sha512: LazyLock<Sha512> =
    LazyLock::new(|| instantiate_sha512().expect("the embedded sha512 module instantiates"));

/// The default ripemd160 instance (instantiated from the embedded binary).
pub static ripemd160: LazyLock<Ripemd160> =
    LazyLock::new(|| instantiate_ripemd160().expect("the embedded ripemd160 module instantiates"));

/// The default secp256k1 instance (instantiated from the embedded binary).
pub static secp256k1: LazyLock<Secp256k1> =
    LazyLock::new(|| instantiate_secp256k1(None).expect("the embedded secp256k1 module instantiates"));
