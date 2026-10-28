use crate::runtime::webassembly::Instance;

const SECP256K1_FLAGS_TYPE_CONTEXT: u32 = 1 << 0;
const SECP256K1_FLAGS_TYPE_COMPRESSION: u32 = 1 << 1;
const SECP256K1_FLAGS_BIT_CONTEXT_VERIFY: u32 = 1 << 8;
const SECP256K1_FLAGS_BIT_CONTEXT_SIGN: u32 = 1 << 9;
const SECP256K1_FLAGS_BIT_COMPRESSION: u32 = 1 << 8;

const SECP256K1_CONTEXT_VERIFY: u32 = SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY;
const SECP256K1_CONTEXT_SIGN: u32 = SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN;
const SECP256K1_CONTEXT_NONE: u32 = SECP256K1_FLAGS_TYPE_CONTEXT;

const SECP256K1_EC_COMPRESSED: u32 = SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION;
const SECP256K1_EC_UNCOMPRESSED: u32 = SECP256K1_FLAGS_TYPE_COMPRESSION;

/// Flags to pass to secp256k1_context_create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ContextFlag {
    NONE = SECP256K1_CONTEXT_NONE,
    VERIFY = SECP256K1_CONTEXT_VERIFY,
    SIGN = SECP256K1_CONTEXT_SIGN,
    BOTH = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY,
}

/// Flag to pass to secp256k1_ec_pubkey_serialize and
/// secp256k1_ec_privkey_export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CompressionFlag {
    COMPRESSED = SECP256K1_EC_COMPRESSED,
    UNCOMPRESSED = SECP256K1_EC_UNCOMPRESSED,
}

/// An object that wraps the WebAssembly implementation of `libsecp256k1`.
///
/// It's very unlikely that consumers will need to use this interface directly.
/// See {@link Secp256k1} for a more purely-functional API.
///
/// The members of libauth's `Secp256k1Wasm` object (`contextCreate`,
/// `pubkeyParse`, `heapU8`, ...) are this type's methods; they are implemented
/// in `secp256k1-wasm.rs`.
pub struct Secp256k1Wasm {
    /// The underlying WebAssembly instance (libauth's `instance`).
    pub(crate) instance: Instance,
}
