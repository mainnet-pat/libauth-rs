use super::dependencies::{base64_to_bin, instantiate_rust_wasm, HashFunction, ripemd160Base64Bytes};

/// An instantiated ripemd160 hash function: `hash`, `init`, `update`, and
/// `final`. To incrementally construct a hash (e.g. for streaming), use
/// `init`, `update`, and `final`.
pub type Ripemd160 = HashFunction;

/// The most performant way to instantiate ripemd160 functionality. To avoid
/// using Node.js or DOM-specific APIs, you can use {@link instantiateRipemd160}.
pub fn instantiate_ripemd160_bytes(webassembly_bytes: &[u8]) -> Result<Ripemd160, String> {
    instantiate_rust_wasm(
        webassembly_bytes,
        "./ripemd160",
        "ripemd160",
        "ripemd160_init",
        "ripemd160_update",
        "ripemd160_final",
    )
}

/// Get the embedded WebAssembly ripemd160 binary.
pub fn get_embedded_ripemd160_binary() -> Vec<u8> {
    base64_to_bin(ripemd160Base64Bytes)
}

/// An ultimately-portable (but possibly slower) version of
/// {@link instantiateRipemd160Bytes} which does not require the consumer to
/// provide the ripemd160 binary buffer.
pub fn instantiate_ripemd160() -> Result<Ripemd160, String> {
    instantiate_ripemd160_bytes(&get_embedded_ripemd160_binary())
}
