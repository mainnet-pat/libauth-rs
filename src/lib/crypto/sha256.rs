use super::dependencies::{base64_to_bin, instantiate_rust_wasm, HashFunction, sha256Base64Bytes};

/// An instantiated sha256 hash function: `hash`, `init`, `update`, and
/// `final`. To incrementally construct a hash (e.g. for streaming), use
/// `init`, `update`, and `final`.
pub type Sha256 = HashFunction;

/// The most performant way to instantiate sha256 functionality. To avoid
/// using Node.js or DOM-specific APIs, you can use {@link instantiateSha256}.
pub fn instantiate_sha256_bytes(webassembly_bytes: &[u8]) -> Result<Sha256, String> {
    instantiate_rust_wasm(
        webassembly_bytes,
        "./sha256",
        "sha256",
        "sha256_init",
        "sha256_update",
        "sha256_final",
    )
}

/// Get the embedded WebAssembly sha256 binary.
pub fn get_embedded_sha256_binary() -> Vec<u8> {
    base64_to_bin(sha256Base64Bytes)
}

/// An ultimately-portable (but possibly slower) version of
/// {@link instantiateSha256Bytes} which does not require the consumer to
/// provide the sha256 binary buffer.
pub fn instantiate_sha256() -> Result<Sha256, String> {
    instantiate_sha256_bytes(&get_embedded_sha256_binary())
}
