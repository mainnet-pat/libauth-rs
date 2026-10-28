use super::dependencies::{base64_to_bin, instantiate_rust_wasm, HashFunction, sha1Base64Bytes};

/// An instantiated sha1 hash function: `hash`, `init`, `update`, and
/// `final`. To incrementally construct a hash (e.g. for streaming), use
/// `init`, `update`, and `final`.
pub type Sha1 = HashFunction;

/// The most performant way to instantiate sha1 functionality. To avoid
/// using Node.js or DOM-specific APIs, you can use {@link instantiateSha1}.
pub fn instantiate_sha1_bytes(webassembly_bytes: &[u8]) -> Result<Sha1, String> {
    instantiate_rust_wasm(
        webassembly_bytes,
        "./sha1",
        "sha1",
        "sha1_init",
        "sha1_update",
        "sha1_final",
    )
}

/// Get the embedded WebAssembly sha1 binary.
pub fn get_embedded_sha1_binary() -> Vec<u8> {
    base64_to_bin(sha1Base64Bytes)
}

/// An ultimately-portable (but possibly slower) version of
/// {@link instantiateSha1Bytes} which does not require the consumer to
/// provide the sha1 binary buffer.
pub fn instantiate_sha1() -> Result<Sha1, String> {
    instantiate_sha1_bytes(&get_embedded_sha1_binary())
}
