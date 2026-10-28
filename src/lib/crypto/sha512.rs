use super::dependencies::{base64_to_bin, instantiate_rust_wasm, HashFunction, sha512Base64Bytes};

/// An instantiated sha512 hash function: `hash`, `init`, `update`, and
/// `final`. To incrementally construct a hash (e.g. for streaming), use
/// `init`, `update`, and `final`.
pub type Sha512 = HashFunction;

/// The most performant way to instantiate sha512 functionality. To avoid
/// using Node.js or DOM-specific APIs, you can use {@link instantiateSha512}.
pub fn instantiate_sha512_bytes(webassembly_bytes: &[u8]) -> Result<Sha512, String> {
    instantiate_rust_wasm(
        webassembly_bytes,
        "./sha512",
        "sha512",
        "sha512_init",
        "sha512_update",
        "sha512_final",
    )
}

/// Get the embedded WebAssembly sha512 binary.
pub fn get_embedded_sha512_binary() -> Vec<u8> {
    base64_to_bin(sha512Base64Bytes)
}

/// An ultimately-portable (but possibly slower) version of
/// {@link instantiateSha512Bytes} which does not require the consumer to
/// provide the sha512 binary buffer.
pub fn instantiate_sha512() -> Result<Sha512, String> {
    instantiate_sha512_bytes(&get_embedded_sha512_binary())
}
