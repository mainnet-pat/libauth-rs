use crate::format::base64_to_bin;
use crate::runtime::webassembly::{parse_module, HostImports, Instance, Trap};

pub use super::secp256k1_wasm_types::Secp256k1Wasm;
pub use super::secp256k1_wasm_types::{CompressionFlag, ContextFlag};

use super::secp256k1_base64::secp256k1Base64Bytes;

impl Secp256k1Wasm {
    fn call(&mut self, name: &str, args: &[u64]) -> u32 {
        match self.instance.call_export(name, args) {
            Ok(results) => results.first().copied().unwrap_or(0) as u32,
            Err(trap) => panic!("Secp256k1 WebAssembly error in {name}: {trap}"),
        }
    }

    /// Create a secp256k1 context object (`secp256k1_context_create`),
    /// returning a pointer to the context.
    pub fn context_create(&mut self, context: ContextFlag) -> u32 {
        self.call("_secp256k1_context_create", &[context as u64])
    }

    /// Update the context randomization to protect against side-channel
    /// leakage (`secp256k1_context_randomize`); `seed_ptr` points to a 32-byte
    /// random seed. Returns `1` on success.
    pub fn context_randomize(&mut self, context_ptr: u32, seed_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_context_randomize",
            &[u64::from(context_ptr), u64::from(seed_ptr)],
        )
    }

    /// Frees a pointer allocated by the `malloc` method.
    pub fn free(&mut self, pointer: u32) -> u32 {
        self.call("_free", &[u64::from(pointer)])
    }

    /// The WebAssembly module's linear memory as 32-bit words (libauth's
    /// `heapU32`); the word at index `i` holds bytes `4i..4i + 4`.
    pub fn heap_u32(&self, index: u32) -> u32 {
        let bytes = self.read_heap_u8(index * 4, 4);
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Set a word of the module's linear memory (libauth's
    /// `heapU32.set([value], index)`).
    pub fn set_heap_u32(&mut self, index: u32, value: u32) {
        self.heap_u8_mut(index * 4, 4)
            .copy_from_slice(&value.to_le_bytes());
    }

    /// The module's linear memory (libauth's `heapU8`), from `pointer` for
    /// `bytes` bytes, for writing.
    pub fn heap_u8_mut(&mut self, pointer: u32, bytes: u32) -> &mut [u8] {
        self.instance
            .memory_slice_mut(pointer, bytes)
            .expect("secp256k1 memory access is in bounds")
    }

    /// The underlying WebAssembly instance.
    pub fn instance(&self) -> &Instance {
        &self.instance
    }

    /// Allocates the given number of bytes in WebAssembly memory, returning a
    /// pointer to the allocation.
    pub fn malloc(&mut self, bytes: u32) -> u32 {
        self.call("_malloc", &[u64::from(bytes)])
    }

    /// The Rust equivalent of the `secp256k1` `size_t` type; allocates a
    /// 4-byte value holding `value`, returning a pointer to it.
    pub fn malloc_size_t(&mut self, value: u32) -> u32 {
        let pointer = self.malloc(4);
        self.set_heap_u32(pointer >> 2, value);
        pointer
    }

    /// Allocates space for the provided array, and assigns the array to the
    /// space, returning a pointer to it.
    pub fn malloc_uint8_array(&mut self, array: &[u8]) -> u32 {
        let pointer = self.malloc(array.len() as u32);
        self.heap_u8_mut(pointer, array.len() as u32)
            .copy_from_slice(array);
        pointer
    }

    /// Tweak a private key in place by adding a 32-byte tweak
    /// (`secp256k1_ec_privkey_tweak_add`). Returns `1` on success.
    pub fn privkey_tweak_add(&mut self, context_ptr: u32, secret_key_ptr: u32, tweak_num256_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ec_privkey_tweak_add",
            &[u64::from(context_ptr), u64::from(secret_key_ptr), u64::from(tweak_num256_ptr)],
        )
    }

    /// Tweak a private key in place by multiplying it by a 32-byte tweak
    /// (`secp256k1_ec_privkey_tweak_mul`). Returns `1` on success.
    pub fn privkey_tweak_mul(&mut self, context_ptr: u32, secret_key_ptr: u32, tweak_num256_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ec_privkey_tweak_mul",
            &[u64::from(context_ptr), u64::from(secret_key_ptr), u64::from(tweak_num256_ptr)],
        )
    }

    /// Compute the public key for a secret key (`secp256k1_ec_pubkey_create`).
    /// Returns `1` if the secret key was valid.
    pub fn pubkey_create(&mut self, context_ptr: u32, public_key_ptr: u32, secret_key_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ec_pubkey_create",
            &[u64::from(context_ptr), u64::from(public_key_ptr), u64::from(secret_key_ptr)],
        )
    }

    /// Parse a variable-length public key into the internal 64-byte format
    /// (`secp256k1_ec_pubkey_parse`). Returns `1` if the public key was fully
    /// valid.
    pub fn pubkey_parse(
        &mut self,
        context_ptr: u32,
        public_key_out_ptr: u32,
        public_key_in_ptr: u32,
        public_key_in_length: u32,
    ) -> u32 {
        self.call(
            "_secp256k1_ec_pubkey_parse",
            &[
                u64::from(context_ptr),
                u64::from(public_key_out_ptr),
                u64::from(public_key_in_ptr),
                u64::from(public_key_in_length),
            ],
        )
    }

    /// Serialize a public key into a serialized byte sequence
    /// (`secp256k1_ec_pubkey_serialize`). Always returns `1`.
    pub fn pubkey_serialize(
        &mut self,
        context_ptr: u32,
        output_ptr: u32,
        output_length_ptr: u32,
        public_key_ptr: u32,
        compression: CompressionFlag,
    ) -> u32 {
        self.call(
            "_secp256k1_ec_pubkey_serialize",
            &[
                u64::from(context_ptr),
                u64::from(output_ptr),
                u64::from(output_length_ptr),
                u64::from(public_key_ptr),
                compression as u64,
            ],
        )
    }

    /// Tweak a public key by adding tweak times the generator to it
    /// (`secp256k1_ec_pubkey_tweak_add`). Returns `1` on success.
    pub fn pubkey_tweak_add(&mut self, context_ptr: u32, public_key_ptr: u32, tweak_num256_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ec_pubkey_tweak_add",
            &[u64::from(context_ptr), u64::from(public_key_ptr), u64::from(tweak_num256_ptr)],
        )
    }

    /// Tweak a public key by multiplying it by a tweak value
    /// (`secp256k1_ec_pubkey_tweak_mul`). Returns `1` on success.
    pub fn pubkey_tweak_mul(&mut self, context_ptr: u32, public_key_ptr: u32, tweak_num256_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ec_pubkey_tweak_mul",
            &[u64::from(context_ptr), u64::from(public_key_ptr), u64::from(tweak_num256_ptr)],
        )
    }

    /// Read from WebAssembly memory by creating a new Uint8Array beginning at
    /// `pointer` and continuing through the number of `bytes` provided.
    pub fn read_heap_u8(&self, pointer: u32, bytes: u32) -> &[u8] {
        self.instance
            .memory_slice(pointer, bytes)
            .expect("secp256k1 memory access is in bounds")
    }

    /// Read a `size_t` from WebAssembly memory.
    pub fn read_size_t(&self, pointer: u32) -> u32 {
        self.heap_u32(pointer >> 2)
    }

    /// Recover an ECDSA public key from a signature (`secp256k1_ecdsa_recover`).
    /// Returns `1` if the public key was successfully recovered.
    pub fn recover(&mut self, context_ptr: u32, public_key_ptr: u32, r_sig_ptr: u32, msg32_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_recover",
            &[u64::from(context_ptr), u64::from(public_key_ptr), u64::from(r_sig_ptr), u64::from(msg32_ptr)],
        )
    }

    /// Parse an ECDSA signature in compact (64 bytes) format with a recovery
    /// number (`secp256k1_ecdsa_recoverable_signature_parse_compact`). Returns
    /// `1` when the signature could be parsed.
    pub fn recoverable_signature_parse(&mut self, context_ptr: u32, output_r_sig_ptr: u32, input_sig_ptr: u32, rid: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_recoverable_signature_parse_compact",
            &[u64::from(context_ptr), u64::from(output_r_sig_ptr), u64::from(input_sig_ptr), u64::from(rid)],
        )
    }

    /// Serialize an ECDSA signature in compact format (64 bytes + recovery id)
    /// (`secp256k1_ecdsa_recoverable_signature_serialize_compact`). Always
    /// returns `1`.
    pub fn recoverable_signature_serialize(
        &mut self,
        context_ptr: u32,
        sig_out_ptr: u32,
        rec_id_out_ptr: u32,
        r_sig_ptr: u32,
    ) -> u32 {
        self.call(
            "_secp256k1_ecdsa_recoverable_signature_serialize_compact",
            &[u64::from(context_ptr), u64::from(sig_out_ptr), u64::from(rec_id_out_ptr), u64::from(r_sig_ptr)],
        )
    }

    /// Create a Schnorr signature (`secp256k1_schnorr_sign`). Returns `1` if
    /// signing succeeded.
    pub fn schnorr_sign(&mut self, context_ptr: u32, output_sig_ptr: u32, msg32_ptr: u32, secret_key_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_schnorr_sign",
            &[u64::from(context_ptr), u64::from(output_sig_ptr), u64::from(msg32_ptr), u64::from(secret_key_ptr)],
        )
    }

    /// Verify a Schnorr signature (`secp256k1_schnorr_verify`). Returns `1` if
    /// the signature is valid.
    pub fn schnorr_verify(&mut self, context_ptr: u32, sig_ptr: u32, msg32_ptr: u32, public_key_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_schnorr_verify",
            &[u64::from(context_ptr), u64::from(sig_ptr), u64::from(msg32_ptr), u64::from(public_key_ptr)],
        )
    }

    /// Verify an ECDSA secret key (`secp256k1_ec_seckey_verify`). Returns `1`
    /// if the secret key is valid.
    pub fn seckey_verify(&mut self, context_ptr: u32, secret_key_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ec_seckey_verify",
            &[u64::from(context_ptr), u64::from(secret_key_ptr)],
        )
    }

    /// Create an ECDSA signature (`secp256k1_ecdsa_sign`). The created
    /// signature is always in lower-S form. Returns `1` if signing succeeded.
    pub fn sign(&mut self, context_ptr: u32, output_sig_ptr: u32, msg32_ptr: u32, secret_key_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_sign",
            &[u64::from(context_ptr), u64::from(output_sig_ptr), u64::from(msg32_ptr), u64::from(secret_key_ptr)],
        )
    }

    /// Create a recoverable ECDSA signature
    /// (`secp256k1_ecdsa_sign_recoverable`). Returns `1` if signing succeeded.
    pub fn sign_recoverable(&mut self, context_ptr: u32, output_r_sig_ptr: u32, msg32_ptr: u32, secret_key_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_sign_recoverable",
            &[u64::from(context_ptr), u64::from(output_r_sig_ptr), u64::from(msg32_ptr), u64::from(secret_key_ptr)],
        )
    }

    /// Malleate an ECDSA signature (`secp256k1_ecdsa_signature_malleate`).
    /// Always returns `1`.
    pub fn signature_malleate(&mut self, context_ptr: u32, output_sig_ptr: u32, input_sig_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_signature_malleate",
            &[u64::from(context_ptr), u64::from(output_sig_ptr), u64::from(input_sig_ptr)],
        )
    }

    /// Convert a signature to a normalized lower-S form
    /// (`secp256k1_ecdsa_signature_normalize`). Returns `1` if the signature
    /// was not normalized, `0` if it already was.
    pub fn signature_normalize(&mut self, context_ptr: u32, output_sig_ptr: u32, input_sig_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_signature_normalize",
            &[u64::from(context_ptr), u64::from(output_sig_ptr), u64::from(input_sig_ptr)],
        )
    }

    /// Parse an ECDSA signature in compact (64 bytes) format
    /// (`secp256k1_ecdsa_signature_parse_compact`). Returns `1` when the
    /// signature could be parsed.
    pub fn signature_parse_compact(&mut self, context_ptr: u32, sig_out_ptr: u32, compact_sig_in_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_signature_parse_compact",
            &[u64::from(context_ptr), u64::from(sig_out_ptr), u64::from(compact_sig_in_ptr)],
        )
    }

    /// Parse a DER ECDSA signature (`secp256k1_ecdsa_signature_parse_der`).
    /// Returns `1` when the signature could be parsed.
    pub fn signature_parse_der(&mut self, context_ptr: u32, sig_out_ptr: u32, sig_der_in_ptr: u32, sig_der_in_length: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_signature_parse_der",
            &[
                u64::from(context_ptr),
                u64::from(sig_out_ptr),
                u64::from(sig_der_in_ptr),
                u64::from(sig_der_in_length),
            ],
        )
    }

    /// Serialize an ECDSA signature in compact (64 byte) format
    /// (`secp256k1_ecdsa_signature_serialize_compact`). Always returns `1`.
    pub fn signature_serialize_compact(&mut self, context_ptr: u32, output_compact_sig_ptr: u32, input_sig_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_signature_serialize_compact",
            &[u64::from(context_ptr), u64::from(output_compact_sig_ptr), u64::from(input_sig_ptr)],
        )
    }

    /// Serialize an ECDSA signature in DER format
    /// (`secp256k1_ecdsa_signature_serialize_der`). Returns `1` if enough space
    /// was available to serialize.
    pub fn signature_serialize_der(
        &mut self,
        context_ptr: u32,
        output_der_sig_ptr: u32,
        output_der_sig_length_ptr: u32,
        input_sig_ptr: u32,
    ) -> u32 {
        self.call(
            "_secp256k1_ecdsa_signature_serialize_der",
            &[
                u64::from(context_ptr),
                u64::from(output_der_sig_ptr),
                u64::from(output_der_sig_length_ptr),
                u64::from(input_sig_ptr),
            ],
        )
    }

    /// Verify an ECDSA signature (`secp256k1_ecdsa_verify`). Returns `1` for a
    /// correct signature.
    pub fn verify(&mut self, context_ptr: u32, sig_ptr: u32, msg32_ptr: u32, pubkey_ptr: u32) -> u32 {
        self.call(
            "_secp256k1_ecdsa_verify",
            &[u64::from(context_ptr), u64::from(sig_ptr), u64::from(msg32_ptr), u64::from(pubkey_ptr)],
        )
    }
}

const STACK_ALIGN: u32 = 16;
const GLOBAL_BASE: u32 = 1024;
const TOTAL_STACK: u32 = 5_242_880;
const TOTAL_MEMORY: u32 = 16_777_216;
const STATIC_DATA_LENGTH: u32 = 67_696;
const DYNAMICTOP_PTR_SIZE: u32 = 4;

fn align_memory(factor: u32, size: u32) -> u32 {
    size.div_ceil(factor) * factor
}

/// The imports (`env`) provided to the Emscripten-built module.
struct Secp256k1Environment;

impl HostImports for Secp256k1Environment {
    fn call(
        &mut self,
        instance: &mut Instance,
        name: &str,
        args: &[u64],
    ) -> Result<Option<u64>, Trap> {
        match name {
            "abort" | "_abort" => {
                let pointer = args.first().copied().unwrap_or(0) as u32;
                let mut message = String::from("secp256k1 abort");
                if let Ok(bytes) = instance.memory_slice(pointer, 128) {
                    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(0);
                    if end > 0 {
                        message = String::from_utf8_lossy(&bytes[..end]).into_owned();
                    }
                }
                Err(Trap(message))
            }
            "enlargeMemory" | "abortOnCannotGrowMemory" => Err(Trap(
                "Secp256k1 Error: memory growth was requested.".to_string(),
            )),
            "getTotalMemory" => Ok(Some(TOTAL_MEMORY as u64)),
            "___setErrNo" => {
                let value = args.first().copied().unwrap_or(0);
                if let Ok(results) = instance.call_export("___errno_location", &[]) {
                    if let Some(location) = results.first() {
                        let address = *location as u32;
                        if let Ok(bytes) = instance.memory_slice_mut(address, 4) {
                            bytes.copy_from_slice(&(value as u32).to_le_bytes());
                        }
                    }
                }
                Ok(Some(value))
            }
            "_emscripten_memcpy_big" => {
                let destination = args[0] as u32;
                let source = args[1] as u32;
                let count = args[2] as u32;
                let data = instance.memory_slice(source, count)?.to_vec();
                instance.memory_slice_mut(destination, count)?.copy_from_slice(&data);
                Ok(Some(destination as u64))
            }
            other => Err(Trap(format!("Unsupported host import: {other}"))),
        }
    }
}

/// Method to instantiate the WebAssembly secp256k1 module from bytes, returning
/// a {@link Secp256k1Wasm} wrapper.
///
/// Most applications should use {@link instantiateSecp256k1} instead.
pub fn instantiate_secp256k1_wasm_bytes(webassembly_bytes: &[u8]) -> Result<Secp256k1Wasm, String> {
    let module = parse_module(webassembly_bytes)?;
    let static_top_initial = GLOBAL_BASE + STATIC_DATA_LENGTH + STACK_ALIGN;
    let dynamic_top_ptr = static_top_initial;
    let static_top = align_memory(STACK_ALIGN, static_top_initial + DYNAMICTOP_PTR_SIZE);
    let stack_top = align_memory(STACK_ALIGN, static_top);
    let stack_max = stack_top + TOTAL_STACK;
    let dynamic_base = align_memory(STACK_ALIGN, stack_max);
    let mut instance = Instance::new(
        module,
        TOTAL_MEMORY as usize,
        vec![0, dynamic_top_ptr as u64, stack_top as u64],
        Box::new(Secp256k1Environment),
    );
    // Emscripten's preamble writes the initial dynamic top pointer.
    instance
        .memory_slice_mut(dynamic_top_ptr, 4)
        .map_err(|trap| trap.0)?
        .copy_from_slice(&dynamic_base.to_le_bytes());
    if let Some(start) = instance
        .module
        .exports
        .iter()
        .find(|export| export.name == "__start")
        .map(|export| export.index)
    {
        instance.call_function(start, &[]).map_err(|trap| trap.0)?;
    }
    Ok(Secp256k1Wasm { instance })
}

/// Get the embedded WebAssembly secp256k1 binary.
pub fn get_embedded_secp256k1_binary() -> Vec<u8> {
    base64_to_bin(secp256k1Base64Bytes)
}

/// An ultimately-portable (but slower) version of
/// `instantiateSecp256k1WasmBytes` that does not require the consumer to
/// provide the secp256k1 binary.
///
/// Most applications should use {@link instantiateSecp256k1} instead.
pub fn instantiate_secp256k1_wasm() -> Result<Secp256k1Wasm, String> {
    instantiate_secp256k1_wasm_bytes(&get_embedded_secp256k1_binary())
}
