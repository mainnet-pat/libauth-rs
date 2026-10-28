use super::dependencies::{
    instantiate_secp256k1_wasm, instantiate_secp256k1_wasm_bytes, CompressionFlag, ContextFlag,
    Secp256k1Wasm,
};
use super::secp256k1_types::{RecoverableSignature, RecoveryId, Secp256k1};
use crate::runtime::webassembly::PerThread;

/// Errors produced by {@link Secp256k1} operations.
pub struct Secp256k1Error;

impl Secp256k1Error {
    pub const unparsableSignature: &'static str = "Failed to parse signature.";
    pub const unparsablePublicKey: &'static str = "Failed to parse public key.";
    pub const derivePublicKeyFromInvalidPrivateKey: &'static str =
        "Cannot derive public key from invalid private key.";
    pub const signWithInvalidPrivateKey: &'static str =
        "Failed to sign message hash. The private key is not valid.";
    pub const recoverPublicKeyWithUnparsableSignature: &'static str =
        "Failed to recover public key. Could not parse signature.";
    pub const recoverPublicKeyInvalidMaterial: &'static str =
        "Failed to recover public key. The compact signature, recovery, or message hash is invalid.";
    pub const addTweakPrivateKey: &'static str = "Private key is invalid or adding failed.";
    pub const mulTweakPrivateKey: &'static str = "Private key is invalid or multiplying failed.";
    pub const addTweakPublicKey: &'static str = "Failed to tweak public key (by addition).";
    pub const mulTweakPublicKey: &'static str = "Failed to tweak public key (by multiplication).";
}

const COMPACT_SIG_LENGTH: usize = 64;
const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 33;
const INTERNAL_PUBLIC_KEY_LENGTH: usize = 64;
const INTERNAL_SIG_LENGTH: usize = 64;
const MAX_PUBLIC_KEY_LENGTH: usize = 65;
const MAX_ECDSA_SIG_LENGTH: usize = 72;
const MESSAGE_HASH_LENGTH: usize = 32;
const PRIVATE_KEY_LENGTH: usize = 32;
const SCHNORR_SIG_LENGTH: usize = 64;
const UNCOMPRESSED_PUBLIC_KEY_LENGTH: usize = 65;
const RANDOM_SEED_LENGTH: usize = 32;
const RECOVERABLE_SIG_LENGTH: usize = 65;

/// The state captured by libauth's `wrapSecp256k1Wasm`: a context and scratch
/// pointers allocated once in the module's memory.
pub(crate) struct WrappedSecp256k1Wasm {
    wasm: Secp256k1Wasm,
    context_ptr: u32,
    sig_scratch: u32,
    public_key_scratch: u32,
    message_hash_scratch: u32,
    internal_public_key_ptr: u32,
    internal_sig_ptr: u32,
    schnorr_sig_ptr: u32,
    private_key_ptr: u32,
    internal_r_sig_ptr: u32,
    recovery_num_ptr: u32,
    length_ptr: u32,
}


impl WrappedSecp256k1Wasm {
    fn write(&mut self, pointer: u32, data: &[u8]) {
        self.wasm
            .heap_u8_mut(pointer, data.len() as u32)
            .copy_from_slice(data);
    }

    fn write_padded(&mut self, pointer: u32, length: usize, data: &[u8]) {
        let mut padded = vec![0_u8; length];
        let copy_length = core::cmp::min(length, data.len());
        padded[..copy_length].copy_from_slice(&data[..copy_length]);
        self.write(pointer, &padded);
    }

    fn read(&mut self, pointer: u32, length: usize) -> Vec<u8> {
        self.wasm.read_heap_u8(pointer, length as u32).to_vec()
    }

    fn set_length(&mut self, value: u32) {
        self.write(self.length_ptr, &value.to_le_bytes());
    }

    fn get_length(&mut self) -> u32 {
        let bytes = self.read(self.length_ptr, 4);
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn parse_public_key(&mut self, public_key: &[u8]) -> bool {
        self.write_padded(self.public_key_scratch, MAX_PUBLIC_KEY_LENGTH, public_key);
        self.wasm.pubkey_parse(self.context_ptr, self.internal_public_key_ptr, self.public_key_scratch, public_key.len() as u32)
            == 1
    }

    fn serialize_public_key(&mut self, length: u32, flag: CompressionFlag) -> Vec<u8> {
        self.set_length(length);
        let _ = self.wasm.pubkey_serialize(self.context_ptr, self.public_key_scratch, self.length_ptr, self.internal_public_key_ptr, flag);
        let serialized_length = self.get_length() as usize;
        self.read(self.public_key_scratch, serialized_length)
    }

    fn serialized_public_key(&mut self, compressed: bool) -> Vec<u8> {
        if compressed {
            self.serialize_public_key(
                COMPRESSED_PUBLIC_KEY_LENGTH as u32,
                CompressionFlag::COMPRESSED,
            )
        } else {
            self.serialize_public_key(
                UNCOMPRESSED_PUBLIC_KEY_LENGTH as u32,
                CompressionFlag::UNCOMPRESSED,
            )
        }
    }

    fn parse_signature(&mut self, signature: &[u8], is_der: bool) -> bool {
        self.write_padded(self.sig_scratch, MAX_ECDSA_SIG_LENGTH, signature);
        let result = if is_der {
            self.wasm.signature_parse_der(self.context_ptr, self.internal_sig_ptr, self.sig_scratch, signature.len() as u32)
        } else {
            self.wasm.signature_parse_compact(self.context_ptr, self.internal_sig_ptr, self.sig_scratch)
        };
        result == 1
    }

    fn compact_signature(&mut self) -> Vec<u8> {
        let _ = self.wasm.signature_serialize_compact(self.context_ptr, self.sig_scratch, self.internal_sig_ptr);
        self.read(self.sig_scratch, COMPACT_SIG_LENGTH)
    }

    fn der_signature(&mut self) -> Vec<u8> {
        self.set_length(MAX_ECDSA_SIG_LENGTH as u32);
        let _ = self.wasm.signature_serialize_der(self.context_ptr, self.sig_scratch, self.length_ptr, self.internal_sig_ptr);
        let length = self.get_length() as usize;
        self.read(self.sig_scratch, length)
    }

    fn fill_message_hash(&mut self, message_hash: &[u8]) {
        self.write_padded(self.message_hash_scratch, MESSAGE_HASH_LENGTH, message_hash);
    }

    fn fill_private_key(&mut self, private_key: &[u8]) {
        self.write_padded(self.private_key_ptr, PRIVATE_KEY_LENGTH, private_key);
    }

    fn zero_private_key(&mut self) {
        self.write(self.private_key_ptr, &[0_u8; PRIVATE_KEY_LENGTH]);
    }

    /// Convert a public key to compressed form.
    pub fn compress_public_key(&mut self, public_key: &[u8]) -> Result<Vec<u8>, String> {
        if !self.parse_public_key(public_key) {
            return Err(Secp256k1Error::unparsablePublicKey.to_string());
        }
        Ok(self.serialized_public_key(true))
    }

    /// Convert a public key to uncompressed form.
    pub fn uncompress_public_key(&mut self, public_key: &[u8]) -> Result<Vec<u8>, String> {
        if !self.parse_public_key(public_key) {
            return Err(Secp256k1Error::unparsablePublicKey.to_string());
        }
        Ok(self.serialized_public_key(false))
    }

    /// Validate a public key's encoding.
    pub fn validate_public_key(&mut self, public_key: &[u8]) -> bool {
        self.parse_public_key(public_key)
    }

    /// Validate a private key.
    pub fn validate_private_key(&mut self, private_key: &[u8]) -> bool {
        self.fill_private_key(private_key);
        let result = self.wasm.seckey_verify(self.context_ptr, self.private_key_ptr);
        self.zero_private_key();
        result == 1
    }

    /// Derive a public key from a private key.
    pub fn derive_public_key(
        &mut self,
        compressed: bool,
        private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.fill_private_key(private_key);
        let result = self.wasm.pubkey_create(self.context_ptr, self.internal_public_key_ptr, self.private_key_ptr);
        self.zero_private_key();
        if result != 1 {
            return Err(Secp256k1Error::derivePublicKeyFromInvalidPrivateKey.to_string());
        }
        Ok(self.serialized_public_key(compressed))
    }

    /// Derive a compressed public key.
    pub fn derive_public_key_compressed(
        &mut self,
        private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.derive_public_key(true, private_key)
    }

    /// Derive an uncompressed public key.
    pub fn derive_public_key_uncompressed(
        &mut self,
        private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.derive_public_key(false, private_key)
    }

    /// Sign a 32-byte message hash, returning a compact (64-byte) signature.
    pub fn sign_message_hash_compact(
        &mut self,
        private_key: &[u8],
        message_hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.fill_message_hash(message_hash);
        self.fill_private_key(private_key);
        let result = self.wasm.sign(self.context_ptr, self.internal_sig_ptr, self.message_hash_scratch, self.private_key_ptr);
        let failed = result != 1;
        self.zero_private_key();
        if failed {
            return Err(Secp256k1Error::signWithInvalidPrivateKey.to_string());
        }
        Ok(self.compact_signature())
    }

    /// Sign a 32-byte message hash, returning a DER-encoded signature.
    pub fn sign_message_hash_der(
        &mut self,
        private_key: &[u8],
        message_hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.fill_message_hash(message_hash);
        self.fill_private_key(private_key);
        let result = self.wasm.sign(self.context_ptr, self.internal_sig_ptr, self.message_hash_scratch, self.private_key_ptr);
        let failed = result != 1;
        self.zero_private_key();
        if failed {
            return Err(Secp256k1Error::signWithInvalidPrivateKey.to_string());
        }
        Ok(self.der_signature())
    }

    /// Sign a 32-byte message hash with a Schnorr signature (64 bytes).
    pub fn sign_message_hash_schnorr(
        &mut self,
        private_key: &[u8],
        message_hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.fill_message_hash(message_hash);
        self.fill_private_key(private_key);
        let result = self.wasm.schnorr_sign(self.context_ptr, self.schnorr_sig_ptr, self.message_hash_scratch, self.private_key_ptr);
        let failed = result != 1;
        self.zero_private_key();
        if failed {
            return Err(Secp256k1Error::signWithInvalidPrivateKey.to_string());
        }
        Ok(self.read(self.schnorr_sig_ptr, SCHNORR_SIG_LENGTH))
    }

    /// Sign a 32-byte message hash, returning a compact signature and recovery ID.
    pub fn sign_message_hash_recoverable_compact(
        &mut self,
        private_key: &[u8],
        message_hash: &[u8],
    ) -> Result<RecoverableSignature, String> {
        self.fill_message_hash(message_hash);
        self.fill_private_key(private_key);
        let result = self.wasm.sign_recoverable(self.context_ptr, self.internal_r_sig_ptr, self.message_hash_scratch, self.private_key_ptr);
        let failed = result != 1;
        self.zero_private_key();
        if failed {
            return Err(Secp256k1Error::signWithInvalidPrivateKey.to_string());
        }
        let _ = self.wasm.recoverable_signature_serialize(self.context_ptr, self.sig_scratch, self.recovery_num_ptr, self.internal_r_sig_ptr);
        let recovery_bytes = self.read(self.recovery_num_ptr, 4);
        let recovery_id = u32::from_le_bytes([
            recovery_bytes[0],
            recovery_bytes[1],
            recovery_bytes[2],
            recovery_bytes[3],
        ]) as RecoveryId;
        let signature = self.read(self.sig_scratch, COMPACT_SIG_LENGTH);
        Ok(RecoverableSignature {
            recovery_id,
            signature,
        })
    }

    /// Recover a public key from a compact signature, recovery ID, and message hash.
    pub fn recover_public_key(
        &mut self,
        compressed: bool,
        signature: &[u8],
        recovery_id: RecoveryId,
        message_hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.fill_message_hash(message_hash);
        self.write_padded(self.sig_scratch, MAX_ECDSA_SIG_LENGTH, signature);
        let parsed = self.wasm.recoverable_signature_parse(self.context_ptr, self.internal_r_sig_ptr, self.sig_scratch, recovery_id as u32);
        if parsed != 1 {
            return Err(Secp256k1Error::recoverPublicKeyWithUnparsableSignature.to_string());
        }
        let recovered = self.wasm.recover(self.context_ptr, self.internal_public_key_ptr, self.internal_r_sig_ptr, self.message_hash_scratch);
        if recovered != 1 {
            return Err(Secp256k1Error::recoverPublicKeyInvalidMaterial.to_string());
        }
        Ok(self.serialized_public_key(compressed))
    }


    /// Verify a compact signature, normalizing S before checking.
    pub fn verify_signature_compact(
        &mut self,
        signature: &[u8],
        public_key: &[u8],
        message_hash: &[u8],
    ) -> bool {
        self.verify_signature_inner(false, true, signature, public_key, message_hash)
    }

    /// Verify a compact signature without normalizing S (low-S only).
    pub fn verify_signature_compact_low_s(
        &mut self,
        signature: &[u8],
        public_key: &[u8],
        message_hash: &[u8],
    ) -> bool {
        self.verify_signature_inner(false, false, signature, public_key, message_hash)
    }

    /// Verify a DER signature, normalizing S before checking.
    pub fn verify_signature_der(
        &mut self,
        signature: &[u8],
        public_key: &[u8],
        message_hash: &[u8],
    ) -> bool {
        self.verify_signature_inner(true, true, signature, public_key, message_hash)
    }

    /// Verify a DER signature without normalizing S (low-S only).
    pub fn verify_signature_der_low_s(
        &mut self,
        signature: &[u8],
        public_key: &[u8],
        message_hash: &[u8],
    ) -> bool {
        self.verify_signature_inner(true, false, signature, public_key, message_hash)
    }

    fn verify_signature_inner(
        &mut self,
        is_der: bool,
        normalize: bool,
        signature: &[u8],
        public_key: &[u8],
        message_hash: &[u8],
    ) -> bool {
        if !self.parse_public_key(public_key) {
            return false;
        }
        if !self.parse_signature(signature, is_der) {
            return false;
        }
        if normalize {
            let _ = self.wasm.signature_normalize(self.context_ptr, self.internal_sig_ptr, self.internal_sig_ptr);
        }
        self.fill_message_hash(message_hash);
        self.wasm.verify(self.context_ptr, self.internal_sig_ptr, self.message_hash_scratch, self.internal_public_key_ptr)
            == 1
    }

    /// Verify a Schnorr signature.
    pub fn verify_signature_schnorr(
        &mut self,
        signature: &[u8],
        public_key: &[u8],
        message_hash: &[u8],
    ) -> bool {
        if !self.parse_public_key(public_key) {
            return false;
        }
        self.fill_message_hash(message_hash);
        self.write_padded(self.schnorr_sig_ptr, SCHNORR_SIG_LENGTH, signature);
        self.wasm.schnorr_verify(self.context_ptr, self.schnorr_sig_ptr, self.message_hash_scratch, self.internal_public_key_ptr)
            == 1
    }

    /// Convert a compact signature to DER.
    pub fn signature_compact_to_der(
        &mut self,
        signature: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.parse_signature(signature, false) {
            return Err(Secp256k1Error::unparsableSignature.to_string());
        }
        Ok(self.der_signature())
    }

    /// Convert a DER signature to compact form.
    pub fn signature_der_to_compact(
        &mut self,
        signature: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.parse_signature(signature, true) {
            return Err(Secp256k1Error::unparsableSignature.to_string());
        }
        Ok(self.compact_signature())
    }

    fn modify_signature(
        &mut self,
        is_der: bool,
        normalize: bool,
        signature: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.parse_signature(signature, is_der) {
            return Err(Secp256k1Error::unparsableSignature.to_string());
        }
        if normalize {
            let _ = self.wasm.signature_normalize(self.context_ptr, self.internal_sig_ptr, self.internal_sig_ptr);
        } else {
            let _ = self.wasm.signature_malleate(self.context_ptr, self.internal_sig_ptr, self.internal_sig_ptr);
        }
        Ok(if is_der {
            self.der_signature()
        } else {
            self.compact_signature()
        })
    }

    /// Malleate a compact signature.
    pub fn malleate_signature_compact(
        &mut self,
        signature: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.modify_signature(false, false, signature)
    }

    /// Malleate a DER signature.
    pub fn malleate_signature_der(
        &mut self,
        signature: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.modify_signature(true, false, signature)
    }

    /// Normalize a compact signature.
    pub fn normalize_signature_compact(
        &mut self,
        signature: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.modify_signature(false, true, signature)
    }

    /// Normalize a DER signature.
    pub fn normalize_signature_der(
        &mut self,
        signature: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.modify_signature(true, true, signature)
    }

    fn tweak_private_key(
        &mut self,
        add: bool,
        private_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.fill_message_hash(tweak_value);
        self.fill_private_key(private_key);
        let (result, error) = if add {
            (
                self.wasm.privkey_tweak_add(self.context_ptr, self.private_key_ptr, self.message_hash_scratch),
                Secp256k1Error::addTweakPrivateKey,
            )
        } else {
            (
                self.wasm.privkey_tweak_mul(self.context_ptr, self.private_key_ptr, self.message_hash_scratch),
                Secp256k1Error::mulTweakPrivateKey,
            )
        };
        let failed = result != 1;
        let result = if failed {
            Err(error.to_string())
        } else {
            Ok(self.read(self.private_key_ptr, PRIVATE_KEY_LENGTH))
        };
        self.zero_private_key();
        result
    }

    /// Add a tweak to a private key.
    pub fn add_tweak_private_key(
        &mut self,
        private_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.tweak_private_key(true, private_key, tweak_value)
    }

    /// Multiply a private key by a tweak.
    pub fn mul_tweak_private_key(
        &mut self,
        private_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.tweak_private_key(false, private_key, tweak_value)
    }

    fn tweak_public_key(
        &mut self,
        compressed: bool,
        add: bool,
        public_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.parse_public_key(public_key) {
            return Err(Secp256k1Error::unparsablePublicKey.to_string());
        }
        self.fill_message_hash(tweak_value);
        let (result, error) = if add {
            (
                self.wasm.pubkey_tweak_add(self.context_ptr, self.internal_public_key_ptr, self.message_hash_scratch),
                Secp256k1Error::addTweakPublicKey,
            )
        } else {
            (
                self.wasm.pubkey_tweak_mul(self.context_ptr, self.internal_public_key_ptr, self.message_hash_scratch),
                Secp256k1Error::mulTweakPublicKey,
            )
        };
        if result != 1 {
            return Err(error.to_string());
        }
        Ok(self.serialized_public_key(compressed))
    }

    /// Add a tweak to a compressed public key.
    pub fn add_tweak_public_key_compressed(
        &mut self,
        public_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.tweak_public_key(true, true, public_key, tweak_value)
    }

    /// Add a tweak to an uncompressed public key.
    pub fn add_tweak_public_key_uncompressed(
        &mut self,
        public_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.tweak_public_key(false, true, public_key, tweak_value)
    }

    /// Multiply a compressed public key by a tweak.
    pub fn mul_tweak_public_key_compressed(
        &mut self,
        public_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.tweak_public_key(true, false, public_key, tweak_value)
    }

    /// Multiply an uncompressed public key by a tweak.
    pub fn mul_tweak_public_key_uncompressed(
        &mut self,
        public_key: &[u8],
        tweak_value: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.tweak_public_key(false, false, public_key, tweak_value)
    }
}

/// Wrap a {@link Secp256k1Wasm} instance in libauth's {@link Secp256k1}
/// interface: create a signing and verification context, allocate the scratch
/// pointers used by every method, and randomize the context if a `random_seed`
/// is provided.
fn wrap_secp256k1_wasm(mut secp256k1_wasm: Secp256k1Wasm, random_seed: Option<&[u8]>) -> WrappedSecp256k1Wasm {
    let context_ptr = secp256k1_wasm.context_create(ContextFlag::BOTH);
    let sig_scratch = secp256k1_wasm.malloc(MAX_ECDSA_SIG_LENGTH as u32);
    let public_key_scratch = secp256k1_wasm.malloc(MAX_PUBLIC_KEY_LENGTH as u32);
    let message_hash_scratch = secp256k1_wasm.malloc(MESSAGE_HASH_LENGTH as u32);
    let internal_public_key_ptr = secp256k1_wasm.malloc(INTERNAL_PUBLIC_KEY_LENGTH as u32);
    let internal_sig_ptr = secp256k1_wasm.malloc(INTERNAL_SIG_LENGTH as u32);
    let schnorr_sig_ptr = secp256k1_wasm.malloc(SCHNORR_SIG_LENGTH as u32);
    let private_key_ptr = secp256k1_wasm.malloc(PRIVATE_KEY_LENGTH as u32);
    let internal_r_sig_ptr = secp256k1_wasm.malloc(RECOVERABLE_SIG_LENGTH as u32);
    let recovery_num_ptr = secp256k1_wasm.malloc(4);
    let length_ptr = secp256k1_wasm.malloc(4);
    let mut wrapped = WrappedSecp256k1Wasm {
        wasm: secp256k1_wasm,
        context_ptr,
        sig_scratch,
        public_key_scratch,
        message_hash_scratch,
        internal_public_key_ptr,
        internal_sig_ptr,
        schnorr_sig_ptr,
        private_key_ptr,
        internal_r_sig_ptr,
        recovery_num_ptr,
        length_ptr,
    };
    if let Some(random_seed) = random_seed {
        let random_seed_ptr = wrapped.message_hash_scratch;
        wrapped.write_padded(random_seed_ptr, RANDOM_SEED_LENGTH, random_seed);
        wrapped.wasm.context_randomize(wrapped.context_ptr, random_seed_ptr);
        wrapped.write(random_seed_ptr, &[0; RANDOM_SEED_LENGTH]);
    }
    wrapped
}

impl Secp256k1 {    /// Tweak a private key by adding the provided value modulo the order of the curve.
    pub fn add_tweak_private_key(&self, private_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.add_tweak_private_key(private_key, tweak_value))
    }
    /// Tweak a public key by adding the provided value times the generator, returning the compressed result.
    pub fn add_tweak_public_key_compressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.add_tweak_public_key_compressed(public_key, tweak_value))
    }
    /// Tweak a public key by adding the provided value times the generator, returning the uncompressed result.
    pub fn add_tweak_public_key_uncompressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.add_tweak_public_key_uncompressed(public_key, tweak_value))
    }
    /// Compress a valid ECDSA public key.
    pub fn compress_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.compress_public_key(public_key))
    }
    /// Derive a compressed public key from a valid secp256k1 private key.
    pub fn derive_public_key_compressed(&self, private_key: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.derive_public_key_compressed(private_key))
    }
    /// Derive an uncompressed public key from a valid secp256k1 private key.
    pub fn derive_public_key_uncompressed(&self, private_key: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.derive_public_key_uncompressed(private_key))
    }
    /// Malleate a compact-encoded ECDSA signature.
    pub fn malleate_signature_compact(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.malleate_signature_compact(signature))
    }
    /// Malleate a DER-encoded ECDSA signature.
    pub fn malleate_signature_der(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.malleate_signature_der(signature))
    }
    /// Tweak a private key by multiplying it by the provided value modulo the order of the curve.
    pub fn mul_tweak_private_key(&self, private_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.mul_tweak_private_key(private_key, tweak_value))
    }
    /// Tweak a public key by multiplying it by the provided value, returning the compressed result.
    pub fn mul_tweak_public_key_compressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.mul_tweak_public_key_compressed(public_key, tweak_value))
    }
    /// Tweak a public key by multiplying it by the provided value, returning the uncompressed result.
    pub fn mul_tweak_public_key_uncompressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.mul_tweak_public_key_uncompressed(public_key, tweak_value))
    }
    /// Normalize a compact-encoded ECDSA signature to lower-S form.
    pub fn normalize_signature_compact(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.normalize_signature_compact(signature))
    }
    /// Normalize a DER-encoded ECDSA signature to lower-S form.
    pub fn normalize_signature_der(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.normalize_signature_der(signature))
    }
    /// Compute a compressed public key from a valid signature, recovery ID, and the message hash used to generate the signature.
    pub fn recover_public_key_compressed(&self, signature: &[u8], recovery_id: RecoveryId, message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.recover_public_key(true, signature, recovery_id, message_hash))
    }
    /// Compute an uncompressed public key from a valid signature, recovery ID, and the message hash used to generate the signature.
    pub fn recover_public_key_uncompressed(&self, signature: &[u8], recovery_id: RecoveryId, message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.recover_public_key(false, signature, recovery_id, message_hash))
    }
    /// Create an ECDSA signature in compact format.
    pub fn sign_message_hash_compact(&self, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.sign_message_hash_compact(private_key, message_hash))
    }
    /// Create an ECDSA signature in DER format.
    pub fn sign_message_hash_der(&self, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.sign_message_hash_der(private_key, message_hash))
    }
    /// Create an ECDSA signature in compact format with a recovery ID.
    pub fn sign_message_hash_recoverable_compact(&self, private_key: &[u8], message_hash: &[u8]) -> Result<RecoverableSignature, String> {
        self.wrapped.with(|secp256k1| secp256k1.sign_message_hash_recoverable_compact(private_key, message_hash))
    }
    /// Create a Schnorr signature using the BCH Schnorr signature algorithm.
    pub fn sign_message_hash_schnorr(&self, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.sign_message_hash_schnorr(private_key, message_hash))
    }
    /// Convert a compact-encoded ECDSA signature to DER encoding.
    pub fn signature_compact_to_der(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.signature_compact_to_der(signature))
    }
    /// Convert a DER-encoded ECDSA signature to compact encoding.
    pub fn signature_der_to_compact(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.signature_der_to_compact(signature))
    }
    /// Uncompress a valid ECDSA public key.
    pub fn uncompress_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, String> {
        self.wrapped.with(|secp256k1| secp256k1.uncompress_public_key(public_key))
    }
    /// Verify a private key is valid for secp256k1.
    pub fn validate_private_key(&self, private_key: &[u8]) -> bool {
        self.wrapped.with(|secp256k1| secp256k1.validate_private_key(private_key))
    }
    /// Verify that a public key is valid.
    pub fn validate_public_key(&self, public_key: &[u8]) -> bool {
        self.wrapped.with(|secp256k1| secp256k1.validate_public_key(public_key))
    }
    /// Normalize a compact-encoded signature to lower-S form, then verify it.
    pub fn verify_signature_compact(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.wrapped.with(|secp256k1| secp256k1.verify_signature_compact(signature, public_key, message_hash))
    }
    /// Verify a compact-encoded signature (which must be in lower-S form).
    pub fn verify_signature_compact_low_s(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.wrapped.with(|secp256k1| secp256k1.verify_signature_compact_low_s(signature, public_key, message_hash))
    }
    /// Normalize a DER-encoded signature to lower-S form, then verify it.
    pub fn verify_signature_der(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.wrapped.with(|secp256k1| secp256k1.verify_signature_der(signature, public_key, message_hash))
    }
    /// Verify a DER-encoded signature (which must be in lower-S form).
    pub fn verify_signature_der_low_s(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.wrapped.with(|secp256k1| secp256k1.verify_signature_der_low_s(signature, public_key, message_hash))
    }
    /// Verify a Schnorr signature using the BCH Schnorr signature algorithm.
    pub fn verify_signature_schnorr(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.wrapped.with(|secp256k1| secp256k1.verify_signature_schnorr(signature, public_key, message_hash))
    }
}

/// This method is like {@link instantiateSecp256k1}, but requires the consumer
/// to `Window.fetch` or `fs.readFile` the `secp256k1.wasm` binary and provide
/// it to this method as `webassemblyBytes`. This skips a base64 decoding of an
/// embedded binary.
///
/// ### Randomizing the Context with `randomSeed`
/// See {@link instantiateSecp256k1}.
///
/// @param webassemblyBytes - an ArrayBuffer containing the bytes from Libauth's
/// `secp256k1.wasm` binary. Providing this buffer manually may be faster than
/// the internal base64 decode that happens in {@link instantiateSecp256k1}.
/// @param randomSeed - a 32-byte random seed used to randomize the secp256k1
/// context after creation. See {@link instantiateSecp256k1} for details.
pub fn instantiate_secp256k1_bytes(
    webassembly_bytes: &[u8],
    random_seed: Option<&[u8]>,
) -> Result<Secp256k1, String> {
    let bytes = std::sync::Arc::new(webassembly_bytes.to_vec());
    let random_seed = random_seed.map(<[u8]>::to_vec);
    // Instantiate once on the calling thread to report any errors.
    instantiate_secp256k1_wasm_bytes(&bytes)?;
    Ok(Secp256k1 {
        wrapped: PerThread::new(move || {
            wrap_secp256k1_wasm(
                instantiate_secp256k1_wasm_bytes(&bytes)
                    .expect("the module instantiated successfully on another thread"),
                random_seed.as_deref(),
            )
        }),
    })
}

/// Create and wrap a Secp256k1 WebAssembly instance to expose a set of
/// purely-functional Secp256k1 methods. For slightly faster initialization, use
/// {@link instantiateSecp256k1Bytes}.
///
/// ### Randomizing the Context with `randomSeed`
/// This method also accepts an optional, 32-byte `randomSeed`, which is passed
/// to the `contextRandomize` method in the underlying WebAssembly.
///
/// The value of this seed will be used by the secp256k1 library to randomize
/// the secp256k1 context after creation. Context randomization protects
/// against side-channel leakage of private key information.
///
/// @param randomSeed - a 32-byte random seed used to randomize the secp256k1
/// context after creation (see above for details)
pub fn instantiate_secp256k1(random_seed: Option<&[u8]>) -> Result<Secp256k1, String> {
    let random_seed = random_seed.map(<[u8]>::to_vec);
    // Instantiate once on the calling thread to report any errors.
    instantiate_secp256k1_wasm()?;
    Ok(Secp256k1 {
        wrapped: PerThread::new(move || {
            wrap_secp256k1_wasm(
                instantiate_secp256k1_wasm().expect("the embedded module instantiates"),
                random_seed.as_deref(),
            )
        }),
    })
}
