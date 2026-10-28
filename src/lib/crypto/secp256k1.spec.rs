//! Port of `crypto/secp256k1.spec.ts`.
//!
//! Substitutions:
//! - `randomBytes` (from Node.js's `crypto` module) is replaced by the
//!   runtime's `crypto.getRandomValues` (`get_random_values`).
//! - The `elliptic` and `secp256k1` (native) packages are JavaScript-only
//!   references. Each `[fast-check]` property which compares libauth with them
//!   runs over the 16 fixed inputs of [`REFERENCE_VECTORS`] – sampled from this
//!   spec's own arbitraries (`fcValidPrivateKey`, `fcUint8Array32()`,
//!   `fc.boolean()`, `fc.boolean()`) with `fc.sample(..., { seed: 1, numRuns:
//!   16 })` – and compares libauth's results with the values those packages
//!   produced in Node.js. Where a reference library was applied to a value
//!   produced by libauth (e.g. `ellipticCheckSignature(sig, key, message)`),
//!   the port asserts that libauth produced the value which the reference
//!   checked, and the reference's precomputed verdict. Properties which only
//!   use libauth still run 100 times over the fast-check stand-in.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use std::sync::LazyLock;

use libauth::runtime::crypto::get_random_values;
use libauth::{
    assert_success, hex_to_bin, instantiate_secp256k1, secp256k1 as internal_secp256k1,
    RecoverableSignature, Secp256k1, Secp256k1Error,
};

// test vectors (from `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong`, m/0 and m/1):

#[rustfmt::skip]
const KEY_TWEAK_VAL: [u8; 32] = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01];

#[rustfmt::skip]
const MESSAGE_HASH: [u8; 32] = [0xda, 0xde, 0x12, 0xe0, 0x6a, 0x5b, 0xbf, 0x5e, 0x11, 0x16, 0xf9, 0xbc, 0x44, 0x99, 0x8b, 0x87, 0x68, 0x13, 0xe9, 0x48, 0xe1, 0x07, 0x07, 0xdc, 0xb4, 0x80, 0x08, 0xa1, 0xda, 0xf3, 0x51, 0x2d];

#[rustfmt::skip]
const PRIVKEY: [u8; 32] = [0xf8, 0x5d, 0x4b, 0xd8, 0xa0, 0x3c, 0xa1, 0x06, 0xc9, 0xde, 0xb4, 0x7b, 0x79, 0x18, 0x03, 0xda, 0xc7, 0xf0, 0x33, 0x38, 0x09, 0xe3, 0xf1, 0xdd, 0x04, 0xd1, 0x82, 0xe0, 0xab, 0xa6, 0xe5, 0x53];

#[rustfmt::skip]
const SECP256K1_ORDER_N: [u8; 32] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41];

#[rustfmt::skip]
const PUBKEY_UNCOMPRESSED: [u8; 65] = [0x04, 0x76, 0xea, 0x9e, 0x36, 0xa7, 0x5d, 0x2e, 0xcf, 0x9c, 0x93, 0xa0, 0xbe, 0x76, 0x88, 0x5e, 0x36, 0xf8, 0x22, 0x52, 0x9d, 0xb2, 0x2a, 0xcf, 0xdc, 0x76, 0x1c, 0x9b, 0x5b, 0x45, 0x44, 0xf5, 0xc5, 0x6d, 0xd5, 0x3b, 0x07, 0xc7, 0xa9, 0x83, 0xbb, 0x2d, 0xdd, 0x71, 0x55, 0x1f, 0x06, 0x33, 0x19, 0x4a, 0x2f, 0xe3, 0x30, 0xf9, 0x0a, 0xaf, 0x67, 0x5d, 0xde, 0x25, 0xb1, 0x37, 0xef, 0xd2, 0x85];

#[rustfmt::skip]
const PUBKEY_COMPRESSED: [u8; 33] = [0x03, 0x76, 0xea, 0x9e, 0x36, 0xa7, 0x5d, 0x2e, 0xcf, 0x9c, 0x93, 0xa0, 0xbe, 0x76, 0x88, 0x5e, 0x36, 0xf8, 0x22, 0x52, 0x9d, 0xb2, 0x2a, 0xcf, 0xdc, 0x76, 0x1c, 0x9b, 0x5b, 0x45, 0x44, 0xf5, 0xc5];

#[rustfmt::skip]
const INVALID_PUBKEY_COMPRESSED: [u8; 33] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[rustfmt::skip]
const PRIVKEY_TWEAKED_ADD: [u8; 32] = [0xf9, 0x5e, 0x4c, 0xd9, 0xa1, 0x3d, 0xa2, 0x07, 0xca, 0xdf, 0xb5, 0x7c, 0x7a, 0x19, 0x04, 0xdb, 0xc8, 0xf1, 0x34, 0x39, 0x0a, 0xe4, 0xf2, 0xde, 0x05, 0xd2, 0x83, 0xe1, 0xac, 0xa7, 0xe6, 0x54];

#[rustfmt::skip]
const PUBKEY_TWEAKED_ADD_UNCOMPRESSED: [u8; 65] = [0x04, 0x6f, 0x1d, 0xf3, 0x4a, 0x81, 0xdf, 0x8c, 0xec, 0x18, 0x33, 0x34, 0xce, 0xb2, 0x56, 0x49, 0x9e, 0xc6, 0xe7, 0x57, 0x04, 0x57, 0x57, 0x6a, 0x92, 0x37, 0x1b, 0x74, 0x75, 0xc3, 0x4f, 0x2c, 0x19, 0xa8, 0xed, 0xd5, 0xc4, 0x29, 0x44, 0x80, 0xc1, 0xb0, 0xb3, 0x3c, 0xc8, 0xa4, 0xfd, 0x0a, 0x5c, 0x53, 0xc3, 0xd8, 0x9b, 0xd7, 0x93, 0xa7, 0x1f, 0x78, 0x03, 0x5c, 0x74, 0x00, 0xab, 0x34, 0xfc];

#[rustfmt::skip]
const PUBKEY_TWEAKED_ADD_COMPRESSED: [u8; 33] = [0x02, 0x6f, 0x1d, 0xf3, 0x4a, 0x81, 0xdf, 0x8c, 0xec, 0x18, 0x33, 0x34, 0xce, 0xb2, 0x56, 0x49, 0x9e, 0xc6, 0xe7, 0x57, 0x04, 0x57, 0x57, 0x6a, 0x92, 0x37, 0x1b, 0x74, 0x75, 0xc3, 0x4f, 0x2c, 0x19];

#[rustfmt::skip]
const PRIVKEY_TWEAKED_MUL: [u8; 32] = [0x29, 0x9f, 0x6a, 0x4d, 0xe3, 0xa0, 0xfd, 0x06, 0x8c, 0x80, 0x31, 0xef, 0xd6, 0xcf, 0x3a, 0xc6, 0xb8, 0x89, 0x02, 0x5e, 0x65, 0xd2, 0xe6, 0x2d, 0x8e, 0xb9, 0xd6, 0x88, 0x2a, 0xc2, 0x1a, 0x4a];

#[rustfmt::skip]
const PUBKEY_TWEAKED_MUL_UNCOMPRESSED: [u8; 65] = [0x04, 0xb7, 0x98, 0x58, 0x0c, 0x33, 0x8c, 0x02, 0xed, 0xc3, 0x8a, 0xd9, 0xb6, 0x19, 0x7d, 0x4c, 0x56, 0x64, 0xe6, 0xaa, 0x85, 0x49, 0x10, 0xad, 0xa7, 0x5d, 0xc6, 0x10, 0x14, 0x2b, 0x5a, 0x7a, 0x38, 0xb5, 0x0f, 0xb1, 0x55, 0x6c, 0x03, 0x3d, 0x7f, 0xb2, 0x24, 0x21, 0x69, 0x01, 0xc2, 0x86, 0x05, 0x26, 0xad, 0xeb, 0x74, 0xa8, 0x50, 0xf2, 0x9a, 0x50, 0x8f, 0x7a, 0xb3, 0x0b, 0x66, 0x20, 0x74];

#[rustfmt::skip]
const PUBKEY_TWEAKED_MUL_COMPRESSED: [u8; 33] = [0x02, 0xb7, 0x98, 0x58, 0x0c, 0x33, 0x8c, 0x02, 0xed, 0xc3, 0x8a, 0xd9, 0xb6, 0x19, 0x7d, 0x4c, 0x56, 0x64, 0xe6, 0xaa, 0x85, 0x49, 0x10, 0xad, 0xa7, 0x5d, 0xc6, 0x10, 0x14, 0x2b, 0x5a, 0x7a, 0x38];

#[rustfmt::skip]
const SIG_DER: [u8; 71] = [0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x02, 0x20, 0x29, 0x72, 0x21, 0x88, 0xbd, 0x93, 0x7f, 0x54, 0xc8, 0x61, 0x58, 0x2c, 0xa6, 0xfc, 0x68, 0x5b, 0x8d, 0xa2, 0xb4, 0x0d, 0x05, 0xf0, 0x6b, 0x36, 0x83, 0x74, 0xd3, 0x5e, 0x4a, 0xf2, 0xb7, 0x64];

#[rustfmt::skip]
const SIG_DER_HIGH_S: [u8; 72] = [0x30, 0x46, 0x02, 0x21, 0x00, 0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x02, 0x21, 0x00, 0xd6, 0x8d, 0xde, 0x77, 0x42, 0x6c, 0x80, 0xab, 0x37, 0x9e, 0xa7, 0xd3, 0x59, 0x03, 0x97, 0xa3, 0x2d, 0x0c, 0x28, 0xd9, 0xa9, 0x58, 0x35, 0x05, 0x3c, 0x5d, 0x8b, 0x2e, 0x85, 0x43, 0x89, 0xdd];

#[rustfmt::skip]
const SIG_COMPACT: [u8; 64] = [0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x29, 0x72, 0x21, 0x88, 0xbd, 0x93, 0x7f, 0x54, 0xc8, 0x61, 0x58, 0x2c, 0xa6, 0xfc, 0x68, 0x5b, 0x8d, 0xa2, 0xb4, 0x0d, 0x05, 0xf0, 0x6b, 0x36, 0x83, 0x74, 0xd3, 0x5e, 0x4a, 0xf2, 0xb7, 0x64];

#[rustfmt::skip]
const SIG_COMPACT_HIGH_S: [u8; 64] = [0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0xd6, 0x8d, 0xde, 0x77, 0x42, 0x6c, 0x80, 0xab, 0x37, 0x9e, 0xa7, 0xd3, 0x59, 0x03, 0x97, 0xa3, 0x2d, 0x0c, 0x28, 0xd9, 0xa9, 0x58, 0x35, 0x05, 0x3c, 0x5d, 0x8b, 0x2e, 0x85, 0x43, 0x89, 0xdd];

#[rustfmt::skip]
const SCHNORR_MSG_HASH: [u8; 32] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[rustfmt::skip]
const SIG_SCHNORR: [u8; 64] = [0xb5, 0x10, 0x41, 0x58, 0x7d, 0xa9, 0x46, 0xeb, 0x67, 0x9c, 0xb3, 0x93, 0x6e, 0x1d, 0xbe, 0x5b, 0xf1, 0xd0, 0xd8, 0xac, 0xff, 0x37, 0x8d, 0xc9, 0xc6, 0xc2, 0x0a, 0x32, 0x9f, 0xb0, 0x1b, 0x79, 0xad, 0x65, 0x54, 0x65, 0xf2, 0x26, 0xa0, 0x28, 0x7b, 0x2d, 0xcf, 0x0e, 0x74, 0x6b, 0xc4, 0x55, 0xa9, 0x40, 0xfe, 0x01, 0xbc, 0xd8, 0x0f, 0xa9, 0xb6, 0x63, 0x3e, 0xcb, 0xe0, 0xc7, 0x04, 0x33];

const SIG_RECOVERY: u8 = 1;

// libauth setup
/// `const secp256k1Promise = instantiateSecp256k1();`
static SECP256K1_PROMISE: LazyLock<Secp256k1> =
    LazyLock::new(|| instantiate_secp256k1(None));

/// `randomBytes(32)`
fn random_bytes_32() -> Vec<u8> {
    let mut bytes = vec![0; 32];
    get_random_values(&mut bytes).expect("random bytes");
    bytes
}

// fast-check helpers
fn fc_uint8_array_32() -> impl Fn(&mut fc::Random) -> Vec<u8> {
    fc::uint8_array(Some(32), Some(32))
}

/// `fcUint8Array32().filter((generated) => internalSecp256k1.validatePrivateKey(generated))`
fn fc_valid_private_key() -> impl Fn(&mut fc::Random) -> Vec<u8> {
    let generate = fc_uint8_array_32();
    move |random| loop {
        let generated = generate(random);
        if internal_secp256k1.validate_private_key(&generated) {
            return generated;
        }
    }
}

/// `Uint8Array.prototype.fill(0, start, end)` on a copy.
fn fill_zero(bin: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut copy = bin.to_vec();
    copy[start..end].fill(0);
    copy
}

/// The precomputed results of the `secp256k1` (native) and `elliptic`
/// packages for one fixed input (see the module documentation).
struct ReferenceVector {
    /// Input: `fcValidPrivateKey`
    private_key: &'static str,
    /// Input: `fcUint8Array32()` (`message`/`hash`)
    message_hash: &'static str,
    /// Input: `fc.boolean()` (`compressed`)
    compressed: bool,
    /// Input: `fc.boolean()` (`invalidate`)
    invalidate: bool,
    /// `secp256k1Node.publicKeyCreate(privateKey, true)`; equal to
    /// `setupElliptic(privateKey).pubCompressed`,
    /// `secp256k1Node.publicKeyConvert(pubkeyU, true)`,
    /// `ec.keyFromPublic(pubkeyU).getPublic().encodeCompressed()`, and
    /// `secp256k1Node.ecdsaRecover(signature, recid, hash, true)`.
    public_key_compressed: &'static str,
    /// `secp256k1Node.publicKeyCreate(privateKey, false)`; equal to
    /// `setupElliptic(privateKey).pubUncompressed`,
    /// `secp256k1Node.publicKeyConvert(pubkeyC, false)`, and
    /// `secp256k1Node.ecdsaRecover(signature, recid, hash, false)`.
    public_key_uncompressed: &'static str,
    /// `secp256k1Node.privateKeyTweakAdd(privateKey, keyTweakVal)`
    private_key_tweak_add: &'static str,
    /// `secp256k1Node.publicKeyTweakAdd(pubkeyC, keyTweakVal, true)`
    public_key_compressed_tweak_add: &'static str,
    /// `secp256k1Node.publicKeyTweakAdd(pubkeyU, keyTweakVal, false)`
    public_key_uncompressed_tweak_add: &'static str,
    /// `secp256k1Node.privateKeyTweakMul(privateKey, keyTweakVal)`
    private_key_tweak_mul: &'static str,
    /// `secp256k1Node.publicKeyTweakMul(pubkeyC, keyTweakVal, true)`
    public_key_compressed_tweak_mul: &'static str,
    /// `secp256k1Node.publicKeyTweakMul(pubkeyU, keyTweakVal, false)`
    public_key_uncompressed_tweak_mul: &'static str,
    /// `secp256k1Node.ecdsaSign(hash, privateKey).signature`; equal to
    /// `secp256k1Node.signatureNormalize(malleated)` and
    /// `secp256k1Node.signatureImport(signatureDer)`.
    signature_compact: &'static str,
    /// `secp256k1Node.ecdsaSign(hash, privateKey).recid`
    recovery_id: u8,
    /// `secp256k1Node.signatureExport(signatureCompact)`; equal to
    /// `secp256k1Node.signatureExport(secp256k1Node.signatureNormalize(secp256k1Node.signatureImport(malleated)))`.
    signature_der: &'static str,
    /// `signatureCompact` with `s` replaced by `n - s` (computed with `BigInt`).
    signature_compact_malleated: &'static str,
    /// `secp256k1Node.signatureExport(signatureCompactMalleated)`
    signature_der_malleated: &'static str,
    /// `secp256k1Node.ecdsaVerify(signatureCompact, hash, publicKeyCompressed)`
    node_verifies_signature_compact: bool,
    /// `secp256k1Node.ecdsaVerify(signatureCompactMalleated, hash, publicKeyCompressed)`
    node_verifies_malleated_compact: bool,
    /// `ellipticCheckSignature(signatureDer, key, hash)`
    elliptic_verifies_signature_der: bool,
    /// `ellipticCheckSignature(signatureDerMalleated, key, hash)`
    elliptic_verifies_malleated_der: bool,
    /// `ellipticSignMessageDER(key, hash)`
    elliptic_signature_der: &'static str,
    /// `secp256k1Node.ecdsaVerify(invalidate ? signatureCompact.fill(0, 6, 7) : signatureCompact, hash, pub)`
    node_verifies_test_signature_compact: bool,
    /// `ellipticCheckSignature(invalidate ? ellipticSignatureDer.fill(0, 6, 20) : ellipticSignatureDer, key, hash)`
    elliptic_verifies_test_signature_der: bool,
    /// `ellipticCheckSignature(invalidate ? signatureDer.fill(0, 6, 20) : signatureDer, key, hash)`
    elliptic_verifies_test_normalized_signature_der: bool,
    /// `secp256k1Node.ecdsaVerify(secp256k1Node.signatureImport(invalidate ? signatureDer.fill(0, 6, 7) : signatureDer), hash, pub)`
    node_verifies_test_signature_der: bool,
    /// `ellipticCheckSignature(invalidate ? ellipticSignatureDer.fill(0, 6, 7) : ellipticSignatureDer, key, hash)`
    elliptic_verifies_test_signature_der_byte_6: bool,
}

impl ReferenceVector {
    fn private_key(&self) -> Vec<u8> {
        hex_to_bin(self.private_key)
    }

    fn message_hash(&self) -> Vec<u8> {
        hex_to_bin(self.message_hash)
    }

    /// `compressed ? pubCompressed : pubUncompressed`
    fn public_key(&self) -> Vec<u8> {
        hex_to_bin(if self.compressed {
            self.public_key_compressed
        } else {
            self.public_key_uncompressed
        })
    }
}

/// The fixed inputs and precomputed reference results (see the module
/// documentation).
const REFERENCE_VECTORS: [ReferenceVector; 16] = [
    ReferenceVector {
        private_key: "fcff0185c80386d7ff02a2042efd97fbe6012dac0102751cfcc14507a6055a00",
        message_hash: "0404056e45034e07c201fb0406492403fa8b0105af01c0feefd0fe03dd1bd029",
        compressed: false,
        invalidate: true,
        public_key_compressed: "03451372868687a27669ac25fa674cc3473f6df32e6c178f13565086a6a34d5aa5",
        public_key_uncompressed: "04451372868687a27669ac25fa674cc3473f6df32e6c178f13565086a6a34d5aa585f91565207b8134ab629a0fa7fbdf50ac84850b2af33aa2b282bd93241d83cd",
        private_key_tweak_add: "fe000286c90487d90003a3052ffe98fce7022ead0203761dfdc24608a7065b01",
        public_key_compressed_tweak_add: "026fe3e0f3e58ff94833bb5b22645f84c816da34593ae48cae815f2474532479b8",
        public_key_uncompressed_tweak_add: "046fe3e0f3e58ff94833bb5b22645f84c816da34593ae48cae815f2474532479b88bfbd7f1cb5531158a6577540ad1af00288af37d506bd79a8ddbd69563ffaf5a",
        private_key_tweak_mul: "c76b4a9698247884b883a17a0f58e2bbcfbebaf0a4d8ecf79f22659b217bb23d",
        public_key_compressed_tweak_mul: "020d219c2cdf69968860d6fffbf046ed6fbf9c6046d3d156f691020ccd1a1412f4",
        public_key_uncompressed_tweak_mul: "040d219c2cdf69968860d6fffbf046ed6fbf9c6046d3d156f691020ccd1a1412f442ff9939c6283799095db69accae43708ec166d98ce3944424fdb75f8f3104dc",
        signature_compact: "64219bf2eb43f565b4d935ad379d2db2793821bc67590fc45f89d181b63f2ecd7bc9f99ff37609ac1240ed40ad463cc305aa60b62b28548f21a4b2e0ddb8a4c9",
        recovery_id: 0,
        signature_der: "3044022064219bf2eb43f565b4d935ad379d2db2793821bc67590fc45f89d181b63f2ecd02207bc9f99ff37609ac1240ed40ad463cc305aa60b62b28548f21a4b2e0ddb8a4c9",
        signature_compact_malleated: "64219bf2eb43f565b4d935ad379d2db2793821bc67590fc45f89d181b63f2ecd843606600c89f653edbf12bf52b9c33bb5047c3084204bac9e2dababf27d9c78",
        signature_der_malleated: "3045022064219bf2eb43f565b4d935ad379d2db2793821bc67590fc45f89d181b63f2ecd022100843606600c89f653edbf12bf52b9c33bb5047c3084204bac9e2dababf27d9c78",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3045022064219bf2eb43f565b4d935ad379d2db2793821bc67590fc45f89d181b63f2ecd022100843606600c89f653edbf12bf52b9c33bb5047c3084204bac9e2dababf27d9c78",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "04f8a7c5d0a836f9fcfcfcff06faf9046e06b002fc3dd70719fe04fb01951aea",
        message_hash: "0705c204fe8a841705fe07f92a064a0507012306d7f9fd0180b90205fa58b625",
        compressed: true,
        invalidate: true,
        public_key_compressed: "0374fcf254abb7d2a8454153cc3938a18987e881a66a17fe95a2977f6fae16bc2b",
        public_key_uncompressed: "0474fcf254abb7d2a8454153cc3938a18987e881a66a17fe95a2977f6fae16bc2b61c224b4891337b33d661ee9c93f109cc3b6de3be9d693eee3b3c0d6f80ace9b",
        private_key_tweak_add: "05f9a8c6d1a937fafdfdfe0007fbfa056f07b103fd3ed8081aff05fc02961beb",
        public_key_compressed_tweak_add: "0245d5881b12fe8bd0ef68ec4b28797838da903353a01b086a76b5dd61ca44f31b",
        public_key_uncompressed_tweak_add: "0445d5881b12fe8bd0ef68ec4b28797838da903353a01b086a76b5dd61ca44f31b2c6b95ac848c418b2d0a4397738bc9294a2003fff29c099da4383a0db1ed0ffa",
        private_key_tweak_mul: "a129eabc16d4829c530d0fe7e3e0bc3fa1dd5eab611b421f2880dffb83f0e82f",
        public_key_compressed_tweak_mul: "02356330dbef2414d5b01f936f9f78b872ae500fd5cc36853a6c10cb6497700933",
        public_key_uncompressed_tweak_mul: "04356330dbef2414d5b01f936f9f78b872ae500fd5cc36853a6c10cb64977009335ac17ac86d41d06b1a70a9299675a307acab57b2f0f98021502582e14184bde8",
        signature_compact: "d5b7fd0e8e6f8e60f0b5968bf42e7ffd6b6933a6c60ef3c9cc57bb13d8c9a66863507e55fa20fcda204f152c3867e3a4d3a3fbbbb788796a513586a8399ed059",
        recovery_id: 1,
        signature_der: "3045022100d5b7fd0e8e6f8e60f0b5968bf42e7ffd6b6933a6c60ef3c9cc57bb13d8c9a668022063507e55fa20fcda204f152c3867e3a4d3a3fbbbb788796a513586a8399ed059",
        signature_compact_malleated: "d5b7fd0e8e6f8e60f0b5968bf42e7ffd6b6933a6c60ef3c9cc57bb13d8c9a6689caf81aa05df0325dfb0ead3c7981c59e70ae12af7c026d16e9cd7e4969770e8",
        signature_der_malleated: "3046022100d5b7fd0e8e6f8e60f0b5968bf42e7ffd6b6933a6c60ef3c9cc57bb13d8c9a6680221009caf81aa05df0325dfb0ead3c7981c59e70ae12af7c026d16e9cd7e4969770e8",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3045022100d5b7fd0e8e6f8e60f0b5968bf42e7ffd6b6933a6c60ef3c9cc57bb13d8c9a668022063507e55fa20fcda204f152c3867e3a4d3a3fbbbb788796a513586a8399ed059",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "fd3e01f30504074806fffb0300fcfcfd0107a800f8700207fd133b00e7fd019f",
        message_hash: "a2f907f9013902cbb50e41fc1205046ffc02fd9270256bc8fb70f251070206d8",
        compressed: false,
        invalidate: true,
        public_key_compressed: "023cf0ef8fedb5bbabf7cf48ec2fdfd25371e91be97208b98c0fce15f4d5f5531f",
        public_key_uncompressed: "043cf0ef8fedb5bbabf7cf48ec2fdfd25371e91be97208b98c0fce15f4d5f5531f469ece23f1e1645d124ca8327585ed55b1bcfe60592b8903e29e23a735443fac",
        private_key_tweak_add: "fe3f02f4060508490800fc0401fdfdfe0208a901f9710308fe143c01e8fe02a0",
        public_key_compressed_tweak_add: "03a822f0b436ff10b5713a461e38ce0fca201827a170ece9c6946c8453b872a5ed",
        public_key_uncompressed_tweak_add: "04a822f0b436ff10b5713a461e38ce0fca201827a170ece9c6946c8453b872a5eddcf28ee4622ac89822adbb7a39cc8ea7faca022db98db0f5ca9671cba0f10dcd",
        private_key_tweak_mul: "fd6fa05a31c5ddc77bfbc60ccbef78fe0366755fe801f8a066ac5c13362d81ab",
        public_key_compressed_tweak_mul: "0232bfa62f942878205c2cda23b703d65168cebb544f0a5078aafca3ceb09cb705",
        public_key_uncompressed_tweak_mul: "0432bfa62f942878205c2cda23b703d65168cebb544f0a5078aafca3ceb09cb7052a4d19b7bb1ed9adcb5febc11ef3084f3c9cb78d9eb2c73b9675fea401d30814",
        signature_compact: "b5d3761b472901643740a74673940147b0bc8973ef3ec99f55dbee305bb409a83e800514b730b1fb1c18005c0278e77ade52c22112eab9f5ea3f772e68621816",
        recovery_id: 0,
        signature_der: "3045022100b5d3761b472901643740a74673940147b0bc8973ef3ec99f55dbee305bb409a802203e800514b730b1fb1c18005c0278e77ade52c22112eab9f5ea3f772e68621816",
        signature_compact_malleated: "b5d3761b472901643740a74673940147b0bc8973ef3ec99f55dbee305bb409a8c17ffaeb48cf4e04e3e7ffa3fd871883dc5c1ac59c5de645d592e75e67d4292b",
        signature_der_malleated: "3046022100b5d3761b472901643740a74673940147b0bc8973ef3ec99f55dbee305bb409a8022100c17ffaeb48cf4e04e3e7ffa3fd871883dc5c1ac59c5de645d592e75e67d4292b",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3046022100b5d3761b472901643740a74673940147b0bc8973ef3ec99f55dbee305bb409a8022100c17ffaeb48cf4e04e3e7ffa3fd871883dc5c1ac59c5de645d592e75e67d4292b",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "0305f90200f806055001927607f901582e142601a702efc4bd5cff000267f25b",
        message_hash: "f8930304fe005afb01fdfe3f046a852bcc1b8592a82bfb0105037004500507fe",
        compressed: true,
        invalidate: true,
        public_key_compressed: "0211d52de61521b3c818f649248a0511890f8dc55b5e4d79abf2a3d292bc94679d",
        public_key_uncompressed: "0411d52de61521b3c818f649248a0511890f8dc55b5e4d79abf2a3d292bc94679dd69c1de9d2080c9142f1c7cd0300388ee9ebd9c0a0cc053c284896ae0156d4a0",
        private_key_tweak_add: "0406fa0301f907065102937708fa02592f152702a803f0c5be5e00010368f35c",
        public_key_compressed_tweak_add: "02a945ba27ade1aad72d2ae370268ffb53d8b55ec8947ea6b43a523d6b06e17615",
        public_key_uncompressed_tweak_add: "04a945ba27ade1aad72d2ae370268ffb53d8b55ec8947ea6b43a523d6b06e17615768e703e1eb5ae9cc0a4f5d7802e039a793915899bd29130c88448d8831e27b0",
        private_key_tweak_mul: "0a085e1c802e8b8386772bfea7402a2e8ee7f449304959b85599e5988eece6f4",
        public_key_compressed_tweak_mul: "03cd2e0b08e192efbed86f347a7fbde8433dfa5c0dba6e4b9a0ed084b3e7fa5973",
        public_key_uncompressed_tweak_mul: "04cd2e0b08e192efbed86f347a7fbde8433dfa5c0dba6e4b9a0ed084b3e7fa5973b4b436182593928751f7a85e6282748b389e801e0973918735b971ab576550ef",
        signature_compact: "e647fb775a1a53acf4ccc15db4c33c6a5b9b97fdb55049ecef36926b4f12d4725e6209fe82f06930aef81767a7ccbb8a5d6a9690547b1c4594a103dea31b210e",
        recovery_id: 1,
        signature_der: "3045022100e647fb775a1a53acf4ccc15db4c33c6a5b9b97fdb55049ecef36926b4f12d47202205e6209fe82f06930aef81767a7ccbb8a5d6a9690547b1c4594a103dea31b210e",
        signature_compact_malleated: "e647fb775a1a53acf4ccc15db4c33c6a5b9b97fdb55049ecef36926b4f12d472a19df6017d0f96cf5107e898583344745d4446565acd83f62b315aae2d1b2033",
        signature_der_malleated: "3046022100e647fb775a1a53acf4ccc15db4c33c6a5b9b97fdb55049ecef36926b4f12d472022100a19df6017d0f96cf5107e898583344745d4446565acd83f62b315aae2d1b2033",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3046022100e647fb775a1a53acf4ccc15db4c33c6a5b9b97fdb55049ecef36926b4f12d472022100a19df6017d0f96cf5107e898583344745d4446565acd83f62b315aae2d1b2033",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "e66b8eb59c25fe001b0304d4025ff9f86a0300f805fd02c5010559cf14a3bc36",
        message_hash: "fe0701f70cfee00106053c0002f90400f846fd0400c4faf90128c2fd07792cff",
        compressed: true,
        invalidate: true,
        public_key_compressed: "02f4ee42f67668a0ba1b42ff3f07ce4b0dc7c7a889d4de9c0da459542383464b6c",
        public_key_uncompressed: "04f4ee42f67668a0ba1b42ff3f07ce4b0dc7c7a889d4de9c0da459542383464b6cf580b301aff5b04b2af78c8da44c88898ee578fdeabec23e85858d5550c88214",
        private_key_tweak_add: "e76c8fb69d26ff011c0405d50360faf96b0401f906fe03c602065ad015a4bd37",
        public_key_compressed_tweak_add: "02f00a0fcf45a669011e77a34854dcda94adb26990045ec9f80179bcdc61b8f429",
        public_key_uncompressed_tweak_add: "04f00a0fcf45a669011e77a34854dcda94adb26990045ec9f80179bcdc61b8f429bdffeec62947b9532f5bfeb7cec0d7974dd632100f9d1a954e5c8069b7433988",
        private_key_tweak_mul: "1ed7a7baf66cc71fbf70150c130f167589bbba80f3af86593d1f9491eab9a31e",
        public_key_compressed_tweak_mul: "02f49169f80846da8c41d1e98960a2a17f1a688a8d72032b93594464cfe1c5dd51",
        public_key_uncompressed_tweak_mul: "04f49169f80846da8c41d1e98960a2a17f1a688a8d72032b93594464cfe1c5dd514642ea5600ee8581aceea49255897a9ebd96ac13d424597dd57dfb96389d928c",
        signature_compact: "6d0167a0e06acb29358f05cd927559870cd8c408872f1454aacf600aa10e68d820e39ade57d1b163f618aac4f7ca53477e029aa31b58317851df4f82a16dd974",
        recovery_id: 0,
        signature_der: "304402206d0167a0e06acb29358f05cd927559870cd8c408872f1454aacf600aa10e68d8022020e39ade57d1b163f618aac4f7ca53477e029aa31b58317851df4f82a16dd974",
        signature_compact_malleated: "6d0167a0e06acb29358f05cd927559870cd8c408872f1454aacf600aa10e68d8df1c6521a82e4e9c09e7553b0835acb73cac424393f06ec36df30f0a2ec867cd",
        signature_der_malleated: "304502206d0167a0e06acb29358f05cd927559870cd8c408872f1454aacf600aa10e68d8022100df1c6521a82e4e9c09e7553b0835acb73cac424393f06ec36df30f0a2ec867cd",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "304402206d0167a0e06acb29358f05cd927559870cd8c408872f1454aacf600aa10e68d8022020e39ade57d1b163f618aac4f7ca53477e029aa31b58317851df4f82a16dd974",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "c7030305a4b1080002fce3d500eafe02040405f9f906ce0604fbcb68aefabc04",
        message_hash: "01f802fdfd06f938a5020c0553c506009afa02fe37e04afefd04ff650740017e",
        compressed: true,
        invalidate: false,
        public_key_compressed: "039821980e2f1d9ed11b0710171ef207ed5be6d6bb63b840f0df22d534b3f27951",
        public_key_uncompressed: "049821980e2f1d9ed11b0710171ef207ed5be6d6bb63b840f0df22d534b3f2795160e822ea6733db929de4ff54f64f005715416062038f757766ff4f3f44cc0af9",
        private_key_tweak_add: "c8040406a5b2090103fde4d601ebff03050506fafa07cf0705fccc69affbbd05",
        public_key_compressed_tweak_add: "03bb7f4674a6afd94630b1a658cecc6efcf6d55f2a825625c1df26a15f45a22b39",
        public_key_uncompressed_tweak_add: "04bb7f4674a6afd94630b1a658cecc6efcf6d55f2a825625c1df26a15f45a22b39b64efa097d1b0294d9c72a7952e1f718c819bed71667bffd9a45f17342977ec9",
        private_key_tweak_mul: "818b802335b92d90fbc03f0c1b36c017a38138726fc5eca7ac99930507a20b4e",
        public_key_compressed_tweak_mul: "03107281141ef644876ff89ba5c401778d0fde77e820012f91599a22aba87101c6",
        public_key_uncompressed_tweak_mul: "04107281141ef644876ff89ba5c401778d0fde77e820012f91599a22aba87101c618576c10f78db7469aca411471616b8ff8895dffbdcc78eda5be4569e07e7a07",
        signature_compact: "ea16c6625ccc2a6b72a3951d4346963e5df48de9e8ec62e96f81b66b3020d6e108807eae7f9a79202d8fd8a0b67c1f0c37e4014270e8ede96ae7d10aeb3c2988",
        recovery_id: 0,
        signature_der: "3045022100ea16c6625ccc2a6b72a3951d4346963e5df48de9e8ec62e96f81b66b3020d6e1022008807eae7f9a79202d8fd8a0b67c1f0c37e4014270e8ede96ae7d10aeb3c2988",
        signature_compact_malleated: "ea16c6625ccc2a6b72a3951d4346963e5df48de9e8ec62e96f81b66b3020d6e1f77f8151806586dfd270275f4983e0f282cadba43e5fb25254ea8d81e4fa17b9",
        signature_der_malleated: "3046022100ea16c6625ccc2a6b72a3951d4346963e5df48de9e8ec62e96f81b66b3020d6e1022100f77f8151806586dfd270275f4983e0f282cadba43e5fb25254ea8d81e4fa17b9",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3046022100ea16c6625ccc2a6b72a3951d4346963e5df48de9e8ec62e96f81b66b3020d6e1022100f77f8151806586dfd270275f4983e0f282cadba43e5fb25254ea8d81e4fa17b9",
        node_verifies_test_signature_compact: true,
        elliptic_verifies_test_signature_der: true,
        elliptic_verifies_test_normalized_signature_der: true,
        node_verifies_test_signature_der: true,
        elliptic_verifies_test_signature_der_byte_6: true,
    },
    ReferenceVector {
        private_key: "d61f0427b8586a851faa020e33050205040401000605760207fffd039f05fd70",
        message_hash: "f9cfff0ad8cd8777066606b7b800046157c401fa3720168105b1f88ffe056203",
        compressed: true,
        invalidate: false,
        public_key_compressed: "032c0305baac65d057e35b76d9a7301e4e1f579599d917992ee7095fb56f9c42ad",
        public_key_uncompressed: "042c0305baac65d057e35b76d9a7301e4e1f579599d917992ee7095fb56f9c42ad12c3b9580d96932061f78c2359420be038cb6af019c7605f66fbf791087da8e5",
        private_key_tweak_add: "d7200528b9596b8620ab030f3406030605050201070677030900fe04a006fe71",
        public_key_compressed_tweak_add: "027708aa830f1ead68180b0fe9475076fef84d3acf8ccd85c87a9427fb46fa8a8e",
        public_key_uncompressed_tweak_add: "047708aa830f1ead68180b0fe9475076fef84d3acf8ccd85c87a9427fb46fa8a8e18f691d7ad4cdac0545ab64c5fefdb5da724c1d108632799ee3459f29206877c",
        private_key_tweak_mul: "e310780b52d58e64489ac23812150afabe5ac45e4ad485360c8d97ad7f66fc35",
        public_key_compressed_tweak_mul: "03779c0b88ead1c27f68273447d28273f83816a2e17d2b4f9241a96b9b38f6b30b",
        public_key_uncompressed_tweak_mul: "04779c0b88ead1c27f68273447d28273f83816a2e17d2b4f9241a96b9b38f6b30b1c0bad6e5e8e2587d690cf3fd6b998e04396f279fd45c7f09af6f9555e0af5e5",
        signature_compact: "4624deefd2d6382c01f3cf390078e2e78acd5d002270ba759740c666f6f690c02bff4fddf48aa97a628724f24a12598ca11aa1ed753602583d1aa305bc464950",
        recovery_id: 0,
        signature_der: "304402204624deefd2d6382c01f3cf390078e2e78acd5d002270ba759740c666f6f690c002202bff4fddf48aa97a628724f24a12598ca11aa1ed753602583d1aa305bc464950",
        signature_compact_malleated: "4624deefd2d6382c01f3cf390078e2e78acd5d002270ba759740c666f6f690c0d400b0220b7556859d78db0db5eda67219943af93a129de382b7bb8713eff7f1",
        signature_der_malleated: "304502204624deefd2d6382c01f3cf390078e2e78acd5d002270ba759740c666f6f690c0022100d400b0220b7556859d78db0db5eda67219943af93a129de382b7bb8713eff7f1",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "304402204624deefd2d6382c01f3cf390078e2e78acd5d002270ba759740c666f6f690c002202bff4fddf48aa97a628724f24a12598ca11aa1ed753602583d1aa305bc464950",
        node_verifies_test_signature_compact: true,
        elliptic_verifies_test_signature_der: true,
        elliptic_verifies_test_normalized_signature_der: true,
        node_verifies_test_signature_der: true,
        elliptic_verifies_test_signature_der_byte_6: true,
    },
    ReferenceVector {
        private_key: "4df9b5fe05ba15f70402fcab0703050163fde802076f01db450207040305f507",
        message_hash: "5adaea06ff23257234e857fd000700000504e3f9fe01fc041dff67fae703ae00",
        compressed: false,
        invalidate: false,
        public_key_compressed: "03a2c67db64d1fa8dbfd0ccb4d5ac7469ce74ec20a6999e2d5be7d8eb512a445dc",
        public_key_uncompressed: "04a2c67db64d1fa8dbfd0ccb4d5ac7469ce74ec20a6999e2d5be7d8eb512a445dc1ca02de30850965e4203e9d4515f561879fe45a7ceb06abae23818b6a542328f",
        private_key_tweak_add: "4efab6ff06bb16f80503fdac0804060264fee903087002dc460308050406f608",
        public_key_compressed_tweak_add: "0344a118beb3b4c29e33c3f74225a7baec60a70fcfdcb7c479de02c1115e954fea",
        public_key_uncompressed_tweak_add: "0444a118beb3b4c29e33c3f74225a7baec60a70fcfdcb7c479de02c1115e954feaf596b3736843f40ea91549197505594541231231852b04d4ffb6503277b27d79",
        private_key_tweak_mul: "a7ca4e07f117e6b73a4cbdce71ea15b03fe2a1b84f02604db0e52c7390d96111",
        public_key_compressed_tweak_mul: "02e32e1d01f7c7e4d66d24161f8a30605060d0f9adb177371c14f80952501029d1",
        public_key_uncompressed_tweak_mul: "04e32e1d01f7c7e4d66d24161f8a30605060d0f9adb177371c14f80952501029d1f22999c2eefe3d0fc0dface9a98477c2165c03b30955e086de92e5688adb47a8",
        signature_compact: "d8e6fa54793333595847f37a317a7e41878374901bf344b56807cb7f1fea26ec292ed2756b5641ff994cce5919710e1ef5378a75672762e741b00b5c9998d7ce",
        recovery_id: 1,
        signature_der: "3045022100d8e6fa54793333595847f37a317a7e41878374901bf344b56807cb7f1fea26ec0220292ed2756b5641ff994cce5919710e1ef5378a75672762e741b00b5c9998d7ce",
        signature_compact_malleated: "d8e6fa54793333595847f37a317a7e41878374901bf344b56807cb7f1fea26ecd6d12d8a94a9be0066b331a6e68ef1dfc577527148213d547e225330369d6973",
        signature_der_malleated: "3046022100d8e6fa54793333595847f37a317a7e41878374901bf344b56807cb7f1fea26ec022100d6d12d8a94a9be0066b331a6e68ef1dfc577527148213d547e225330369d6973",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3045022100d8e6fa54793333595847f37a317a7e41878374901bf344b56807cb7f1fea26ec0220292ed2756b5641ff994cce5919710e1ef5378a75672762e741b00b5c9998d7ce",
        node_verifies_test_signature_compact: true,
        elliptic_verifies_test_signature_der: true,
        elliptic_verifies_test_normalized_signature_der: true,
        node_verifies_test_signature_der: true,
        elliptic_verifies_test_signature_der_byte_6: true,
    },
    ReferenceVector {
        private_key: "5dfa041bfdd9e789f2f9f801000392fba102690501c7a3ecfca3fa04315b7d06",
        message_hash: "18060703faf884ff5ea435f955842e07f2005a00790603a1cb00f0ff038f7cfb",
        compressed: true,
        invalidate: true,
        public_key_compressed: "023d217459b328fe9267e0fa5dba765b1ddebb9bad039af2ec48174d382a47c106",
        public_key_uncompressed: "043d217459b328fe9267e0fa5dba765b1ddebb9bad039af2ec48174d382a47c106b2e1757b8089fcda41938543c3c9eda71cc0cd51c6131d8f3e3a559040c3e254",
        private_key_tweak_add: "5efb051cfedae88af3faf902010493fca2036a0602c8a4edfda4fb05325c7e07",
        public_key_compressed_tweak_add: "020f25d1effa7046abccac205c912ab5b04d8e3017597e96650c7ee58182a7ff34",
        public_key_uncompressed_tweak_add: "040f25d1effa7046abccac205c912ab5b04d8e3017597e96650c7ee58182a7ff340c809c2c3adcbd0892186bb87ede5ddf9156f6d2ff2609fba1ea4a10ded784f6",
        private_key_tweak_mul: "4daab72a6711d1699a6e22a97cf7f024ec87900eaf0c9e107c9c5e17ed80360a",
        public_key_compressed_tweak_mul: "0226632861506849250db08889461c7d20bd39c72b6e2224f677e5953c11850dc1",
        public_key_uncompressed_tweak_mul: "0426632861506849250db08889461c7d20bd39c72b6e2224f677e5953c11850dc12c03d699fa4ffc60a260af710636269a8670b22eb2cec36f0e913939342f1132",
        signature_compact: "3ff1cc0a0b3ac57bb0dacb5b56c7aa07d92569bddfd1efc2d731205ec2c22965244a85c4227d4e65f5fbab94c2678c36c133afe2e6023960b1fd4a18503ae38b",
        recovery_id: 0,
        signature_der: "304402203ff1cc0a0b3ac57bb0dacb5b56c7aa07d92569bddfd1efc2d731205ec2c229650220244a85c4227d4e65f5fbab94c2678c36c133afe2e6023960b1fd4a18503ae38b",
        signature_compact_malleated: "3ff1cc0a0b3ac57bb0dacb5b56c7aa07d92569bddfd1efc2d731205ec2c22965dbb57a3bdd82b19a0a04546b3d9873c7f97b2d03c94666db0dd514747ffb5db6",
        signature_der_malleated: "304502203ff1cc0a0b3ac57bb0dacb5b56c7aa07d92569bddfd1efc2d731205ec2c22965022100dbb57a3bdd82b19a0a04546b3d9873c7f97b2d03c94666db0dd514747ffb5db6",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "304402203ff1cc0a0b3ac57bb0dacb5b56c7aa07d92569bddfd1efc2d731205ec2c229650220244a85c4227d4e65f5fbab94c2678c36c133afe2e6023960b1fd4a18503ae38b",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "2e05c3ce0307a00702538b067905d1fdb20281af7301050006ffc3fa60fa03d9",
        message_hash: "b87d36a2d13207a679f9d0b0f2079afffadac2024e010102a60036eb4116fb04",
        compressed: true,
        invalidate: true,
        public_key_compressed: "03e1b08bcd11343790c81de34c9888ca417cc5c623f81707694fd1f8bca9cb8cd6",
        public_key_uncompressed: "04e1b08bcd11343790c81de34c9888ca417cc5c623f81707694fd1f8bca9cb8cd62cc613da7e709fa82ffefa79c8100ff86c16ded28c67dbbe85e2ccc453c2e401",
        private_key_tweak_add: "2f06c4cf0408a10803548c077a06d2feb30382b0740206010800c4fb61fb04da",
        public_key_compressed_tweak_add: "0316a5b87466d38e3d207eaab7091068e6f9948a95379ac7dc772ca0f0345a3a51",
        public_key_uncompressed_tweak_add: "0416a5b87466d38e3d207eaab7091068e6f9948a95379ac7dc772ca0f0345a3a5107ede6ff5c501cc39c10f653897b1e8c0b8941104378c9f1ab691b3a5ec5047f",
        private_key_tweak_mul: "ad51f8456cc3a6e7bd495c4c3867dc5d22a28ce6bb1dbee6efb547249e9d1e17",
        public_key_compressed_tweak_mul: "023048a5c8af05276203bacf92d65a25ff8a398618b13afde58d9aea4cbd0dc29e",
        public_key_uncompressed_tweak_mul: "043048a5c8af05276203bacf92d65a25ff8a398618b13afde58d9aea4cbd0dc29eab43dd1b3d6996de2464bc8915c7777d53ab0b3dc3cd50b62ae68adb8a4d5cd6",
        signature_compact: "7dceb3c5ca29b0179add0aebb51b7e3f2b1ff980a652c0af1339410d393aa642792de4075497c7d031f434f1f65f13df65e25a0604e18c7bc76dfda2267b61cf",
        recovery_id: 0,
        signature_der: "304402207dceb3c5ca29b0179add0aebb51b7e3f2b1ff980a652c0af1339410d393aa6420220792de4075497c7d031f434f1f65f13df65e25a0604e18c7bc76dfda2267b61cf",
        signature_compact_malleated: "7dceb3c5ca29b0179add0aebb51b7e3f2b1ff980a652c0af1339410d393aa64286d21bf8ab68382fce0bcb0e09a0ec1f54cc82e0aa6713bff86460eaa9badf72",
        signature_der_malleated: "304502207dceb3c5ca29b0179add0aebb51b7e3f2b1ff980a652c0af1339410d393aa64202210086d21bf8ab68382fce0bcb0e09a0ec1f54cc82e0aa6713bff86460eaa9badf72",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "304402207dceb3c5ca29b0179add0aebb51b7e3f2b1ff980a652c0af1339410d393aa6420220792de4075497c7d031f434f1f65f13df65e25a0604e18c7bc76dfda2267b61cf",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "73b18c2d00fbcb04fc996978ecfbfa82ff0750c7b679812245ec2e5c822ffd04",
        message_hash: "c85ac10782ff61faf860fc10078965f96b8b0302f6fad5006dbd0503f98704ca",
        compressed: false,
        invalidate: false,
        public_key_compressed: "02a1f9ae94bc403f59cb86da1d00942916506667ff86bd3180b53ae459a040d69a",
        public_key_uncompressed: "04a1f9ae94bc403f59cb86da1d00942916506667ff86bd3180b53ae459a040d69af61d3295526c9ba1e80f17862e3a7c85d526ee31d011f073456afe0804c029f2",
        private_key_tweak_add: "74b28d2e01fccc05fd9a6a79edfcfb84000851c8b77a822346ed2f5d8330fe05",
        public_key_compressed_tweak_add: "025f58c1673ceb5081525fb009b55963b8a8abcf1cdbc7e2a686668b2b48c225a3",
        public_key_uncompressed_tweak_add: "045f58c1673ceb5081525fb009b55963b8a8abcf1cdbc7e2a686668b2b48c225a35dabdaf05e840e157d063249931f6dbb590cfb4675d8b8f5172d02e1f656c3b0",
        private_key_tweak_mul: "bdd5f9ab47cfa32a6d896581be2e0a071f35e0fb648ccc07bda4736c78038f63",
        public_key_compressed_tweak_mul: "024e2dcfdbf2523fc27b08dfb8be21801b20e27b9229320a0023ed639ba1a24c68",
        public_key_uncompressed_tweak_mul: "044e2dcfdbf2523fc27b08dfb8be21801b20e27b9229320a0023ed639ba1a24c68b9901f552edb675287295c7be2ad9d602e9a3826d1a95e87dd8fcab4b9940ce4",
        signature_compact: "9f12cd2d3bd7a5a135b8c36d97c4763ee1c1b8dc84ef3354eeaae934288ea2b016cdb9113e23a4695d5998af4ccb7603971616488614cafdf9dd32a0ad095971",
        recovery_id: 1,
        signature_der: "30450221009f12cd2d3bd7a5a135b8c36d97c4763ee1c1b8dc84ef3354eeaae934288ea2b0022016cdb9113e23a4695d5998af4ccb7603971616488614cafdf9dd32a0ad095971",
        signature_compact_malleated: "9f12cd2d3bd7a5a135b8c36d97c4763ee1c1b8dc84ef3354eeaae934288ea2b0e93246eec1dc5b96a2a66750b33489fb2398c69e2933d53dc5f52bec232ce7d0",
        signature_der_malleated: "30460221009f12cd2d3bd7a5a135b8c36d97c4763ee1c1b8dc84ef3354eeaae934288ea2b0022100e93246eec1dc5b96a2a66750b33489fb2398c69e2933d53dc5f52bec232ce7d0",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "30460221009f12cd2d3bd7a5a135b8c36d97c4763ee1c1b8dc84ef3354eeaae934288ea2b0022100e93246eec1dc5b96a2a66750b33489fb2398c69e2933d53dc5f52bec232ce7d0",
        node_verifies_test_signature_compact: true,
        elliptic_verifies_test_signature_der: true,
        elliptic_verifies_test_normalized_signature_der: true,
        node_verifies_test_signature_der: true,
        elliptic_verifies_test_signature_der_byte_6: true,
    },
    ReferenceVector {
        private_key: "4411adb30abf02a9fda606f5012ef8f642b603d87b01c1189af82800ff8a069f",
        message_hash: "06fe568ae0f2b006819868fe05035405f203cabb898f4ef91dfee4fdf9cfa15e",
        compressed: false,
        invalidate: false,
        public_key_compressed: "03a29f329ede3f1d0d57c763a84808973f9abe725e435e3286715f01c5865213e7",
        public_key_uncompressed: "04a29f329ede3f1d0d57c763a84808973f9abe725e435e3286715f01c5865213e73f4fbe1daaf021132c435e6aa230cb79c1cac9e309ef8bb9ccff814aaa2291a9",
        private_key_tweak_add: "4512aeb40bc003aafea707f6022ff9f743b704d97c02c2199bf92902008b07a0",
        public_key_compressed_tweak_add: "025da7bc18b04e411a823592e9c4986f23319b54095bd59205fc7882a86a7e35c7",
        public_key_uncompressed_tweak_add: "045da7bc18b04e411a823592e9c4986f23319b54095bd59205fc7882a86a7e35c715eb0a0b3db3ce3ae2f48fdde472ba27d0686bd0a83fe41dd5395c126a3d99ca",
        private_key_tweak_mul: "ed773090bdc2a4911b128cbce4f28eb695e810114254ab87399c49135d090f63",
        public_key_compressed_tweak_mul: "038d9a76c97c26332e285235e6a03e3db1def780e37aecfa11b415cfefc68cd2a1",
        public_key_uncompressed_tweak_mul: "048d9a76c97c26332e285235e6a03e3db1def780e37aecfa11b415cfefc68cd2a1161a2151d12f73bc5970ffed67b4901eb3662ba69620d17a7b15163535ff10ab",
        signature_compact: "7d812019f224a0f66fbe37db6107b0afd97d0df4380042d5be4a2bdc2f1d2ab8726ad81f0adfc55f1819681ccea6f497cf228d7676e6cca1a3cfe900dfcdb88b",
        recovery_id: 0,
        signature_der: "304402207d812019f224a0f66fbe37db6107b0afd97d0df4380042d5be4a2bdc2f1d2ab80220726ad81f0adfc55f1819681ccea6f497cf228d7676e6cca1a3cfe900dfcdb88b",
        signature_compact_malleated: "7d812019f224a0f66fbe37db6107b0afd97d0df4380042d5be4a2bdc2f1d2ab88d9527e0f5203aa0e7e697e331590b66eb8c4f703861d39a1c02758bf06888b6",
        signature_der_malleated: "304502207d812019f224a0f66fbe37db6107b0afd97d0df4380042d5be4a2bdc2f1d2ab80221008d9527e0f5203aa0e7e697e331590b66eb8c4f703861d39a1c02758bf06888b6",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "304502207d812019f224a0f66fbe37db6107b0afd97d0df4380042d5be4a2bdc2f1d2ab80221008d9527e0f5203aa0e7e697e331590b66eb8c4f703861d39a1c02758bf06888b6",
        node_verifies_test_signature_compact: true,
        elliptic_verifies_test_signature_der: true,
        elliptic_verifies_test_normalized_signature_der: true,
        node_verifies_test_signature_der: true,
        elliptic_verifies_test_signature_der_byte_6: true,
    },
    ReferenceVector {
        private_key: "e78dfeb8802f4cfd9049ae5600f9f1956de5fa66c103be052482cff402209580",
        message_hash: "fcb7036e0505385301fb06f80003670032fcdb04001fa6cef992eab600889f97",
        compressed: true,
        invalidate: true,
        public_key_compressed: "03a44528581de887a772bd88f3c376f8914205bb9feb7b0521de5b95eb341ef371",
        public_key_uncompressed: "04a44528581de887a772bd88f3c376f8914205bb9feb7b0521de5b95eb341ef371026f8b4e6e77d0554257263d90a3a0fd5d707cbd4d18e34367e400ca75a1dc43",
        private_key_tweak_add: "e88effb981304dfe914aaf5701faf2966ee6fb67c204bf062583d0f503219681",
        public_key_compressed_tweak_add: "03c60bcb588aa98e4b6c1943de7b18a356948a9460039d792b718286f8d28d76a3",
        public_key_uncompressed_tweak_add: "04c60bcb588aa98e4b6c1943de7b18a356948a9460039d792b718286f8d28d76a37f9340f3ab297d2e3ea29563c902ec1e4b3b68e062b574c207e5c6d17c3399e9",
        private_key_tweak_mul: "129fd3469aae720443995cdd2ae88e5dd9031d425155a2d89eaae6cf7c4616ab",
        public_key_compressed_tweak_mul: "03998162c371fbf9703f766472dfd5c62d4ccf274813b539753fe431ed9cbac2ef",
        public_key_uncompressed_tweak_mul: "04998162c371fbf9703f766472dfd5c62d4ccf274813b539753fe431ed9cbac2ef506adbeb506aa51ce36a6d2f8e4391e37b009e66a1389d2f753a02d6be58011f",
        signature_compact: "f12b8dd99cd7ed4f5784572e3de15859a4c2b2ae3ec2b094203dc25ad41abc9914cbf84632f025179e90b0431ef090825a9b4d34be6e2692ee69cb9cfc6697b8",
        recovery_id: 1,
        signature_der: "3045022100f12b8dd99cd7ed4f5784572e3de15859a4c2b2ae3ec2b094203dc25ad41abc99022014cbf84632f025179e90b0431ef090825a9b4d34be6e2692ee69cb9cfc6697b8",
        signature_compact_malleated: "f12b8dd99cd7ed4f5784572e3de15859a4c2b2ae3ec2b094203dc25ad41abc99eb3407b9cd0fdae8616f4fbce10f6f7c60138fb1f0da79a8d16892efd3cfa989",
        signature_der_malleated: "3046022100f12b8dd99cd7ed4f5784572e3de15859a4c2b2ae3ec2b094203dc25ad41abc99022100eb3407b9cd0fdae8616f4fbce10f6f7c60138fb1f0da79a8d16892efd3cfa989",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3045022100f12b8dd99cd7ed4f5784572e3de15859a4c2b2ae3ec2b094203dc25ad41abc99022014cbf84632f025179e90b0431ef090825a9b4d34be6e2692ee69cb9cfc6697b8",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "0668eea28301f132c0abf8fc27355c59f884fbe8bf03f5aefd80030205c0b15b",
        message_hash: "0092fe072ad601ebff019ed7f8c45ee2e84380c01a0601c18c03d71f07f9ff27",
        compressed: true,
        invalidate: true,
        public_key_compressed: "02f24bdd9f6ba0d27d0debaa4b6c2d13f474aaa992607b18f162d73c0217cbfb92",
        public_key_uncompressed: "04f24bdd9f6ba0d27d0debaa4b6c2d13f474aaa992607b18f162d73c0217cbfb92e63d11252db4c28af9e12f79f3cd3499fd6c94b2f0d272cdcde9292e0f14b522",
        private_key_tweak_add: "0769efa38402f233c1acf9fd28365d5af985fce9c004f6affe81040306c1b25c",
        public_key_compressed_tweak_add: "023b3e81f48c14e06f9a83895ca53f7431117b6696b46f117bee2323abb3707bf1",
        public_key_uncompressed_tweak_add: "043b3e81f48c14e06f9a83895ca53f7431117b6696b46f117bee2323abb3707bf171b066be2646dd4b803be31f968b4760401ec4d43e5f563a8d67fdd79b799d82",
        private_key_tweak_mul: "24dce181ca45fc63d6c2deaaa2053a9a7681a4d650b1f4ef31a0b647270bdc8a",
        public_key_compressed_tweak_mul: "0373876cee991caeca68f44e5e2a44413e0ace7982aad4ee88950a2377669641a2",
        public_key_uncompressed_tweak_mul: "0473876cee991caeca68f44e5e2a44413e0ace7982aad4ee88950a2377669641a25940bb2deda83818d3b72ad6fcb36ae76b59d416cacdd9359876fa93c04e8f61",
        signature_compact: "ae57a7992ff9d8b98234e7303c3085e6fa4d88a17569dab54caf21fffe6f0182011f70b46cb6064992735a95a0f9deb18b523d72bc14593ea13f3b3b4a47ce0c",
        recovery_id: 0,
        signature_der: "3045022100ae57a7992ff9d8b98234e7303c3085e6fa4d88a17569dab54caf21fffe6f01820220011f70b46cb6064992735a95a0f9deb18b523d72bc14593ea13f3b3b4a47ce0c",
        signature_compact_malleated: "ae57a7992ff9d8b98234e7303c3085e6fa4d88a17569dab54caf21fffe6f0182fee08f4b9349f9b66d8ca56a5f06214d2f5c9f73f33446fd1e93235185ee7335",
        signature_der_malleated: "3046022100ae57a7992ff9d8b98234e7303c3085e6fa4d88a17569dab54caf21fffe6f0182022100fee08f4b9349f9b66d8ca56a5f06214d2f5c9f73f33446fd1e93235185ee7335",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3046022100ae57a7992ff9d8b98234e7303c3085e6fa4d88a17569dab54caf21fffe6f0182022100fee08f4b9349f9b66d8ca56a5f06214d2f5c9f73f33446fd1e93235185ee7335",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "d33fff8f01ebb401b0abe110f94806fe0ae80200ebfa3ff8d8527ff0d702fcf9",
        message_hash: "0604020ffec801950575ed0250f4a316ea07fd015d60939a01b1fc0110c20047",
        compressed: false,
        invalidate: true,
        public_key_compressed: "0281025b6a389c844890c9abf650ee657f37d6944ca998fe40402eccf53de0b15e",
        public_key_uncompressed: "0481025b6a389c844890c9abf650ee657f37d6944ca998fe40402eccf53de0b15e25aad5dd9a6c9abc2828ada3b93859dd66cce02d7661e95a00558934b5d42ad6",
        private_key_tweak_add: "d441009002ecb502b1ace211fa4907ff0be90301ecfb40f9d95380f1d803fdfa",
        public_key_compressed_tweak_add: "03c2511b16aa48aae7170b23a96ee03b813eaa17c38aa3520625a87cf16b43dc9e",
        public_key_uncompressed_tweak_add: "04c2511b16aa48aae7170b23a96ee03b813eaa17c38aa3520625a87cf16b43dc9e12ac88822498234c86288423b8f8c186331ab19b9cf3112867703e3046e6647d",
        private_key_tweak_mul: "0fe8c661aa370dd651bf409d58ebf01076e22fef47b0a550966b1cf6c5031bcd",
        public_key_compressed_tweak_mul: "020ca24df34f2d166c918810e5395c8de5a66d710c4ce71b03ce24e34cfe97a103",
        public_key_uncompressed_tweak_mul: "040ca24df34f2d166c918810e5395c8de5a66d710c4ce71b03ce24e34cfe97a103ab654b471440dd1539bdae78162f4651819a577e2348f7f73ce45b996eeea9fa",
        signature_compact: "49001b675a7d3043b5fd3444f14698dd9372fe484a5a811cea95eb22c1d1a62c5de597a429d38990bcba066cb8ef5a3f8570d6a2ba110bf21f64d7831f551791",
        recovery_id: 0,
        signature_der: "3044022049001b675a7d3043b5fd3444f14698dd9372fe484a5a811cea95eb22c1d1a62c02205de597a429d38990bcba066cb8ef5a3f8570d6a2ba110bf21f64d7831f551791",
        signature_compact_malleated: "49001b675a7d3043b5fd3444f14698dd9372fe484a5a811cea95eb22c1d1a62ca21a685bd62c766f4345f9934710a5bf353e0643f5379449a06d8709b0e129b0",
        signature_der_malleated: "3045022049001b675a7d3043b5fd3444f14698dd9372fe484a5a811cea95eb22c1d1a62c022100a21a685bd62c766f4345f9934710a5bf353e0643f5379449a06d8709b0e129b0",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "3044022049001b675a7d3043b5fd3444f14698dd9372fe484a5a811cea95eb22c1d1a62c02205de597a429d38990bcba066cb8ef5a3f8570d6a2ba110bf21f64d7831f551791",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
    ReferenceVector {
        private_key: "7d4d02260513b4e107050533b2fe02cefd037e1a2fa62e6404430003ff02d101",
        message_hash: "d8022865bee2036c8a061d4aac34fd001bfb95770107e7f2d1a901fefb803c65",
        compressed: false,
        invalidate: true,
        public_key_compressed: "0223c10aae677eb2161f1e4e4f3ca8b40873fbcb0a950433e59660c1dc1872982e",
        public_key_uncompressed: "0423c10aae677eb2161f1e4e4f3ca8b40873fbcb0a950433e59660c1dc1872982e5b893dc0b0a245c12af943958f1905f01832025a04ab62485fefc8bf88442a50",
        private_key_tweak_add: "7e4e03270614b5e208060634b3ff03cffe047f1b30a72f65054401050003d202",
        public_key_compressed_tweak_add: "0314ac742d1835297a50b7be84096114467105248cc0c53355bf61a3ac0fc8536e",
        public_key_uncompressed_tweak_add: "0414ac742d1835297a50b7be84096114467105248cc0c53355bf61a3ac0fc8536e807c5bd372652281b97e3cd497051776f512c463f94a8196a2e67f71ddbaa119",
        private_key_tweak_mul: "72c51f1171c5335e4408b9e9c108f85a7f54e5e6986a1cc2823a23403631254d",
        public_key_compressed_tweak_mul: "02a64a4129372a17f9439e48444b18313e3367dc5ad320e1abd10c8824ec6ab9bd",
        public_key_uncompressed_tweak_mul: "04a64a4129372a17f9439e48444b18313e3367dc5ad320e1abd10c8824ec6ab9bd56c65ffa604da98fa47f19bc3c80a2920d94235059ce76165f28e028681380a8",
        signature_compact: "414afb308a2d07b8c052827c8e86274053078ca41f72075b51bd574b099db4947969d0cd328e2997182260b336e8e21bb45d42aebcea9d996d2e81b9a2c5b703",
        recovery_id: 1,
        signature_der: "30440220414afb308a2d07b8c052827c8e86274053078ca41f72075b51bd574b099db49402207969d0cd328e2997182260b336e8e21bb45d42aebcea9d996d2e81b9a2c5b703",
        signature_compact_malleated: "414afb308a2d07b8c052827c8e86274053078ca41f72075b51bd574b099db49486962f32cd71d668e7dd9f4cc9171de306519a37f25e02a252a3dcd32d708a3e",
        signature_der_malleated: "30450220414afb308a2d07b8c052827c8e86274053078ca41f72075b51bd574b099db49402210086962f32cd71d668e7dd9f4cc9171de306519a37f25e02a252a3dcd32d708a3e",
        node_verifies_signature_compact: true,
        node_verifies_malleated_compact: false,
        elliptic_verifies_signature_der: true,
        elliptic_verifies_malleated_der: true,
        elliptic_signature_der: "30450220414afb308a2d07b8c052827c8e86274053078ca41f72075b51bd574b099db49402210086962f32cd71d668e7dd9f4cc9171de306519a37f25e02a252a3dcd32d708a3e",
        node_verifies_test_signature_compact: false,
        elliptic_verifies_test_signature_der: false,
        elliptic_verifies_test_normalized_signature_der: false,
        node_verifies_test_signature_der: false,
        elliptic_verifies_test_signature_der_byte_6: false,
    },
];

// `[crypto] instantiateSecp256k1 with binary` is not ported: this port's
// secp256k1 is native, so `instantiateSecp256k1Bytes` does not exist.

#[test]
fn crypto_instantiate_secp256k1_with_randomization() {
    let secp256k1 = instantiate_secp256k1(Some(&random_bytes_32()));
    assert!(secp256k1.verify_signature_der_low_s(&SIG_DER, &PUBKEY_UNCOMPRESSED, &MESSAGE_HASH));
}

#[test]
fn crypto_secp256k1_add_tweak_private_key() {
    let secp256k1 = &*SECP256K1_PROMISE;
    assert_eq!(
        secp256k1.add_tweak_private_key(&PRIVKEY, &KEY_TWEAK_VAL),
        Ok(PRIVKEY_TWEAKED_ADD.to_vec())
    );
    assert_eq!(
        secp256k1.add_tweak_private_key(&PRIVKEY, &[255; 32]),
        Err(Secp256k1Error::addTweakPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_add_tweak_private_key() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.privateKeyTweakAdd`, precomputed)
    for vector in &REFERENCE_VECTORS {
        assert_eq!(
            secp256k1.add_tweak_private_key(&vector.private_key(), &KEY_TWEAK_VAL),
            Ok(hex_to_bin(vector.private_key_tweak_add))
        );
    }
    /*
     * the elliptic library doesn't implement public or private key tweaking.
     * perhaps future tests can do the math in JavaScript and compare with that.
     */
}

#[test]
fn crypto_secp256k1_add_tweak_public_key_compressed() {
    assert_eq!(
        internal_secp256k1.add_tweak_public_key_compressed(&PUBKEY_COMPRESSED, &KEY_TWEAK_VAL),
        Ok(PUBKEY_TWEAKED_ADD_COMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.add_tweak_public_key_compressed(&[0; 65], &KEY_TWEAK_VAL),
        Err(Secp256k1Error::unparsablePublicKey.to_string())
    );
    assert_eq!(
        internal_secp256k1.add_tweak_public_key_compressed(&PUBKEY_COMPRESSED, &[255; 32]),
        Err(Secp256k1Error::addTweakPublicKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_add_tweak_public_key_compressed() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyTweakAdd`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let pubkey_c = assert_success(secp256k1.derive_public_key_compressed(&vector.private_key()), None);
        assert_eq!(
            secp256k1.add_tweak_public_key_compressed(&pubkey_c, &KEY_TWEAK_VAL),
            Ok(hex_to_bin(vector.public_key_compressed_tweak_add))
        );
    }
    /*
     * the elliptic library doesn't implement public or private key tweaking.
     * perhaps future tests can do the math in JavaScript and compare with that.
     */
}

#[test]
fn crypto_secp256k1_add_tweak_public_key_uncompressed() {
    assert_eq!(
        internal_secp256k1.add_tweak_public_key_uncompressed(&PUBKEY_UNCOMPRESSED, &KEY_TWEAK_VAL),
        Ok(PUBKEY_TWEAKED_ADD_UNCOMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.add_tweak_public_key_uncompressed(&[0; 65], &KEY_TWEAK_VAL),
        Err(Secp256k1Error::unparsablePublicKey.to_string())
    );
    assert_eq!(
        internal_secp256k1.add_tweak_public_key_uncompressed(&PUBKEY_COMPRESSED, &[255; 32]),
        Err(Secp256k1Error::addTweakPublicKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_add_tweak_public_key_uncompressed() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyTweakAdd`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let pubkey_u = assert_success(secp256k1.derive_public_key_uncompressed(&vector.private_key()), None);
        assert_eq!(
            secp256k1.add_tweak_public_key_uncompressed(&pubkey_u, &KEY_TWEAK_VAL),
            Ok(hex_to_bin(vector.public_key_uncompressed_tweak_add))
        );
    }
    /*
     * the elliptic library doesn't implement public or private key tweaking.
     * perhaps future tests can do the math in JavaScript and compare with that.
     */
}

#[test]
fn crypto_secp256k1_compress_public_key() {
    assert_eq!(
        internal_secp256k1.compress_public_key(&PUBKEY_UNCOMPRESSED),
        Ok(PUBKEY_COMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.compress_public_key(&[0; 65]),
        Err(Secp256k1Error::unparsablePublicKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_compress_public_key() {
    let secp256k1: &'static Secp256k1 = &SECP256K1_PROMISE;
    let reverses_uncompress = fc::property(fc_valid_private_key(), move |private_key| {
        let pubkey_c = assert_success(secp256k1.derive_public_key_compressed(private_key), None);
        assert_eq!(
            Ok(pubkey_c.clone()),
            secp256k1.compress_public_key(&assert_success(secp256k1.uncompress_public_key(&pubkey_c), None))
        );
        true
    });

    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyConvert(pubkeyU, true)`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            let pubkey_u = assert_success(secp256k1.derive_public_key_uncompressed(&vector.private_key()), None);
            assert_eq!(
                secp256k1.compress_public_key(&pubkey_u),
                Ok(hex_to_bin(vector.public_key_compressed))
            );
        }
    };

    // equivalentToElliptic (`ec.keyFromPublic(pubkeyU).getPublic().encodeCompressed()`, precomputed)
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            let pubkey_u = assert_success(secp256k1.derive_public_key_uncompressed(&vector.private_key()), None);
            assert_eq!(
                secp256k1.compress_public_key(&pubkey_u),
                Ok(hex_to_bin(vector.public_key_compressed))
            );
        }
    };
    fc::assert(reverses_uncompress, None);
    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_derive_public_key_compressed() {
    assert_eq!(
        internal_secp256k1.derive_public_key_compressed(&PRIVKEY),
        Ok(PUBKEY_COMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.derive_public_key_compressed(&SECP256K1_ORDER_N),
        Err(Secp256k1Error::derivePublicKeyFromInvalidPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_derive_public_key_compressed() {
    let secp256k1: &'static Secp256k1 = &SECP256K1_PROMISE;
    let is_equivalent_to_derive_uncompressed_then_compress = fc::property(fc_valid_private_key(), move |private_key| {
        let pubkey_u = assert_success(secp256k1.derive_public_key_uncompressed(private_key), None);
        let pubkey_c = secp256k1.derive_public_key_compressed(private_key);
        assert_eq!(pubkey_c, secp256k1.compress_public_key(&pubkey_u));
        true
    });

    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyCreate(privateKey, true)`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.derive_public_key_compressed(&vector.private_key()),
                Ok(hex_to_bin(vector.public_key_compressed))
            );
        }
    };

    // equivalentToElliptic (`setupElliptic(privateKey).pubCompressed`, precomputed)
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.derive_public_key_compressed(&vector.private_key()),
                Ok(hex_to_bin(vector.public_key_compressed))
            );
        }
    };
    fc::assert(is_equivalent_to_derive_uncompressed_then_compress, None);
    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_derive_public_key_uncompressed() {
    assert_eq!(
        internal_secp256k1.derive_public_key_uncompressed(&PRIVKEY),
        Ok(PUBKEY_UNCOMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.derive_public_key_uncompressed(&SECP256K1_ORDER_N),
        Err(Secp256k1Error::derivePublicKeyFromInvalidPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_derive_public_key_uncompressed() {
    let secp256k1: &'static Secp256k1 = &SECP256K1_PROMISE;
    let is_equivalent_to_derive_compressed_then_uncompress = fc::property(fc_valid_private_key(), move |private_key| {
        let pubkey_c = assert_success(secp256k1.derive_public_key_compressed(private_key), None);
        let pubkey_u = secp256k1.derive_public_key_uncompressed(private_key);
        assert_eq!(pubkey_u, secp256k1.uncompress_public_key(&pubkey_c));
        true
    });

    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyCreate(privateKey, false)`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.derive_public_key_uncompressed(&vector.private_key()),
                Ok(hex_to_bin(vector.public_key_uncompressed))
            );
        }
    };

    // equivalentToElliptic (`setupElliptic(privateKey).pubUncompressed`, precomputed)
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.derive_public_key_uncompressed(&vector.private_key()),
                Ok(hex_to_bin(vector.public_key_uncompressed))
            );
        }
    };
    fc::assert(is_equivalent_to_derive_compressed_then_uncompress, None);
    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_malleate_signature_der() {
    assert_eq!(
        internal_secp256k1.malleate_signature_der(&SIG_DER),
        Ok(SIG_DER_HIGH_S.to_vec())
    );
}

#[test]
fn fast_check_crypto_secp256k1_malleate_signature_der() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // malleationIsJustNegation (over the fixed inputs: it includes `elliptic` checks)
    for vector in &REFERENCE_VECTORS {
        let (private_key, message) = (vector.private_key(), vector.message_hash());
        // const { key } = setupElliptic(privateKey);
        let pubkey = assert_success(secp256k1.derive_public_key_compressed(&private_key), None);
        let sig = assert_success(secp256k1.sign_message_hash_der(&private_key, &message), None);
        assert!(secp256k1.verify_signature_der_low_s(&sig, &pubkey, &message));
        // t.true(ellipticCheckSignature(sig, key, message));
        assert_eq!(sig, hex_to_bin(vector.signature_der));
        assert!(vector.elliptic_verifies_signature_der);
        let malleated = assert_success(secp256k1.malleate_signature_der(&sig), None);
        assert!(secp256k1.verify_signature_der(&malleated, &pubkey, &message));
        // t.true(ellipticCheckSignature(malleated, key, message));
        assert_eq!(malleated, hex_to_bin(vector.signature_der_malleated));
        assert!(vector.elliptic_verifies_malleated_der);
        assert!(!secp256k1.verify_signature_der_low_s(&malleated, &pubkey, &message));
        assert_eq!(Ok(sig), secp256k1.malleate_signature_der(&malleated));
    }
}

#[test]
fn crypto_secp256k1_malleate_signature_compact() {
    assert_eq!(
        internal_secp256k1.malleate_signature_compact(&SIG_COMPACT),
        Ok(SIG_COMPACT_HIGH_S.to_vec())
    );
}

#[test]
fn fast_check_crypto_secp256k1_malleate_signature_compact() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // malleationIsJustNegation (over the fixed inputs: it includes `secp256k1Node` checks)
    for vector in &REFERENCE_VECTORS {
        let (private_key, message) = (vector.private_key(), vector.message_hash());
        let pubkey = assert_success(secp256k1.derive_public_key_compressed(&private_key), None);
        let sig = assert_success(secp256k1.sign_message_hash_compact(&private_key, &message), None);
        assert!(secp256k1.verify_signature_compact_low_s(&sig, &pubkey, &message));
        // t.true(secp256k1Node.ecdsaVerify(sig, message, pubkey));
        assert_eq!(sig, hex_to_bin(vector.signature_compact));
        assert!(vector.node_verifies_signature_compact);
        let malleated = assert_success(secp256k1.malleate_signature_compact(&sig), None);
        assert!(secp256k1.verify_signature_compact(&malleated, &pubkey, &message));
        assert!(!secp256k1.verify_signature_compact_low_s(&malleated, &pubkey, &message));
        // t.false(secp256k1Node.ecdsaVerify(malleated, message, pubkey));
        assert_eq!(malleated, hex_to_bin(vector.signature_compact_malleated));
        assert!(!vector.node_verifies_malleated_compact);
        let malleated_malleated = assert_success(secp256k1.malleate_signature_compact(&malleated), None);
        // t.true(secp256k1Node.ecdsaVerify(malleatedMalleated, message, pubkey));
        assert_eq!(malleated_malleated, hex_to_bin(vector.signature_compact));
        assert!(vector.node_verifies_signature_compact);
        assert!(secp256k1.verify_signature_compact_low_s(&malleated_malleated, &pubkey, &message));
        assert_eq!(sig, malleated_malleated);
    }
}

#[test]
fn crypto_secp256k1_mul_tweak_private_key() {
    assert_eq!(
        internal_secp256k1.mul_tweak_private_key(&PRIVKEY, &KEY_TWEAK_VAL),
        Ok(PRIVKEY_TWEAKED_MUL.to_vec())
    );
    assert_eq!(
        internal_secp256k1.mul_tweak_private_key(&PRIVKEY, &[255; 32]),
        Err(Secp256k1Error::mulTweakPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_mul_tweak_private_key() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.privateKeyTweakMul`, precomputed)
    for vector in &REFERENCE_VECTORS {
        assert_eq!(
            secp256k1.mul_tweak_private_key(&vector.private_key(), &KEY_TWEAK_VAL),
            Ok(hex_to_bin(vector.private_key_tweak_mul))
        );
    }
    /*
     * the elliptic library doesn't implement public or private key tweaking.
     * perhaps future tests can do the math in JavaScript and compare with that.
     */
}

#[test]
fn crypto_secp256k1_mul_tweak_public_key_compressed() {
    assert_eq!(
        internal_secp256k1.mul_tweak_public_key_compressed(&PUBKEY_COMPRESSED, &KEY_TWEAK_VAL),
        Ok(PUBKEY_TWEAKED_MUL_COMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.mul_tweak_public_key_compressed(&[0; 65], &KEY_TWEAK_VAL),
        Err(Secp256k1Error::unparsablePublicKey.to_string())
    );
    assert_eq!(
        internal_secp256k1.mul_tweak_public_key_compressed(&PUBKEY_COMPRESSED, &[255; 32]),
        Err(Secp256k1Error::mulTweakPublicKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_mul_tweak_public_key_compressed() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyTweakMul`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let pubkey_c = assert_success(secp256k1.derive_public_key_compressed(&vector.private_key()), None);
        assert_eq!(
            secp256k1.mul_tweak_public_key_compressed(&pubkey_c, &KEY_TWEAK_VAL),
            Ok(hex_to_bin(vector.public_key_compressed_tweak_mul))
        );
    }
    /*
     * the elliptic library doesn't implement public or private key tweaking.
     * perhaps future tests can do the math in JavaScript and compare with that.
     */
}

#[test]
fn crypto_secp256k1_mul_tweak_public_key_uncompressed() {
    assert_eq!(
        internal_secp256k1.mul_tweak_public_key_uncompressed(&PUBKEY_UNCOMPRESSED, &KEY_TWEAK_VAL),
        Ok(PUBKEY_TWEAKED_MUL_UNCOMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.mul_tweak_public_key_uncompressed(&[0; 65], &KEY_TWEAK_VAL),
        Err(Secp256k1Error::unparsablePublicKey.to_string())
    );
    assert_eq!(
        internal_secp256k1.mul_tweak_public_key_uncompressed(&PUBKEY_COMPRESSED, &[255; 32]),
        Err(Secp256k1Error::mulTweakPublicKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_mul_tweak_public_key_uncompressed() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyTweakMul`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let pubkey_u = assert_success(secp256k1.derive_public_key_uncompressed(&vector.private_key()), None);
        assert_eq!(
            secp256k1.mul_tweak_public_key_uncompressed(&pubkey_u, &KEY_TWEAK_VAL),
            Ok(hex_to_bin(vector.public_key_uncompressed_tweak_mul))
        );
    }
    /*
     * the elliptic library doesn't implement public or private key tweaking.
     * perhaps future tests can do the math in JavaScript and compare with that.
     */
}

#[test]
fn crypto_secp256k1_normalize_signature_compact() {
    assert_eq!(
        internal_secp256k1.normalize_signature_compact(&SIG_COMPACT_HIGH_S),
        Ok(SIG_COMPACT.to_vec())
    );
}

#[test]
fn fast_check_crypto_secp256k1_normalize_signature_compact() {
    let secp256k1: &'static Secp256k1 = &SECP256K1_PROMISE;
    let malleate_then_normalize_equals_initial = fc::property(
        {
            let private_key = fc_valid_private_key();
            let hash = fc_uint8_array_32();
            move |random: &mut fc::Random| (private_key(random), hash(random))
        },
        move |(private_key, hash)| {
            let sig = assert_success(secp256k1.sign_message_hash_compact(private_key, hash), None);
            assert_eq!(
                Ok(sig.clone()),
                secp256k1.normalize_signature_compact(&assert_success(secp256k1.malleate_signature_compact(&sig), None))
            );
            true
        },
    );

    // equivalentToSecp256k1Node (`secp256k1Node.signatureNormalize(malleated)`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            let sig = assert_success(
                secp256k1.sign_message_hash_compact(&vector.private_key(), &vector.message_hash()),
                None,
            );
            let malleated = assert_success(secp256k1.malleate_signature_compact(&sig), None);
            assert_eq!(
                secp256k1.normalize_signature_compact(&malleated),
                Ok(hex_to_bin(vector.signature_compact))
            );
        }
    };

    fc::assert(malleate_then_normalize_equals_initial, None);
    equivalent_to_secp256k1_node();
}

#[test]
fn crypto_secp256k1_normalize_signature_der() {
    assert_eq!(internal_secp256k1.normalize_signature_der(&SIG_DER_HIGH_S), Ok(SIG_DER.to_vec()));
    assert_eq!(
        internal_secp256k1.normalize_signature_der(&SIG_DER_HIGH_S[1..]),
        Err(Secp256k1Error::unparsableSignature.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_normalize_signature_der() {
    let secp256k1: &'static Secp256k1 = &SECP256K1_PROMISE;
    let malleate_then_normalize_equals_initial = fc::property(
        {
            let private_key = fc_valid_private_key();
            let hash = fc_uint8_array_32();
            move |random: &mut fc::Random| (private_key(random), hash(random))
        },
        move |(private_key, hash)| {
            let sig = assert_success(secp256k1.sign_message_hash_der(private_key, hash), None);
            assert_eq!(
                Ok(sig.clone()),
                secp256k1.normalize_signature_der(&assert_success(secp256k1.malleate_signature_der(&sig), None))
            );
            true
        },
    );

    // equivalentToSecp256k1Node
    // (`secp256k1Node.signatureExport(secp256k1Node.signatureNormalize(secp256k1Node.signatureImport(malleated)))`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            let sig = assert_success(
                secp256k1.sign_message_hash_der(&vector.private_key(), &vector.message_hash()),
                None,
            );
            let malleated = assert_success(secp256k1.malleate_signature_der(&sig), None);
            assert_eq!(
                secp256k1.normalize_signature_der(&malleated),
                Ok(hex_to_bin(vector.signature_der))
            );
        }
    };

    fc::assert(malleate_then_normalize_equals_initial, None);
    equivalent_to_secp256k1_node();
}

#[test]
fn crypto_secp256k1_recover_public_key_compressed() {
    assert_eq!(
        internal_secp256k1.recover_public_key_compressed(&SIG_COMPACT, SIG_RECOVERY, &MESSAGE_HASH),
        Ok(PUBKEY_COMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.recover_public_key_compressed(&[255; 64], SIG_RECOVERY, &MESSAGE_HASH),
        Err(Secp256k1Error::recoverPublicKeyWithUnparsableSignature.to_string())
    );
    let fail_recover = 2;
    assert_eq!(
        internal_secp256k1.recover_public_key_compressed(&SIG_COMPACT, fail_recover, &MESSAGE_HASH),
        Err(Secp256k1Error::recoverPublicKeyInvalidMaterial.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_recover_public_key_compressed() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.ecdsaRecover(signature, recoveryId, hash, true)`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let hash = vector.message_hash();
        let recoverable_stuff: RecoverableSignature = assert_success(
            secp256k1.sign_message_hash_recoverable_compact(&vector.private_key(), &hash),
            None,
        );
        assert_eq!(
            secp256k1.recover_public_key_compressed(&recoverable_stuff.signature, recoverable_stuff.recovery_id, &hash),
            Ok(hex_to_bin(vector.public_key_compressed))
        );
    }
}

#[test]
fn crypto_secp256k1_recover_public_key_uncompressed() {
    assert_eq!(
        internal_secp256k1.recover_public_key_uncompressed(&SIG_COMPACT, SIG_RECOVERY, &MESSAGE_HASH),
        Ok(PUBKEY_UNCOMPRESSED.to_vec())
    );
}

#[test]
fn fast_check_crypto_secp256k1_recover_public_key_uncompressed() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.ecdsaRecover(signature, recoveryId, hash, false)`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let hash = vector.message_hash();
        let recoverable_stuff: RecoverableSignature = assert_success(
            secp256k1.sign_message_hash_recoverable_compact(&vector.private_key(), &hash),
            None,
        );
        assert_eq!(
            secp256k1.recover_public_key_uncompressed(&recoverable_stuff.signature, recoverable_stuff.recovery_id, &hash),
            Ok(hex_to_bin(vector.public_key_uncompressed))
        );
    }
}

#[test]
fn crypto_secp256k1_sign_message_hash_compact() {
    assert_eq!(
        internal_secp256k1.sign_message_hash_compact(&PRIVKEY, &MESSAGE_HASH),
        Ok(SIG_COMPACT.to_vec())
    );
    assert_ne!(
        internal_secp256k1.sign_message_hash_compact(&PRIVKEY, &[]),
        Ok(SIG_COMPACT.to_vec())
    );
    assert_eq!(
        internal_secp256k1.sign_message_hash_compact(&SECP256K1_ORDER_N, &MESSAGE_HASH),
        Err(Secp256k1Error::signWithInvalidPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_sign_message_hash_compact() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.ecdsaSign(hash, privateKey).signature`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.sign_message_hash_compact(&vector.private_key(), &vector.message_hash()),
                Ok(hex_to_bin(vector.signature_compact))
            );
        }
    };

    // equivalentToElliptic (`ellipticSignMessageDER(key, hash)`, precomputed)
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.sign_message_hash_compact(&vector.private_key(), &vector.message_hash()),
                secp256k1.signature_der_to_compact(&assert_success(
                    secp256k1.normalize_signature_der(&hex_to_bin(vector.elliptic_signature_der)),
                    None
                ))
            );
        }
    };

    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_sign_message_hash_der() {
    assert_eq!(
        internal_secp256k1.sign_message_hash_der(&PRIVKEY, &MESSAGE_HASH),
        Ok(SIG_DER.to_vec())
    );
    assert_ne!(
        internal_secp256k1.sign_message_hash_der(&PRIVKEY, &[]),
        Ok(SIG_DER.to_vec())
    );
    assert_eq!(
        internal_secp256k1.sign_message_hash_der(&SECP256K1_ORDER_N, &MESSAGE_HASH),
        Err(Secp256k1Error::signWithInvalidPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_sign_message_hash_der() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node
    // (`secp256k1Node.signatureExport(secp256k1Node.ecdsaSign(hash, privateKey).signature)`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.sign_message_hash_der(&vector.private_key(), &vector.message_hash()),
                Ok(hex_to_bin(vector.signature_der))
            );
        }
    };

    // equivalentToElliptic (`ellipticSignMessageDER(key, hash)`, precomputed)
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            assert_eq!(
                secp256k1.sign_message_hash_der(&vector.private_key(), &vector.message_hash()),
                secp256k1.normalize_signature_der(&hex_to_bin(vector.elliptic_signature_der))
            );
        }
    };

    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_sign_message_hash_recoverable_compact() {
    let recoverable_stuff: RecoverableSignature =
        assert_success(internal_secp256k1.sign_message_hash_recoverable_compact(&PRIVKEY, &MESSAGE_HASH), None);
    assert_eq!(recoverable_stuff.recovery_id, SIG_RECOVERY);
    assert_eq!(recoverable_stuff.signature, SIG_COMPACT);
    assert_eq!(
        internal_secp256k1.sign_message_hash_recoverable_compact(&SECP256K1_ORDER_N, &MESSAGE_HASH),
        Err(Secp256k1Error::signWithInvalidPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_sign_message_hash_recoverable_compact() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.ecdsaSign(hash, privateKey)`, precomputed)
    for vector in &REFERENCE_VECTORS {
        assert_eq!(
            secp256k1.sign_message_hash_recoverable_compact(&vector.private_key(), &vector.message_hash()),
            Ok(RecoverableSignature {
                recovery_id: vector.recovery_id,
                signature: hex_to_bin(vector.signature_compact),
            })
        );
    }
}

#[test]
fn crypto_secp256k1_signature_compact_to_der() {
    assert_eq!(internal_secp256k1.signature_compact_to_der(&SIG_COMPACT), Ok(SIG_DER.to_vec()));
}

#[test]
fn fast_check_crypto_secp256k1_signature_compact_to_der() {
    let secp256k1: &'static Secp256k1 = &SECP256K1_PROMISE;
    let reverses_compress = fc::property(fc_valid_private_key(), move |private_key| {
        let pubkey_u = assert_success(secp256k1.derive_public_key_uncompressed(private_key), None);
        assert_eq!(
            Ok(pubkey_u.clone()),
            secp256k1.uncompress_public_key(&assert_success(secp256k1.compress_public_key(&pubkey_u), None))
        );
        true
    });

    // equivalentToSecp256k1Node (`secp256k1Node.signatureExport(sig)`, precomputed)
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            let sig = assert_success(
                secp256k1.sign_message_hash_compact(&vector.private_key(), &vector.message_hash()),
                None,
            );
            assert_eq!(Ok(hex_to_bin(vector.signature_der)), secp256k1.signature_compact_to_der(&sig));
        }
    };

    fc::assert(reverses_compress, None);
    equivalent_to_secp256k1_node();
}

#[test]
fn crypto_secp256k1_signature_der_to_compact() {
    assert_eq!(internal_secp256k1.signature_der_to_compact(&SIG_DER), Ok(SIG_COMPACT.to_vec()));
    let sig_der_with_broken_encoding = fill_zero(&SIG_DER, 0, 1);
    assert_eq!(
        internal_secp256k1.signature_der_to_compact(&sig_der_with_broken_encoding),
        Err(Secp256k1Error::unparsableSignature.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_signature_der_to_compact() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.signatureImport(sig)`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let sig = assert_success(
            secp256k1.sign_message_hash_der(&vector.private_key(), &vector.message_hash()),
            None,
        );
        assert_eq!(Ok(hex_to_bin(vector.signature_compact)), secp256k1.signature_der_to_compact(&sig));
    }
}

#[test]
fn crypto_secp256k1_uncompress_public_key() {
    assert_eq!(
        internal_secp256k1.uncompress_public_key(&PUBKEY_COMPRESSED),
        Ok(PUBKEY_UNCOMPRESSED.to_vec())
    );
    assert_eq!(
        internal_secp256k1.uncompress_public_key(&[0; 33]),
        Err(Secp256k1Error::unparsablePublicKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_uncompress_public_key() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node (`secp256k1Node.publicKeyConvert(pubkeyC, false)`, precomputed)
    for vector in &REFERENCE_VECTORS {
        let pubkey_c = assert_success(secp256k1.derive_public_key_compressed(&vector.private_key()), None);
        assert_eq!(
            Ok(hex_to_bin(vector.public_key_uncompressed)),
            secp256k1.uncompress_public_key(&pubkey_c)
        );
    }
}

#[test]
fn crypto_secp256k1_validate_private_key() {
    assert!(internal_secp256k1.validate_private_key(&PRIVKEY));
    assert!(!internal_secp256k1.validate_private_key(&SECP256K1_ORDER_N));
}

/// `secp256k1Node.privateKeyVerify(privateKey)` (computed in Node.js) for 100
/// private keys made of `almostInvalid` (15 bytes of `255`) followed by 17
/// bytes sampled from the test's arbitrary (`fc.sample(..., { seed: 1,
/// numRuns: 100 })`): `(the 17 sampled bytes, privateKeyVerify result)`.
const NODE_PRIVATE_KEY_VERIFY: [(&str, bool); 100] = [
    ("fcff0185c80386d7ff02a2042efd97fbe6", true),
    ("04f8a7c5d0a836f9fcfcfcff06faf9046e", true),
    ("fd3e01f30504074806fffb0300fcfcfd01", true),
    ("0305f90200f806055001927607f901582e", true),
    ("e66b8eb59c25fe001b0304d4025ff9f86a", true),
    ("c7030305a4b1080002fce3d500eafe0204", true),
    ("d61f0427b8586a851faa020e3305020504", true),
    ("4df9b5fe05ba15f70402fcab0703050163", true),
    ("5dfa041bfdd9e789f2f9f801000392fba1", true),
    ("2e05c3ce0307a00702538b067905d1fdb2", true),
    ("73b18c2d00fbcb04fc996978ecfbfa82ff", true),
    ("4411adb30abf02a9fda606f5012ef8f642", true),
    ("e78dfeb8802f4cfd9049ae5600f9f1956d", true),
    ("0668eea28301f132c0abf8fc27355c59f8", true),
    ("d33fff8f01ebb401b0abe110f94806fe0a", true),
    ("7d4d02260513b4e107050533b2fe02cefd", true),
    ("6c7e0171b4e84dcbf3ffe63d0401010069", true),
    ("03f872dd049fb642a489ff0435ee04aa03", true),
    ("bc3085f5c8fcbe03a06f01c8f9b8fe0700", true),
    ("1fca85f9fb519a3a05a6037b52c1e4a86a", true),
    ("95d60a6e7339011666a804450254c83d01", true),
    ("6193f8c867f96ff8afc5d2dd06f98800a8", true),
    ("5500b8cc0494a1e6dd38f8b7f85279067a", true),
    ("7f03a761fb161566cdb0e70000b8f36106", true),
    ("0efafaf9cddfd653dd76a420053a9e203f", true),
    ("358fd302b4c2cafb24004a8400fef8adff", true),
    ("240efe78a90747250304fa01ab0266c9b9", true),
    ("78ab2b96d8f9040002fc6a04aecd9401fc", true),
    ("fa99927ae0d3032b016765e69e5302da04", true),
    ("f9fddae6a304370201fa02567b4c2ffac1", true),
    ("06fba252fc2e7906e1f907338e4804f7b6", true),
    ("ea05038402c6020407d0940505f707f904", true),
    ("fbf8b4210305775afb43f1a773fd090138", true),
    ("9807018c8f2e04b5981793016bb0079707", true),
    ("02c837c0e781e11843091e51f879cefa92", true),
    ("ff042ef8fe560205bc3c030003e81b2154", false),
    ("b6fbfdffbf044bfef17efdac03c80bde04", true),
    ("cf0106000533fc56063e1303bb46af9e35", true),
    ("d2ff2d576cf96e56f42eff505902c0eb00", true),
    ("c102c1e5bc008fce037a74fafd2dfe62a2", true),
    ("7e046a3b01076afc0601870138f998ea5e", true),
    ("f95ba6010242d6c002045121500301061c", true),
    ("384a076693c4fdb80b05f97c01ff349c99", true),
    ("f9aef4e4fef8e2060006ddf600059efcd3", true),
    ("e8730798f98a5706318c9f7d8c05457f6e", true),
    ("b3b213d1fa0405fb9b584bfccc34d1c7b9", true),
    ("e2150306f84f8003fb1002060302fe0e59", true),
    ("fbad6d5703094137079933e202eb11649f", true),
    ("30ff0303fdf27cc0cefefe06cfc9df1250", true),
    ("8404590ab16c1cfe6f5bfc06054ed3f803", true),
    ("39b07b74ea2d01f404e881d5f904055c8c", true),
    ("35377b04c2f606ff1055077b000312057b", true),
    ("c29bf8fefb031dfe6c33017306053e00a6", true),
    ("27771a9a061f07a801f40205a73d195b02", true),
    ("04010600068b524557902a03027901f8ef", true),
    ("00b5fface607890307dfd007076d6c0200", true),
    ("ac61b91fe90150004299073e43fda39c75", true),
    ("74071801760210e17eff810806fb0a7d5c", true),
    ("fb0427f8078705f8037d4ff702f993adef", true),
    ("44fdf9a20658fef107f95bc67f033537a6", true),
    ("75c203fb3304319234e4fd25fd015402f8", true),
    ("073e9d22d1eb87f0069afb20692c06918c", true),
    ("34ff0205f85e1430f2020585a9bbb5f81d", true),
    ("f40315020f05160183bbfb8e0683143577", true),
    ("5731053addff7a059e9639075faefcfff9", true),
    ("9c991d32fa013ed30bc49e01416142faff", true),
    ("b34834053f092c76cacc3603260632c8b6", true),
    ("012abe291d000403770700fe2e935d6740", true),
    ("033281faff065f80f9a4c2077af90601f8", true),
    ("1fac01060707fe320461d6a09b17b738d4", true),
    ("668de99dd7d9309f07c6fafaa23c09033c", true),
    ("04f8f6ffff4874208cff0b5ae63cb1f85c", true),
    ("faf80006e3f29dfb848c1600c49af86d87", true),
    ("5991f9fa04acffff661d72c60dac044903", true),
    ("220a03ff011de2ba030ba30501fe1fc539", true),
    ("fe7bc25d006539026d00c9f9940e5d190e", true),
    ("170327040783f10053db07022a036f61ae", true),
    ("c1060041954103050514040201e9031363", true),
    ("fb33d9fe0223d3fca10352037e54a01efd", true),
    ("060fb278fb024d057ef3f82cbc3ad503d0", true),
    ("bf838b4892ff076805e92f6973a20b1502", true),
    ("02e1066605027c05bc9aa7c90286f8fc00", true),
    ("0be81a45faf6e419c5c001003173ffea91", true),
    ("f4f949f85051c241faf902a51b9f972a50", true),
    ("7e0661fa07016bffef002956d5055bfe5a", true),
    ("fb375f05ef9af70274620706c5e395f9fb", true),
    ("8e637f001e165d172882fbc70268a0edd2", true),
    ("b04280ab0306070307a1000366a287bd79", true),
    ("ffa50403f0d9561505402936f0069ad3fd", false),
    ("1bca619ec8c7f8f9909e58a036f3037d75", true),
    ("f8c405bdf298fcfb26fcf2fa9ff0060103", true),
    ("fd05fa9afc03b76eac656107640550f844", true),
    ("1845e9197e00faf8e3ddf9e7b04275fd54", true),
    ("07db1f1a1807ff7c705afd00074af866d1", true),
    ("5403cc93e90233b494fe03bb7e0ffffad2", true),
    ("41fcf8e6dfff018956fa02af7599809302", true),
    ("8b1801a92719f567df0118fd00c3710bda", true),
    ("fee303f9ebf83b0d03fbe806e207f00783", false),
    ("0440b46efba99d3cfc02ff331e1f21e4fe", true),
    ("dec550624dd246d23ff80203c94ffa0031", true),
];

#[test]
fn fast_check_crypto_secp256k1_validate_private_key() {
    let secp256k1 = &*SECP256K1_PROMISE;

    /*
     * Invalid values are greater than or equal to: `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
     */
    let almost_invalid = vec![255_u8; 15];
    // equivalentToSecp256k1Node (`secp256k1Node.privateKeyVerify(privateKey)`, precomputed)
    for (random, node_private_key_verify) in NODE_PRIVATE_KEY_VERIFY {
        let private_key = [almost_invalid.clone(), hex_to_bin(random)].concat();
        assert_eq!(
            secp256k1.validate_private_key(&private_key),
            node_private_key_verify,
            "privateKey: {random}"
        );
    }
}

#[test]
fn crypto_secp256k1_validate_public_key() {
    assert!(internal_secp256k1.validate_public_key(&PUBKEY_UNCOMPRESSED));
    assert!(internal_secp256k1.validate_public_key(&PUBKEY_COMPRESSED));
    assert!(!internal_secp256k1.validate_public_key(&INVALID_PUBKEY_COMPRESSED));
}

#[test]
#[ignore = "test.todo: [fast-check] [crypto] secp256k1.validatePublicKey"]
fn fast_check_crypto_secp256k1_validate_public_key() {}

#[test]
fn crypto_secp256k1_verify_signature_compact() {
    assert!(internal_secp256k1.verify_signature_compact(&SIG_COMPACT_HIGH_S, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_compact(&SIG_COMPACT_HIGH_S, &PUBKEY_COMPRESSED, &[]));
    assert!(internal_secp256k1.verify_signature_compact(&SIG_COMPACT_HIGH_S, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_compact(&[], &PUBKEY_COMPRESSED, &MESSAGE_HASH));
}

#[test]
fn fast_check_crypto_secp256k1_verify_signature_compact() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            let message = vector.message_hash();
            // const pubUncompressed = secp256k1Node.publicKeyCreate(privateKey, false);
            // const pubCompressed = secp256k1Node.publicKeyCreate(privateKey, true);
            // const sig = secp256k1Node.ecdsaSign(message, privateKey).signature;
            let sig = hex_to_bin(vector.signature_compact);
            let test_sig = if vector.invalidate { fill_zero(&sig, 6, 7) } else { sig };
            let pub_ = vector.public_key();
            let malleated = assert_success(secp256k1.malleate_signature_compact(&test_sig), None);
            // secp256k1Node.ecdsaVerify(testSig, message, pub) === secp256k1.verifySignatureCompact(malleated, pub, message)
            assert_eq!(
                vector.node_verifies_test_signature_compact,
                secp256k1.verify_signature_compact(&malleated, &pub_, &message)
            );
        }
    };

    // equivalentToElliptic
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            let message = vector.message_hash();
            // const { key, pubUncompressed, pubCompressed } = setupElliptic(privateKey);
            // const sig = ellipticSignMessageDER(key, message);
            let sig = hex_to_bin(vector.elliptic_signature_der);
            let test_sig = if vector.invalidate { fill_zero(&sig, 6, 20) } else { sig };
            let pub_ = vector.public_key();
            let compact_sig = assert_success(secp256k1.signature_der_to_compact(&test_sig), None);
            // ellipticCheckSignature(testSig, key, message) === secp256k1.verifySignatureCompact(compactSig, pub, message)
            assert_eq!(
                vector.elliptic_verifies_test_signature_der,
                secp256k1.verify_signature_compact(&compact_sig, &pub_, &message)
            );
        }
    };

    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_verify_signature_compact_low_s() {
    assert!(internal_secp256k1.verify_signature_compact_low_s(&SIG_COMPACT, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_compact_low_s(&[], &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(internal_secp256k1.verify_signature_compact_low_s(&SIG_COMPACT, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_compact_low_s(&SIG_COMPACT, &PUBKEY_COMPRESSED, &[]));
}

#[test]
fn fast_check_crypto_secp256k1_verify_signature_compact_low_s() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            let message = vector.message_hash();
            // const sig = secp256k1Node.ecdsaSign(message, privateKey).signature;
            let sig = hex_to_bin(vector.signature_compact);
            let test_sig = if vector.invalidate { fill_zero(&sig, 6, 7) } else { sig };
            let pub_ = vector.public_key();
            // secp256k1Node.ecdsaVerify(testSig, message, pub) === secp256k1.verifySignatureCompactLowS(testSig, pub, message)
            assert_eq!(
                vector.node_verifies_test_signature_compact,
                secp256k1.verify_signature_compact_low_s(&test_sig, &pub_, &message)
            );
        }
    };

    // equivalentToElliptic
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            let message = vector.message_hash();
            let sig = assert_success(
                secp256k1.normalize_signature_der(&hex_to_bin(vector.elliptic_signature_der)),
                None,
            );
            let test_sig = if vector.invalidate { fill_zero(&sig, 6, 20) } else { sig };
            let pub_ = vector.public_key();
            let compact_sig = assert_success(secp256k1.signature_der_to_compact(&test_sig), None);
            // ellipticCheckSignature(testSig, key, message) === secp256k1.verifySignatureCompactLowS(compactSig, pub, message)
            // (elliptic checked `signature_der` – the normalized elliptic signature – with the same bytes zeroed)
            let signature_der = hex_to_bin(vector.signature_der);
            assert_eq!(
                test_sig,
                if vector.invalidate { fill_zero(&signature_der, 6, 20) } else { signature_der }
            );
            assert_eq!(
                vector.elliptic_verifies_test_normalized_signature_der,
                secp256k1.verify_signature_compact_low_s(&compact_sig, &pub_, &message)
            );
        }
    };

    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_verify_signature_der() {
    assert!(internal_secp256k1.verify_signature_der(&SIG_DER_HIGH_S, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_der(&[], &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(internal_secp256k1.verify_signature_der(&SIG_DER_HIGH_S, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_der(&SIG_DER_HIGH_S, &PUBKEY_COMPRESSED, &[]));
    assert!(!internal_secp256k1.verify_signature_der(&[], &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(internal_secp256k1.verify_signature_der(&SIG_DER_HIGH_S, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_der(&SIG_DER_HIGH_S, &PUBKEY_COMPRESSED, &[]));
}

#[test]
fn crypto_secp256k1_verify_signature_der_low_s() {
    assert!(internal_secp256k1.verify_signature_der_low_s(&SIG_DER, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_der_low_s(&[], &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(internal_secp256k1.verify_signature_der_low_s(&SIG_DER, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_der_low_s(&SIG_DER, &PUBKEY_COMPRESSED, &[]));
    assert!(!internal_secp256k1.verify_signature_der_low_s(&[], &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(internal_secp256k1.verify_signature_der_low_s(&SIG_DER, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    assert!(!internal_secp256k1.verify_signature_der_low_s(&SIG_DER, &PUBKEY_COMPRESSED, &[]));
    let pubkey_with_broken_encoding = fill_zero(&PUBKEY_COMPRESSED, 0, 1);
    assert!(!internal_secp256k1.verify_signature_der_low_s(&SIG_DER, &pubkey_with_broken_encoding, &MESSAGE_HASH));
    let sig_der_with_broken_encoding = fill_zero(&SIG_DER, 0, 1);
    assert!(!internal_secp256k1.verify_signature_der_low_s(&sig_der_with_broken_encoding, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
    let sig_der_with_bad_signature = fill_zero(&SIG_DER, 6, 7);
    assert!(!internal_secp256k1.verify_signature_der_low_s(&sig_der_with_bad_signature, &PUBKEY_COMPRESSED, &MESSAGE_HASH));
}

#[test]
fn fast_check_crypto_secp256k1_verify_signature_der_low_s() {
    let secp256k1 = &*SECP256K1_PROMISE;
    // equivalentToSecp256k1Node
    let equivalent_to_secp256k1_node = || {
        for vector in &REFERENCE_VECTORS {
            let message = vector.message_hash();
            // const original = secp256k1Node.ecdsaSign(message, privateKey).signature;
            // const sig = secp256k1Node.signatureExport(original);
            let sig = hex_to_bin(vector.signature_der);
            let test_sig = if vector.invalidate { fill_zero(&sig, 6, 7) } else { sig };
            let pub_ = vector.public_key();
            // const imported = secp256k1Node.signatureImport(testSig);
            // secp256k1Node.ecdsaVerify(imported, message, pub) === secp256k1.verifySignatureDERLowS(testSig, pub, message)
            assert_eq!(
                vector.node_verifies_test_signature_der,
                secp256k1.verify_signature_der_low_s(&test_sig, &pub_, &message)
            );
        }
    };

    // equivalentToElliptic
    let equivalent_to_elliptic = || {
        for vector in &REFERENCE_VECTORS {
            let message = vector.message_hash();
            // const sig = ellipticSignMessageDER(key, message);
            let sig = hex_to_bin(vector.elliptic_signature_der);
            let test_sig = if vector.invalidate { fill_zero(&sig, 6, 7) } else { sig };
            let pub_ = vector.public_key();
            // ellipticCheckSignature(testSig, key, message) === secp256k1.verifySignatureDERLowS(secp256k1.normalizeSignatureDER(testSig), pub, message)
            assert_eq!(
                vector.elliptic_verifies_test_signature_der_byte_6,
                secp256k1.verify_signature_der_low_s(
                    &assert_success(secp256k1.normalize_signature_der(&test_sig), None),
                    &pub_,
                    &message
                )
            );
        }
    };

    equivalent_to_secp256k1_node();
    equivalent_to_elliptic();
}

#[test]
fn crypto_secp256k1_sign_message_hash_schnorr() {
    assert_eq!(
        internal_secp256k1.sign_message_hash_schnorr(&PRIVKEY, &SCHNORR_MSG_HASH),
        Ok(SIG_SCHNORR.to_vec())
    );
    assert_ne!(
        internal_secp256k1.sign_message_hash_schnorr(&[], &SCHNORR_MSG_HASH),
        Ok(SIG_SCHNORR.to_vec())
    );
    assert_eq!(
        internal_secp256k1.sign_message_hash_schnorr(&SECP256K1_ORDER_N, &SCHNORR_MSG_HASH),
        Err(Secp256k1Error::signWithInvalidPrivateKey.to_string())
    );
}

#[test]
fn fast_check_crypto_secp256k1_sign_message_hash_schnorr() {
    let secp256k1: &'static Secp256k1 = &SECP256K1_PROMISE;
    let creates_valid_signatures = fc::property(
        {
            let private_key = fc_valid_private_key();
            let hash = fc_uint8_array_32();
            let invalidate = fc::boolean();
            move |random: &mut fc::Random| (private_key(random), hash(random), invalidate(random))
        },
        move |(private_key, hash, invalidate)| {
            let public_key = assert_success(secp256k1.derive_public_key_compressed(private_key), None);
            let signature = assert_success(secp256k1.sign_message_hash_schnorr(private_key, hash), None);
            // `invalidate ? signature : signature.fill(0)`
            let signature = if *invalidate { signature } else { vec![0; signature.len()] };
            assert_eq!(secp256k1.verify_signature_schnorr(&signature, &public_key, hash), *invalidate);
            true
        },
    );
    fc::assert(creates_valid_signatures, None);
}

#[test]
fn crypto_secp256k1_verify_signature_schnorr() {
    assert!(internal_secp256k1.verify_signature_schnorr(&SIG_SCHNORR, &PUBKEY_COMPRESSED, &SCHNORR_MSG_HASH));
    assert!(!internal_secp256k1.verify_signature_schnorr(&[], &PUBKEY_COMPRESSED, &SCHNORR_MSG_HASH));
    let pubkey_with_broken_encoding = fill_zero(&PUBKEY_COMPRESSED, 0, 1);
    assert!(!internal_secp256k1.verify_signature_schnorr(&SIG_SCHNORR, &pubkey_with_broken_encoding, &SCHNORR_MSG_HASH));
    let sig_schnorr_with_bad_signature = fill_zero(&SIG_SCHNORR, 6, 7);
    assert!(!internal_secp256k1.verify_signature_schnorr(&sig_schnorr_with_bad_signature, &PUBKEY_COMPRESSED, &SCHNORR_MSG_HASH));

    // test vectors from Bitcoin ABC libsecp256k1

    /* Test vector 1 */
    #[rustfmt::skip]
    const PK1: [u8; 33] = [0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98];
    #[rustfmt::skip]
    const MSG1: [u8; 32] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    #[rustfmt::skip]
    const SIG1: [u8; 64] = [0x78, 0x7a, 0x84, 0x8e, 0x71, 0x04, 0x3d, 0x28, 0x0c, 0x50, 0x47, 0x0e, 0x8e, 0x15, 0x32, 0xb2, 0xdd, 0x5d, 0x20, 0xee, 0x91, 0x2a, 0x45, 0xdb, 0xdd, 0x2b, 0xd1, 0xdf, 0xbf, 0x18, 0x7e, 0xf6, 0x70, 0x31, 0xa9, 0x88, 0x31, 0x85, 0x9d, 0xc3, 0x4d, 0xff, 0xee, 0xdd, 0xa8, 0x68, 0x31, 0x84, 0x2c, 0xcd, 0x00, 0x79, 0xe1, 0xf9, 0x2a, 0xf1, 0x77, 0xf7, 0xf2, 0x2c, 0xc1, 0xdc, 0xed, 0x05];
    assert!(internal_secp256k1.verify_signature_schnorr(&SIG1, &PK1, &MSG1));

    /* Test vector 2 */
    #[rustfmt::skip]
    const PK2: [u8; 33] = [0x02, 0xdf, 0xf1, 0xd7, 0x7f, 0x2a, 0x67, 0x1c, 0x5f, 0x36, 0x18, 0x37, 0x26, 0xdb, 0x23, 0x41, 0xbe, 0x58, 0xfe, 0xae, 0x1d, 0xa2, 0xde, 0xce, 0xd8, 0x43, 0x24, 0x0f, 0x7b, 0x50, 0x2b, 0xa6, 0x59];
    #[rustfmt::skip]
    const MSG2: [u8; 32] = [0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44, 0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0, 0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89];
    #[rustfmt::skip]
    const SIG2: [u8; 64] = [0x2a, 0x29, 0x8d, 0xac, 0xae, 0x57, 0x39, 0x5a, 0x15, 0xd0, 0x79, 0x5d, 0xdb, 0xfd, 0x1d, 0xcb, 0x56, 0x4d, 0xa8, 0x2b, 0x0f, 0x26, 0x9b, 0xc7, 0x0a, 0x74, 0xf8, 0x22, 0x04, 0x29, 0xba, 0x1d, 0x1e, 0x51, 0xa2, 0x2c, 0xce, 0xc3, 0x55, 0x99, 0xb8, 0xf2, 0x66, 0x91, 0x22, 0x81, 0xf8, 0x36, 0x5f, 0xfc, 0x2d, 0x03, 0x5a, 0x23, 0x04, 0x34, 0xa1, 0xa6, 0x4d, 0xc5, 0x9f, 0x70, 0x13, 0xfd];
    assert!(internal_secp256k1.verify_signature_schnorr(&SIG2, &PK2, &MSG2));

    /* Test vector 6: R.y is not a quadratic residue */
    #[rustfmt::skip]
    const PK6: [u8; 33] = [0x02, 0xdf, 0xf1, 0xd7, 0x7f, 0x2a, 0x67, 0x1c, 0x5f, 0x36, 0x18, 0x37, 0x26, 0xdb, 0x23, 0x41, 0xbe, 0x58, 0xfe, 0xae, 0x1d, 0xa2, 0xde, 0xce, 0xd8, 0x43, 0x24, 0x0f, 0x7b, 0x50, 0x2b, 0xa6, 0x59];
    #[rustfmt::skip]
    const MSG6: [u8; 32] = [0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44, 0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0, 0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89];
    #[rustfmt::skip]
    const SIG6: [u8; 64] = [0x2a, 0x29, 0x8d, 0xac, 0xae, 0x57, 0x39, 0x5a, 0x15, 0xd0, 0x79, 0x5d, 0xdb, 0xfd, 0x1d, 0xcb, 0x56, 0x4d, 0xa8, 0x2b, 0x0f, 0x26, 0x9b, 0xc7, 0x0a, 0x74, 0xf8, 0x22, 0x04, 0x29, 0xba, 0x1d, 0xfa, 0x16, 0xae, 0xe0, 0x66, 0x09, 0x28, 0x0a, 0x19, 0xb6, 0x7a, 0x24, 0xe1, 0x97, 0x7e, 0x46, 0x97, 0x71, 0x2b, 0x5f, 0xd2, 0x94, 0x39, 0x14, 0xec, 0xd5, 0xf7, 0x30, 0x90, 0x1b, 0x4a, 0xb7];
    assert!(!internal_secp256k1.verify_signature_schnorr(&SIG6, &PK6, &MSG6));
}
