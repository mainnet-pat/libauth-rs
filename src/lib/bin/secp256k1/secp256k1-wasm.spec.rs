//! Port of `bin/secp256k1/secp256k1-wasm.spec.ts`.
//!
//! `randomBytes` (from Node.js's `crypto` module) is replaced by the runtime's
//! `crypto.getRandomValues` (`get_random_values`).

use libauth::runtime::crypto::get_random_values;
use libauth::runtime::webassembly::Instance;
use libauth::{
    get_embedded_secp256k1_binary, instantiate_secp256k1_wasm, instantiate_secp256k1_wasm_bytes,
    CompressionFlag, ContextFlag, Secp256k1Wasm,
};

// test vectors from `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong` (`xprv9s21ZrQH143K2PfMvkNViFc1fgumGqBew45JD8SxA59Jc5M66n3diqb92JjvaR61zT9P89Grys12kdtV4EFVo6tMwER7U2hcUmZ9VfMYPLC`), m/0 and m/1:

#[rustfmt::skip]
const KEY_TWEAK_VAL: [u8; 32] = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01];

#[rustfmt::skip]
const MESSAGE_HASH: [u8; 32] = [0xda, 0xde, 0x12, 0xe0, 0x6a, 0x5b, 0xbf, 0x5e, 0x11, 0x16, 0xf9, 0xbc, 0x44, 0x99, 0x8b, 0x87, 0x68, 0x13, 0xe9, 0x48, 0xe1, 0x07, 0x07, 0xdc, 0xb4, 0x80, 0x08, 0xa1, 0xda, 0xf3, 0x51, 0x2d];

#[rustfmt::skip]
const PRIVKEY: [u8; 32] = [0xf8, 0x5d, 0x4b, 0xd8, 0xa0, 0x3c, 0xa1, 0x06, 0xc9, 0xde, 0xb4, 0x7b, 0x79, 0x18, 0x03, 0xda, 0xc7, 0xf0, 0x33, 0x38, 0x09, 0xe3, 0xf1, 0xdd, 0x04, 0xd1, 0x82, 0xe0, 0xab, 0xa6, 0xe5, 0x53];

#[rustfmt::skip]
const PUBKEY_UNCOMPRESSED: [u8; 65] = [0x04, 0x76, 0xea, 0x9e, 0x36, 0xa7, 0x5d, 0x2e, 0xcf, 0x9c, 0x93, 0xa0, 0xbe, 0x76, 0x88, 0x5e, 0x36, 0xf8, 0x22, 0x52, 0x9d, 0xb2, 0x2a, 0xcf, 0xdc, 0x76, 0x1c, 0x9b, 0x5b, 0x45, 0x44, 0xf5, 0xc5, 0x6d, 0xd5, 0x3b, 0x07, 0xc7, 0xa9, 0x83, 0xbb, 0x2d, 0xdd, 0x71, 0x55, 0x1f, 0x06, 0x33, 0x19, 0x4a, 0x2f, 0xe3, 0x30, 0xf9, 0x0a, 0xaf, 0x67, 0x5d, 0xde, 0x25, 0xb1, 0x37, 0xef, 0xd2, 0x85];

#[rustfmt::skip]
const PUBKEY_COMPRESSED: [u8; 33] = [0x03, 0x76, 0xea, 0x9e, 0x36, 0xa7, 0x5d, 0x2e, 0xcf, 0x9c, 0x93, 0xa0, 0xbe, 0x76, 0x88, 0x5e, 0x36, 0xf8, 0x22, 0x52, 0x9d, 0xb2, 0x2a, 0xcf, 0xdc, 0x76, 0x1c, 0x9b, 0x5b, 0x45, 0x44, 0xf5, 0xc5];

#[rustfmt::skip]
const PRIVKEY_TWEAKED_ADD: [u8; 32] = [0xf9, 0x5e, 0x4c, 0xd9, 0xa1, 0x3d, 0xa2, 0x07, 0xca, 0xdf, 0xb5, 0x7c, 0x7a, 0x19, 0x04, 0xdb, 0xc8, 0xf1, 0x34, 0x39, 0x0a, 0xe4, 0xf2, 0xde, 0x05, 0xd2, 0x83, 0xe1, 0xac, 0xa7, 0xe6, 0x54];

#[rustfmt::skip]
const PUBKEY_TWEAKED_ADD_COMPRESSED: [u8; 33] = [0x02, 0x6f, 0x1d, 0xf3, 0x4a, 0x81, 0xdf, 0x8c, 0xec, 0x18, 0x33, 0x34, 0xce, 0xb2, 0x56, 0x49, 0x9e, 0xc6, 0xe7, 0x57, 0x04, 0x57, 0x57, 0x6a, 0x92, 0x37, 0x1b, 0x74, 0x75, 0xc3, 0x4f, 0x2c, 0x19];

#[rustfmt::skip]
const PRIVKEY_TWEAKED_MUL: [u8; 32] = [0x29, 0x9f, 0x6a, 0x4d, 0xe3, 0xa0, 0xfd, 0x06, 0x8c, 0x80, 0x31, 0xef, 0xd6, 0xcf, 0x3a, 0xc6, 0xb8, 0x89, 0x02, 0x5e, 0x65, 0xd2, 0xe6, 0x2d, 0x8e, 0xb9, 0xd6, 0x88, 0x2a, 0xc2, 0x1a, 0x4a];

#[rustfmt::skip]
const PUBKEY_TWEAKED_MUL_COMPRESSED: [u8; 33] = [0x02, 0xb7, 0x98, 0x58, 0x0c, 0x33, 0x8c, 0x02, 0xed, 0xc3, 0x8a, 0xd9, 0xb6, 0x19, 0x7d, 0x4c, 0x56, 0x64, 0xe6, 0xaa, 0x85, 0x49, 0x10, 0xad, 0xa7, 0x5d, 0xc6, 0x10, 0x14, 0x2b, 0x5a, 0x7a, 0x38];

#[rustfmt::skip]
const SIG_DER: [u8; 71] = [0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x02, 0x20, 0x29, 0x72, 0x21, 0x88, 0xbd, 0x93, 0x7f, 0x54, 0xc8, 0x61, 0x58, 0x2c, 0xa6, 0xfc, 0x68, 0x5b, 0x8d, 0xa2, 0xb4, 0x0d, 0x05, 0xf0, 0x6b, 0x36, 0x83, 0x74, 0xd3, 0x5e, 0x4a, 0xf2, 0xb7, 0x64];

#[rustfmt::skip]
const SIG_COMPACT: [u8; 64] = [0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x29, 0x72, 0x21, 0x88, 0xbd, 0x93, 0x7f, 0x54, 0xc8, 0x61, 0x58, 0x2c, 0xa6, 0xfc, 0x68, 0x5b, 0x8d, 0xa2, 0xb4, 0x0d, 0x05, 0xf0, 0x6b, 0x36, 0x83, 0x74, 0xd3, 0x5e, 0x4a, 0xf2, 0xb7, 0x64];

#[rustfmt::skip]
const SCHNORR_MSG_HASH: [u8; 32] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[rustfmt::skip]
const SIG_SCHNORR: [u8; 64] = [0xb5, 0x10, 0x41, 0x58, 0x7d, 0xa9, 0x46, 0xeb, 0x67, 0x9c, 0xb3, 0x93, 0x6e, 0x1d, 0xbe, 0x5b, 0xf1, 0xd0, 0xd8, 0xac, 0xff, 0x37, 0x8d, 0xc9, 0xc6, 0xc2, 0x0a, 0x32, 0x9f, 0xb0, 0x1b, 0x79, 0xad, 0x65, 0x54, 0x65, 0xf2, 0x26, 0xa0, 0x28, 0x7b, 0x2d, 0xcf, 0x0e, 0x74, 0x6b, 0xc4, 0x55, 0xa9, 0x40, 0xfe, 0x01, 0xbc, 0xd8, 0x0f, 0xa9, 0xb6, 0x63, 0x3e, 0xcb, 0xe0, 0xc7, 0x04, 0x33];

/// `new Uint8Array(randomBytes(32))`
fn random_bytes_32() -> Vec<u8> {
    let mut bytes = vec![0; 32];
    get_random_values(&mut bytes).expect("random bytes");
    bytes
}

/// `secp256k1Wasm.heapU8.copyWithin(target, start, start + length)`
fn copy_within(secp256k1_wasm: &mut Secp256k1Wasm, target: u32, start: u32, length: u32) {
    let source = secp256k1_wasm.read_heap_u8(start, length).to_vec();
    secp256k1_wasm.heap_u8_mut(target, length).copy_from_slice(&source);
}

/// The `testSecp256k1Wasm` helper.
fn test_secp256k1_wasm(secp256k1_wasm: &mut Secp256k1Wasm) {
    // t.truthy(secp256k1Wasm.heapU32); t.truthy(secp256k1Wasm.heapU8);
    // t.truthy(secp256k1Wasm.instance); (the heap views and the instance exist)
    let _ = secp256k1_wasm.heap_u32(0);
    assert_eq!(secp256k1_wasm.read_heap_u8(0, 1).len(), 1);
    let _instance: &Instance = secp256k1_wasm.instance();

    let context_ptr = secp256k1_wasm.context_create(ContextFlag::BOTH);
    {
        let seed_ptr = secp256k1_wasm.malloc_uint8_array(&random_bytes_32());
        assert_eq!(secp256k1_wasm.context_randomize(context_ptr, seed_ptr), 1);
        secp256k1_wasm.free(seed_ptr);
    }
    let privkey_ptr = secp256k1_wasm.malloc_uint8_array(&PRIVKEY);
    assert_eq!(secp256k1_wasm.seckey_verify(context_ptr, privkey_ptr), 1);

    // derive the public key from the private key
    let raw_pubkey_ptr = secp256k1_wasm.malloc(64);
    assert_eq!(secp256k1_wasm.pubkey_create(context_ptr, raw_pubkey_ptr, privkey_ptr), 1);

    // serialize, uncompressed
    let uncompressed_output_ptr = secp256k1_wasm.malloc(65);
    let uncompressed_output_length_ptr = secp256k1_wasm.malloc_size_t(65);
    secp256k1_wasm.pubkey_serialize(
        context_ptr,
        uncompressed_output_ptr,
        uncompressed_output_length_ptr,
        raw_pubkey_ptr,
        CompressionFlag::UNCOMPRESSED,
    );
    let uncompressed_length = secp256k1_wasm.read_size_t(uncompressed_output_length_ptr);
    let uncompressed_public_key = secp256k1_wasm
        .read_heap_u8(uncompressed_output_ptr, uncompressed_length)
        .to_vec();
    assert_eq!(PUBKEY_UNCOMPRESSED.to_vec(), uncompressed_public_key);

    // serialize, compressed
    let compressed_output_ptr = secp256k1_wasm.malloc(33);
    let compressed_output_length_ptr = secp256k1_wasm.malloc_size_t(33);
    secp256k1_wasm.pubkey_serialize(
        context_ptr,
        compressed_output_ptr,
        compressed_output_length_ptr,
        raw_pubkey_ptr,
        CompressionFlag::COMPRESSED,
    );
    let compressed_length = secp256k1_wasm.read_size_t(compressed_output_length_ptr);
    let compressed_public_key = secp256k1_wasm
        .read_heap_u8(compressed_output_ptr, compressed_length)
        .to_vec();
    assert_eq!(PUBKEY_COMPRESSED.to_vec(), compressed_public_key);

    // parse the uncompressed pubkey, convert it to compressed
    let raw_pubkey2_ptr = secp256k1_wasm.malloc(64);
    assert_eq!(
        secp256k1_wasm.pubkey_parse(context_ptr, raw_pubkey2_ptr, uncompressed_output_ptr, 65),
        1
    );
    let compressed_output2_ptr = secp256k1_wasm.malloc(33);
    let compressed_output2_length_ptr = secp256k1_wasm.malloc_size_t(33);
    assert_eq!(
        secp256k1_wasm.pubkey_serialize(
            context_ptr,
            compressed_output2_ptr,
            compressed_output2_length_ptr,
            raw_pubkey2_ptr,
            CompressionFlag::COMPRESSED,
        ),
        1
    );
    let converted_length = secp256k1_wasm.read_size_t(compressed_output2_length_ptr);
    let converted_public_key = secp256k1_wasm
        .read_heap_u8(compressed_output2_ptr, converted_length)
        .to_vec();
    assert_eq!(converted_public_key, PUBKEY_COMPRESSED.to_vec());
    assert_eq!(converted_public_key, compressed_public_key);

    // sign sigHash using privkey
    let raw_sig_ptr = secp256k1_wasm.malloc(64);
    let sig_hash_ptr = secp256k1_wasm.malloc_uint8_array(&MESSAGE_HASH);
    assert_eq!(secp256k1_wasm.sign(context_ptr, raw_sig_ptr, sig_hash_ptr, privkey_ptr), 1);

    // serialize the signature in DER format
    let sig_der_ptr = secp256k1_wasm.malloc(72);
    let sig_der_length_ptr = secp256k1_wasm.malloc_size_t(72);
    assert_eq!(
        secp256k1_wasm.signature_serialize_der(context_ptr, sig_der_ptr, sig_der_length_ptr, raw_sig_ptr),
        1
    );
    let sig_der_length = secp256k1_wasm.read_size_t(sig_der_length_ptr);
    assert_eq!(sig_der_length, 71);
    let signature_der = secp256k1_wasm.read_heap_u8(sig_der_ptr, sig_der_length).to_vec();
    assert_eq!(signature_der, SIG_DER.to_vec());

    // parse the DER format signature
    let raw_sig2_ptr = secp256k1_wasm.malloc(64);
    assert_eq!(
        secp256k1_wasm.signature_parse_der(context_ptr, raw_sig2_ptr, sig_der_ptr, sig_der_length),
        1
    );

    // serialize the signature in compact format
    let compact_sig_ptr = secp256k1_wasm.malloc(64);
    secp256k1_wasm.signature_serialize_compact(context_ptr, compact_sig_ptr, raw_sig2_ptr);
    let compact_sig = secp256k1_wasm.read_heap_u8(compact_sig_ptr, 64).to_vec();
    assert_eq!(compact_sig, SIG_COMPACT.to_vec());

    // parse the compact format signature
    let raw_sig3_ptr = secp256k1_wasm.malloc(64);
    assert_eq!(
        secp256k1_wasm.signature_parse_compact(context_ptr, raw_sig3_ptr, compact_sig_ptr),
        1
    );

    // verify the signature
    assert_eq!(
        secp256k1_wasm.verify(context_ptr, raw_sig3_ptr, sig_hash_ptr, raw_pubkey_ptr),
        1
    );

    // malleate, verify and fail
    let malleated_sig_ptr = secp256k1_wasm.malloc(64);
    let malleated_twice_ptr = secp256k1_wasm.malloc(64);
    secp256k1_wasm.signature_malleate(context_ptr, malleated_sig_ptr, raw_sig3_ptr);
    secp256k1_wasm.signature_malleate(context_ptr, malleated_twice_ptr, malleated_sig_ptr);
    assert_eq!(
        secp256k1_wasm.verify(context_ptr, malleated_sig_ptr, sig_hash_ptr, raw_pubkey_ptr),
        0
    );
    let raw_sig3 = secp256k1_wasm.read_heap_u8(raw_sig3_ptr, 64).to_vec();
    let malleated_twice_sig = secp256k1_wasm.read_heap_u8(malleated_twice_ptr, 64).to_vec();
    assert_eq!(raw_sig3, malleated_twice_sig);

    // normalize, verify and pass
    let normalized_sig_ptr = secp256k1_wasm.malloc(64);
    assert_eq!(
        secp256k1_wasm.signature_normalize(context_ptr, normalized_sig_ptr, malleated_sig_ptr),
        1
    );
    assert_eq!(
        secp256k1_wasm.verify(context_ptr, normalized_sig_ptr, sig_hash_ptr, raw_pubkey_ptr),
        1
    );

    // recovery signature
    let raw_r_sig_ptr = secp256k1_wasm.malloc(65);
    assert_ne!(raw_r_sig_ptr, 0);
    assert_eq!(
        secp256k1_wasm.sign_recoverable(context_ptr, raw_r_sig_ptr, sig_hash_ptr, privkey_ptr),
        1
    );

    // the r and s portions of the signature should match that of a non-recoverable signature
    let r_id_ptr = secp256k1_wasm.malloc(4);
    let compact_r_sig_ptr = secp256k1_wasm.malloc(64);
    assert_ne!(compact_r_sig_ptr, 0);
    secp256k1_wasm.recoverable_signature_serialize(context_ptr, compact_r_sig_ptr, r_id_ptr, raw_r_sig_ptr);
    let compact_r_sig = secp256k1_wasm.read_heap_u8(compact_r_sig_ptr, 64).to_vec();
    let r_id = secp256k1_wasm.heap_u32(r_id_ptr >> 2);

    assert_eq!(compact_r_sig, SIG_COMPACT.to_vec());
    assert_eq!(r_id, 1);

    // re-parsing the signature should produce the same internal format.
    let raw_r_sig2_ptr = secp256k1_wasm.malloc(65);
    assert_eq!(
        secp256k1_wasm.recoverable_signature_parse(context_ptr, raw_r_sig2_ptr, compact_r_sig_ptr, r_id),
        1
    );
    assert_eq!(
        secp256k1_wasm.read_heap_u8(raw_r_sig_ptr, 65),
        secp256k1_wasm.read_heap_u8(raw_r_sig2_ptr, 65)
    );

    // the recovered public key should match the derived public key
    let recovered_public_key_ptr = secp256k1_wasm.malloc(65);
    let recovered_public_key_compressed_ptr = secp256k1_wasm.malloc(33);
    let recovered_public_key_compressed_length_ptr = secp256k1_wasm.malloc_size_t(33);

    assert_eq!(
        secp256k1_wasm.recover(context_ptr, recovered_public_key_ptr, raw_r_sig_ptr, sig_hash_ptr),
        1
    );

    secp256k1_wasm.pubkey_serialize(
        context_ptr,
        recovered_public_key_compressed_ptr,
        recovered_public_key_compressed_length_ptr,
        recovered_public_key_ptr,
        CompressionFlag::COMPRESSED,
    );
    assert_eq!(
        PUBKEY_COMPRESSED.to_vec(),
        secp256k1_wasm.read_heap_u8(recovered_public_key_compressed_ptr, 33).to_vec()
    );

    // skipping uncompressed checks since we already verified that parsing and serializing works.

    let key_tweak_ptr = secp256k1_wasm.malloc(32);

    let privkey_tweaked_add_ptr = secp256k1_wasm.malloc(32);
    let raw_pubkey_derived_tweaked_add_ptr = secp256k1_wasm.malloc(64);
    let pubkey_derived_tweaked_add_compressed_ptr = secp256k1_wasm.malloc(33);
    let pubkey_derived_tweaked_add_compressed_length_ptr = secp256k1_wasm.malloc_size_t(33);
    let raw_pubkey_tweaked_add_ptr = secp256k1_wasm.malloc(64);
    let pubkey_tweaked_add_compressed_ptr = secp256k1_wasm.malloc(33);
    let pubkey_tweaked_add_compressed_length_ptr = secp256k1_wasm.malloc_size_t(33);

    let privkey_tweaked_mul_ptr = secp256k1_wasm.malloc(32);
    let raw_pubkey_derived_tweaked_mul_ptr = secp256k1_wasm.malloc(64);
    let pubkey_derived_tweaked_mul_compressed_ptr = secp256k1_wasm.malloc(33);
    let pubkey_derived_tweaked_mul_compressed_length_ptr = secp256k1_wasm.malloc_size_t(33);
    let raw_pubkey_tweaked_mul_ptr = secp256k1_wasm.malloc(64);
    let pubkey_tweaked_mul_compressed_ptr = secp256k1_wasm.malloc(33);
    let pubkey_tweaked_mul_compressed_length_ptr = secp256k1_wasm.malloc_size_t(33);

    assert_ne!(raw_pubkey_tweaked_mul_ptr, 0);
    assert_ne!(pubkey_tweaked_mul_compressed_ptr, 0);
    assert_ne!(pubkey_tweaked_mul_compressed_length_ptr, 0);

    // set pre determine values
    secp256k1_wasm.heap_u8_mut(key_tweak_ptr, 32).copy_from_slice(&KEY_TWEAK_VAL);

    secp256k1_wasm.heap_u8_mut(privkey_tweaked_add_ptr, 32).copy_from_slice(&PRIVKEY);
    // we already verified that rawPubkeyPtr matches the given pubkeyCompressed, so let's re-use that.
    copy_within(secp256k1_wasm, raw_pubkey_tweaked_add_ptr, raw_pubkey_ptr, 64);

    secp256k1_wasm.heap_u8_mut(privkey_tweaked_mul_ptr, 32).copy_from_slice(&PRIVKEY);
    copy_within(secp256k1_wasm, raw_pubkey_tweaked_mul_ptr, raw_pubkey_ptr, 64);

    /*
     * actually test the stuff
     * tweak add
     */
    assert_eq!(
        secp256k1_wasm.privkey_tweak_add(context_ptr, privkey_tweaked_add_ptr, key_tweak_ptr),
        1
    );
    assert_eq!(
        secp256k1_wasm.read_heap_u8(privkey_tweaked_add_ptr, 32),
        PRIVKEY_TWEAKED_ADD
    );
    assert_eq!(
        secp256k1_wasm.pubkey_create(context_ptr, raw_pubkey_derived_tweaked_add_ptr, privkey_tweaked_add_ptr),
        1
    );
    secp256k1_wasm.pubkey_serialize(
        context_ptr,
        pubkey_derived_tweaked_add_compressed_ptr,
        pubkey_derived_tweaked_add_compressed_length_ptr,
        raw_pubkey_derived_tweaked_add_ptr,
        CompressionFlag::COMPRESSED,
    );
    assert_eq!(
        secp256k1_wasm.read_heap_u8(pubkey_derived_tweaked_add_compressed_ptr, 33),
        PUBKEY_TWEAKED_ADD_COMPRESSED
    );
    assert_eq!(
        secp256k1_wasm.pubkey_tweak_add(context_ptr, raw_pubkey_tweaked_add_ptr, key_tweak_ptr),
        1
    );
    secp256k1_wasm.pubkey_serialize(
        context_ptr,
        pubkey_tweaked_add_compressed_ptr,
        pubkey_tweaked_add_compressed_length_ptr,
        raw_pubkey_tweaked_add_ptr,
        CompressionFlag::COMPRESSED,
    );
    assert_eq!(
        secp256k1_wasm.read_heap_u8(pubkey_tweaked_add_compressed_ptr, 33),
        PUBKEY_TWEAKED_ADD_COMPRESSED
    );

    // tweak mul
    assert_eq!(
        secp256k1_wasm.privkey_tweak_mul(context_ptr, privkey_tweaked_mul_ptr, key_tweak_ptr),
        1
    );
    assert_eq!(
        secp256k1_wasm.read_heap_u8(privkey_tweaked_mul_ptr, 32),
        PRIVKEY_TWEAKED_MUL
    );
    assert_eq!(
        secp256k1_wasm.pubkey_create(context_ptr, raw_pubkey_derived_tweaked_mul_ptr, privkey_tweaked_mul_ptr),
        1
    );
    secp256k1_wasm.pubkey_serialize(
        context_ptr,
        pubkey_derived_tweaked_mul_compressed_ptr,
        pubkey_derived_tweaked_mul_compressed_length_ptr,
        raw_pubkey_derived_tweaked_mul_ptr,
        CompressionFlag::COMPRESSED,
    );
    assert_eq!(
        secp256k1_wasm.read_heap_u8(pubkey_derived_tweaked_mul_compressed_ptr, 33),
        PUBKEY_TWEAKED_MUL_COMPRESSED
    );
    assert_eq!(
        secp256k1_wasm.pubkey_tweak_mul(context_ptr, raw_pubkey_tweaked_mul_ptr, key_tweak_ptr),
        1
    );
    secp256k1_wasm.pubkey_serialize(
        context_ptr,
        pubkey_tweaked_mul_compressed_ptr,
        pubkey_tweaked_mul_compressed_length_ptr,
        raw_pubkey_tweaked_mul_ptr,
        CompressionFlag::COMPRESSED,
    );
    assert_eq!(
        secp256k1_wasm.read_heap_u8(pubkey_tweaked_mul_compressed_ptr, 33),
        PUBKEY_TWEAKED_MUL_COMPRESSED
    );

    // create schnorr signature
    let schnorr_sig_ptr = secp256k1_wasm.malloc(64);
    let schnorr_msg_hash_ptr = secp256k1_wasm.malloc_uint8_array(&SCHNORR_MSG_HASH);
    assert_eq!(
        secp256k1_wasm.schnorr_sign(context_ptr, schnorr_sig_ptr, schnorr_msg_hash_ptr, privkey_ptr),
        1
    );
    assert_eq!(secp256k1_wasm.read_heap_u8(schnorr_sig_ptr, 64), SIG_SCHNORR);

    // verify the schnorr signature
    assert_eq!(
        secp256k1_wasm.schnorr_verify(context_ptr, schnorr_sig_ptr, schnorr_msg_hash_ptr, raw_pubkey_ptr),
        1
    );
}

/// `const binary = getEmbeddedSecp256k1Binary();`
fn binary() -> Vec<u8> {
    get_embedded_secp256k1_binary()
}

#[test]
fn crypto_get_embedded_secp256k1_binary_returns_the_proper_binary() {
    let path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib/bin/secp256k1")).join("secp256k1.wasm");
    let binary_from_disk = std::fs::read(path).expect("the binary exists");
    assert_eq!(binary(), binary_from_disk);
}

#[test]
fn crypto_secp256k1_wasm_instantiated_with_embedded_binary() {
    let mut secp256k1_wasm = instantiate_secp256k1_wasm().expect("the embedded binary instantiates");
    test_secp256k1_wasm(&mut secp256k1_wasm);
}

#[test]
fn crypto_secp256k1_wasm_instantiated_with_bytes() {
    let mut secp256k1_wasm = instantiate_secp256k1_wasm_bytes(&binary()).expect("the binary instantiates");
    test_secp256k1_wasm(&mut secp256k1_wasm);
}
