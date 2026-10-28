//! libauth's `Secp256k1` interface, implemented natively.
//!
//! libauth compiles its fork of libsecp256k1 (`bitauth/libauth-secp256k1`,
//! commit `2b8e4e6`) to WebAssembly. This port implements the same operations
//! with the `k256` crate's field and group arithmetic, reproducing that
//! version's behavior: its DER parser, its RFC6979 nonce function (which hashes
//! the message without reducing it), its unvalidated private key tweaks, BCH
//! Schnorr signatures, and libauth's handling of inputs (`cloneAndPad`).

use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::{LinearCombination, MulByGenerator, Reduce};
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

use super::secp256k1_types::{RecoverableSignature, RecoveryId, Secp256k1};

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
const MAX_PUBLIC_KEY_LENGTH: usize = 65;
const MAX_ECDSA_SIG_LENGTH: usize = 72;
const MESSAGE_HASH_LENGTH: usize = 32;
const PRIVATE_KEY_LENGTH: usize = 32;
const SCHNORR_SIG_LENGTH: usize = 64;
const RANDOM_SEED_LENGTH: usize = 32;

/// The group order, `n`.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The field size minus the group order, `p - n`.
const P_MINUS_ORDER: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4,
    0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// libauth's `cloneAndPad`: `value`, zero-padded to `LENGTH` bytes. Like
/// `Uint8Array#set`, a longer `value` throws (here, panics).
fn clone_and_pad<const LENGTH: usize>(value: &[u8]) -> [u8; LENGTH] {
    assert!(value.len() <= LENGTH, "RangeError: offset is out of bounds");
    let mut padded = [0; LENGTH];
    padded[..value.len()].copy_from_slice(value);
    padded
}

/// `secp256k1_scalar_set_b32`: the value modulo the group order, and whether
/// it was out of range.
fn scalar_set_b32(bytes: &[u8; 32]) -> (Scalar, bool) {
    let repr = FieldBytes::from(*bytes);
    match Option::<Scalar>::from(Scalar::from_repr(repr)) {
        Some(scalar) => (scalar, false),
        None => (<Scalar as Reduce<U256>>::reduce_bytes(&repr), true),
    }
}

fn scalar_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
}

fn is_zero(scalar: &Scalar) -> bool {
    bool::from(scalar.is_zero())
}

/// `secp256k1_eckey_pubkey_parse`: compressed (`0x02`/`0x03`), uncompressed
/// (`0x04`), and hybrid (`0x06`/`0x07`) encodings.
fn parse_public_key(input: &[u8]) -> Option<AffinePoint> {
    match (input.len(), input.first()) {
        (33, Some(&tag @ (0x02 | 0x03))) => Option::from(AffinePoint::decompress(
            FieldBytes::from_slice(&input[1..33]),
            Choice::from(u8::from(tag == 0x03)),
        )),
        (65, Some(&tag @ (0x04 | 0x06 | 0x07))) => {
            if tag != 0x04 && (input[64] & 1 == 1) != (tag == 0x07) {
                return None;
            }
            Option::from(AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
                FieldBytes::from_slice(&input[1..33]),
                FieldBytes::from_slice(&input[33..65]),
                false,
            )))
        }
        _ => None,
    }
}

/// `secp256k1_eckey_pubkey_serialize` (which fails, producing no bytes, for the
/// point at infinity).
fn serialize_public_key(point: &AffinePoint, compressed: bool) -> Vec<u8> {
    if *point == AffinePoint::IDENTITY {
        return Vec::new();
    }
    point.to_encoded_point(compressed).as_bytes().to_vec()
}

fn affine_y(point: &AffinePoint) -> FieldElement {
    let encoded = point.to_encoded_point(false);
    Option::from(FieldElement::from_bytes(FieldBytes::from_slice(&encoded.as_bytes()[33..65])))
        .expect("an affine coordinate is a field element")
}

/// `secp256k1_fe_is_quad_var`.
fn is_quadratic_residue(value: &FieldElement) -> bool {
    bool::from(value.sqrt().is_some())
}

/// `secp256k1_der_read_len`.
fn der_read_len(input: &[u8], position: &mut usize) -> Option<usize> {
    let end = input.len();
    if *position >= end {
        return None;
    }
    let first = input[*position];
    *position += 1;
    if first == 0xff {
        return None;
    }
    if first & 0x80 == 0 {
        return Some(usize::from(first));
    }
    if first == 0x80 {
        return None;
    }
    let mut remaining = usize::from(first & 0x7f);
    if remaining > end - *position || input[*position] == 0 {
        return None;
    }
    // `sizeof(size_t)` in libauth's (wasm32) build.
    if remaining > 4 {
        return None;
    }
    let mut length = 0_usize;
    while remaining > 0 {
        length = (length << 8) | usize::from(input[*position]);
        *position += 1;
        remaining -= 1;
    }
    if length > end - *position || length < 128 {
        return None;
    }
    Some(length)
}

/// `secp256k1_der_parse_integer`: out-of-range and negative values parse as
/// zero.
fn der_parse_integer(input: &[u8], position: &mut usize) -> Option<Scalar> {
    let end = input.len();
    if *position == end || input[*position] != 0x02 {
        return None;
    }
    *position += 1;
    let mut length = der_read_len(input, position)?;
    if length == 0 || *position + length > end {
        return None;
    }
    let first = input[*position];
    if length > 1 && first == 0x00 && input[*position + 1] & 0x80 == 0 {
        return None;
    }
    if length > 1 && first == 0xff && input[*position + 1] & 0x80 == 0x80 {
        return None;
    }
    let mut overflow = first & 0x80 == 0x80;
    if first == 0 {
        length -= 1;
        *position += 1;
    }
    if length > 32 {
        overflow = true;
    }
    let mut value = Scalar::ZERO;
    if !overflow {
        let mut bytes = [0; 32];
        bytes[32 - length..].copy_from_slice(&input[*position..*position + length]);
        let (scalar, out_of_range) = scalar_set_b32(&bytes);
        if !out_of_range {
            value = scalar;
        }
    }
    *position += length;
    Some(value)
}

/// `secp256k1_ecdsa_sig_parse`.
fn parse_signature_der(input: &[u8]) -> Option<(Scalar, Scalar)> {
    let mut position = 0;
    if input.first() != Some(&0x30) {
        return None;
    }
    position += 1;
    let length = der_read_len(input, &mut position)?;
    if length != input.len() - position {
        return None;
    }
    let r = der_parse_integer(input, &mut position)?;
    let s = der_parse_integer(input, &mut position)?;
    (position == input.len()).then_some((r, s))
}

/// `secp256k1_ecdsa_signature_parse_compact`.
fn parse_signature_compact(input: &[u8; COMPACT_SIG_LENGTH]) -> Option<(Scalar, Scalar)> {
    let (r, r_overflow) = scalar_set_b32(input[..32].try_into().expect("32 bytes"));
    let (s, s_overflow) = scalar_set_b32(input[32..].try_into().expect("32 bytes"));
    (!r_overflow && !s_overflow).then_some((r, s))
}

/// libauth's `parseSignature`.
fn parse_signature(signature: &[u8], is_der: bool) -> Option<(Scalar, Scalar)> {
    let padded = clone_and_pad::<MAX_ECDSA_SIG_LENGTH>(signature);
    if is_der {
        parse_signature_der(signature)
    } else {
        parse_signature_compact(padded[..COMPACT_SIG_LENGTH].try_into().expect("64 bytes"))
    }
}

/// `secp256k1_ecdsa_sig_serialize`.
fn serialize_signature_der(r: &Scalar, s: &Scalar) -> Vec<u8> {
    let integer = |scalar: &Scalar| {
        let mut bytes = vec![0];
        bytes.extend_from_slice(&scalar_bytes(scalar));
        let mut start = 0;
        while bytes.len() - start > 1 && bytes[start] == 0 && bytes[start + 1] < 0x80 {
            start += 1;
        }
        bytes.split_off(start)
    };
    let (r, s) = (integer(r), integer(s));
    let mut der = vec![0x30, (4 + r.len() + s.len()) as u8, 0x02, r.len() as u8];
    der.extend_from_slice(&r);
    der.extend_from_slice(&[0x02, s.len() as u8]);
    der.extend_from_slice(&s);
    der
}

fn serialize_signature_compact(r: &Scalar, s: &Scalar) -> Vec<u8> {
    [scalar_bytes(r), scalar_bytes(s)].concat()
}

fn serialize_signature(r: &Scalar, s: &Scalar, is_der: bool) -> Vec<u8> {
    if is_der {
        serialize_signature_der(r, s)
    } else {
        serialize_signature_compact(r, s)
    }
}

/// HMAC-SHA256 of the concatenated `parts`.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The RFC6979 HMAC-SHA256 generator behind libsecp256k1's
/// `nonce_function_rfc6979`, keyed with the private key, the message hash
/// (not reduced modulo the order), and (for Schnorr signatures) an algorithm
/// tag. Successive calls return the nonces for successive `counter` values.
struct Rfc6979 {
    k: [u8; 32],
    v: [u8; 32],
    retry: bool,
}

impl Rfc6979 {
    fn new(key: &[u8]) -> Self {
        let mut k = [0; 32];
        let mut v = [1; 32];
        k = hmac_sha256(&k, &[&v, &[0], key]);
        v = hmac_sha256(&k, &[&v]);
        k = hmac_sha256(&k, &[&v, &[1], key]);
        v = hmac_sha256(&k, &[&v]);
        Self { k, v, retry: false }
    }

    fn generate(&mut self) -> [u8; 32] {
        if self.retry {
            self.k = hmac_sha256(&self.k, &[&self.v, &[0]]);
            self.v = hmac_sha256(&self.k, &[&self.v]);
        }
        self.v = hmac_sha256(&self.k, &[&self.v]);
        self.retry = true;
        self.v
    }
}

/// `secp256k1_ecdsa_sign` and `secp256k1_ecdsa_sign_recoverable`: `(r, s,
/// recovery ID)`, or `None` for an invalid private key.
fn sign_ecdsa(private_key: &[u8; 32], message_hash: &[u8; 32]) -> Option<(Scalar, Scalar, RecoveryId)> {
    let (secret, overflow) = scalar_set_b32(private_key);
    if overflow || is_zero(&secret) {
        return None;
    }
    let message = scalar_set_b32(message_hash).0;
    let mut nonces = Rfc6979::new(&[&private_key[..], &message_hash[..]].concat());
    loop {
        let (nonce, overflow) = scalar_set_b32(&nonces.generate());
        if overflow || is_zero(&nonce) {
            continue;
        }
        let point = ProjectivePoint::mul_by_generator(&nonce).to_affine();
        let (r, r_overflow) = scalar_set_b32(&point.x().into());
        let mut recovery_id = if r_overflow { 2 } else { 0 } | u8::from(bool::from(point.y_is_odd()));
        let mut s = nonce.invert().expect("a non-zero nonce") * (r * secret + message);
        if is_zero(&s) {
            continue;
        }
        if bool::from(s.is_high()) {
            s = -s;
            recovery_id ^= 1;
        }
        return Some((r, s, recovery_id));
    }
}

/// `secp256k1_ecdsa_verify`: high-S signatures are rejected.
fn verify_ecdsa(r: &Scalar, s: &Scalar, public_key: &AffinePoint, message_hash: &[u8; 32]) -> bool {
    if bool::from(s.is_high()) || is_zero(r) || is_zero(s) {
        return false;
    }
    let message = scalar_set_b32(message_hash).0;
    let s_inverse = s.invert().expect("a non-zero s");
    let point = ProjectivePoint::lincomb(
        &ProjectivePoint::GENERATOR,
        &(message * s_inverse),
        &ProjectivePoint::from(*public_key),
        &(*r * s_inverse),
    );
    if bool::from(point.is_identity()) {
        return false;
    }
    <Scalar as Reduce<U256>>::reduce_bytes(&point.to_affine().x()) == *r
}

/// `secp256k1_ecdsa_recover`.
fn recover_ecdsa(r: &Scalar, s: &Scalar, recovery_id: RecoveryId, message_hash: &[u8; 32]) -> Option<AffinePoint> {
    if is_zero(r) || is_zero(s) {
        return None;
    }
    let mut x = scalar_bytes(r);
    if recovery_id & 2 != 0 {
        if x >= P_MINUS_ORDER {
            return None;
        }
        let mut carry = 0_u16;
        for index in (0..32).rev() {
            let sum = u16::from(x[index]) + u16::from(ORDER[index]) + carry;
            x[index] = sum as u8;
            carry = sum >> 8;
        }
    }
    let point = Option::<AffinePoint>::from(AffinePoint::decompress(
        FieldBytes::from_slice(&x),
        Choice::from(recovery_id & 1),
    ))?;
    let message = scalar_set_b32(message_hash).0;
    let r_inverse = r.invert().expect("a non-zero r");
    let recovered = ProjectivePoint::lincomb(
        &ProjectivePoint::from(point),
        &(r_inverse * s),
        &ProjectivePoint::GENERATOR,
        &-(r_inverse * message),
    );
    (!bool::from(recovered.is_identity())).then(|| recovered.to_affine())
}

/// `secp256k1_schnorr_compute_e`: `SHA256(R.x || compressed public key ||
/// message hash)`, modulo the order.
fn schnorr_challenge(r_x: &[u8], public_key: &AffinePoint, message_hash: &[u8; 32]) -> Scalar {
    let digest = Sha256::new()
        .chain_update(r_x)
        .chain_update(serialize_public_key(public_key, true))
        .chain_update(message_hash)
        .finalize();
    scalar_set_b32(&digest.into()).0
}

/// `secp256k1_schnorr_sign`: a BCH Schnorr signature, or `None` for an invalid
/// private key.
fn sign_schnorr(private_key: &[u8; 32], message_hash: &[u8; 32]) -> Option<[u8; SCHNORR_SIG_LENGTH]> {
    let (secret, overflow) = scalar_set_b32(private_key);
    if overflow || is_zero(&secret) {
        return None;
    }
    let public_key = ProjectivePoint::mul_by_generator(&secret).to_affine();
    let mut nonces = Rfc6979::new(&[&private_key[..], &message_hash[..], b"Schnorr+SHA256  "].concat());
    let mut nonce = loop {
        let (nonce, overflow) = scalar_set_b32(&nonces.generate());
        if !overflow && !is_zero(&nonce) {
            break nonce;
        }
    };
    let point = ProjectivePoint::mul_by_generator(&nonce).to_affine();
    if !is_quadratic_residue(&affine_y(&point)) {
        nonce = -nonce;
    }
    let r_x: [u8; 32] = point.x().into();
    let s = schnorr_challenge(&r_x, &public_key, message_hash) * secret + nonce;
    let mut signature = [0; SCHNORR_SIG_LENGTH];
    signature[..32].copy_from_slice(&r_x);
    signature[32..].copy_from_slice(&scalar_bytes(&s));
    Some(signature)
}

/// `secp256k1_schnorr_verify`.
fn verify_schnorr(signature: &[u8; SCHNORR_SIG_LENGTH], public_key: &AffinePoint, message_hash: &[u8; 32]) -> bool {
    let (s, overflow) = scalar_set_b32(signature[32..].try_into().expect("32 bytes"));
    if overflow || Option::<FieldElement>::from(FieldElement::from_bytes(FieldBytes::from_slice(&signature[..32]))).is_none() {
        return false;
    }
    let challenge = schnorr_challenge(&signature[..32], public_key, message_hash);
    let point = ProjectivePoint::lincomb(&ProjectivePoint::from(*public_key), &-challenge, &ProjectivePoint::GENERATOR, &s);
    if bool::from(point.is_identity()) {
        return false;
    }
    let point = point.to_affine();
    point.x().as_slice() == &signature[..32] && is_quadratic_residue(&affine_y(&point))
}

/// `secp256k1_ec_privkey_tweak_add` and `_tweak_mul`: the private key is
/// reduced modulo the order but not otherwise validated.
fn tweak_private_key(add: bool, private_key: &[u8; 32], tweak_value: &[u8; 32]) -> Option<[u8; 32]> {
    let (tweak, overflow) = scalar_set_b32(tweak_value);
    let secret = scalar_set_b32(private_key).0;
    if overflow {
        return None;
    }
    let tweaked = if add {
        let sum = secret + tweak;
        if is_zero(&sum) {
            return None;
        }
        sum
    } else {
        if is_zero(&tweak) {
            return None;
        }
        secret * tweak
    };
    Some(scalar_bytes(&tweaked))
}

/// `secp256k1_ec_pubkey_tweak_add` and `_tweak_mul`.
fn tweak_public_key(add: bool, public_key: &AffinePoint, tweak_value: &[u8; 32]) -> Option<AffinePoint> {
    let (tweak, overflow) = scalar_set_b32(tweak_value);
    if overflow {
        return None;
    }
    let point = ProjectivePoint::from(*public_key);
    let tweaked = if add {
        point + ProjectivePoint::mul_by_generator(&tweak)
    } else {
        if is_zero(&tweak) {
            return None;
        }
        point * tweak
    };
    (!bool::from(tweaked.is_identity())).then(|| tweaked.to_affine())
}

/// libauth's `parsePublicKey`.
fn parse_public_key_input(public_key: &[u8]) -> Option<AffinePoint> {
    clone_and_pad::<MAX_PUBLIC_KEY_LENGTH>(public_key);
    parse_public_key(public_key)
}

impl Secp256k1 {
    /// Tweak a private key by adding the provided value modulo the order of the curve.
    pub fn add_tweak_private_key(&self, private_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        let tweak_value = clone_and_pad::<MESSAGE_HASH_LENGTH>(tweak_value);
        let private_key = clone_and_pad::<PRIVATE_KEY_LENGTH>(private_key);
        tweak_private_key(true, &private_key, &tweak_value)
            .map(|key| key.to_vec())
            .ok_or_else(|| Secp256k1Error::addTweakPrivateKey.to_string())
    }

    /// Tweak a public key by adding the provided value times the generator, returning the compressed result.
    pub fn add_tweak_public_key_compressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.tweak_public_key(true, true, public_key, tweak_value)
    }

    /// Tweak a public key by adding the provided value times the generator, returning the uncompressed result.
    pub fn add_tweak_public_key_uncompressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.tweak_public_key(false, true, public_key, tweak_value)
    }

    /// Compress a valid ECDSA public key.
    pub fn compress_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, String> {
        parse_public_key_input(public_key)
            .map(|point| serialize_public_key(&point, true))
            .ok_or_else(|| Secp256k1Error::unparsablePublicKey.to_string())
    }

    /// Derive a compressed public key from a valid secp256k1 private key.
    pub fn derive_public_key_compressed(&self, private_key: &[u8]) -> Result<Vec<u8>, String> {
        self.derive_public_key(true, private_key)
    }

    /// Derive an uncompressed public key from a valid secp256k1 private key.
    pub fn derive_public_key_uncompressed(&self, private_key: &[u8]) -> Result<Vec<u8>, String> {
        self.derive_public_key(false, private_key)
    }

    /// Malleate a compact-encoded ECDSA signature.
    pub fn malleate_signature_compact(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.modify_signature(false, false, signature)
    }

    /// Malleate a DER-encoded ECDSA signature.
    pub fn malleate_signature_der(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.modify_signature(true, false, signature)
    }

    /// Tweak a private key by multiplying it by the provided value modulo the order of the curve.
    pub fn mul_tweak_private_key(&self, private_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        let tweak_value = clone_and_pad::<MESSAGE_HASH_LENGTH>(tweak_value);
        let private_key = clone_and_pad::<PRIVATE_KEY_LENGTH>(private_key);
        tweak_private_key(false, &private_key, &tweak_value)
            .map(|key| key.to_vec())
            .ok_or_else(|| Secp256k1Error::mulTweakPrivateKey.to_string())
    }

    /// Tweak a public key by multiplying it by the provided value, returning the compressed result.
    pub fn mul_tweak_public_key_compressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.tweak_public_key(true, false, public_key, tweak_value)
    }

    /// Tweak a public key by multiplying it by the provided value, returning the uncompressed result.
    pub fn mul_tweak_public_key_uncompressed(&self, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        self.tweak_public_key(false, false, public_key, tweak_value)
    }

    /// Normalize a compact-encoded ECDSA signature to lower-S form.
    pub fn normalize_signature_compact(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.modify_signature(false, true, signature)
    }

    /// Normalize a DER-encoded ECDSA signature to lower-S form.
    pub fn normalize_signature_der(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        self.modify_signature(true, true, signature)
    }

    /// Compute a compressed public key from a valid signature, recovery ID, and the message hash used to generate the signature.
    pub fn recover_public_key_compressed(&self, signature: &[u8], recovery_id: RecoveryId, message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.recover_public_key(true, signature, recovery_id, message_hash)
    }

    /// Compute an uncompressed public key from a valid signature, recovery ID, and the message hash used to generate the signature.
    pub fn recover_public_key_uncompressed(&self, signature: &[u8], recovery_id: RecoveryId, message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.recover_public_key(false, signature, recovery_id, message_hash)
    }

    /// Create an ECDSA signature in compact format.
    pub fn sign_message_hash_compact(&self, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.sign(false, private_key, message_hash)
    }

    /// Create an ECDSA signature in DER format.
    pub fn sign_message_hash_der(&self, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
        self.sign(true, private_key, message_hash)
    }

    /// Create an ECDSA signature in compact format with a recovery ID.
    pub fn sign_message_hash_recoverable_compact(&self, private_key: &[u8], message_hash: &[u8]) -> Result<RecoverableSignature, String> {
        let message_hash = clone_and_pad::<MESSAGE_HASH_LENGTH>(message_hash);
        let private_key = clone_and_pad::<PRIVATE_KEY_LENGTH>(private_key);
        let (r, s, recovery_id) = sign_ecdsa(&private_key, &message_hash)
            .ok_or_else(|| Secp256k1Error::signWithInvalidPrivateKey.to_string())?;
        Ok(RecoverableSignature {
            recovery_id,
            signature: serialize_signature_compact(&r, &s),
        })
    }

    /// Create a Schnorr signature using the BCH Schnorr signature algorithm.
    pub fn sign_message_hash_schnorr(&self, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
        let message_hash = clone_and_pad::<MESSAGE_HASH_LENGTH>(message_hash);
        let private_key = clone_and_pad::<PRIVATE_KEY_LENGTH>(private_key);
        sign_schnorr(&private_key, &message_hash)
            .map(|signature| signature.to_vec())
            .ok_or_else(|| Secp256k1Error::signWithInvalidPrivateKey.to_string())
    }

    /// Convert a compact-encoded ECDSA signature to DER encoding.
    pub fn signature_compact_to_der(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        parse_signature(signature, false)
            .map(|(r, s)| serialize_signature_der(&r, &s))
            .ok_or_else(|| Secp256k1Error::unparsableSignature.to_string())
    }

    /// Convert a DER-encoded ECDSA signature to compact encoding.
    pub fn signature_der_to_compact(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        parse_signature(signature, true)
            .map(|(r, s)| serialize_signature_compact(&r, &s))
            .ok_or_else(|| Secp256k1Error::unparsableSignature.to_string())
    }

    /// Uncompress a valid ECDSA public key.
    pub fn uncompress_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, String> {
        parse_public_key_input(public_key)
            .map(|point| serialize_public_key(&point, false))
            .ok_or_else(|| Secp256k1Error::unparsablePublicKey.to_string())
    }

    /// Verify a private key is valid for secp256k1.
    pub fn validate_private_key(&self, private_key: &[u8]) -> bool {
        let (secret, overflow) = scalar_set_b32(&clone_and_pad::<PRIVATE_KEY_LENGTH>(private_key));
        !overflow && !is_zero(&secret)
    }

    /// Verify that a public key is valid.
    pub fn validate_public_key(&self, public_key: &[u8]) -> bool {
        parse_public_key_input(public_key).is_some()
    }

    /// Normalize a compact-encoded signature to lower-S form, then verify it.
    pub fn verify_signature_compact(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.verify_signature(false, true, signature, public_key, message_hash)
    }

    /// Verify a compact-encoded signature (which must be in lower-S form).
    pub fn verify_signature_compact_low_s(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.verify_signature(false, false, signature, public_key, message_hash)
    }

    /// Normalize a DER-encoded signature to lower-S form, then verify it.
    pub fn verify_signature_der(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.verify_signature(true, true, signature, public_key, message_hash)
    }

    /// Verify a DER-encoded signature (which must be in lower-S form).
    pub fn verify_signature_der_low_s(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        self.verify_signature(true, false, signature, public_key, message_hash)
    }

    /// Verify a Schnorr signature using the BCH Schnorr signature algorithm.
    pub fn verify_signature_schnorr(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> bool {
        let Some(public_key) = parse_public_key_input(public_key) else {
            return false;
        };
        let message_hash = clone_and_pad::<MESSAGE_HASH_LENGTH>(message_hash);
        let signature = clone_and_pad::<SCHNORR_SIG_LENGTH>(signature);
        verify_schnorr(&signature, &public_key, &message_hash)
    }

    fn derive_public_key(&self, compressed: bool, private_key: &[u8]) -> Result<Vec<u8>, String> {
        let (secret, overflow) = scalar_set_b32(&clone_and_pad::<PRIVATE_KEY_LENGTH>(private_key));
        if overflow || is_zero(&secret) {
            return Err(Secp256k1Error::derivePublicKeyFromInvalidPrivateKey.to_string());
        }
        Ok(serialize_public_key(&ProjectivePoint::mul_by_generator(&secret).to_affine(), compressed))
    }

    fn sign(&self, is_der: bool, private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, String> {
        let message_hash = clone_and_pad::<MESSAGE_HASH_LENGTH>(message_hash);
        let private_key = clone_and_pad::<PRIVATE_KEY_LENGTH>(private_key);
        let (r, s, _) = sign_ecdsa(&private_key, &message_hash)
            .ok_or_else(|| Secp256k1Error::signWithInvalidPrivateKey.to_string())?;
        Ok(serialize_signature(&r, &s, is_der))
    }

    fn recover_public_key(
        &self,
        compressed: bool,
        signature: &[u8],
        recovery_id: RecoveryId,
        message_hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        let message_hash = clone_and_pad::<MESSAGE_HASH_LENGTH>(message_hash);
        let signature = clone_and_pad::<MAX_ECDSA_SIG_LENGTH>(signature);
        // libsecp256k1's `ARG_CHECK` aborts, and libauth's `abort` import
        // throws `new Error('Secp256k1 Error')`.
        assert!(recovery_id <= 3, "Secp256k1 Error");
        let (r, s) = parse_signature_compact(signature[..COMPACT_SIG_LENGTH].try_into().expect("64 bytes"))
            .ok_or_else(|| Secp256k1Error::recoverPublicKeyWithUnparsableSignature.to_string())?;
        recover_ecdsa(&r, &s, recovery_id, &message_hash)
            .map(|point| serialize_public_key(&point, compressed))
            .ok_or_else(|| Secp256k1Error::recoverPublicKeyInvalidMaterial.to_string())
    }

    fn verify_signature(
        &self,
        is_der: bool,
        normalize: bool,
        signature: &[u8],
        public_key: &[u8],
        message_hash: &[u8],
    ) -> bool {
        let Some(public_key) = parse_public_key_input(public_key) else {
            return false;
        };
        let Some((r, mut s)) = parse_signature(signature, is_der) else {
            return false;
        };
        if normalize && bool::from(s.is_high()) {
            s = -s;
        }
        verify_ecdsa(&r, &s, &public_key, &clone_and_pad::<MESSAGE_HASH_LENGTH>(message_hash))
    }

    /// Normalize (to lower-S form) or malleate (negate S of) a signature.
    fn modify_signature(&self, is_der: bool, normalize: bool, signature: &[u8]) -> Result<Vec<u8>, String> {
        let (r, s) = parse_signature(signature, is_der).ok_or_else(|| Secp256k1Error::unparsableSignature.to_string())?;
        let s = if !normalize || bool::from(s.is_high()) { -s } else { s };
        Ok(serialize_signature(&r, &s, is_der))
    }

    fn tweak_public_key(&self, compressed: bool, add: bool, public_key: &[u8], tweak_value: &[u8]) -> Result<Vec<u8>, String> {
        let public_key = parse_public_key_input(public_key).ok_or_else(|| Secp256k1Error::unparsablePublicKey.to_string())?;
        let tweak_value = clone_and_pad::<MESSAGE_HASH_LENGTH>(tweak_value);
        tweak_public_key(add, &public_key, &tweak_value)
            .map(|point| serialize_public_key(&point, compressed))
            .ok_or_else(|| {
                if add { Secp256k1Error::addTweakPublicKey } else { Secp256k1Error::mulTweakPublicKey }.to_string()
            })
    }
}

/// Instantiate libauth's {@link Secp256k1} interface (implemented natively in
/// this port; libauth instantiates its embedded WebAssembly binary).
///
/// libauth passes the optional, 32-byte `randomSeed` to libsecp256k1's
/// `contextRandomize`, which blinds the library's computations to protect
/// against side-channel attacks without affecting any result. This port's
/// arithmetic is constant-time, so the seed is not used (but, as in libauth, a
/// seed longer than 32 bytes throws).
pub const fn instantiate_secp256k1(random_seed: Option<&[u8]>) -> Secp256k1 {
    if let Some(random_seed) = random_seed {
        assert!(random_seed.len() <= RANDOM_SEED_LENGTH, "RangeError: offset is out of bounds");
    }
    Secp256k1
}
