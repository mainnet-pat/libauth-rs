//! BIP32 hierarchical deterministic keys (port of `key/hd-key.ts`).

use crate::crypto::{
    hmac_sha512, ripemd160 as internal_ripemd160, secp256k1 as internal_secp256k1,
    sha256 as internal_sha256, sha512 as internal_sha512, Ripemd160, Secp256k1, Sha256, Sha512,
};
use crate::format::{
    base58_to_bin, big_int_to_bin_uint256_be_clamped, bin_to_base58, bin_to_big_int_uint256_be,
    bin_to_hex, bins_are_equal, flatten_bin_array, format_error, number_to_bin_uint32_be,
};
use crate::runtime::bigint::BigInt;
use crate::runtime::number::number_to_string;

const SECP256K1_PRIVATE_KEY_LENGTH: usize = 32;

/// Verify that a private key is valid for the Secp256k1 curve. Returns `true`
/// for success, or `false` on failure.
///
/// Private keys are 256-bit numbers encoded as a 32-byte, big-endian byte
/// array. Nearly every 256-bit number is a valid secp256k1 private key.
/// Specifically, any 256-bit number greater than `0x01` and less than
/// `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
/// is a valid private key. This range is part of the definition of the
/// secp256k1 elliptic curve parameters.
///
/// This method does not require a `Secp256k1` implementation.
pub fn validate_secp256k1_private_key(private_key: &[u8]) -> bool {
    if private_key.len() != SECP256K1_PRIVATE_KEY_LENGTH || private_key.iter().all(|value| *value == 0) {
        return false;
    }
    // The largest possible Secp256k1 private key – equal to the order of the
    // Secp256k1 curve minus one.
    const MAXIMUM_SECP256K1_PRIVATE_KEY: [u8; 32] = [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174,
        220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 64,
    ];
    let first_difference = private_key
        .iter()
        .zip(MAXIMUM_SECP256K1_PRIVATE_KEY.iter())
        .position(|(value, maximum)| value != maximum);
    match first_difference {
        None => true,
        Some(index) => private_key[index] < MAXIMUM_SECP256K1_PRIVATE_KEY[index],
    }
}

/// The networks that can be referenced by an HD public or private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HdKeyNetwork {
    /// `mainnet`
    Mainnet,
    /// `testnet`
    Testnet,
}

/// A valid private node in a Hierarchical Deterministic (HD) key tree. This
/// node can be used to derive further nodes, or the private key can be used to
/// generate a wallet address.
///
/// (`depth` and `child_index` are JavaScript numbers in libauth; they are
/// `i64` here so that out-of-range values can be represented and rejected
/// exactly as libauth rejects them.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdPrivateNodeValid {
    /// 32 bytes of additional entropy that can be used to derive HD child
    /// nodes.
    pub chain_code: Vec<u8>,
    /// The child index at which this node is derived from its parent node
    /// (identified via `parent_fingerprint`). Indexes less than `0x80000000`
    /// (`2147483648`) use standard derivation, while indexes equal to or
    /// greater than `0x80000000` use the "hardened" derivation algorithm. The
    /// maximum index is `0xffffffff` (`4294967295`).
    pub child_index: i64,
    /// The depth of this node, between `0` (for master nodes) and `255`. E.g.
    /// for a path of `m/0/0`, `depth` is `2`.
    pub depth: i64,
    /// The first 4 bytes of the parent node's identifier. This is used to
    /// quickly identify the parent node in data structures, but collisions can
    /// occur. To resolve collisions, use the full parent identifier. (See
    /// [`derive_hd_public_node_identifier`] for details.)
    pub parent_fingerprint: Vec<u8>,
    /// The full identifier of the parent node. This can be used to resolve
    /// collisions where two possible parent nodes share a
    /// `parent_fingerprint`. Since the full `parent_identifier` is not encoded
    /// in BIP32 HD keys, it might be unknown.
    pub parent_identifier: Option<Vec<u8>>,
    /// This node's valid Secp256k1 private key.
    pub private_key: Vec<u8>,
}

/// An HD private node for which the HMAC-SHA512 derivation produced an invalid
/// Secp256k1 private key (an astronomically rare result).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdPrivateNodeInvalid {
    /// See [`HdPrivateNodeValid::chain_code`].
    pub chain_code: Vec<u8>,
    /// See [`HdPrivateNodeValid::child_index`].
    pub child_index: i64,
    /// See [`HdPrivateNodeValid::depth`].
    pub depth: i64,
    /// See [`HdPrivateNodeValid::parent_fingerprint`].
    pub parent_fingerprint: Vec<u8>,
    /// See [`HdPrivateNodeValid::parent_identifier`].
    pub parent_identifier: Option<Vec<u8>>,
    /// The 32-byte derivation result which is not a valid Secp256k1 private
    /// key. This occurs with a probability of less than 1 in 2^127.
    pub invalid_material: Vec<u8>,
}

/// An HD private node (`HdPrivateNodeInvalid | HdPrivateNodeValid`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HdPrivateNode {
    /// An [`HdPrivateNodeInvalid`].
    Invalid(HdPrivateNodeInvalid),
    /// An [`HdPrivateNodeValid`].
    Valid(HdPrivateNodeValid),
}

/// An HD private node for which the full `parent_identifier` is known (in
/// libauth, `HdPrivateNodeType & { parentIdentifier: Uint8Array }`).
pub type HdPrivateNodeKnownParent<HdPrivateNodeType = HdPrivateNodeValid> = HdPrivateNodeType;

/// A valid public node in a Hierarchical Deterministic (HD) key tree. This
/// node can be used to derive further public nodes, or the public key can be
/// used to generate a wallet address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdPublicNodeValid {
    /// See [`HdPrivateNodeValid::chain_code`].
    pub chain_code: Vec<u8>,
    /// See [`HdPrivateNodeValid::child_index`].
    pub child_index: i64,
    /// See [`HdPrivateNodeValid::depth`].
    pub depth: i64,
    /// See [`HdPrivateNodeValid::parent_fingerprint`].
    pub parent_fingerprint: Vec<u8>,
    /// See [`HdPrivateNodeValid::parent_identifier`].
    pub parent_identifier: Option<Vec<u8>>,
    /// This node's valid Secp256k1 public key, in compressed format.
    pub public_key: Vec<u8>,
}

/// An HD public node for which the HMAC-SHA512 derivation produced an invalid
/// Secp256k1 public key (an astronomically rare result).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdPublicNodeInvalid {
    /// See [`HdPrivateNodeValid::chain_code`].
    pub chain_code: Vec<u8>,
    /// See [`HdPrivateNodeValid::child_index`].
    pub child_index: i64,
    /// See [`HdPrivateNodeValid::depth`].
    pub depth: i64,
    /// See [`HdPrivateNodeValid::parent_fingerprint`].
    pub parent_fingerprint: Vec<u8>,
    /// See [`HdPrivateNodeValid::parent_identifier`].
    pub parent_identifier: Option<Vec<u8>>,
    /// The 32-byte derivation result which is not a valid Secp256k1 public
    /// key. This occurs with a probability of less than 1 in 2^127.
    pub invalid_material: Vec<u8>,
}

/// An HD public node (`HdPublicNodeInvalid | HdPublicNodeValid`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HdPublicNode {
    /// An [`HdPublicNodeInvalid`].
    Invalid(HdPublicNodeInvalid),
    /// An [`HdPublicNodeValid`].
    Valid(HdPublicNodeValid),
}

/// An HD public node for which the full `parent_identifier` is known (in
/// libauth, `HdPublicNodeType & { parentIdentifier: Uint8Array }`).
pub type HdPublicNodeKnownParent<HdPublicNodeType = HdPublicNodeValid> = HdPublicNodeType;

/// A valid HD private or public node (libauth's anonymous
/// `HdPrivateNodeValid | HdPublicNodeValid`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HdNodeValid {
    /// An [`HdPrivateNodeValid`].
    Private(HdPrivateNodeValid),
    /// An [`HdPublicNodeValid`].
    Public(HdPublicNodeValid),
}

/// The contents of a decoded HD public or private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedHdKey<NodeType = HdNodeValid> {
    /// The decoded HD node.
    pub node: NodeType,
    /// The network encoded by the key's version.
    pub network: HdKeyNetwork,
}

/// Errors produced during HD node derivation (`HdNodeDerivationError`).
pub struct HdNodeDerivationError;

impl HdNodeDerivationError {
    /// The requested child index exceeds `0xffffffff`.
    pub const childIndexExceedsMaximum: &'static str = "HD node derivation error: child index exceeds maximum (4294967295).";
    /// Absolute derivation requires a node with a depth of zero.
    pub const requiresZeroDepthNode: &'static str = "HD node derivation error: absolute derivation requires an HD node with a depth of 0.";
    /// Hardened derivation requires an HD private node.
    pub const hardenedDerivationRequiresPrivateNode: &'static str = "HD node derivation error: derivation for hardened child indexes (indexes greater than or equal to 2147483648) requires an HD private node.";
    /// The absolute derivation path is malformed.
    pub const invalidAbsoluteDerivationPath: &'static str = "HD node derivation error: invalid absolute derivation path; path must begin with \"m\" or \"M\" and contain only positive child index numbers, separated by forward slashes (\"/\"), with zero or one apostrophe (\"'\") after each child index number.";
    /// The relative derivation path is malformed.
    pub const invalidRelativeDerivationPath: &'static str = "HD node derivation error: invalid relative derivation path; path must contain only positive child index numbers, separated by forward slashes (\"/\"), with zero or one apostrophe (\"'\") after each child index number.";
    /// The derived key material is not a valid Secp256k1 key.
    pub const invalidDerivedKey: &'static str = "HD node derivation error: an astronomically rare HMAC-SHA512 result produced an invalid Secp256k1 key.";
    /// Private derivation paths must begin with `m`.
    pub const invalidPrivateDerivationPrefix: &'static str = "HD node derivation error: private derivation paths must begin with \"m\".";
    /// Public derivation paths must begin with `M`.
    pub const invalidPublicDerivationPrefix: &'static str = "HD node derivation error: public derivation paths must begin with \"M\".";
}

/// Errors produced while decoding an HD key (`HdKeyDecodingError`).
pub struct HdKeyDecodingError;

impl HdKeyDecodingError {
    /// The decoded key is not 82 bytes.
    pub const incorrectLength: &'static str = "HD key decoding error: length is incorrect (must encode 82 bytes).";
    /// The trailing checksum does not match the payload.
    pub const invalidChecksum: &'static str = "HD key decoding error: checksum is invalid.";
    /// The encoded public key is not a valid Secp256k1 public key.
    pub const invalidPublicKey: &'static str = "HD key decoding error: the public key for this HD public node is not a valid Secp256k1 public key.";
    /// The encoded private key is not a valid Secp256k1 private key.
    pub const invalidPrivateKey: &'static str = "HD key decoding error: the key for this HD private node is not a valid Secp256k1 private key.";
    /// A private key version was used without the `0x00` padding byte.
    pub const missingPrivateKeyPaddingByte: &'static str = "HD key decoding error: version indicates a private key, but the key data is missing a padding byte.";
    /// An HD private key was expected, but an HD public key was decoded.
    pub const privateKeyExpected: &'static str = "HD key decoding error: expected an HD private key, but encountered an HD public key.";
    /// An HD public key was expected, but an HD private key was decoded.
    pub const publicKeyExpected: &'static str = "HD key decoding error: expected an HD public key, but encountered an HD private key.";
    /// The key includes a character outside the base58 alphabet.
    pub const unknownCharacter: &'static str = "HD key decoding error: key includes a non-base58 character.";
    /// The key uses an unrecognized version.
    pub const unknownVersion: &'static str = "HD key decoding error: key uses an unknown version.";
    /// A depth-zero key encodes a non-zero child index.
    pub const zeroDepthWithNonZeroChildIndex: &'static str = "HD key decoding error: key encodes a depth of zero with a non-zero child index.";
    /// A depth-zero key encodes a non-zero parent fingerprint.
    pub const zeroDepthWithNonZeroParentFingerprint: &'static str = "HD key decoding error: key encodes a depth of zero with a non-zero parent fingerprint.";
}

/// Errors produced while encoding an HD key (`HdKeyEncodingError`).
pub struct HdKeyEncodingError;

impl HdKeyEncodingError {
    /// The chain code is not 32 bytes.
    pub const invalidChainCodeLength: &'static str = "HD key encoding error: invalid chain code length. Chain code must be 32 bytes.";
    /// The depth exceeds the encodable maximum (255).
    pub const invalidChildDepth: &'static str = "HD key encoding error: invalid child depth. Child depth must be between 0 and 255 (inclusive).";
    /// The child index is not between 0 and 4294967295 (inclusive).
    pub const invalidChildIndex: &'static str =
        "HD key encoding error: invalid child index. Child index must be between 0 and 4294967295 (inclusive).";
    /// The parent fingerprint is not 4 bytes.
    pub const invalidParentFingerprintLength: &'static str = "HD key encoding error: invalid parent fingerprint length. Parent fingerprint must be 4 bytes.";
    /// The private key is not 32 bytes.
    pub const invalidPrivateKeyLength: &'static str = "HD key encoding error: invalid private key length. Secp256k1 private keys must be 32 bytes.";
    /// The public key is not 33 bytes.
    pub const invalidPublicKeyLength: &'static str = "HD key encoding error: invalid public key length. Public key must be 33 bytes (compressed).";
    /// The public key is not a valid Secp256k1 public key.
    pub const invalidPublicKey: &'static str = "HD key encoding error: the public key for this HD public node is not a valid Secp256k1 public key.";
    /// A depth-zero key encodes a non-zero child index.
    pub const zeroDepthWithNonZeroChildIndex: &'static str = "HD key encoding error: attempted to encode a zero depth key with a non-zero child index.";
    /// A depth-zero key encodes a non-zero parent fingerprint.
    pub const zeroDepthWithNonZeroParentFingerprint: &'static str = "HD key encoding error: attempted to encode a zero depth key with a non-zero parent fingerprint.";
}

/// Errors produced while cracking an HD private node (`HdNodeCrackingError`).
pub struct HdNodeCrackingError;

impl HdNodeCrackingError {
    /// Hardened child nodes cannot be used to crack the parent node.
    pub const cannotCrackHardenedDerivation: &'static str = "HD node cracking error: cannot crack an HD parent node using hardened child node.";
}

/// HD key version bytes (`HdKeyVersion`).
pub struct HdKeyVersion;

impl HdKeyVersion {
    /// Mainnet HD private key (`xprv`).
    pub const mainnetPrivateKey: u32 = 0x0488_ade4;
    /// Mainnet HD public key (`xpub`).
    pub const mainnetPublicKey: u32 = 0x0488_b21e;
    /// Testnet HD private key (`tprv`).
    pub const testnetPrivateKey: u32 = 0x0435_8394;
    /// Testnet HD public key (`tpub`).
    pub const testnetPublicKey: u32 = 0x0435_87cf;
}

const PARENT_FINGERPRINT_LENGTH: usize = 4;
const HALF_HMAC_SHA512_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 33;
const HD_KEY_LENGTH: usize = 82;
const HD_KEY_CHECKSUM_INDEX: usize = 78;
const HD_KEY_CHECKSUM_LENGTH: usize = 4;
const MAXIMUM_ENCODING_DEPTH: i64 = 255;
const MAXIMUM_CHILD_INDEX: i64 = 4_294_967_295;
const HARDENED_INDEX_OFFSET: i64 = 0x8000_0000;

const EMPTY_PARENT_FINGERPRINT: [u8; 4] = [0, 0, 0, 0];

/// The HMAC SHA-512 key used by BIP32, "Bitcoin seed"
/// (`utf8ToBin('Bitcoin seed')`)
pub const bip32HmacSha512Key: &[u8] = b"Bitcoin seed";

/// Derive an [`HdPrivateNode`] from the provided seed following the BIP32
/// specification. A seed should include between 16 bytes and 64 bytes of
/// entropy (recommended: 32 bytes).
///
/// - `assume_validity`: if set, the derived private key will not be checked
///   for validity, and will be assumed valid if `true` or invalid if `false`
///   (this is useful for testing).
/// - `crypto`: an optional implementation of sha512.
/// - `hmac_sha512_key`: the HMAC SHA-512 key to use (defaults to the HMAC
///   SHA-512 key used by BIP32, [`bip32HmacSha512Key`]).
///
/// Invalid key derivations (probability less than 1 in 2^127) return an
/// [`HdPrivateNodeInvalid`] (libauth's `throwErrors: false` behavior).
pub fn derive_hd_private_node_from_seed(
    seed: &[u8],
    assume_validity: Option<bool>,
    crypto: Option<&Sha512>,
    hmac_sha512_key: Option<&[u8]>,
) -> HdPrivateNode {
    let mac = hmac_sha512(
        hmac_sha512_key.unwrap_or(bip32HmacSha512Key),
        seed,
        Some(crypto.unwrap_or(&internal_sha512)),
    );
    let private_key = mac[..HALF_HMAC_SHA512_LENGTH].to_vec();
    let chain_code = mac[HALF_HMAC_SHA512_LENGTH..].to_vec();
    let depth = 0;
    let child_index = 0;
    let parent_fingerprint = EMPTY_PARENT_FINGERPRINT.to_vec();
    let valid = assume_validity.unwrap_or_else(|| validate_secp256k1_private_key(&private_key));
    if valid {
        HdPrivateNode::Valid(HdPrivateNodeValid {
            chain_code,
            child_index,
            depth,
            parent_fingerprint,
            parent_identifier: None,
            private_key,
        })
    } else {
        HdPrivateNode::Invalid(HdPrivateNodeInvalid {
            chain_code,
            child_index,
            depth,
            invalid_material: private_key,
            parent_fingerprint,
            parent_identifier: None,
        })
    }
}

/// Derive the public identifier for a given [`HdPrivateNodeValid`]. This is
/// used to uniquely identify HD nodes in software. The first 4 bytes of this
/// identifier are considered its "fingerprint".
///
/// - `crypto`: optional implementations of ripemd160, secp256k1, and sha256.
pub fn derive_hd_private_node_identifier(
    hd_private_node: &HdPrivateNodeValid,
    crypto: Option<(&Ripemd160, &Secp256k1, &Sha256)>,
) -> Result<Vec<u8>, String> {
    let (ripemd160, secp256k1, sha256) =
        crypto.unwrap_or((&internal_ripemd160, &internal_secp256k1, &internal_sha256));
    let public_key = secp256k1.derive_public_key_compressed(&hd_private_node.private_key)?;
    Ok(ripemd160.hash(&sha256.hash(&public_key)))
}

/// Derive the public identifier for a given [`HdPublicNodeValid`]. This is
/// used to uniquely identify HD nodes in software. The first 4 bytes of this
/// identifier are considered its fingerprint.
///
/// For details, see BIP32.
///
/// - `crypto`: optional implementations of ripemd160 and sha256.
pub fn derive_hd_public_node_identifier(
    node: &HdPublicNodeValid,
    crypto: Option<(&Ripemd160, &Sha256)>,
) -> Vec<u8> {
    let (ripemd160, sha256) = crypto.unwrap_or((&internal_ripemd160, &internal_sha256));
    ripemd160.hash(&sha256.hash(&node.public_key))
}

/// Returns `true` if the provided `version` is a public key version.
pub fn hd_key_version_is_public_key(version: u32) -> bool {
    version == HdKeyVersion::mainnetPublicKey || version == HdKeyVersion::testnetPublicKey
}

/// Returns `true` if the provided `version` is a private key version.
pub fn hd_key_version_is_private_key(version: u32) -> bool {
    version == HdKeyVersion::mainnetPrivateKey || version == HdKeyVersion::testnetPrivateKey
}

/// Any HD node, valid or invalid (the union of node types which
/// [`decode_hd_key_unchecked`] may return).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HdNode {
    /// An [`HdPrivateNode`].
    Private(HdPrivateNode),
    /// An [`HdPublicNode`].
    Public(HdPublicNode),
}

/// The result of [`decode_hd_key_unchecked`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedHdKeyUnchecked {
    /// The decoded HD node.
    pub node: HdNode,
    /// The decoded version.
    pub version: u32,
}

/// Decode an HD private key as defined by BIP32, returning a `node` and a
/// `network`. Decoding errors are returned as strings.
///
/// Unlike [`decode_hd_key`], this function does not validate the depth, child
/// index, parent fingerprint, or key material of the decoded node; invalid
/// keys are returned as [`HdPrivateNodeInvalid`] or [`HdPublicNodeInvalid`]
/// nodes.
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn decode_hd_key_unchecked(
    hd_key: &str,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<DecodedHdKeyUnchecked, String> {
    let (secp256k1, sha256) = crypto.unwrap_or((&internal_secp256k1, &internal_sha256));
    let decoded = base58_to_bin(hd_key)
        .map_err(|error| format_error(HdKeyDecodingError::unknownCharacter, Some(&error)))?;

    if decoded.len() != HD_KEY_LENGTH {
        return Err(format_error(
            HdKeyDecodingError::incorrectLength,
            Some(&format!("Length: {}.", decoded.len())),
        ));
    }

    let payload = &decoded[..HD_KEY_CHECKSUM_INDEX];
    let checksum_bits = &decoded[HD_KEY_CHECKSUM_INDEX..];
    let checksum = sha256.hash(&sha256.hash(payload));
    if !checksum_bits.iter().zip(checksum.iter()).all(|(value, expected)| value == expected) {
        return Err(format_error(
            HdKeyDecodingError::invalidChecksum,
            Some(&format!(
                "Encoded: {}; computed: {}.",
                bin_to_hex(checksum_bits),
                bin_to_hex(&checksum[..HD_KEY_CHECKSUM_LENGTH])
            )),
        ));
    }

    const DEPTH_INDEX: usize = 4;
    const FINGERPRINT_INDEX: usize = 5;
    const CHILD_INDEX_INDEX: usize = 9;
    const CHAIN_CODE_INDEX: usize = 13;
    const KEY_DATA_INDEX: usize = 45;

    let read_uint32_be = |index: usize| {
        u32::from_be_bytes(decoded[index..index + 4].try_into().expect("4 bytes"))
    };
    let version = read_uint32_be(0);
    let depth = i64::from(decoded[DEPTH_INDEX]);
    let parent_fingerprint = decoded[FINGERPRINT_INDEX..CHILD_INDEX_INDEX].to_vec();
    let child_index = i64::from(read_uint32_be(CHILD_INDEX_INDEX));
    let chain_code = decoded[CHAIN_CODE_INDEX..KEY_DATA_INDEX].to_vec();
    let key_data = &decoded[KEY_DATA_INDEX..HD_KEY_CHECKSUM_INDEX];

    let is_private_key = hd_key_version_is_private_key(version);
    if is_private_key && key_data[0] != 0x00 {
        return Err(HdKeyDecodingError::missingPrivateKeyPaddingByte.to_string());
    }
    if is_private_key {
        let private_key = key_data[1..].to_vec();
        let valid = validate_secp256k1_private_key(&private_key);
        return Ok(DecodedHdKeyUnchecked {
            node: HdNode::Private(if valid {
                HdPrivateNode::Valid(HdPrivateNodeValid {
                    chain_code,
                    child_index,
                    depth,
                    parent_fingerprint,
                    parent_identifier: None,
                    private_key,
                })
            } else {
                HdPrivateNode::Invalid(HdPrivateNodeInvalid {
                    chain_code,
                    child_index,
                    depth,
                    invalid_material: private_key,
                    parent_fingerprint,
                    parent_identifier: None,
                })
            }),
            version,
        });
    }

    let is_public_key = hd_key_version_is_public_key(version);
    if !is_public_key {
        return Err(format_error(
            HdKeyDecodingError::unknownVersion,
            Some(&format!("Version: {version}")),
        ));
    }

    let public_key = key_data.to_vec();
    let valid = secp256k1.validate_public_key(&public_key);
    Ok(DecodedHdKeyUnchecked {
        node: HdNode::Public(if valid {
            HdPublicNode::Valid(HdPublicNodeValid {
                chain_code,
                child_index,
                depth,
                parent_fingerprint,
                parent_identifier: None,
                public_key,
            })
        } else {
            HdPublicNode::Invalid(HdPublicNodeInvalid {
                chain_code,
                child_index,
                depth,
                invalid_material: public_key,
                parent_fingerprint,
                parent_identifier: None,
            })
        }),
        version,
    })
}

fn join_bytes(bin: &[u8]) -> String {
    bin.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
}

/// Decode an HD private key as defined by BIP32, returning a `node` and a
/// `network`. Decoding errors are returned as strings.
///
/// If the type of the key is known, use [`decode_hd_private_key`] or
/// [`decode_hd_public_key`].
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn decode_hd_key(
    hd_key: &str,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<DecodedHdKey, String> {
    let decoded = decode_hd_key_unchecked(hd_key, crypto)?;
    let DecodedHdKeyUnchecked { node, version } = decoded;
    let (depth, child_index, parent_fingerprint) = match &node {
        HdNode::Private(HdPrivateNode::Valid(node)) => (node.depth, node.child_index, &node.parent_fingerprint),
        HdNode::Private(HdPrivateNode::Invalid(node)) => (node.depth, node.child_index, &node.parent_fingerprint),
        HdNode::Public(HdPublicNode::Valid(node)) => (node.depth, node.child_index, &node.parent_fingerprint),
        HdNode::Public(HdPublicNode::Invalid(node)) => (node.depth, node.child_index, &node.parent_fingerprint),
    };

    if depth == 0 {
        if child_index != 0 {
            return Err(format_error(
                HdKeyDecodingError::zeroDepthWithNonZeroChildIndex,
                Some(&format!("Child index: {child_index}.")),
            ));
        }
        if !bins_are_equal(parent_fingerprint, &EMPTY_PARENT_FINGERPRINT) {
            return Err(format_error(
                HdKeyDecodingError::zeroDepthWithNonZeroParentFingerprint,
                Some(&format!("Parent fingerprint: {}.", join_bytes(parent_fingerprint))),
            ));
        }
    }

    let is_public_key = hd_key_version_is_public_key(version);

    let node = match node {
        HdNode::Private(HdPrivateNode::Valid(node)) => HdNodeValid::Private(node),
        HdNode::Public(HdPublicNode::Valid(node)) => HdNodeValid::Public(node),
        HdNode::Private(HdPrivateNode::Invalid(HdPrivateNodeInvalid { invalid_material, .. }))
        | HdNode::Public(HdPublicNode::Invalid(HdPublicNodeInvalid { invalid_material, .. })) => {
            return Err(if is_public_key {
                format_error(
                    HdKeyDecodingError::invalidPublicKey,
                    Some(&format!("Invalid public key: {}.", bin_to_hex(&invalid_material))),
                )
            } else {
                format_error(HdKeyDecodingError::invalidPrivateKey, None)
            });
        }
    };

    let network = if version == HdKeyVersion::mainnetPrivateKey || version == HdKeyVersion::mainnetPublicKey {
        HdKeyNetwork::Mainnet
    } else {
        HdKeyNetwork::Testnet
    };

    Ok(DecodedHdKey { network, node })
}

/// Decode an HD private key as defined by BIP32.
///
/// This function is similar to [`decode_hd_key`] but errors if the result is
/// not an [`HdPrivateNodeValid`].
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn decode_hd_private_key(
    hd_private_key: &str,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<DecodedHdKey<HdPrivateNodeValid>, String> {
    let DecodedHdKey { network, node } = decode_hd_key(hd_private_key, crypto)?;
    match node {
        HdNodeValid::Public(_) => Err(HdKeyDecodingError::privateKeyExpected.to_string()),
        HdNodeValid::Private(node) => Ok(DecodedHdKey { network, node }),
    }
}

/// Decode an HD public key as defined by BIP32.
///
/// This function is similar to [`decode_hd_key`] but errors if the result is
/// not an [`HdPublicNodeValid`].
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn decode_hd_public_key(
    hd_public_key: &str,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<DecodedHdKey<HdPublicNodeValid>, String> {
    let DecodedHdKey { network, node } = decode_hd_key(hd_public_key, crypto)?;
    match node {
        HdNodeValid::Private(_) => Err(HdKeyDecodingError::publicKeyExpected.to_string()),
        HdNodeValid::Public(node) => Ok(DecodedHdKey { network, node }),
    }
}

/// Decode the provided HD private key and compute its identifier. Error
/// messages are returned as a string.
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn hd_private_key_to_identifier(
    hd_private_key: &str,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<Vec<u8>, String> {
    let private_key_params = decode_hd_private_key(hd_private_key, crypto)?;
    derive_hd_private_node_identifier(&private_key_params.node, None)
}

/// Decode the provided HD public key and compute its identifier. Error
/// messages are returned as a string.
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn hd_public_key_to_identifier(
    hd_public_key: &str,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<Vec<u8>, String> {
    let public_key_params = decode_hd_public_key(hd_public_key, crypto)?;
    Ok(derive_hd_public_node_identifier(&public_key_params.node, None))
}

/// Encode the metadata portion of an HD key payload (the version, depth,
/// parent fingerprint, child index, and chain code).
///
/// - `version`: the 4-byte HD key version.
/// - `key_parameters`: the HD key for which to encode the metadata.
pub fn encode_hd_key_payload_metadata(
    version: &[u8],
    key_parameters: &DecodedHdKey,
) -> Result<Vec<u8>, String> {
    let (chain_code, child_index, depth, parent_fingerprint) = match &key_parameters.node {
        HdNodeValid::Private(node) => (&node.chain_code, node.child_index, node.depth, &node.parent_fingerprint),
        HdNodeValid::Public(node) => (&node.chain_code, node.child_index, node.depth, &node.parent_fingerprint),
    };
    if depth == 0 {
        if child_index != 0 {
            return Err(format_error(
                HdKeyEncodingError::zeroDepthWithNonZeroChildIndex,
                Some(&format!("Child index: {child_index}.")),
            ));
        }
        if !bins_are_equal(parent_fingerprint, &EMPTY_PARENT_FINGERPRINT) {
            return Err(format_error(
                HdKeyEncodingError::zeroDepthWithNonZeroParentFingerprint,
                Some(&format!("Parent fingerprint: {}.", join_bytes(parent_fingerprint))),
            ));
        }
    }
    if chain_code.len() != HALF_HMAC_SHA512_LENGTH {
        return Err(format_error(
            HdKeyEncodingError::invalidChainCodeLength,
            Some(&format!("Chain code length: {}.", chain_code.len())),
        ));
    }
    if parent_fingerprint.len() != PARENT_FINGERPRINT_LENGTH {
        return Err(format_error(
            HdKeyEncodingError::invalidParentFingerprintLength,
            Some(&format!("Parent fingerprint length: {}.", parent_fingerprint.len())),
        ));
    }
    if !(0..=MAXIMUM_ENCODING_DEPTH).contains(&depth) {
        return Err(format_error(
            HdKeyEncodingError::invalidChildDepth,
            Some(&format!("Depth: {depth}.")),
        ));
    }
    let depth = vec![depth as u8];
    if !(0..=MAXIMUM_CHILD_INDEX).contains(&child_index) {
        return Err(format_error(
            HdKeyEncodingError::invalidChildIndex,
            Some(&format!("Child index: {child_index}.")),
        ));
    }
    let child_index = number_to_bin_uint32_be(child_index as u32);
    Ok(flatten_bin_array(&[
        version.to_vec(),
        depth,
        parent_fingerprint.clone(),
        child_index,
        chain_code.clone(),
    ]))
}

/// Encode an HD private key payload (without the checksum) as defined by
/// BIP32.
pub fn encode_hd_private_key_payload(
    key_parameters: &DecodedHdKey<HdPrivateNodeValid>,
) -> Result<Vec<u8>, String> {
    let version = number_to_bin_uint32_be(match key_parameters.network {
        HdKeyNetwork::Mainnet => HdKeyVersion::mainnetPrivateKey,
        HdKeyNetwork::Testnet => HdKeyVersion::testnetPrivateKey,
    });
    if key_parameters.node.private_key.len() != HALF_HMAC_SHA512_LENGTH {
        return Err(format_error(
            HdKeyEncodingError::invalidPrivateKeyLength,
            Some(&format!("Private key length: {}.", key_parameters.node.private_key.len())),
        ));
    }
    let metadata = encode_hd_key_payload_metadata(
        &version,
        &DecodedHdKey {
            network: key_parameters.network,
            node: HdNodeValid::Private(key_parameters.node.clone()),
        },
    )?;
    let is_private_key = vec![0x00];
    Ok(flatten_bin_array(&[metadata, is_private_key, key_parameters.node.private_key.clone()]))
}

/// Encode an HD public key payload (without the checksum) as defined by
/// BIP32.
pub fn encode_hd_public_key_payload(
    key_parameters: &DecodedHdKey<HdPublicNodeValid>,
) -> Result<Vec<u8>, String> {
    let version = number_to_bin_uint32_be(match key_parameters.network {
        HdKeyNetwork::Mainnet => HdKeyVersion::mainnetPublicKey,
        HdKeyNetwork::Testnet => HdKeyVersion::testnetPublicKey,
    });
    if key_parameters.node.public_key.len() != PUBLIC_KEY_LENGTH {
        return Err(format_error(
            HdKeyEncodingError::invalidPublicKeyLength,
            Some(&format!("Public key length: {}.", key_parameters.node.public_key.len())),
        ));
    }
    let metadata = encode_hd_key_payload_metadata(
        &version,
        &DecodedHdKey {
            network: key_parameters.network,
            node: HdNodeValid::Public(key_parameters.node.clone()),
        },
    )?;
    Ok(flatten_bin_array(&[metadata, key_parameters.node.public_key.clone()]))
}

/// Encode an HD key payload with its 4-byte checksum (the first 4 bytes of the
/// double-SHA256 hash of the payload) in base58.
///
/// - `crypto`: an optional implementation of sha256.
pub fn encode_hd_key_payload_with_checksum(payload: &[u8], crypto: Option<&Sha256>) -> String {
    let sha256 = crypto.unwrap_or(&internal_sha256);
    const CHECKSUM_LENGTH: usize = 4;
    let checksum = sha256.hash(&sha256.hash(payload))[..CHECKSUM_LENGTH].to_vec();
    bin_to_base58(&flatten_bin_array(&[payload.to_vec(), checksum]))
}

/// The result of [`encode_hd_private_key`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdPrivateKeyEncodeResult {
    /// The encoded HD private key.
    pub hd_private_key: String,
}

/// Encode an HD private key (as defined by BIP32) given an HD private node.
///
/// - `crypto`: an optional implementation of sha256.
pub fn encode_hd_private_key(
    key_parameters: &DecodedHdKey<HdPrivateNodeValid>,
    crypto: Option<&Sha256>,
) -> Result<HdPrivateKeyEncodeResult, String> {
    let payload = encode_hd_private_key_payload(key_parameters)?;
    Ok(HdPrivateKeyEncodeResult {
        hd_private_key: encode_hd_key_payload_with_checksum(&payload, crypto),
    })
}

/// The result of [`encode_hd_public_key`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdPublicKeyEncodeResult {
    /// The encoded HD public key.
    pub hd_public_key: String,
}

/// Encode an HD public key (as defined by BIP32) given an HD public node.
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn encode_hd_public_key(
    key_parameters: &DecodedHdKey<HdPublicNodeValid>,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<HdPublicKeyEncodeResult, String> {
    let (secp256k1, sha256) = crypto.unwrap_or((&internal_secp256k1, &internal_sha256));
    if !secp256k1.validate_public_key(&key_parameters.node.public_key) {
        return Err(format_error(
            HdKeyEncodingError::invalidPublicKey,
            Some(&format!(
                "Invalid public key: \"{}\".",
                bin_to_hex(&key_parameters.node.public_key)
            )),
        ));
    }
    let payload = encode_hd_public_key_payload(key_parameters)?;
    Ok(HdPublicKeyEncodeResult {
        hd_public_key: encode_hd_key_payload_with_checksum(&payload, Some(sha256)),
    })
}

/// Derive the HD public node of an HD private node.
///
/// Though private keys cannot be derived from HD public keys, sharing HD
/// public keys still carries risk. Along with allowing an attacker to
/// associate wallet addresses together (breaking privacy), should an attacker
/// gain knowledge of a single child private key, **it's possible to derive all
/// parent HD private keys**. See
/// [`crack_hd_private_node_from_hd_public_node_and_child_private_node`] for
/// details.
///
/// Errors only if the node's private key is invalid (which the type of `node`
/// excludes; libauth does not check).
///
/// - `crypto`: an optional implementation of secp256k1.
pub fn derive_hd_public_node(
    node: &HdPrivateNodeValid,
    crypto: Option<&Secp256k1>,
) -> Result<HdPublicNodeValid, String> {
    let secp256k1 = crypto.unwrap_or(&internal_secp256k1);
    Ok(HdPublicNodeValid {
        chain_code: node.chain_code.clone(),
        child_index: node.child_index,
        depth: node.depth,
        parent_fingerprint: node.parent_fingerprint.clone(),
        parent_identifier: node.parent_identifier.clone(),
        public_key: secp256k1.derive_public_key_compressed(&node.private_key)?,
    })
}

/// Derive the HD public key of an HD private key.
///
/// - `crypto`: optional implementations of secp256k1 and sha256.
pub fn derive_hd_public_key(
    private_key: &str,
    crypto: Option<(&Secp256k1, &Sha256)>,
) -> Result<HdPublicKeyEncodeResult, String> {
    let decoded = decode_hd_private_key(private_key, crypto)?;
    let node = derive_hd_public_node(&decoded.node, crypto.map(|(secp256k1, _)| secp256k1))?;
    encode_hd_public_key(
        &DecodedHdKey {
            network: decoded.network,
            node,
        },
        crypto,
    )
}

/// Derive a child HD private node from an HD private node.
///
/// To derive a child HD public node, use [`derive_hd_public_node`] on the
/// result of this method. If the child is a hardened derivation (index
/// greater than or equal to `0x80000000`), this method must be used.
///
/// - `crypto`: optional implementations of ripemd160, secp256k1, sha256, and
///   sha512.
/// - `return_invalid_nodes`: if `true`, an [`HdPrivateNodeInvalid`] is
///   returned rather than an error when the derivation produces an invalid
///   key (probability less than 1 in 2^127; defaults to `false`).
pub fn derive_hd_private_node_child(
    node: &HdPrivateNodeValid,
    index: i64,
    crypto: Option<(&Ripemd160, &Secp256k1, &Sha256, &Sha512)>,
    return_invalid_nodes: Option<bool>,
) -> Result<HdPrivateNodeKnownParent<HdPrivateNode>, String> {
    let (ripemd160, secp256k1, sha256, sha512) = crypto.unwrap_or((
        &internal_ripemd160,
        &internal_secp256k1,
        &internal_sha256,
        &internal_sha512,
    ));
    if index > MAXIMUM_CHILD_INDEX {
        return Err(format_error(
            HdNodeDerivationError::childIndexExceedsMaximum,
            Some(&format!("Child index: {index}.")),
        ));
    }
    let parent_identifier = derive_hd_private_node_identifier(node, Some((ripemd160, secp256k1, sha256)))?;
    let parent_fingerprint = parent_identifier[..PARENT_FINGERPRINT_LENGTH].to_vec();
    let depth = node.depth + 1;
    let use_hardened_algorithm = index >= HARDENED_INDEX_OFFSET;
    let key_material = if use_hardened_algorithm {
        node.private_key.clone()
    } else {
        secp256k1.derive_public_key_compressed(&node.private_key)?
    };
    let serialization = flatten_bin_array(&[
        if use_hardened_algorithm { vec![0x00] } else { vec![] },
        key_material,
        number_to_bin_uint32_be(index as u32),
    ]);
    let derivation = hmac_sha512(&node.chain_code, &serialization, Some(sha512));
    const TWEAK_VALUE_LENGTH: usize = 32;
    let tweak_value = derivation[..TWEAK_VALUE_LENGTH].to_vec();
    let next_chain_code = derivation[TWEAK_VALUE_LENGTH..].to_vec();
    match secp256k1.add_tweak_private_key(&node.private_key, &tweak_value) {
        Err(_) => {
            if return_invalid_nodes == Some(true) {
                return Ok(HdPrivateNode::Invalid(HdPrivateNodeInvalid {
                    chain_code: next_chain_code,
                    child_index: index,
                    depth,
                    invalid_material: tweak_value,
                    parent_fingerprint,
                    parent_identifier: Some(parent_identifier),
                }));
            }
            Err(format_error(
                HdNodeDerivationError::invalidDerivedKey,
                Some(&format!("Invalid child index: {index}.")),
            ))
        }
        Ok(next_private_key) => Ok(HdPrivateNode::Valid(HdPrivateNodeValid {
            chain_code: next_chain_code,
            child_index: index,
            depth,
            parent_fingerprint,
            parent_identifier: Some(parent_identifier),
            private_key: next_private_key,
        })),
    }
}

/// Derive a non-hardened, child HD public node from an HD public node.
///
/// Because hardened derivation also requires knowledge of the parent private
/// node, it's not possible to use an HD public node to derive a hardened child
/// HD public node.
///
/// Though private keys cannot be derived from HD public keys, sharing HD
/// public keys still carries risk. Along with allowing an attacker to
/// associate wallet addresses together (breaking privacy), should an attacker
/// gain knowledge of a single child private key, **it's possible to derive all
/// parent HD private keys**. See
/// [`crack_hd_private_node_from_hd_public_node_and_child_private_node`] for
/// details.
///
/// - `crypto`: optional implementations of ripemd160, secp256k1, sha256, and
///   sha512.
/// - `return_invalid_nodes`: if `true`, an [`HdPublicNodeInvalid`] is
///   returned rather than an error when the derivation produces an invalid
///   key (probability less than 1 in 2^127; defaults to `false`).
pub fn derive_hd_public_node_child(
    node: &HdPublicNodeValid,
    index: i64,
    crypto: Option<(&Ripemd160, &Secp256k1, &Sha256, &Sha512)>,
    return_invalid_nodes: Option<bool>,
) -> Result<HdPublicNodeKnownParent<HdPublicNode>, String> {
    let (ripemd160, secp256k1, sha256, sha512) = crypto.unwrap_or((
        &internal_ripemd160,
        &internal_secp256k1,
        &internal_sha256,
        &internal_sha512,
    ));
    if index >= HARDENED_INDEX_OFFSET {
        return Err(format_error(
            HdNodeDerivationError::hardenedDerivationRequiresPrivateNode,
            Some(&format!("Requested index: {index}.")),
        ));
    }
    let parent_identifier = derive_hd_public_node_identifier(node, Some((ripemd160, sha256)));
    let parent_fingerprint = parent_identifier[..PARENT_FINGERPRINT_LENGTH].to_vec();
    let depth = node.depth + 1;
    let serialization = flatten_bin_array(&[node.public_key.clone(), number_to_bin_uint32_be(index as u32)]);
    let derivation = hmac_sha512(&node.chain_code, &serialization, Some(sha512));
    const TWEAK_VALUE_LENGTH: usize = 32;
    let tweak_value = derivation[..TWEAK_VALUE_LENGTH].to_vec();
    let next_chain_code = derivation[TWEAK_VALUE_LENGTH..].to_vec();
    match secp256k1.add_tweak_public_key_compressed(&node.public_key, &tweak_value) {
        Err(_) => {
            if return_invalid_nodes == Some(true) {
                return Ok(HdPublicNode::Invalid(HdPublicNodeInvalid {
                    chain_code: next_chain_code,
                    child_index: index,
                    depth,
                    invalid_material: tweak_value,
                    parent_fingerprint,
                    parent_identifier: Some(parent_identifier),
                }));
            }
            Err(format_error(
                HdNodeDerivationError::invalidDerivedKey,
                Some(&format!("Invalid child index: {index}.")),
            ))
        }
        Ok(next_public_key) => Ok(HdPublicNode::Valid(HdPublicNodeValid {
            chain_code: next_chain_code,
            child_index: index,
            depth,
            parent_fingerprint,
            parent_identifier: Some(parent_identifier),
            public_key: next_public_key,
        })),
    }
}

/// The known-parent node type derived from `NodeType` (in libauth,
/// `HdPrivateNodeKnownParent` for private nodes and `HdPublicNodeKnownParent`
/// for public nodes).
pub type HdNodeKnownParent<NodeType> = NodeType;

/// Test `path` against `^(?:[0-9]+'?)(?:\/[0-9]+'?)*$` (`relative`) or
/// `^[mM](?:\/[0-9]+'?)*$`.
fn is_valid_path(path: &str, relative: bool) -> bool {
    let components = if relative {
        path.split('/').collect::<Vec<_>>()
    } else {
        match path.as_bytes() {
            [b'm' | b'M'] => return true,
            [b'm' | b'M', b'/', ..] => path[2..].split('/').collect(),
            _ => return false,
        }
    };
    components.iter().all(|component| {
        let digits = component.strip_suffix('\'').unwrap_or(component);
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Derive a child HD node from a parent node given a relative derivation
/// path. The resulting node is the same type as the parent node – private
/// nodes return private nodes, public nodes return public nodes. (To prevent
/// implementation errors, this function will not internally derive a public
/// node from any private node; for public derivation, use
/// [`derive_hd_public_node`] at the desired BIP32 account level and provide
/// the HD public key to this function.)
///
/// Where possible, consider instead using [`derive_hd_path`] to reduce the
/// likelihood of implementation errors.
///
/// Errors are returned when the provided path is invalid or cannot be derived
/// from the provided HD node (e.g. the path requests an excessive child index,
/// a hardened path is requested from a public node, or an astronomically rare
/// HMAC-SHA512 result produces an invalid node).
///
/// The derivation path uses the notation specified in BIP32; see
/// [`derive_hd_path`] for details.
///
/// - `node`: the HD node from which to begin the derivation – for private
///   derivation, an [`HdPrivateNodeValid`]; for public derivation, an
///   [`HdPublicNodeValid`].
/// - `path`: the relative BIP32 derivation path, e.g. `1'/2` or `3/4/5`.
/// - `crypto`: optional implementations of ripemd160, secp256k1, sha256, and
///   sha512.
pub fn derive_hd_path_relative(
    node: &HdNodeValid,
    path: &str,
    crypto: Option<(&Ripemd160, &Secp256k1, &Sha256, &Sha512)>,
) -> Result<HdNodeKnownParent<HdNodeValid>, String> {
    if path.is_empty() {
        return Ok(node.clone());
    }
    if !is_valid_path(path, true) {
        return Err(format_error(
            HdNodeDerivationError::invalidRelativeDerivationPath,
            Some(&format!("Invalid path: \"{path}\".")),
        ));
    }
    // `parseInt(index, 10)`: the index as a JavaScript number.
    let indexes = path.split('/').map(|index| match index.strip_suffix('\'') {
        Some(digits) => digits.parse::<f64>().expect("validated digits") + HARDENED_INDEX_OFFSET as f64,
        None => index.parse::<f64>().expect("validated digits"),
    });
    match node {
        HdNodeValid::Private(node) => {
            let mut result = node.clone();
            for next_index in indexes {
                if next_index > MAXIMUM_CHILD_INDEX as f64 {
                    return Err(format_error(
                        HdNodeDerivationError::childIndexExceedsMaximum,
                        Some(&format!("Child index: {}.", number_to_string(next_index))),
                    ));
                }
                result = match derive_hd_private_node_child(&result, next_index as i64, crypto, None)? {
                    HdPrivateNode::Valid(node) => node,
                    HdPrivateNode::Invalid(_) => unreachable!("invalid nodes are only returned on request"),
                };
            }
            Ok(HdNodeValid::Private(result))
        }
        HdNodeValid::Public(node) => {
            let mut result = node.clone();
            for next_index in indexes {
                if next_index >= HARDENED_INDEX_OFFSET as f64 {
                    return Err(format_error(
                        HdNodeDerivationError::hardenedDerivationRequiresPrivateNode,
                        Some(&format!("Requested index: {}.", number_to_string(next_index))),
                    ));
                }
                result = match derive_hd_public_node_child(&result, next_index as i64, crypto, None)? {
                    HdPublicNode::Valid(node) => node,
                    HdPublicNode::Invalid(_) => unreachable!("invalid nodes are only returned on request"),
                };
            }
            Ok(HdNodeValid::Public(result))
        }
    }
}

/// Derive a child HD node from a master node given an absolute derivation
/// path. The resulting node is the same type as the master node – private
/// nodes return private nodes, public nodes return public nodes.
///
/// The derivation path uses the notation specified in BIP32:
///
/// The first character must be either `m` for private derivation or `M` for
/// public derivation, followed by sets of `/` and a number representing the
/// child index used in the derivation at that depth. Hardened derivation is
/// represented by a trailing `'`, and may only appear in private derivation
/// paths (hardened derivation requires knowledge of the private key). Hardened
/// child indexes are represented with the hardened index offset (`2147483648`)
/// subtracted.
///
/// For example, `m/0/1'/2` uses private derivation (`m`), with child indexes
/// in the following order:
///
/// `derive(derive(derive(node, 0), 2147483648 + 1), 2)`
///
/// Likewise, `M/3/4/5` uses public derivation (`M`), with child indexes in the
/// following order:
///
/// `derive(derive(derive(node, 3), 4), 5)`
///
/// Because hardened derivation requires a private node, paths that require
/// hardened derivation will produce an error if used with a public node.
///
/// - `node`: the HD node from which to begin the derivation (for paths
///   beginning with `m`, an [`HdPrivateNodeValid`]; for paths beginning with
///   `M`, an [`HdPublicNodeValid`]).
/// - `path`: the BIP32 derivation path, e.g. `m/0/1'/2` or `M/3/4/5`.
/// - `crypto`: optional implementations of ripemd160, secp256k1, sha256, and
///   sha512.
pub fn derive_hd_path(
    node: &HdNodeValid,
    path: &str,
    crypto: Option<(&Ripemd160, &Secp256k1, &Sha256, &Sha512)>,
) -> Result<HdNodeValid, String> {
    let depth = match node {
        HdNodeValid::Private(node) => node.depth,
        HdNodeValid::Public(node) => node.depth,
    };
    if depth != 0 {
        return Err(format_error(
            HdNodeDerivationError::requiresZeroDepthNode,
            Some(&format!("Depth of provided HD node: {depth}.")),
        ));
    }
    if !is_valid_path(path, false) {
        return Err(format_error(
            HdNodeDerivationError::invalidAbsoluteDerivationPath,
            Some(&format!("Invalid path: \"{path}\".")),
        ));
    }
    let parsed = path.split('/').collect::<Vec<_>>();
    let is_private_derivation = matches!(node, HdNodeValid::Private(_));
    if is_private_derivation && parsed[0] != "m" {
        return Err(format_error(
            HdNodeDerivationError::invalidPrivateDerivationPrefix,
            Some(&format!("Invalid path: \"{path}\".")),
        ));
    }
    if !is_private_derivation && parsed[0] != "M" {
        return Err(format_error(
            HdNodeDerivationError::invalidPublicDerivationPrefix,
            Some(&format!("Invalid path: \"{path}\".")),
        ));
    }
    if parsed.len() == 1 {
        return Ok(node.clone());
    }
    let relative_path = parsed[1..].join("/");
    derive_hd_path_relative(node, &relative_path, crypto)
}

/// Derive the HD private node from a HD public node, given any non-hardened
/// child private node.
///
/// This exploits the "non-hardened" BIP32 derivation algorithm. Because
/// non-hardened derivation only requires knowledge of the "chain code" (rather
/// than requiring knowledge of the parent private key) it's possible to
/// calculate the value by which the parent private key is "tweaked" to arrive
/// at the child private key. Since we have the child private key, we simply
/// subtract this "tweaked" amount to get back to the parent private key.
///
/// The BIP32 "hardened" derivation algorithm is designed to address this
/// weakness. Using hardened derivation, child private nodes can be shared
/// without risk of leaking the parent private node, but this comes at the
/// cost of public node derivation. Given only a parent public node, it is not
/// possible to derive hardened child public keys, so applications must choose
/// between support for HD public node derivation or support for sharing child
/// private nodes.
///
/// - `parent_public_node`: the parent HD public node for which to derive a
///   private node.
/// - `child_private_node`: any non-hardened child private node of the parent
///   node (only the `child_index` and `private_key` are used).
/// - `crypto`: an optional implementation of sha512.
pub fn crack_hd_private_node_from_hd_public_node_and_child_private_node(
    parent_public_node: &HdPublicNodeValid,
    child_private_node: &HdPrivateNodeValid,
    crypto: Option<&Sha512>,
) -> Result<HdPrivateNodeValid, String> {
    let sha512 = crypto.unwrap_or(&internal_sha512);
    if child_private_node.child_index >= HARDENED_INDEX_OFFSET {
        return Err(HdNodeCrackingError::cannotCrackHardenedDerivation.to_string());
    }
    let serialization = flatten_bin_array(&[
        parent_public_node.public_key.clone(),
        number_to_bin_uint32_be(child_private_node.child_index as u32),
    ]);
    let derivation = hmac_sha512(&parent_public_node.chain_code, &serialization, Some(sha512));
    const TWEAK_VALUE_LENGTH: usize = 32;
    let tweak_value = bin_to_big_int_uint256_be(&derivation[..TWEAK_VALUE_LENGTH]);
    let child_private_value = bin_to_big_int_uint256_be(&child_private_node.private_key);
    let secp256k1_order_n =
        BigInt::parse("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .expect("a valid bigint literal");
    let true_mod = |n: &BigInt, m: &BigInt| n.div_mod(m).1.add(m).div_mod(m).1;
    let parent_private_value = true_mod(&child_private_value.sub(&tweak_value), &secp256k1_order_n);
    let private_key = big_int_to_bin_uint256_be_clamped(&parent_private_value);
    Ok(HdPrivateNodeValid {
        chain_code: parent_public_node.chain_code.clone(),
        child_index: parent_public_node.child_index,
        depth: parent_public_node.depth,
        parent_fingerprint: parent_public_node.parent_fingerprint.clone(),
        parent_identifier: parent_public_node.parent_identifier.clone(),
        private_key,
    })
}
