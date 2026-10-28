/// The recovery identifier of a recoverable signature: `0`, `1`, `2`, or `3`.
pub type RecoveryId = u8;

/// A compact ECDSA signature and the recovery identifier required to recover
/// the public key from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// The recovery identifier.
    pub recovery_id: RecoveryId,
    /// The compact signature.
    pub signature: Vec<u8>,
}

/// An object that exposes a set of purely-functional Secp256k1 methods.
///
/// The members of libauth's `Secp256k1` object (`addTweakPrivateKey`,
/// `compressPublicKey`, ...) are this type's methods; they are implemented
/// natively in `secp256k1.rs`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Secp256k1;
