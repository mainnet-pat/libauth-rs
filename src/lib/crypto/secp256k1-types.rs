use super::secp256k1::WrappedSecp256k1Wasm;
use crate::runtime::webassembly::PerThread;

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
/// `compressPublicKey`, ...) are this type's methods; they are implemented in
/// `secp256k1.rs`. Each thread that uses a `Secp256k1` runs its own instance of
/// the WebAssembly module (see `PerThread`), as each JavaScript agent would.
#[derive(Clone, Debug)]
pub struct Secp256k1 {
    pub(crate) wrapped: PerThread<WrappedSecp256k1Wasm>,
}
