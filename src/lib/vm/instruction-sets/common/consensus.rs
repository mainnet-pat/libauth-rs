use crate::vm::SigningSerializationTypeBch;

/// Consensus settings for the `BCH_2023_05` instruction set.
pub struct ConsensusCommon;

#[allow(non_upper_case_globals)]
impl ConsensusCommon {
    /// A.K.A. `MAX_SCRIPT_SIZE`
    pub const maximumBytecodeLength: usize = 10000;
    pub const maximumControlStackDepth: usize = 100;
    /// A.K.A. `MAX_OP_RETURN_RELAY`, `nMaxDatacarrierBytes`
    pub const maximumDataCarrierBytes: usize = 223;
    /// A.K.A. `MAX_OPS_PER_SCRIPT`
    pub const maximumOperationCount: usize = 201;
    /// A.K.A. `MAX_STACK_SIZE`
    pub const maximumStackDepth: usize = 1000;
    /// A.K.A. `MAX_SCRIPT_ELEMENT_SIZE`
    pub const maximumStackItemLength: usize = 520;
    /// A.K.A. `MAX_STANDARD_VERSION`
    pub const maximumStandardVersion: usize = 2;
    /// A.K.A. `MAX_TX_IN_SCRIPT_SIG_SIZE`
    pub const maximumStandardUnlockingBytecodeLength: usize = 1650;
    /// A.K.A. `MIN_TX_SIZE`
    pub const minimumTransactionSize: usize = 100;
    /// A.K.A. `MAX_STANDARD_TX_SIZE`
    pub const maximumStandardTransactionSize: usize = 100_000;
    /// A.K.A. `MAX_TX_SIZE`
    pub const maximumTransactionSize: usize = 1_000_000;
    /// A.K.A. `MAXIMUM_ELEMENT_SIZE_64_BIT`
    pub const maximumVmNumberByteLength: usize = 8;
    pub const minVmNumber: &'static str = "-9223372036854775807";
    pub const maxVmNumber: &'static str = "9223372036854775807";
    pub const schnorrSignatureLength: usize = 64;
}

/// The signing serialization types which are valid in all BCH instruction sets.
pub const SigningSerializationTypesCommon: &[u8] = &[
    SigningSerializationTypeBch::allOutputs,
    SigningSerializationTypeBch::allOutputsSingleInput,
    SigningSerializationTypeBch::correspondingOutput,
    SigningSerializationTypeBch::correspondingOutputSingleInput,
    SigningSerializationTypeBch::noOutputs,
    SigningSerializationTypeBch::noOutputsSingleInput,
];

/// The signing serialization types which are valid in the BCH instruction sets
/// following the 2023 upgrade (adding the `SIGHASH_UTXOS` types).
pub const SigningSerializationTypesBch: &[u8] = &[
    SigningSerializationTypeBch::allOutputs,
    SigningSerializationTypeBch::allOutputsSingleInput,
    SigningSerializationTypeBch::correspondingOutput,
    SigningSerializationTypeBch::correspondingOutputSingleInput,
    SigningSerializationTypeBch::noOutputs,
    SigningSerializationTypeBch::noOutputsSingleInput,
    SigningSerializationTypeBch::allOutputsAllUtxos,
    SigningSerializationTypeBch::correspondingOutputAllUtxos,
    SigningSerializationTypeBch::noOutputsAllUtxos,
];
