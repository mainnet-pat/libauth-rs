use crate::vm::{ConsensusBch2023, ConsensusBch2025};

/// Consensus setting overrides for the `BCH_SPEC` instruction set.
pub struct ConsensusBch2026Overrides;

#[allow(non_upper_case_globals)]
impl ConsensusBch2026Overrides {
    pub const baseInstructionCost: f64 = 100.0;
    pub const maximumFunctionIdentifierLength: usize = 7;
    /// A.K.A. `MAX_MEMORY_SLOTS`
    pub const maximumMemorySlots: usize = 1000;
    pub const maximumStandardLockingBytecodeLength: i64 = 201;
    pub const maximumStandardUnlockingBytecodeLength: usize = 10000;
    pub const maximumTokenCommitmentLength: usize = 128;
}

/// Consensus settings for the `BCH_SPEC` instruction set.
pub const ConsensusBch2026: ConsensusBch2023 = ConsensusBch2023 {
    base_instruction_cost: ConsensusBch2026Overrides::baseInstructionCost,
    maximum_function_identifier_length: Some(ConsensusBch2026Overrides::maximumFunctionIdentifierLength),
    maximum_memory_slots: Some(ConsensusBch2026Overrides::maximumMemorySlots),
    maximum_standard_locking_bytecode_length: ConsensusBch2026Overrides::maximumStandardLockingBytecodeLength,
    maximum_standard_unlocking_bytecode_length: ConsensusBch2026Overrides::maximumStandardUnlockingBytecodeLength,
    maximum_token_commitment_length: ConsensusBch2026Overrides::maximumTokenCommitmentLength,
    ..ConsensusBch2025
};
