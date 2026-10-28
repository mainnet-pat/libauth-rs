use crate::vm::instruction_sets::bch::bch_2026::bch_2026_consensus::ConsensusBch2026;
use crate::vm::ConsensusBch2023;

/// Consensus setting overrides for the `BCH_SPEC` instruction set.
pub struct ConsensusBchSpecOverrides;

#[allow(non_upper_case_globals)]
impl ConsensusBchSpecOverrides {
    /// Because BCH_SPEC is used to compile CashAssembly internal evaluations,
    /// setting a per-input overhead value equal to the current (BCH_2025)
    /// `maximumBytecodeLength` ensures that any reasonable internal evaluation can
    /// be compiled without exceeding operation cost limits.
    pub const densityControlBaseLength: usize = 10_000;
    pub const maximumBytecodeLength: usize = 100_000;
    pub const maximumStackItemLength: usize = 100_000;
    pub const maximumStandardUnlockingBytecodeLength: usize = 100_000;
    pub const maximumVmNumberByteLength: usize = 100_000;
}

/// Consensus settings for the `BCH_SPEC` instruction set.
pub const ConsensusBchSpec: ConsensusBch2023 = ConsensusBch2023 {
    density_control_base_length: ConsensusBchSpecOverrides::densityControlBaseLength,
    maximum_bytecode_length: ConsensusBchSpecOverrides::maximumBytecodeLength,
    maximum_stack_item_length: ConsensusBchSpecOverrides::maximumStackItemLength,
    maximum_standard_unlocking_bytecode_length: ConsensusBchSpecOverrides::maximumStandardUnlockingBytecodeLength,
    maximum_vm_number_byte_length: ConsensusBchSpecOverrides::maximumVmNumberByteLength,
    ..ConsensusBch2026
};
