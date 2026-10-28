use crate::vm::ConsensusBch2023;

/// Consensus setting overrides for the `BCH_2025_05` instruction set.
pub struct ConsensusXec2020Overrides;

#[allow(non_upper_case_globals)]
impl ConsensusXec2020Overrides {
    pub const maximumVmNumberByteLength: usize = 4;
}

/// Consensus settings for the `XEC_2020_11` instruction set.
pub const ConsensusXec: ConsensusBch2023 = ConsensusBch2023 {
    maximum_vm_number_byte_length: ConsensusXec2020Overrides::maximumVmNumberByteLength,
    ..ConsensusBch2023
};
