use std::sync::LazyLock;

use crate::runtime::bigint::BigInt;
use crate::vm::{AuthenticationProgramStateMetrics, ConsensusBch2023};

/// Consensus setting overrides for the `BCH_2025_05` instruction set.
pub struct ConsensusBch2025Overrides;

#[allow(non_upper_case_globals)]
impl ConsensusBch2025Overrides {
    pub const maximumStackItemLength: usize = 10_000;
    pub const maximumVmNumberByteLength: usize = 10_000;
}

/// The range of VM Numbers in the `BCH_2025_05` instruction set (libauth's
/// `{ maxVmNumber, minVmNumber }`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigIntRange {
    pub max_vm_number: BigInt,
    pub min_vm_number: BigInt,
}

/// The VM Number range of the `BCH_2025_05` instruction set.
///
/// libauth computes `maxVmNumber` as `base ** (maxLength * bytes) - 1n / signed`,
/// in which `1n / signed` is `0n`.
pub static bigIntRange: LazyLock<BigIntRange> = LazyLock::new(|| {
    let base = BigInt::from_u64(2);
    let max_length = ConsensusBch2025Overrides::maximumVmNumberByteLength as u32;
    let bytes = 8;
    let signed = BigInt::from_u64(2);
    let (one_over_signed, _) = BigInt::from_u64(1).div_mod(&signed);
    let max_vm_number = base.pow(max_length * bytes).sub(&one_over_signed);
    BigIntRange {
        min_vm_number: max_vm_number.negate(),
        max_vm_number,
    }
});

/// Consensus settings for the `BCH_2025_05` instruction set.
pub const ConsensusBch2025: ConsensusBch2023 = ConsensusBch2023 {
    maximum_stack_item_length: ConsensusBch2025Overrides::maximumStackItemLength,
    maximum_vm_number_byte_length: ConsensusBch2025Overrides::maximumVmNumberByteLength,
    ..ConsensusBch2023
};

/// Measure the operation cost of the provided metrics (by default using the
/// standard costs of `ConsensusBch2025`).
pub fn measure_operation_cost(
    metrics: &AuthenticationProgramStateMetrics,
    base_instruction_cost: Option<f64>,
    hash_digest_iteration_cost: Option<f64>,
    signature_check_cost: Option<f64>,
) -> f64 {
    let base_instruction_cost = base_instruction_cost.unwrap_or(ConsensusBch2025.base_instruction_cost);
    let hash_digest_iteration_cost =
        hash_digest_iteration_cost.unwrap_or(ConsensusBch2025.hash_digest_iteration_cost_standard);
    let signature_check_cost = signature_check_cost.unwrap_or(ConsensusBch2025.signature_check_cost);
    metrics.evaluated_instruction_count * base_instruction_cost
        + metrics.signature_check_count * signature_check_cost
        + metrics.hash_digest_iterations * hash_digest_iteration_cost
        + metrics.arithmetic_cost
        + metrics.stack_pushed_bytes
}
