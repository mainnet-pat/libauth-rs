use std::collections::BTreeMap;
use std::rc::Rc;

use crate::crypto::{Ripemd160, Secp256k1, Sha1, Sha256};
use crate::vm::{
    apply_error, conditionally_evaluate, create_instruction_set_bch_2023,
    increment_operation_count, map_over_operations, measure_operation_cost, op_check_multi_sig,
    op_check_multi_sig_verify, AuthenticationErrorBch2025, AuthenticationProgramBch,
    AuthenticationProgramStateBch2025, ConsensusBch2023, ConsensusBch2025, InstructionSet,
    OpcodesBch2023, ResolvedTransactionBch,
};

/// Initialize a virtual machine using the `BCH_2025_05` instruction set.
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
///
/// The remaining parameters (libauth's second, object parameter) default to
/// `ConsensusBch2025` and the internal crypto instances.
pub fn create_instruction_set_bch_2025(
    standard: Option<bool>,
    consensus: Option<ConsensusBch2023>,
    ripemd160: Option<Ripemd160>,
    secp256k1: Option<Secp256k1>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
) -> InstructionSet<ResolvedTransactionBch, AuthenticationProgramBch, AuthenticationProgramStateBch2025> {
    let standard = standard.unwrap_or(true);
    let consensus = consensus.unwrap_or(ConsensusBch2025);
    let secp256k1 = secp256k1.unwrap_or_else(|| crate::crypto::secp256k1.clone());
    let sha256 = sha256.unwrap_or_else(|| crate::crypto::sha256.clone());
    let instruction_set = create_instruction_set_bch_2023(
        Some(standard),
        Some(consensus),
        ripemd160,
        Some(secp256k1.clone()),
        sha1,
        Some(sha256.clone()),
    );
    let every = Rc::new(move |state: &mut AuthenticationProgramStateBch2025| {
        state.metrics.operation_cost = measure_operation_cost(
            &state.metrics,
            Some(consensus.base_instruction_cost),
            Some(if standard {
                consensus.hash_digest_iteration_cost_standard
            } else {
                consensus.hash_digest_iteration_cost_consensus
            }),
            Some(consensus.signature_check_cost),
        );
        if state.metrics.operation_cost > state.metrics.maximum_operation_cost {
            let details = format!(
                "Maximum operation cost: {} (density control length: {}); operation cost following operation: {}.",
                state.metrics.maximum_operation_cost,
                state.metrics.density_control_length,
                state.metrics.operation_cost
            );
            apply_error(state, AuthenticationErrorBch2025::excessiveOperationCost, Some(&details));
            return;
        }
        if state.metrics.hash_digest_iterations > state.metrics.maximum_hash_digest_iterations {
            let details = format!(
                "Maximum hash digest iterations: {} (density control length: {}); hash digest iterations following operation: {}.",
                state.metrics.maximum_hash_digest_iterations,
                state.metrics.density_control_length,
                state.metrics.hash_digest_iterations
            );
            apply_error(state, AuthenticationErrorBch2025::excessiveHashing, Some(&details));
            return;
        }
        if state.stack.len() + state.alternate_stack.len() > consensus.maximum_stack_depth {
            let details = format!("Maximum stack depth: {} items.", consensus.maximum_stack_depth);
            apply_error(state, AuthenticationErrorBch2025::exceededMaximumStackDepth, Some(&details));
            return;
        }
        if state.control_stack.len() > consensus.maximum_control_stack_depth {
            let details = format!(
                "Maximum control stack depth: {}.",
                consensus.maximum_control_stack_depth
            );
            apply_error(
                state,
                AuthenticationErrorBch2025::exceededMaximumControlStackDepth,
                Some(&details),
            );
            return;
        }
        if standard && state.metrics.signature_check_count > state.metrics.maximum_signature_check_count {
            let details = format!(
                "Maximum signature check count: {}; signature check count following operation: {}.",
                state.metrics.maximum_signature_check_count, state.metrics.signature_check_count
            );
            apply_error(
                state,
                AuthenticationErrorBch2025::exceededMaximumSignatureCheckCount,
                Some(&details),
            );
        }
    });
    let mut operations = instruction_set.operations.clone();
    operations.extend(map_over_operations(
        &[&increment_operation_count, &conditionally_evaluate],
        BTreeMap::from([
            (
                OpcodesBch2023::OP_CHECKMULTISIG,
                op_check_multi_sig(Some(secp256k1.clone()), Some(sha256.clone()), Some(false)),
            ),
            (
                OpcodesBch2023::OP_CHECKMULTISIGVERIFY,
                op_check_multi_sig_verify(false, secp256k1, sha256),
            ),
        ]),
    ));
    InstructionSet {
        every: Some(every),
        operations,
        ..instruction_set
    }
}
