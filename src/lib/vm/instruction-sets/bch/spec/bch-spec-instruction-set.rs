use std::rc::Rc;

use crate::crypto::{Ripemd160, Secp256k1, Sha1, Sha256};
use crate::vm::instruction_sets::bch::bch_spec::bch_spec_consensus::ConsensusBchSpec;
use crate::vm::instruction_sets::bch::bch_spec::bch_spec_eval::op_eval;
use crate::vm::instruction_sets::bch::bch_spec::bch_spec_pow::create_op_pow;
use crate::vm::{
    conditionally_evaluate, create_instruction_set_bch_2026, increment_operation_count,
    AuthenticationProgramBch, AuthenticationProgramStateBchSpec, ConsensusBch2023, InstructionSet,
    Operation, OpcodesBchSpec, ResolvedTransactionBch,
};

/// create an instance of the `BCH_SPEC` virtual machine instruction set, an
/// informal, speculative instruction set that implements a variety of future
/// Bitcoin Cash Improvement Proposals (CHIPs).
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
///
/// The remaining parameters (libauth's second, object parameter) default to
/// `ConsensusBchSpec` and the internal crypto instances.
pub fn create_instruction_set_bch_spec(
    standard: Option<bool>,
    consensus: Option<ConsensusBch2023>,
    ripemd160: Option<Ripemd160>,
    secp256k1: Option<Secp256k1>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
) -> InstructionSet<ResolvedTransactionBch, AuthenticationProgramBch, AuthenticationProgramStateBchSpec> {
    let consensus = consensus.unwrap_or(ConsensusBchSpec);
    let instruction_set = create_instruction_set_bch_2026(
        standard,
        Some(consensus),
        ripemd160,
        secp256k1,
        sha1,
        sha256,
    );
    let stack_size = |stack: &[Vec<u8>]| stack.iter().map(Vec::len).sum::<usize>();
    let previous_every = instruction_set.every.clone();
    let every = Rc::new(move |state: &mut AuthenticationProgramStateBchSpec| {
        if let Some(previous_every) = &previous_every {
            previous_every(state);
        }
        let memory_usage = (stack_size(&state.stack) + stack_size(&state.alternate_stack)) as f64;
        // libauth never initializes `maxMemoryUsage` (it remains `undefined`,
        // and `undefined < memoryUsage` is `false`).
        if let Some(max_memory_usage) = state.metrics.max_memory_usage {
            if max_memory_usage < memory_usage {
                state.metrics.max_memory_usage = Some(memory_usage);
            }
        }
    });
    let mut operations = instruction_set.operations.clone();
    operations.extend([
        (OpcodesBchSpec::OP_EVAL, Rc::new(op_eval) as Operation<AuthenticationProgramStateBchSpec>),
        (
            OpcodesBchSpec::OP_POW,
            increment_operation_count(conditionally_evaluate(create_op_pow(Some(
                consensus.maximum_vm_number_byte_length,
            )))),
        ),
    ]);
    InstructionSet {
        every: Some(every),
        operations,
        ..instruction_set
    }
}
