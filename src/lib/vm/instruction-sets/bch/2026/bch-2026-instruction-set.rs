use std::rc::Rc;

use crate::crypto::{Ripemd160, Secp256k1, Sha1, Sha256};
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_bitwise::{
    create_op_l_shift_num, create_op_r_shift_num, op_invert, op_l_shift_bin, op_r_shift_bin,
};
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_consensus::ConsensusBch2026;
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_errors::AuthenticationErrorBch2026;
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_functions::{create_op_define, op_invoke};
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_loops::{op_begin, op_until};
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_opcodes::OpcodesBch2026;
use crate::vm::{
    apply_error, conditionally_evaluate, create_instruction_set_bch_2025, AuthenticationProgramBch,
    AuthenticationProgramStateBch2026, AuthenticationProgramStateControlStackItem, ConsensusBch2023,
    InstructionSet, Operation, ResolvedTransactionBch,
};

/// * Initialize a virtual machine using the `BCH_2026_05` instruction set.
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
///
/// The remaining parameters (libauth's second, object parameter) default to
/// `ConsensusBch2026` and the internal crypto instances.
pub fn create_instruction_set_bch_2026(
    standard: Option<bool>,
    consensus: Option<ConsensusBch2023>,
    ripemd160: Option<Ripemd160>,
    secp256k1: Option<Secp256k1>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
) -> InstructionSet<ResolvedTransactionBch, AuthenticationProgramBch, AuthenticationProgramStateBch2026> {
    let consensus = consensus.unwrap_or(ConsensusBch2026);
    let instruction_set = create_instruction_set_bch_2025(
        standard,
        Some(consensus),
        ripemd160,
        secp256k1,
        sha1,
        sha256,
    );
    let r#continue = Rc::new(|state: &mut AuthenticationProgramStateBch2026| {
        if state.error.is_some() {
            return false;
        }
        while state.ip >= state.instructions.len() as isize {
            let Some(AuthenticationProgramStateControlStackItem::Frame(_)) = state.control_stack.last() else {
                break;
            };
            let Some(AuthenticationProgramStateControlStackItem::Frame(frame)) = state.control_stack.pop() else {
                unreachable!("the top of the control stack is a frame");
            };
            state.ip = frame.ip;
            state.instructions = frame.instructions;
        }
        state.ip < state.instructions.len() as isize
    });
    let previous_every = instruction_set
        .every
        .clone()
        .expect("the BCH_2025_05 instruction set defines every");
    let every = Rc::new(move |state: &mut AuthenticationProgramStateBch2026| {
        previous_every(state);
        if let Some(maximum_memory_slots) = consensus.maximum_memory_slots {
            if state.stack.len() + state.alternate_stack.len() + state.function_count > maximum_memory_slots {
                let details = format!("Maximum memory slots: {maximum_memory_slots}.");
                apply_error(
                    state,
                    AuthenticationErrorBch2026::exceededMaximumMemorySlots,
                    Some(&details),
                );
            }
        }
    });
    let op = |operation: fn(&mut AuthenticationProgramStateBch2026)| -> Operation { Rc::new(operation) };
    let mut operations = instruction_set.operations.clone();
    operations.extend([
        (OpcodesBch2026::OP_BEGIN, op(op_begin)),
        (OpcodesBch2026::OP_UNTIL, op(op_until)),
        (OpcodesBch2026::OP_INVERT, conditionally_evaluate(op(op_invert))),
        (
            OpcodesBch2026::OP_DEFINE,
            conditionally_evaluate(create_op_define(consensus.maximum_function_identifier_length)),
        ),
        (OpcodesBch2026::OP_INVOKE, conditionally_evaluate(op(op_invoke))),
        (
            OpcodesBch2026::OP_LSHIFTNUM,
            conditionally_evaluate(create_op_l_shift_num(Some(consensus.maximum_stack_item_length))),
        ),
        (
            OpcodesBch2026::OP_RSHIFTNUM,
            conditionally_evaluate(create_op_r_shift_num(Some(consensus.maximum_stack_item_length))),
        ),
        (OpcodesBch2026::OP_LSHIFTBIN, conditionally_evaluate(op(op_l_shift_bin))),
        (OpcodesBch2026::OP_RSHIFTBIN, conditionally_evaluate(op(op_r_shift_bin))),
    ]);
    InstructionSet {
        r#continue,
        every: Some(every),
        operations,
        ..instruction_set
    }
}
