use std::rc::Rc;

use crate::format::int32_unsigned_to_signed;
use crate::message::{Input, Output};
use crate::runtime::bigint::BigInt;
use crate::vm::{
    apply_error, encode_authentication_instructions, push_to_stack, push_to_stack_checked,
    push_to_stack_vm_number, use_one_vm_number, AuthenticationErrorCommon,
    AuthenticationProgramStateCommon, ConsensusCommon, Operation,
};

pub fn op_input_index(state: &mut AuthenticationProgramStateCommon) {
    let input_index = state.program.input_index;
    push_to_stack_vm_number(state, &BigInt::from_u64(input_index as u64));
}

pub fn create_op_active_bytecode(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        let start = usize::try_from(state.last_code_separator + 1).unwrap_or(0);
        let active_bytecode = encode_authentication_instructions(
            &state.instructions[start.min(state.instructions.len())..],
        );
        push_to_stack_checked(state, active_bytecode, Some(maximum_stack_item_length));
    })
}

pub fn op_active_bytecode(state: &mut AuthenticationProgramStateCommon) {
    create_op_active_bytecode(None)(state);
}

pub fn op_tx_version(state: &mut AuthenticationProgramStateCommon) {
    let version = int32_unsigned_to_signed(state.program.transaction.version);
    push_to_stack_vm_number(state, &BigInt::from_i64(version as i64));
}

pub fn op_tx_input_count(state: &mut AuthenticationProgramStateCommon) {
    let count = state.program.transaction.inputs.len();
    push_to_stack_vm_number(state, &BigInt::from_u64(count as u64));
}

pub fn op_tx_output_count(state: &mut AuthenticationProgramStateCommon) {
    let count = state.program.transaction.outputs.len();
    push_to_stack_vm_number(state, &BigInt::from_u64(count as u64));
}

pub fn op_tx_locktime(state: &mut AuthenticationProgramStateCommon) {
    let locktime = state.program.transaction.locktime;
    push_to_stack_vm_number(state, &BigInt::from_u64(locktime as u64));
}

/// Look up `items[Number(index)]` as JavaScript would (`undefined` for
/// negative, fractional, or out-of-range indexes).
fn index_into<'a, T>(items: &'a [T], index: &BigInt) -> Option<&'a T> {
    let index = index.to_number();
    if index < 0.0 || index.fract() != 0.0 {
        return None;
    }
    items.get(index as usize)
}

/// Pop a transaction UTXO index from the stack and provide the indicated
/// source output to `operation`.
pub fn use_transaction_utxo(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [&Output; 1]),
) {
    use_one_vm_number(
        state,
        |next_state, [index]| {
            let program = Rc::clone(&next_state.program);
            match index_into(&program.source_outputs, &index) {
                None => {
                    let details = format!(
                        "Transaction UTXO count: {}; requested index: {index}.",
                        program.source_outputs.len()
                    );
                    apply_error(
                        next_state,
                        AuthenticationErrorCommon::invalidTransactionUtxoIndex,
                        Some(&details),
                    );
                }
                Some(utxo) => operation(next_state, [utxo]),
            }
        },
        None,
        None,
    );
}

pub fn op_utxo_value(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_utxo(state, |next_state, [utxo]| {
        push_to_stack_vm_number(next_state, &BigInt::from_u64(utxo.value_satoshis));
    });
}

pub fn create_op_utxo_bytecode(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_transaction_utxo(state, |next_state, [utxo]| {
            push_to_stack_checked(
                next_state,
                utxo.locking_bytecode.clone(),
                Some(maximum_stack_item_length),
            );
        });
    })
}

pub fn op_utxo_bytecode(state: &mut AuthenticationProgramStateCommon) {
    create_op_utxo_bytecode(None)(state);
}

/// Pop a transaction input index from the stack and provide the indicated
/// input to `operation`.
pub fn use_transaction_input(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [&Input; 1]),
) {
    use_one_vm_number(
        state,
        |next_state, [index]| {
            let program = Rc::clone(&next_state.program);
            match index_into(&program.transaction.inputs, &index) {
                None => {
                    let details = format!(
                        "Transaction input count: {}; requested index: {index}.",
                        program.transaction.inputs.len()
                    );
                    apply_error(
                        next_state,
                        AuthenticationErrorCommon::invalidTransactionInputIndex,
                        Some(&details),
                    );
                }
                Some(input) => operation(next_state, [input]),
            }
        },
        None,
        None,
    );
}

pub fn op_outpoint_tx_hash(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_input(state, |next_state, [input]| {
        let mut outpoint_transaction_hash = input.outpoint_transaction_hash.clone();
        outpoint_transaction_hash.reverse();
        push_to_stack(next_state, vec![outpoint_transaction_hash], None);
    });
}

pub fn op_outpoint_index(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_input(state, |next_state, [input]| {
        push_to_stack_vm_number(next_state, &BigInt::from_u64(input.outpoint_index as u64));
    });
}

pub fn create_op_input_bytecode(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_transaction_input(state, |next_state, [input]| {
            push_to_stack_checked(
                next_state,
                input.unlocking_bytecode.clone(),
                Some(maximum_stack_item_length),
            );
        });
    })
}

pub fn op_input_bytecode(state: &mut AuthenticationProgramStateCommon) {
    create_op_input_bytecode(None)(state);
}

pub fn op_input_sequence_number(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_input(state, |next_state, [input]| {
        push_to_stack_vm_number(next_state, &BigInt::from_u64(input.sequence_number as u64));
    });
}

/// Pop a transaction output index from the stack and provide the indicated
/// output to `operation`.
pub fn use_transaction_output(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [&Output; 1]),
) {
    use_one_vm_number(
        state,
        |next_state, [index]| {
            let program = Rc::clone(&next_state.program);
            match index_into(&program.transaction.outputs, &index) {
                None => {
                    let details = format!(
                        "Transaction output count: {}; requested index: {index}.",
                        program.transaction.outputs.len()
                    );
                    apply_error(
                        next_state,
                        AuthenticationErrorCommon::invalidTransactionOutputIndex,
                        Some(&details),
                    );
                }
                Some(output) => operation(next_state, [output]),
            }
        },
        None,
        None,
    );
}

pub fn op_output_value(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_output(state, |next_state, [output]| {
        push_to_stack_vm_number(next_state, &BigInt::from_u64(output.value_satoshis));
    });
}

pub fn create_op_output_bytecode(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_transaction_output(state, |next_state, [output]| {
            push_to_stack_checked(
                next_state,
                output.locking_bytecode.clone(),
                Some(maximum_stack_item_length),
            );
        });
    })
}

pub fn op_output_bytecode(state: &mut AuthenticationProgramStateCommon) {
    create_op_output_bytecode(None)(state);
}
