use std::rc::Rc;

use crate::runtime::bigint::BigInt;
use crate::vm::{
    apply_error, big_int_to_vm_number, vm_number_to_big_int, AuthenticationErrorCommon,
    AuthenticationProgramStateCommon, AuthenticationProgramStateControlStackItem, ConsensusCommon,
    InstructionSetOperationMapping, Operation,
};

/// Wrap an operation so that the program state's `operationCount` is
/// incremented after the operation.
pub fn increment_operation_count(operation: Operation) -> Operation {
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        operation(state);
        state.operation_count += 1;
    })
}

/// Test whether execution is active: no `false` values are present in the
/// control stack (no unexecuted `OP_IF`/`OP_NOTIF` branch is open).
pub fn execution_is_active(state: &AuthenticationProgramStateCommon) -> bool {
    state
        .control_stack
        .iter()
        .all(|item| *item != AuthenticationProgramStateControlStackItem::Boolean(false))
}

/// Conditionally evaluate an operation given the program's control stack
/// state: the operation is skipped within unexecuted branches.
pub fn conditionally_evaluate(operation: Operation) -> Operation {
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        if execution_is_active(state) {
            operation(state);
        }
    })
}

/// Map a function over each operation in an {@link InstructionSet.operations}
/// object, assigning the result to the same `opcode` in the resulting object.
///
/// The `combinators` are applied in order: the first combinator wraps the
/// original operation, and each following combinator wraps the result.
pub fn map_over_operations<State>(
    combinators: &[&dyn Fn(Operation<State>) -> Operation<State>],
    operation_map: InstructionSetOperationMapping<State>,
) -> InstructionSetOperationMapping<State> {
    operation_map
        .into_iter()
        .map(|(opcode, operation)| {
            (
                opcode,
                combinators
                    .iter()
                    .fold(operation, |op, combinator| combinator(op)),
            )
        })
        .collect()
}

/// Pop one stack item off of `state.stack` and provide that item to
/// `operation`.
pub fn use_one_stack_item(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [Vec<u8>; 1]),
) {
    match state.stack.pop() {
        None => apply_error(state, AuthenticationErrorCommon::emptyStack, None),
        Some(item) => operation(state, [item]),
    }
}

/// Pop two stack items off of `state.stack` and provide them to `operation`
/// (`[valueTop, valueTwo]`, the item which was deeper in the stack first).
pub fn use_two_stack_items(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [Vec<u8>; 2]),
) {
    use_one_stack_item(state, |next_state, [value_two]| {
        use_one_stack_item(next_state, |last_state, [value_top]| {
            operation(last_state, [value_top, value_two]);
        });
    });
}

/// Pop three stack items off of `state.stack` and provide them to
/// `operation`.
pub fn use_three_stack_items(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [Vec<u8>; 3]),
) {
    use_one_stack_item(state, |next_state, [value_three]| {
        use_two_stack_items(next_state, |last_state, [value_top, value_two]| {
            operation(last_state, [value_top, value_two, value_three]);
        });
    });
}

/// Pop four stack items off of `state.stack` and provide them to
/// `operation`.
pub fn use_four_stack_items(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [Vec<u8>; 4]),
) {
    use_two_stack_items(state, |next_state, [value_three, value_four]| {
        use_two_stack_items(next_state, |last_state, [value_top, value_two]| {
            operation(last_state, [value_top, value_two, value_three, value_four]);
        });
    });
}

/// Pop six stack items off of `state.stack` and provide them to `operation`.
pub fn use_six_stack_items(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [Vec<u8>; 6]),
) {
    use_four_stack_items(
        state,
        |next_state, [value_three, value_four, value_five, value_six]| {
            use_two_stack_items(next_state, |last_state, [value_top, value_two]| {
                operation(
                    last_state,
                    [value_top, value_two, value_three, value_four, value_five, value_six],
                );
            });
        },
    );
}

/// Pop one VM Number off of `state.stack` and provide it to `operation`,
/// applying an error if the stack item is not a valid VM Number.
///
/// `maximum_vm_number_byte_length` defaults to `0` (no maximum) and
/// `require_minimal_encoding` defaults to `true`.
pub fn use_one_vm_number(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [BigInt; 1]),
    maximum_vm_number_byte_length: Option<usize>,
    require_minimal_encoding: Option<bool>,
) {
    use_one_stack_item(state, |next_state, [item]| {
        match vm_number_to_big_int(
            &item,
            Some(maximum_vm_number_byte_length.unwrap_or(0)),
            Some(require_minimal_encoding.unwrap_or(true)),
        ) {
            Err(value) => apply_error(
                next_state,
                AuthenticationErrorCommon::invalidVmNumber,
                Some(&value),
            ),
            Ok(value) => operation(next_state, [value]),
        }
    });
}

/// Pop two VM Numbers off of `state.stack` and provide them to `operation`
/// (`[firstValue, secondValue]`, the number which was deeper in the stack
/// first).
pub fn use_two_vm_numbers(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [BigInt; 2]),
    maximum_vm_number_byte_length: Option<usize>,
    require_minimal_encoding: Option<bool>,
) {
    use_one_vm_number(
        state,
        |next_state, [second_value]| {
            use_one_vm_number(
                next_state,
                |last_state, [first_value]| operation(last_state, [first_value, second_value]),
                maximum_vm_number_byte_length,
                require_minimal_encoding,
            );
        },
        maximum_vm_number_byte_length,
        require_minimal_encoding,
    );
}

/// Pop three VM Numbers off of `state.stack` and provide them to
/// `operation`.
pub fn use_three_vm_numbers(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [BigInt; 3]),
    maximum_vm_number_byte_length: Option<usize>,
    require_minimal_encoding: Option<bool>,
) {
    use_two_vm_numbers(
        state,
        |next_state, [second_value, third_value]| {
            use_one_vm_number(
                next_state,
                |last_state, [first_value]| {
                    operation(last_state, [first_value, second_value, third_value]);
                },
                maximum_vm_number_byte_length,
                require_minimal_encoding,
            );
        },
        maximum_vm_number_byte_length,
        require_minimal_encoding,
    );
}

/// Push items to the stack, incrementing the `stackPushedBytes` metric by
/// `pushed_bytes` (default: the total length of `data`).
pub fn push_to_stack(
    state: &mut AuthenticationProgramStateCommon,
    data: Vec<Vec<u8>>,
    pushed_bytes: Option<usize>,
) {
    let pushed_bytes = pushed_bytes.unwrap_or_else(|| data.iter().map(Vec::len).sum());
    state.stack.extend(data);
    state.metrics.stack_pushed_bytes += pushed_bytes as f64;
}

/// Push an item to the stack after verifying that its length does not exceed
/// `maximum_stack_item_length` (default: `ConsensusCommon.maximumStackItemLength`).
pub fn push_to_stack_checked(
    state: &mut AuthenticationProgramStateCommon,
    item: Vec<u8>,
    maximum_stack_item_length: Option<usize>,
) {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    if item.len() > maximum_stack_item_length {
        apply_error(
            state,
            AuthenticationErrorCommon::exceededMaximumStackItemLength,
            Some(&format!(
                "Maximum stack item length: {maximum_stack_item_length}; item length: {} bytes.",
                item.len()
            )),
        );
        return;
    }
    state.metrics.stack_pushed_bytes += item.len() as f64;
    state.stack.push(item);
}

/// Push a VM Number to the stack.
pub fn push_to_stack_vm_number(state: &mut AuthenticationProgramStateCommon, vm_number: &BigInt) {
    push_to_stack(state, vec![big_int_to_vm_number(vm_number)], None);
}

/// Push a VM Number to the stack after verifying that its encoded length does
/// not exceed `maximum_vm_number_byte_length` (default:
/// `ConsensusCommon.maximumVmNumberByteLength`), adding the encoded length to
/// the `arithmeticCost` metric if `has_encoding_cost` (default: `true`).
pub fn push_to_stack_vm_number_checked(
    state: &mut AuthenticationProgramStateCommon,
    vm_number: &BigInt,
    maximum_vm_number_byte_length: Option<usize>,
    has_encoding_cost: Option<bool>,
) {
    let maximum_vm_number_byte_length =
        maximum_vm_number_byte_length.unwrap_or(ConsensusCommon::maximumVmNumberByteLength);
    let has_encoding_cost = has_encoding_cost.unwrap_or(true);
    let encoded = big_int_to_vm_number(vm_number);
    if encoded.len() > maximum_vm_number_byte_length {
        apply_error(
            state,
            AuthenticationErrorCommon::overflowsVmNumberRange,
            Some(&format!(
                "Maximum VM number byte length: {maximum_vm_number_byte_length}; encoded number length: {}.",
                encoded.len()
            )),
        );
        return;
    }
    state.metrics.arithmetic_cost += if has_encoding_cost { encoded.len() as f64 } else { 0.0 };
    push_to_stack(state, vec![encoded], None);
}

/// Return the provided operations combined into a single operation: the
/// second operation is applied to the result of the first.
pub fn combine_operations<State: 'static>(
    first_operation: Operation<State>,
    second_operation: Operation<State>,
) -> Operation<State> {
    Rc::new(move |state: &mut State| {
        first_operation(state);
        second_operation(state);
    })
}

/// Given a message length, compute and return the number of hash digest
/// iterations required (by SHA-256, RIPEMD-160, or SHA-1).
pub fn length_to_hash_digest_iteration_count(message_length: usize) -> usize {
    1 + (message_length + 8) / 64
}

/// Increment the `hashDigestIterations` metric for a hashing operation over a
/// message of `message_length` bytes (plus one iteration if
/// `result_is_hashed`), then apply `operation`.
pub fn increment_hash_digest_iterations(
    state: &mut AuthenticationProgramStateCommon,
    message_length: usize,
    result_is_hashed: bool,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon),
) {
    let new_iterations = length_to_hash_digest_iteration_count(message_length);
    let second_round = if result_is_hashed { 1 } else { 0 };
    let required_total_iterations =
        state.metrics.hash_digest_iterations + (new_iterations + second_round) as f64;
    state.metrics.hash_digest_iterations = required_total_iterations;
    operation(state);
}
