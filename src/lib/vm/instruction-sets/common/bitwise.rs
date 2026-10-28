use std::rc::Rc;

use crate::format::bins_are_equal;
use crate::vm::{
    apply_error, boolean_to_vm_number, op_verify, push_to_stack, use_two_stack_items,
    AuthenticationErrorCommon, AuthenticationProgramStateCommon, Operation,
};

pub fn op_equal(state: &mut AuthenticationProgramStateCommon) {
    use_two_stack_items(state, |next_state, [element1, element2]| {
        push_to_stack(
            next_state,
            vec![boolean_to_vm_number(bins_are_equal(&element1, &element2))],
            None,
        );
    });
}

/// `combineOperations(opEqual, opVerify)`
pub fn op_equal_verify(state: &mut AuthenticationProgramStateCommon) {
    op_equal(state);
    op_verify(state);
}

fn apply_bitwise_operation(
    state: &mut AuthenticationProgramStateCommon,
    combine: impl FnOnce(&[u8], &[u8]) -> Vec<u8>,
) {
    use_two_stack_items(state, |next_state, [a, b]| {
        if a.len() == b.len() {
            push_to_stack(next_state, vec![combine(&a, &b)], None);
        } else {
            let details = format!(
                "First item length: {} bytes. Second item length: {} bytes.",
                a.len(),
                b.len()
            );
            apply_error(
                next_state,
                AuthenticationErrorCommon::mismatchedBitwiseOperandLength,
                Some(&details),
            );
        }
    });
}

/// Create a bitwise operation from a function combining two equal-length
/// stack items.
pub fn bitwise_operation(combine: fn(&[u8], &[u8]) -> Vec<u8>) -> Operation {
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        apply_bitwise_operation(state, combine);
    })
}

pub fn op_and(state: &mut AuthenticationProgramStateCommon) {
    apply_bitwise_operation(state, |a, b| a.iter().zip(b).map(|(v, w)| v & w).collect());
}

pub fn op_or(state: &mut AuthenticationProgramStateCommon) {
    apply_bitwise_operation(state, |a, b| a.iter().zip(b).map(|(v, w)| v | w).collect());
}

pub fn op_xor(state: &mut AuthenticationProgramStateCommon) {
    apply_bitwise_operation(state, |a, b| a.iter().zip(b).map(|(v, w)| v ^ w).collect());
}
