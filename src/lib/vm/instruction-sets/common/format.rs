use std::rc::Rc;

use crate::format::flatten_bin_array;
use crate::runtime::number::number_to_string;
use crate::vm::{
    apply_error, big_int_to_vm_number, push_to_stack, push_to_stack_checked, use_one_stack_item,
    use_one_vm_number, use_two_stack_items, AuthenticationErrorCommon,
    AuthenticationProgramStateCommon, ConsensusCommon, Operation,
};

pub fn create_op_cat(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_two_stack_items(state, |next_state, [a, b]| {
            push_to_stack_checked(
                next_state,
                flatten_bin_array(&[a, b]),
                Some(maximum_stack_item_length),
            );
        });
    })
}

pub fn op_cat(state: &mut AuthenticationProgramStateCommon) {
    create_op_cat(None)(state);
}

pub fn op_split(state: &mut AuthenticationProgramStateCommon) {
    use_one_vm_number(
        state,
        |next_state, [value]| {
            let index = value.to_number();
            use_one_stack_item(next_state, |final_state, [item]| {
                if index < 0.0 || index > item.len() as f64 {
                    let details = format!(
                        "stack item length: {}; requested split index: {}.",
                        item.len(),
                        number_to_string(index)
                    );
                    apply_error(final_state, AuthenticationErrorCommon::invalidSplitIndex, Some(&details));
                    return;
                }
                let index = index as usize;
                push_to_stack(final_state, vec![item[..index].to_vec(), item[index..].to_vec()], None);
            });
        },
        None,
        None,
    );
}

const POSITIVE_SIGN: u8 = 0x00;
const NEGATIVE_SIGN: u8 = 0x80;

/// Pad a minimally-encoded VM Number for `OP_NUM2BIN`.
pub fn pad_minimally_encoded_vm_number(mut vm_number: Vec<u8>, length: usize) -> Vec<u8> {
    if vm_number.len() == length {
        return vm_number;
    }
    let mut sign_bit = POSITIVE_SIGN;
    if let Some(last) = vm_number.last_mut() {
        sign_bit = *last & NEGATIVE_SIGN;
        *last &= NEGATIVE_SIGN - 1;
    }
    let mut result = vm_number;
    while result.len() < length.saturating_sub(1) {
        result.push(0);
    }
    result.push(sign_bit);
    result
}

pub fn create_op_num2_bin(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_vm_number(
            state,
            |next_state, [value]| {
                let target_length = value.to_number();
                if target_length > maximum_stack_item_length as f64 {
                    let details = format!(
                        "Maximum stack item length: {maximum_stack_item_length} bytes. Item length: {} bytes.",
                        number_to_string(target_length)
                    );
                    apply_error(
                        next_state,
                        AuthenticationErrorCommon::exceededMaximumStackItemLength,
                        Some(&details),
                    );
                    return;
                }
                use_one_vm_number(
                    next_state,
                    |final_state, [target]| {
                        let minimally_encoded = big_int_to_vm_number(&target);
                        if minimally_encoded.len() as f64 > target_length {
                            let details = format!(
                                "Minimum necessary byte length: {}. Requested byte length: {}.",
                                minimally_encoded.len(),
                                number_to_string(target_length)
                            );
                            apply_error(
                                final_state,
                                AuthenticationErrorCommon::insufficientLength,
                                Some(&details),
                            );
                            return;
                        }
                        push_to_stack(
                            final_state,
                            vec![pad_minimally_encoded_vm_number(minimally_encoded, target_length as usize)],
                            None,
                        );
                    },
                    Some(maximum_stack_item_length),
                    Some(false),
                );
            },
            None,
            None,
        );
    })
}

pub fn op_num2_bin(state: &mut AuthenticationProgramStateCommon) {
    create_op_num2_bin(None)(state);
}

pub fn create_op_bin2_num(
    maximum_stack_item_length: Option<usize>,
    maximum_vm_number_byte_length: Option<usize>,
) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    let maximum_vm_number_byte_length =
        maximum_vm_number_byte_length.unwrap_or(ConsensusCommon::maximumVmNumberByteLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_vm_number(
            state,
            |next_state, [target]| {
                let minimally_encoded = big_int_to_vm_number(&target);
                if minimally_encoded.len() > maximum_vm_number_byte_length {
                    let details = format!(
                        "Maximum VM number byte length: {maximum_vm_number_byte_length}; required byte length: {}.",
                        minimally_encoded.len()
                    );
                    apply_error(
                        next_state,
                        AuthenticationErrorCommon::exceededMaximumVmNumberByteLength,
                        Some(&details),
                    );
                    return;
                }
                push_to_stack(next_state, vec![minimally_encoded], None);
            },
            Some(maximum_stack_item_length),
            Some(false),
        );
    })
}

pub fn op_bin2_num(state: &mut AuthenticationProgramStateCommon) {
    create_op_bin2_num(None, None)(state);
}
