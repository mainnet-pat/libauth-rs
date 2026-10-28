use std::cmp::Ordering;
use std::rc::Rc;

use crate::runtime::bigint::BigInt;
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_consensus::ConsensusBch2026;
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_errors::AuthenticationErrorBch2026;
use crate::vm::{
    apply_error, push_to_stack, push_to_stack_vm_number, push_to_stack_vm_number_checked,
    use_one_stack_item, use_one_vm_number, AuthenticationProgramStateCommon, Operation,
};

const ALL_BITS: u8 = 0xff;
const BITS_PER_BYTE: usize = 8;

pub fn op_invert(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [a]| {
        push_to_stack(next_state, vec![a.iter().map(|v| v ^ ALL_BITS).collect()], None);
    });
}

fn use_one_shift_bit_count(
    state: &mut AuthenticationProgramStateCommon,
    shift_operation: impl FnOnce(&mut AuthenticationProgramStateCommon, [BigInt; 1]),
) {
    use_one_vm_number(
        state,
        |next_state, [bit_count]| {
            if bit_count.is_negative() {
                let details = format!(
                    "Bit count must be greater than or equal to 0. Provided bit count: {bit_count}."
                );
                apply_error(
                    next_state,
                    AuthenticationErrorBch2026::invalidShiftBitCount,
                    Some(&details),
                );
                return;
            }
            shift_operation(next_state, [bit_count]);
        },
        None,
        None,
    );
}

/// `maximum_stack_item_length` defaults to
/// `ConsensusBch2026.maximumStackItemLength`.
pub fn create_op_l_shift_num(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusBch2026.maximum_stack_item_length);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        let fast_fail_bit_count = BigInt::from_u64((maximum_stack_item_length * BITS_PER_BYTE) as u64);
        use_one_shift_bit_count(state, |next_state, [bit_count]| {
            use_one_vm_number(
                next_state,
                |final_state, [numeric_value]| {
                    if numeric_value.is_zero() {
                        push_to_stack_vm_number(final_state, &BigInt::zero());
                        return;
                    }
                    if bit_count.cmp(&fast_fail_bit_count) == Ordering::Greater {
                        let details =
                            format!("Abandoned excessive OP_LSHIFTNUM. Provided bit count: {bit_count}.");
                        apply_error(
                            final_state,
                            AuthenticationErrorBch2026::invalidShiftBitCount,
                            Some(&details),
                        );
                        return;
                    }
                    let shift = bit_count.to_u64().expect("the bit count is bounded");
                    push_to_stack_vm_number_checked(
                        final_state,
                        &numeric_value.shl(shift),
                        Some(maximum_stack_item_length),
                        Some(false),
                    );
                },
                None,
                None,
            );
        });
    })
}

/// `maximum_stack_item_length` defaults to
/// `ConsensusBch2026.maximumStackItemLength`.
pub fn create_op_r_shift_num(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusBch2026.maximum_stack_item_length);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_shift_bit_count(state, |next_state, [bit_count]| {
            let next_stack_item_length = next_state.stack.last().map_or(0, Vec::len);
            let numeric_value_bits = BigInt::from_u64((next_stack_item_length * BITS_PER_BYTE) as u64);
            let fast_return_if_valid = bit_count.cmp(&numeric_value_bits) == Ordering::Greater;
            use_one_vm_number(
                next_state,
                |final_state, [numeric_value]| {
                    if numeric_value.is_zero() {
                        push_to_stack_vm_number(final_state, &BigInt::zero());
                        return;
                    }
                    if fast_return_if_valid {
                        let is_negative = numeric_value.is_negative();
                        push_to_stack_vm_number(
                            final_state,
                            &BigInt::from_i64(if is_negative { -1 } else { 0 }),
                        );
                        return;
                    }
                    let shift = bit_count.to_u64().expect("the bit count is bounded");
                    push_to_stack_vm_number_checked(
                        final_state,
                        &numeric_value.shr(shift),
                        Some(maximum_stack_item_length),
                        Some(false),
                    );
                },
                None,
                None,
            );
        });
    })
}

fn copy_whole_bytes(src: &[u8], dst: &mut [u8], byte_shift: usize, left: bool) {
    if byte_shift >= src.len() {
        return;
    }
    if left {
        dst[..src.len() - byte_shift].copy_from_slice(&src[byte_shift..]);
        return;
    }
    dst[byte_shift..].copy_from_slice(&src[..src.len() - byte_shift]);
}

fn residual_left_shift(mut buf: Vec<u8>, bit_shift: u32) -> Vec<u8> {
    let mut carry = 0_u8;
    for i in (0..buf.len()).rev() {
        let v = buf[i];
        buf[i] = ((v << bit_shift) | carry) & ALL_BITS;
        carry = v >> (BITS_PER_BYTE as u32 - bit_shift);
    }
    buf
}

fn residual_right_shift(mut buf: Vec<u8>, bit_shift: u32) -> Vec<u8> {
    let mut carry = 0_u8;
    for value in buf.iter_mut() {
        let v = *value;
        *value = ((v >> bit_shift) | carry) & ALL_BITS;
        carry = (v << (BITS_PER_BYTE as u32 - bit_shift)) & ALL_BITS;
    }
    buf
}

fn shift_fixed(src: &[u8], bit_count: &BigInt, is_left_shift: bool) -> Vec<u8> {
    let s = bit_count.to_number();
    if s == 0.0 || s.is_nan() || src.is_empty() {
        return src.to_vec();
    }
    let len = src.len();
    let mut dst = vec![0_u8; len];
    let byte_shift = (s / BITS_PER_BYTE as f64).floor();
    let bit_shift = s % BITS_PER_BYTE as f64;
    if byte_shift < len as f64 {
        copy_whole_bytes(src, &mut dst, byte_shift as usize, is_left_shift);
    }
    if bit_shift == 0.0 || bit_shift.is_nan() {
        return dst;
    }
    if is_left_shift {
        residual_left_shift(dst, bit_shift as u32)
    } else {
        residual_right_shift(dst, bit_shift as u32)
    }
}

/// Perform a fixed-length, logical left shift of `bin` by the `bitCount`,
/// equivalent to `OP_LSHIFTBIN` in the Bitcoin Cash VM.
/// @param bin - the Uint8Array to shift.
/// @param bitCount - the count of bits by which to shift `bin`.
pub fn binary_shift_left(bin: &[u8], bit_count: &BigInt) -> Vec<u8> {
    shift_fixed(bin, bit_count, true)
}

/// Perform a fixed-length, logical right shift of `bin` by the `bitCount`,
/// equivalent to `OP_RSHIFTBIN` in the Bitcoin Cash VM.
/// @param bin - the Uint8Array to shift.
/// @param bitCount - the count of bits by which to shift `bin`.
pub fn binary_shift_right(bin: &[u8], bit_count: &BigInt) -> Vec<u8> {
    shift_fixed(bin, bit_count, false)
}

pub fn op_l_shift_bin(state: &mut AuthenticationProgramStateCommon) {
    use_one_shift_bit_count(state, |next_state, [bit_count]| {
        use_one_stack_item(next_state, |final_state, [bin]| {
            push_to_stack(final_state, vec![binary_shift_left(&bin, &bit_count)], None);
        });
    });
}

pub fn op_r_shift_bin(state: &mut AuthenticationProgramStateCommon) {
    use_one_shift_bit_count(state, |next_state, [bit_count]| {
        use_one_stack_item(next_state, |final_state, [bin]| {
            push_to_stack(final_state, vec![binary_shift_right(&bin, &bit_count)], None);
        });
    });
}
