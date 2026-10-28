use std::cmp::Ordering;
use std::rc::Rc;

use crate::runtime::bigint::BigInt;
use crate::vm::{
    apply_error, combine_operations, op_verify, push_to_stack_vm_number_checked,
    use_one_vm_number, use_three_vm_numbers, use_two_vm_numbers, AuthenticationErrorCommon,
    AuthenticationProgramStateCommon, ConsensusCommon, Operation,
};

/// Create a numeric operation which reads one VM Number from the stack and
/// pushes the result of `operate`.
pub fn numeric_operation_unary(
    operate: impl Fn([BigInt; 1]) -> BigInt + 'static,
    has_encoding_cost: bool,
    maximum_vm_number_byte_length: usize,
) -> Operation {
    let operate = Rc::new(operate);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        let operate = Rc::clone(&operate);
        use_one_vm_number(
            state,
            move |next_state, values| {
                let result = operate(values);
                push_to_stack_vm_number_checked(
                    next_state,
                    &result,
                    Some(maximum_vm_number_byte_length),
                    Some(has_encoding_cost),
                );
            },
            Some(maximum_vm_number_byte_length),
            None,
        );
    })
}

/// Create a numeric operation which reads two VM Numbers from the stack and
/// pushes the result of `operate`.
pub fn numeric_operation_binary(
    operate: impl Fn([BigInt; 2]) -> BigInt + 'static,
    has_encoding_cost: bool,
    maximum_vm_number_byte_length: usize,
) -> Operation {
    let operate = Rc::new(operate);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        let operate = Rc::clone(&operate);
        use_two_vm_numbers(
            state,
            move |next_state, values| {
                let result = operate(values);
                push_to_stack_vm_number_checked(
                    next_state,
                    &result,
                    Some(maximum_vm_number_byte_length),
                    Some(has_encoding_cost),
                );
            },
            Some(maximum_vm_number_byte_length),
            None,
        );
    })
}

/// Create a numeric operation which reads three VM Numbers from the stack and
/// pushes the result of `operate`.
pub fn numeric_operation_ternary(
    operate: impl Fn([BigInt; 3]) -> BigInt + 'static,
    has_encoding_cost: bool,
    maximum_vm_number_byte_length: usize,
) -> Operation {
    let operate = Rc::new(operate);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        let operate = Rc::clone(&operate);
        use_three_vm_numbers(
            state,
            move |next_state, values| {
                let result = operate(values);
                push_to_stack_vm_number_checked(
                    next_state,
                    &result,
                    Some(maximum_vm_number_byte_length),
                    Some(has_encoding_cost),
                );
            },
            Some(maximum_vm_number_byte_length),
            None,
        );
    })
}

fn maximum_or_default(maximum_vm_number_byte_length: Option<usize>) -> usize {
    maximum_vm_number_byte_length.unwrap_or(ConsensusCommon::maximumVmNumberByteLength)
}

fn boolean(value: bool) -> BigInt {
    BigInt::from_u64(value as u64)
}

pub fn create_op_1_add(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_unary(
        |[value]| value.add(&BigInt::from_u64(1)),
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_1_add(state: &mut AuthenticationProgramStateCommon) {
    create_op_1_add(None)(state);
}

pub fn create_op_1_sub(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_unary(
        |[value]| value.sub(&BigInt::from_u64(1)),
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_1_sub(state: &mut AuthenticationProgramStateCommon) {
    create_op_1_sub(None)(state);
}

pub fn create_op_negate(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_unary(
        |[value]| value.negate(),
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_negate(state: &mut AuthenticationProgramStateCommon) {
    create_op_negate(None)(state);
}

pub fn create_op_abs(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_unary(
        |[value]| value.abs(),
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_abs(state: &mut AuthenticationProgramStateCommon) {
    create_op_abs(None)(state);
}

pub fn create_op_not(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_unary(
        |[value]| boolean(value.is_zero()),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_not(state: &mut AuthenticationProgramStateCommon) {
    create_op_not(None)(state);
}

pub fn create_op_0_not_equal(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_unary(
        |[value]| boolean(!value.is_zero()),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_0_not_equal(state: &mut AuthenticationProgramStateCommon) {
    create_op_0_not_equal(None)(state);
}

pub fn create_op_add(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| a.add(&b),
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_add(state: &mut AuthenticationProgramStateCommon) {
    create_op_add(None)(state);
}

pub fn create_op_sub(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| a.sub(&b),
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_sub(state: &mut AuthenticationProgramStateCommon) {
    create_op_sub(None)(state);
}

pub fn create_op_bool_and(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(!a.is_zero() && !b.is_zero()),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_bool_and(state: &mut AuthenticationProgramStateCommon) {
    create_op_bool_and(None)(state);
}

pub fn create_op_bool_or(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(!a.is_zero() || !b.is_zero()),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_bool_or(state: &mut AuthenticationProgramStateCommon) {
    create_op_bool_or(None)(state);
}

pub fn create_op_num_equal(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(a == b),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_num_equal(state: &mut AuthenticationProgramStateCommon) {
    create_op_num_equal(None)(state);
}

pub fn create_op_num_equal_verify(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    combine_operations(
        create_op_num_equal(Some(maximum_or_default(maximum_vm_number_byte_length))),
        Rc::new(op_verify),
    )
}

pub fn op_num_equal_verify(state: &mut AuthenticationProgramStateCommon) {
    create_op_num_equal_verify(None)(state);
}

pub fn create_op_num_not_equal(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(a != b),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_num_not_equal(state: &mut AuthenticationProgramStateCommon) {
    create_op_num_not_equal(None)(state);
}

pub fn create_op_less_than(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(a.cmp(&b) == Ordering::Less),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_less_than(state: &mut AuthenticationProgramStateCommon) {
    create_op_less_than(None)(state);
}

pub fn create_op_less_than_or_equal(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(a.cmp(&b) != Ordering::Greater),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

/// Note: libauth defines `opLessThanOrEqual` as `createOpLessThan()`.
pub fn op_less_than_or_equal(state: &mut AuthenticationProgramStateCommon) {
    create_op_less_than(None)(state);
}

pub fn create_op_greater_than(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(a.cmp(&b) == Ordering::Greater),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_greater_than(state: &mut AuthenticationProgramStateCommon) {
    create_op_greater_than(None)(state);
}

pub fn create_op_greater_than_or_equal(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| boolean(a.cmp(&b) != Ordering::Less),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_greater_than_or_equal(state: &mut AuthenticationProgramStateCommon) {
    create_op_greater_than_or_equal(None)(state);
}

pub fn create_op_min(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| if a.cmp(&b) == Ordering::Less { a } else { b },
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_min(state: &mut AuthenticationProgramStateCommon) {
    create_op_min(None)(state);
}

pub fn create_op_max(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_binary(
        |[a, b]| if a.cmp(&b) == Ordering::Greater { a } else { b },
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_max(state: &mut AuthenticationProgramStateCommon) {
    create_op_max(None)(state);
}

pub fn create_op_within(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    numeric_operation_ternary(
        |[a, b, c]| boolean(b.cmp(&a) != Ordering::Greater && a.cmp(&c) == Ordering::Less),
        false,
        maximum_or_default(maximum_vm_number_byte_length),
    )
}

pub fn op_within(state: &mut AuthenticationProgramStateCommon) {
    create_op_within(None)(state);
}

/// Measure the arithmetic cost of an operation (the product of the lengths of
/// the top two stack items), then apply the operation.
pub fn measure_arithmetic_cost(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon),
) {
    let length = state.stack.len();
    let last_two_items = &state.stack[length.saturating_sub(2)..];
    let first_length = last_two_items.first().map_or(0, Vec::len);
    let second_length = last_two_items.get(1).map_or(0, Vec::len);
    state.metrics.arithmetic_cost += (first_length * second_length) as f64;
    operation(state);
}

pub fn create_op_mul(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    let multiply = numeric_operation_binary(
        |[a, b]| a.mul(&b),
        true,
        maximum_or_default(maximum_vm_number_byte_length),
    );
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        measure_arithmetic_cost(state, |state| multiply(state));
    })
}

pub fn op_mul(state: &mut AuthenticationProgramStateCommon) {
    create_op_mul(None)(state);
}

fn divide(
    state: &mut AuthenticationProgramStateCommon,
    maximum_vm_number_byte_length: usize,
    remainder: bool,
) {
    measure_arithmetic_cost(state, |state| {
        use_two_vm_numbers(
            state,
            |next_state, [a, b]| {
                if b.is_zero() {
                    apply_error(next_state, AuthenticationErrorCommon::divisionByZero, None);
                    return;
                }
                let (quotient, modulo) = a.div_mod(&b);
                push_to_stack_vm_number_checked(
                    next_state,
                    if remainder { &modulo } else { &quotient },
                    Some(maximum_vm_number_byte_length),
                    Some(true),
                );
            },
            Some(maximum_vm_number_byte_length),
            None,
        );
    });
}

pub fn create_op_div(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    let maximum_vm_number_byte_length = maximum_or_default(maximum_vm_number_byte_length);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        divide(state, maximum_vm_number_byte_length, false);
    })
}

pub fn op_div(state: &mut AuthenticationProgramStateCommon) {
    create_op_div(None)(state);
}

pub fn create_op_mod(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    let maximum_vm_number_byte_length = maximum_or_default(maximum_vm_number_byte_length);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        divide(state, maximum_vm_number_byte_length, true);
    })
}

/// Note: libauth defines `opMod` as `createOpDiv()`.
pub fn op_mod(state: &mut AuthenticationProgramStateCommon) {
    create_op_div(None)(state);
}
