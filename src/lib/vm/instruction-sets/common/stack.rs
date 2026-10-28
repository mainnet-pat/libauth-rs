use crate::runtime::bigint::BigInt;
use crate::vm::{
    apply_error, big_int_to_vm_number, push_to_stack, stack_item_is_truthy, use_four_stack_items,
    use_one_stack_item, use_one_vm_number, use_six_stack_items, use_three_stack_items,
    use_two_stack_items, AuthenticationErrorCommon, AuthenticationProgramStateCommon,
};

pub fn op_to_alt_stack(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [item]| {
        next_state.alternate_stack.push(item);
    });
}

pub fn op_from_alt_stack(state: &mut AuthenticationProgramStateCommon) {
    match state.alternate_stack.pop() {
        None => apply_error(state, AuthenticationErrorCommon::emptyAlternateStack, None),
        Some(item) => push_to_stack(state, vec![item], None),
    }
}

pub fn op_2_drop(state: &mut AuthenticationProgramStateCommon) {
    use_two_stack_items(state, |_, _| {});
}

pub fn op_2_dup(state: &mut AuthenticationProgramStateCommon) {
    use_two_stack_items(state, |next_state, [a, b]| {
        let pushed_bytes = a.len() + b.len();
        push_to_stack(next_state, vec![a.clone(), b.clone(), a, b], Some(pushed_bytes));
    });
}

pub fn op_3_dup(state: &mut AuthenticationProgramStateCommon) {
    use_three_stack_items(state, |next_state, [a, b, c]| {
        let pushed_bytes = a.len() + b.len() + c.len();
        push_to_stack(
            next_state,
            vec![a.clone(), b.clone(), c.clone(), a, b, c],
            Some(pushed_bytes),
        );
    });
}

pub fn op_2_over(state: &mut AuthenticationProgramStateCommon) {
    use_four_stack_items(state, |next_state, [a, b, c, d]| {
        let pushed_bytes = a.len() + b.len();
        push_to_stack(next_state, vec![a.clone(), b.clone(), c, d, a, b], Some(pushed_bytes));
    });
}

pub fn op_2_rot(state: &mut AuthenticationProgramStateCommon) {
    use_six_stack_items(state, |next_state, [a, b, c, d, e, f]| {
        let pushed_bytes = a.len() + b.len();
        push_to_stack(next_state, vec![c, d, e, f, a, b], Some(pushed_bytes));
    });
}

pub fn op_2_swap(state: &mut AuthenticationProgramStateCommon) {
    use_four_stack_items(state, |next_state, [a, b, c, d]| {
        push_to_stack(next_state, vec![c, d, a, b], Some(0));
    });
}

pub fn op_if_dup(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [item]| {
        if stack_item_is_truthy(&item) {
            let pushed_bytes = item.len();
            push_to_stack(next_state, vec![item.clone(), item], Some(pushed_bytes));
        } else {
            push_to_stack(next_state, vec![item], Some(0));
        }
    });
}

pub fn op_depth(state: &mut AuthenticationProgramStateCommon) {
    let depth = big_int_to_vm_number(&BigInt::from_u64(state.stack.len() as u64));
    push_to_stack(state, vec![depth], None);
}

pub fn op_drop(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |_, _| {});
}

pub fn op_dup(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [item]| {
        let pushed_bytes = item.len();
        push_to_stack(next_state, vec![item.clone(), item], Some(pushed_bytes));
    });
}

pub fn op_nip(state: &mut AuthenticationProgramStateCommon) {
    use_two_stack_items(state, |next_state, [_, b]| {
        push_to_stack(next_state, vec![b], Some(0));
    });
}

pub fn op_over(state: &mut AuthenticationProgramStateCommon) {
    use_two_stack_items(state, |next_state, [a, b]| {
        let pushed_bytes = a.len();
        push_to_stack(next_state, vec![a.clone(), b, a], Some(pushed_bytes));
    });
}

pub fn op_pick(state: &mut AuthenticationProgramStateCommon) {
    use_one_vm_number(
        state,
        |next_state, [depth]| {
            let index = (next_state.stack.len() as f64) - 1.0 - depth.to_number();
            let item = (index >= 0.0 && index < next_state.stack.len() as f64)
                .then(|| next_state.stack[index as usize].clone());
            match item {
                None => {
                    let details = format!(
                        "Current stack depth: {}; requested depth: {depth}.",
                        next_state.stack.len()
                    );
                    apply_error(next_state, AuthenticationErrorCommon::invalidStackIndex, Some(&details));
                }
                Some(item) => push_to_stack(next_state, vec![item], None),
            }
        },
        None,
        None,
    );
}

pub fn op_roll(state: &mut AuthenticationProgramStateCommon) {
    use_one_vm_number(
        state,
        |next_state, [depth_big_int]| {
            let depth = depth_big_int.to_number();
            let index = (next_state.stack.len() as f64) - 1.0 - depth;
            if index < 0.0 || index > (next_state.stack.len() as f64) - 1.0 {
                let details = format!(
                    "Current stack depth: {}; requested depth: {}.",
                    next_state.stack.len(),
                    crate::runtime::number::number_to_string(depth)
                );
                apply_error(next_state, AuthenticationErrorCommon::invalidStackIndex, Some(&details));
                return;
            }
            let item = next_state.stack.remove(index as usize);
            let pushed_bytes = item.len() + depth as usize;
            push_to_stack(next_state, vec![item], Some(pushed_bytes));
        },
        None,
        None,
    );
}

pub fn op_rot(state: &mut AuthenticationProgramStateCommon) {
    use_three_stack_items(state, |next_state, [a, b, c]| {
        push_to_stack(next_state, vec![b, c, a], Some(0));
    });
}

pub fn op_swap(state: &mut AuthenticationProgramStateCommon) {
    use_two_stack_items(state, |next_state, [a, b]| {
        push_to_stack(next_state, vec![b, a], Some(0));
    });
}

pub fn op_tuck(state: &mut AuthenticationProgramStateCommon) {
    use_two_stack_items(state, |next_state, [a, b]| {
        let pushed_bytes = b.len();
        push_to_stack(next_state, vec![b.clone(), a, b], Some(pushed_bytes));
    });
}

pub fn op_size(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [item]| {
        let size = big_int_to_vm_number(&BigInt::from_u64(item.len() as u64));
        let pushed_bytes = size.len();
        push_to_stack(next_state, vec![item, size], Some(pushed_bytes));
    });
}
