use crate::vm::{
    apply_error, execution_is_active, stack_item_is_truthy, use_one_stack_item,
    AuthenticationErrorCommon, AuthenticationProgramStateCommon,
    AuthenticationProgramStateControlStackItem,
};

pub fn op_verify(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [item]| {
        if !stack_item_is_truthy(&item) {
            apply_error(next_state, AuthenticationErrorCommon::failedVerify, None);
        }
    });
}

pub fn reserved_operation(state: &mut AuthenticationProgramStateCommon) {
    apply_error(state, AuthenticationErrorCommon::calledReserved, None);
}

pub fn op_return(state: &mut AuthenticationProgramStateCommon) {
    apply_error(state, AuthenticationErrorCommon::calledReturn, None);
}

/// Return the provided state with the provided value pushed to its control stack.
/// @param state - the state to update and return
/// @param data - the value to push to the stack
pub fn push_to_control_stack(
    state: &mut AuthenticationProgramStateCommon,
    value: AuthenticationProgramStateControlStackItem,
) {
    state.control_stack.push(value);
}

pub fn op_if(state: &mut AuthenticationProgramStateCommon) {
    if execution_is_active(state) {
        use_one_stack_item(state, |next_state, [item]| {
            push_to_control_stack(
                next_state,
                AuthenticationProgramStateControlStackItem::Boolean(stack_item_is_truthy(&item)),
            );
        });
        return;
    }
    push_to_control_stack(state, AuthenticationProgramStateControlStackItem::Boolean(false));
}

/// Note, `OP_NOTIF` is not completely equivalent to `OP_NOT OP_IF`. `OP_NOT`
/// operates on a VM Number (as the inverse of `OP_0NOTEQUAL`), while `OP_NOTIF`
/// checks the "truthy-ness" of a stack item like `OP_IF`.
pub fn op_not_if(state: &mut AuthenticationProgramStateCommon) {
    if execution_is_active(state) {
        use_one_stack_item(state, |next_state, [item]| {
            push_to_control_stack(
                next_state,
                AuthenticationProgramStateControlStackItem::Boolean(!stack_item_is_truthy(&item)),
            );
        });
        return;
    }
    push_to_control_stack(state, AuthenticationProgramStateControlStackItem::Boolean(false));
}

pub fn op_end_if(state: &mut AuthenticationProgramStateCommon) {
    let element = state.control_stack.pop();
    if !matches!(element, Some(AuthenticationProgramStateControlStackItem::Boolean(_))) {
        apply_error(state, AuthenticationErrorCommon::unexpectedEndIf, None);
    }
}

pub fn op_else(state: &mut AuthenticationProgramStateCommon) {
    match state.control_stack.last_mut() {
        Some(AuthenticationProgramStateControlStackItem::Boolean(top)) => *top = !*top,
        _ => apply_error(state, AuthenticationErrorCommon::unexpectedElse, None),
    }
}
