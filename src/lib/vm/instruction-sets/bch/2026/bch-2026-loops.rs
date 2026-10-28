use crate::vm::instruction_sets::bch::bch_2026::bch_2026_errors::AuthenticationErrorBch2026;
use crate::vm::{
    apply_error, execution_is_active, push_to_control_stack, stack_item_is_truthy,
    use_one_stack_item, AuthenticationProgramStateBch2026,
    AuthenticationProgramStateControlStackItem,
};

const MARK_INACTIVE_OP_BEGIN: isize = -1;

pub fn op_begin(state: &mut AuthenticationProgramStateBch2026) {
    let value = if execution_is_active(state) {
        state.ip
    } else {
        MARK_INACTIVE_OP_BEGIN
    };
    push_to_control_stack(state, AuthenticationProgramStateControlStackItem::Number(value));
}

pub fn op_until(state: &mut AuthenticationProgramStateBch2026) {
    let Some(&AuthenticationProgramStateControlStackItem::Number(control_value)) = state.control_stack.last()
    else {
        apply_error(state, AuthenticationErrorBch2026::unexpectedUntil, None);
        return;
    };
    if !execution_is_active(state) {
        state.control_stack.pop();
        if control_value != MARK_INACTIVE_OP_BEGIN {
            apply_error(state, AuthenticationErrorBch2026::unexpectedUntilMissingEndIf, None);
        }
        return;
    }
    use_one_stack_item(state, |next_state, [item]| {
        if stack_item_is_truthy(&item) {
            next_state.control_stack.pop();
            return;
        }
        next_state.ip = control_value;
    });
}
