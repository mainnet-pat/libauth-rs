use std::rc::Rc;

use crate::vm::{
    apply_error, numeric_operation_binary, vm_number_to_big_int, AuthenticationErrorBchSpec,
    AuthenticationProgramStateCommon, ConsensusCommon, Operation,
};

const BITS_PER_BYTE: usize = 8;

/// `maximum_vm_number_byte_length` defaults to
/// `ConsensusCommon.maximumVmNumberByteLength`.
pub fn create_op_pow(maximum_vm_number_byte_length: Option<usize>) -> Operation {
    let maximum_vm_number_byte_length =
        maximum_vm_number_byte_length.unwrap_or(ConsensusCommon::maximumVmNumberByteLength);
    let exponentiate =
        numeric_operation_binary(|[a, b]| a.exponentiate(&b), true, maximum_vm_number_byte_length);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        let length = state.stack.len();
        let last_two_items = &state.stack[length.saturating_sub(2)..];
        let base_length = last_two_items.first().map_or(0, Vec::len);
        let exponent = last_two_items.get(1).cloned().unwrap_or_default();
        let exponent_value = match vm_number_to_big_int(&exponent, Some(8), None) {
            Err(error) => {
                let details =
                    format!("Attempted an OP_POW operation with an invalid exponent. {error}");
                apply_error(state, AuthenticationErrorBchSpec::invalidVmNumber, Some(&details));
                return;
            }
            Ok(value) => value,
        };
        state.metrics.arithmetic_cost +=
            (base_length * base_length * BITS_PER_BYTE) as f64 * exponent_value.to_number();
        if state.metrics.operation_cost + state.metrics.arithmetic_cost
            > state.metrics.maximum_operation_cost
        {
            let details = format!(
                "Maximum operation cost: {} (density control length: {}); minimum operation cost following operation: {} (excludes costs following rejected OP_POW).",
                state.metrics.maximum_operation_cost,
                state.metrics.density_control_length,
                state.metrics.operation_cost
            );
            apply_error(state, AuthenticationErrorBchSpec::excessiveOperationCostOpPow, Some(&details));
            return;
        }
        exponentiate(state);
    })
}

pub fn op_pow(state: &mut AuthenticationProgramStateCommon) {
    create_op_pow(None)(state);
}
