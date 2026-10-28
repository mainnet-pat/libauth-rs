use std::rc::Rc;

use crate::format::bin_to_hex;
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_consensus::ConsensusBch2026;
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_errors::AuthenticationErrorBch2026;
use crate::vm::instruction_sets::bch::bch_2026::bch_2026_opcodes::OpcodesBch2026;
use crate::vm::{
    apply_error, authentication_instructions_are_malformed, decode_authentication_instructions,
    disassemble_authentication_instruction_malformed, push_to_control_stack, use_one_stack_item,
    AuthenticationInstructionMaybeMalformed, AuthenticationProgramStackFrame,
    AuthenticationProgramStateCommon, AuthenticationProgramStateControlStackItem, Operation,
};

/// `maximum_function_identifier_length` defaults to
/// `ConsensusBch2026.maximumFunctionIdentifierLength`.
pub fn create_op_define(maximum_function_identifier_length: Option<usize>) -> Operation {
    let maximum_function_identifier_length = maximum_function_identifier_length.unwrap_or(
        ConsensusBch2026
            .maximum_function_identifier_length
            .expect("ConsensusBch2026 defines maximumFunctionIdentifierLength"),
    );
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_stack_item(state, |next_state, [function_identifier]| {
            let function_table_key = bin_to_hex(&function_identifier);
            if function_identifier.len() > maximum_function_identifier_length {
                let details = format!(
                    "Function identifier has excessive length. Maximum length: {maximum_function_identifier_length}. Provided length: {}. Provided identifier: 0x{function_table_key}.",
                    function_identifier.len()
                );
                apply_error(
                    next_state,
                    AuthenticationErrorBch2026::functionIdentifierExcessiveLength,
                    Some(&details),
                );
                return;
            }
            if let Some(existing) = next_state.function_table.get(&function_table_key) {
                let details = format!(
                    "Function identifier: 0x{function_table_key}. Existing contents: {}.",
                    bin_to_hex(existing)
                );
                apply_error(
                    next_state,
                    AuthenticationErrorBch2026::functionIdentifierPreviouslyDefined,
                    Some(&details),
                );
                return;
            }
            use_one_stack_item(next_state, |final_state, [function_body]| {
                final_state.function_table.insert(function_table_key, function_body);
                final_state.function_count += 1;
            });
        });
    })
}

pub fn op_invoke(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [function_identifier]| {
        let function_table_key = bin_to_hex(&function_identifier);
        let Some(function_body) = next_state.function_table.get(&function_table_key) else {
            let details = format!("Function identifier: 0x{function_table_key}.");
            apply_error(
                next_state,
                AuthenticationErrorBch2026::functionIdentifierUndefined,
                Some(&details),
            );
            return;
        };
        let new_instructions = decode_authentication_instructions(function_body);
        if authentication_instructions_are_malformed(&new_instructions) {
            let Some(AuthenticationInstructionMaybeMalformed::Malformed(malformed)) = new_instructions.last()
            else {
                unreachable!("the final instruction is malformed");
            };
            let details = format!(
                "Malformed instruction: {}.",
                disassemble_authentication_instruction_malformed(OpcodesBch2026::MEMBERS, malformed)
            );
            apply_error(next_state, AuthenticationErrorBch2026::malformedFunction, Some(&details));
            return;
        }
        let manually_advance = 1;
        let frame = AuthenticationProgramStackFrame {
            instructions: Rc::clone(&next_state.instructions),
            ip: next_state.ip + manually_advance,
        };
        push_to_control_stack(next_state, AuthenticationProgramStateControlStackItem::Frame(frame));
        next_state.ip = 0 - manually_advance;
        next_state.instructions = Rc::new(
            new_instructions
                .into_iter()
                .filter_map(|instruction| match instruction {
                    AuthenticationInstructionMaybeMalformed::Instruction(instruction) => Some(instruction),
                    AuthenticationInstructionMaybeMalformed::Malformed(_) => None,
                })
                .collect(),
        );
    });
}
