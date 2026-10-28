use std::rc::Rc;

use crate::vm::{
    apply_error, authentication_instructions_are_malformed, decode_authentication_instructions,
    disassemble_authentication_instruction_malformed, execution_is_active, push_to_control_stack,
    use_one_stack_item, AuthenticationErrorBchSpec, AuthenticationInstructionMaybeMalformed,
    AuthenticationProgramStackFrame, AuthenticationProgramStateBch2026,
    AuthenticationProgramStateControlStackItem, OpcodesBchSpec,
};

pub fn op_eval(state: &mut AuthenticationProgramStateBch2026) {
    if !execution_is_active(state) {
        return;
    }
    use_one_stack_item(state, |next_state, [item]| {
        let new_instructions = decode_authentication_instructions(&item);
        if authentication_instructions_are_malformed(&new_instructions) {
            let Some(AuthenticationInstructionMaybeMalformed::Malformed(malformed)) = new_instructions.last()
            else {
                unreachable!("the final instruction is malformed");
            };
            let details = format!(
                "Malformed instruction: {}.",
                disassemble_authentication_instruction_malformed(OpcodesBchSpec::MEMBERS, malformed)
            );
            apply_error(next_state, AuthenticationErrorBchSpec::malformedEval, Some(&details));
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
