use crate::vm::{apply_error, AuthenticationErrorCommon, AuthenticationProgramStateCommon};

pub fn op_nop<State>(_state: &mut State) {}

pub fn op_nop_disallowed(state: &mut AuthenticationProgramStateCommon) {
    apply_error(state, AuthenticationErrorCommon::calledUpgradableNop, None);
}

/// "Disabled" operations are explicitly forbidden from occurring anywhere in VM
/// bytecode, even within an unexecuted branch.
pub fn disabled_operation(state: &mut AuthenticationProgramStateCommon) {
    apply_error(state, AuthenticationErrorCommon::unknownOpcode, None);
}
