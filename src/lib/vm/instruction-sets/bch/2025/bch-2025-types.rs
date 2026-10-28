use crate::vm::{
    AuthenticationProgramBch, AuthenticationProgramStateBch, AuthenticationVirtualMachine,
    ResolvedTransactionBch,
};

pub type AuthenticationProgramStateBch2025 = AuthenticationProgramStateBch;
pub type AuthenticationVirtualMachineBch2025 = AuthenticationVirtualMachine<
    ResolvedTransactionBch,
    AuthenticationProgramBch,
    AuthenticationProgramStateBch2025,
>;
