use crate::vm::{
    AuthenticationProgramBch, AuthenticationProgramStateBch2025, AuthenticationVirtualMachine,
    ResolvedTransactionBch,
};

pub type AuthenticationProgramStateBch2026 = AuthenticationProgramStateBch2025;
pub type AuthenticationVirtualMachineBch2026 = AuthenticationVirtualMachine<
    ResolvedTransactionBch,
    AuthenticationProgramBch,
    AuthenticationProgramStateBch2026,
>;
