use crate::vm::{
    AuthenticationProgramBch, AuthenticationProgramStateBch2026, AuthenticationProgramStateCommon,
    AuthenticationVirtualMachine, ResolvedTransactionBch,
};

/// A program state with the `maxMemoryUsage` metric (see
/// {@link AuthenticationProgramStateMetrics.max_memory_usage}).
pub type AuthenticationProgramStateResourceLimitsBchSpec = AuthenticationProgramStateCommon;
pub type AuthenticationProgramStateBchSpec = AuthenticationProgramStateBch2026;
pub type AuthenticationVirtualMachineBchSpec = AuthenticationVirtualMachine<
    ResolvedTransactionBch,
    AuthenticationProgramBch,
    AuthenticationProgramStateBchSpec,
>;
