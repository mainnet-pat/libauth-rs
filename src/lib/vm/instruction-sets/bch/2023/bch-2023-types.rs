use crate::message::{Input, Output, TransactionCommon};
use crate::vm::{
    AuthenticationProgramCommon, AuthenticationProgramStateCommon, AuthenticationVirtualMachine,
    CompilationContext, ResolvedTransactionCommon,
};

pub type ResolvedTransactionBch = ResolvedTransactionCommon;
pub type ResolvedTransaction = ResolvedTransactionBch;
/// @deprecated Alias of `ResolvedTransactionBch` for backwards-compatibility.
pub type ResolvedTransactionBCH = ResolvedTransactionBch;
pub type AuthenticationProgramBch = AuthenticationProgramCommon;
pub type AuthenticationProgram = AuthenticationProgramBch;
/// @deprecated Alias of `AuthenticationProgramBch` for backwards-compatibility.
pub type AuthenticationProgramBCH = AuthenticationProgramBch;
pub type AuthenticationProgramStateBch = AuthenticationProgramStateCommon;
pub type AuthenticationProgramState = AuthenticationProgramStateBch;
/// @deprecated Alias of `AuthenticationProgramStateBch` for backwards-compatibility.
pub type AuthenticationProgramStateBCH = AuthenticationProgramStateBch;
pub type AuthenticationVirtualMachineBch = AuthenticationVirtualMachine<
    ResolvedTransactionBch,
    AuthenticationProgramBch,
    AuthenticationProgramStateBch,
>;
/// @deprecated Alias of `AuthenticationProgramStateBch` for backwards-compatibility.
pub type AuthenticationVirtualMachineBCH = AuthenticationVirtualMachineBch;
pub type TransactionBch<InputType = Input, OutputType = Output> = TransactionCommon<InputType, OutputType>;
/// @deprecated Alias of `TransactionBch` for backwards-compatibility.
pub type TransactionBCH = TransactionBch;
pub type Transaction<InputType = Input, OutputType = Output> = TransactionBch<InputType, OutputType>;
pub type CompilationContextBch = CompilationContext<TransactionBch<Input<Option<Vec<u8>>>>>;
/// @deprecated Alias of `CompilationContextBch` for backwards-compatibility.
pub type CompilationContextBCH = CompilationContextBch;
pub type CompilerBch = crate::compiler::Compiler;
/// @deprecated Alias of `CompilerBch` for backwards-compatibility.
pub type CompilerBCH = CompilerBch;
