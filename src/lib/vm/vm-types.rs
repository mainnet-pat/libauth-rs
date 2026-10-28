use std::collections::BTreeMap;
use std::rc::Rc;

use crate::message::{Output, TransactionCommon};
use crate::vm::{AuthenticationInstruction, CompilationContext};

/// A stack frame of the authentication virtual machine: the active
/// instructions and the instruction pointer within them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationProgramStackFrame {
    pub instructions: Rc<Vec<AuthenticationInstruction>>,
    pub ip: isize,
}

/// The minimum program state required by an
/// {@link AuthenticationVirtualMachine}: an `instructions` list, an `ip`
/// (instruction pointer), and an `evaluatedInstructionCount` metric.
///
/// TypeScript expresses this as a structural type; Rust expresses it as the
/// trait implemented by every program state a virtual machine can evaluate.
pub trait AuthenticationProgramStateMinimum: Clone {
    /// The active instructions.
    fn instructions(&self) -> &[AuthenticationInstruction];
    /// The instruction pointer.
    fn ip(&self) -> isize;
    /// A mutable reference to the instruction pointer.
    fn ip_mut(&mut self) -> &mut isize;
    /// A mutable reference to `metrics.evaluatedInstructionCount`.
    fn evaluated_instruction_count_mut(&mut self) -> &mut f64;
}

/// A program state with a `stack`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateStack = AuthenticationProgramStateCommon;

/// A program state with an `alternateStack`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateAlternateStack = AuthenticationProgramStateCommon;

/// A program state with a `functionTable` and `functionCount`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateFunctionTable = AuthenticationProgramStateCommon;

/// A program state with a `controlStack`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateControlStack = AuthenticationProgramStateCommon;

/// A program state with an optional `error`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateError = AuthenticationProgramStateCommon;

/// A transaction with the source outputs spent by each of its inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTransactionCommon {
    pub source_outputs: Vec<Output>,
    pub transaction: TransactionCommon,
}

/// A resolved transaction and the index of the input being evaluated.
///
/// libauth's `AuthenticationProgramCommon` (`ResolvedTransactionCommon &
/// { inputIndex }`) is structurally identical to a
/// {@link CompilationContext} of a `TransactionCommon`, and libauth passes
/// authentication programs wherever a compilation context is expected (e.g.
/// to {@link generateSigningSerializationBch}); Rust expresses that identity
/// with a type alias.
pub type AuthenticationProgramCommon = CompilationContext<TransactionCommon>;

/// A program state with a `lastCodeSeparator`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateCodeSeparator = AuthenticationProgramStateCommon;

/// A program state with `signedMessages`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateSignatureAnalysis = AuthenticationProgramStateCommon;

/// A program state with an `operationCount` and resource limit `metrics`,
/// see {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateResourceLimits = AuthenticationProgramStateCommon;

/// A program state with a `program`, see
/// {@link AuthenticationProgramStateCommon}.
pub type AuthenticationProgramStateTransactionContext = AuthenticationProgramStateCommon;

/// An item of the `controlStack`: a stack frame, a boolean (the state of an
/// `OP_IF`/`OP_NOTIF` block), or a number (the instruction index of an
/// `OP_BEGIN`, or `-1` for an `OP_BEGIN` encountered in an unexecuted
/// branch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticationProgramStateControlStackItem {
    Frame(AuthenticationProgramStackFrame),
    Boolean(bool),
    Number(isize),
}

/// A message signed during evaluation: a transaction signing serialization
/// (`OP_CHECKSIG` and `OP_CHECKMULTISIG`) or a data message
/// (`OP_CHECKDATASIG`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticationProgramStateSignedMessage {
    Serialization { digest: Vec<u8>, serialization: Vec<u8> },
    Message { digest: Vec<u8>, message: Vec<u8> },
}

/// The `metrics` of a program state. libauth's metrics are JavaScript
/// numbers, so they are represented as `f64` to compare limits identically.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthenticationProgramStateMetrics {
    pub arithmetic_cost: f64,
    pub defined_functions: f64,
    pub density_control_length: f64,
    pub evaluated_instruction_count: f64,
    pub hash_digest_iterations: f64,
    pub maximum_hash_digest_iterations: f64,
    pub maximum_operation_cost: f64,
    pub maximum_signature_check_count: f64,
    pub operation_cost: f64,
    pub signature_check_count: f64,
    pub stack_pushed_bytes: f64,
    /// The `maxMemoryUsage` metric of {@link AuthenticationProgramStateBchSpec}
    /// (never initialized by libauth, so it remains `undefined`).
    pub max_memory_usage: Option<f64>,
}

/// The program state common to the BCH virtual machines.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticationProgramStateCommon {
    pub alternate_stack: Vec<Vec<u8>>,
    pub control_stack: Vec<AuthenticationProgramStateControlStackItem>,
    pub error: Option<String>,
    /// The functions defined by `OP_DEFINE`, keyed by the hex-encoded
    /// function identifier.
    pub function_table: BTreeMap<String, Vec<u8>>,
    pub function_count: usize,
    pub instructions: Rc<Vec<AuthenticationInstruction>>,
    pub ip: isize,
    pub last_code_separator: isize,
    pub metrics: AuthenticationProgramStateMetrics,
    pub operation_count: usize,
    pub program: Rc<AuthenticationProgramCommon>,
    pub signed_messages: Vec<AuthenticationProgramStateSignedMessage>,
    pub stack: Vec<Vec<u8>>,
}

impl AuthenticationProgramStateMinimum for AuthenticationProgramStateCommon {
    fn instructions(&self) -> &[AuthenticationInstruction] {
        &self.instructions
    }

    fn ip(&self) -> isize {
        self.ip
    }

    fn ip_mut(&mut self) -> &mut isize {
        &mut self.ip
    }

    fn evaluated_instruction_count_mut(&mut self) -> &mut f64 {
        &mut self.metrics.evaluated_instruction_count
    }
}
