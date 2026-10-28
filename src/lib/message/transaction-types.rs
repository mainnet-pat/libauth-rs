use crate::compiler::CompilationData;
use crate::compiler::Compiler;
use crate::language::{CompilationError, ResolvedSegment};

/// A transaction input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input<Bytecode = Vec<u8>, ByteStringRepresentation = Vec<u8>> {
    /// The outpoint transaction hash in user-interface (big-endian) byte order.
    pub outpoint_transaction_hash: ByteStringRepresentation,
    pub outpoint_index: u32,
    pub unlocking_bytecode: Bytecode,
    pub sequence_number: u32,
}

/// The capability assigned to a non-fungible token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NonFungibleTokenCapability {
    None,
    Mutable,
    Minting,
}

impl NonFungibleTokenCapability {
    /// The capability's label (libauth's string enum value).
    pub const fn as_str(self) -> &'static str {
        match self {
            NonFungibleTokenCapability::None => "none",
            NonFungibleTokenCapability::Mutable => "mutable",
            NonFungibleTokenCapability::Minting => "minting",
        }
    }
}

/// A non-fungible token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nft {
    pub capability: NonFungibleTokenCapability,
    pub commitment: Vec<u8>,
}

/// The CashToken contents of an output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The token category ID in user-interface (big-endian) byte order.
    pub category: Vec<u8>,
    pub amount: u64,
    pub nft: Option<Nft>,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub locking_bytecode: Vec<u8>,
    pub token: Option<Token>,
    pub value_satoshis: u64,
}

/// An intentionally-invalid `valueSatoshis` encoding (the maximum uint64,
/// `0xffffffffffffffff`), used by transaction generation to indicate that a
/// value has not yet been set.
pub const excessiveSatoshis: [u8; 8] = [255; 8];

/// A version 1 or 2 transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionCommon<InputType = Input, OutputType = Output> {
    pub version: u32,
    pub inputs: Vec<InputType>,
    pub outputs: Vec<OutputType>,
    pub locktime: u32,
}

/// A compilation directive for a locking script.
#[derive(Clone)]
pub struct CompilationDirectiveLocking {
    /// The compiler with which to generate bytecode.
    pub compiler: Compiler,
    /// The compilation data required to compile the script (if any).
    pub data: Option<CompilationData>,
    /// The script ID to compile.
    pub script: String,
}

/// A compilation directive for an unlocking script.
#[derive(Clone)]
pub struct CompilationDirectiveUnlocking {
    /// The compiler with which to generate bytecode.
    pub compiler: Compiler,
    /// The compilation data required to compile the script (if any).
    pub data: Option<CompilationData>,
    /// The script ID to compile.
    pub script: String,
    /// The value in satoshis of the output being spent by this input.
    pub value_satoshis: u64,
    /// The CashToken contents of the output being spent by this input.
    pub token: Option<Token>,
}

/// libauth's `CompilationDirectiveUnlockingEstimate`: an unlocking
/// compilation directive plus a scenario ID used for fee estimation.
#[derive(Clone)]
pub struct CompilationDirectiveUnlockingEstimate {
    pub compiler: Compiler,
    pub data: Option<CompilationData>,
    pub script: String,
    pub value_satoshis: u64,
    pub token: Option<Token>,
    pub estimate: String,
}

/// The `lockingBytecode` of an output template.
#[derive(Clone)]
pub enum OutputLockingBytecode {
    Bytecode(Vec<u8>),
    Compilation(CompilationDirectiveLocking),
}

/// The `unlockingBytecode` of an input template.
#[derive(Clone)]
pub enum InputUnlockingBytecode {
    Bytecode(Vec<u8>),
    Compilation(CompilationDirectiveUnlocking),
}

/// An output that may optionally use a compilation directive as its
/// `lockingBytecode`.
#[derive(Clone)]
pub struct OutputTemplate {
    pub locking_bytecode: OutputLockingBytecode,
    pub token: Option<Token>,
    pub value_satoshis: u64,
}

/// An input that may optionally use a compilation directive as its
/// `unlockingBytecode`.
#[derive(Clone)]
pub struct InputTemplate {
    pub outpoint_transaction_hash: Vec<u8>,
    pub outpoint_index: u32,
    pub unlocking_bytecode: InputUnlockingBytecode,
    pub sequence_number: u32,
}

/// libauth's `TransactionTemplate`: a transaction whose bytecode may be
/// generated from compilation directives.
pub type TransactionTemplate = TransactionTemplateFixed;

/// A transaction template where all output amounts are provided.
#[derive(Clone)]
pub struct TransactionTemplateFixed {
    pub inputs: Vec<InputTemplate>,
    pub locktime: u32,
    pub outputs: Vec<OutputTemplate>,
    pub version: u32,
}

/// libauth's `TransactionTemplateEstimated`: a transaction template with the
/// total input value required for fee estimation.
#[derive(Clone)]
pub struct TransactionTemplateEstimated {
    pub inputs: Vec<InputTemplate>,
    pub locktime: u32,
    pub outputs: Vec<OutputTemplate>,
    pub version: u32,
    /// The total satoshi value of all transaction inputs.
    pub total_input_value_satoshis: u64,
}

/// The type of bytecode that was being generated when an error occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BytecodeGenerationType {
    Locking,
    Unlocking,
}

impl BytecodeGenerationType {
    pub fn as_str(self) -> &'static str {
        match self {
            BytecodeGenerationType::Locking => "locking",
            BytecodeGenerationType::Unlocking => "unlocking",
        }
    }
}

/// An error resulting from unsuccessful bytecode generation.
#[derive(Clone, Debug)]
pub struct BytecodeGenerationErrorBase {
    pub bytecode_type: BytecodeGenerationType,
    pub index: usize,
    pub resolved: Option<Vec<ResolvedSegment>>,
    pub errors: Vec<CompilationError>,
}

/// The base shared by libauth's bytecode completion objects.
#[derive(Clone, Debug)]
pub struct BytecodeGenerationCompletionBase {
    /// The index of the input or output for which bytecode was generated.
    pub index: usize,
}

/// libauth's `BytecodeGenerationCompletionInput` (`type: 'input'`).
#[derive(Clone, Debug)]
pub struct BytecodeGenerationCompletionInput {
    /// The index of the input for which bytecode was generated.
    pub index: usize,
    /// The successfully generated input.
    pub input: Input,
}

/// libauth's `BytecodeGenerationCompletionOutput` (`type: 'output'`).
#[derive(Clone, Debug)]
pub struct BytecodeGenerationCompletionOutput {
    /// The index of the output for which bytecode was generated.
    pub index: usize,
    /// The successfully generated output.
    pub output: Output,
}

/// libauth's `BytecodeGenerationErrorLocking` (`type: 'locking'`).
pub type BytecodeGenerationErrorLocking = BytecodeGenerationErrorBase;

/// libauth's `BytecodeGenerationErrorUnlocking` (`type: 'unlocking'`).
pub type BytecodeGenerationErrorUnlocking = BytecodeGenerationErrorBase;

/// A successfully generated input or output.
#[derive(Clone, Debug)]
pub enum BytecodeGenerationCompletion {
    Input(BytecodeGenerationCompletionInput),
    Output(BytecodeGenerationCompletionOutput),
}

/// The stage at which transaction generation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionGenerationStage {
    Inputs,
    Outputs,
}

impl TransactionGenerationStage {
    pub fn as_str(self) -> &'static str {
        match self {
            TransactionGenerationStage::Inputs => "inputs",
            TransactionGenerationStage::Outputs => "outputs",
        }
    }
}

/// A successfully generated transaction.
#[derive(Clone, Debug)]
pub struct TransactionGenerationSuccess {
    pub transaction: TransactionCommon,
}

/// An unsuccessful transaction generation attempt.
#[derive(Clone, Debug)]
pub struct TransactionGenerationError {
    pub completions: Vec<BytecodeGenerationCompletion>,
    pub errors: Vec<BytecodeGenerationErrorBase>,
    pub stage: TransactionGenerationStage,
}

/// The result of a transaction generation attempt.
#[derive(Clone, Debug)]
pub enum TransactionGenerationAttempt {
    Success(TransactionGenerationSuccess),
    Error(TransactionGenerationError),
}

impl TransactionGenerationAttempt {
    pub fn is_success(&self) -> bool {
        matches!(self, TransactionGenerationAttempt::Success(_))
    }

    pub fn success(&self) -> Option<&TransactionCommon> {
        match self {
            TransactionGenerationAttempt::Success(success) => Some(&success.transaction),
            TransactionGenerationAttempt::Error(_) => None,
        }
    }

    pub fn error(&self) -> Option<&TransactionGenerationError> {
        match self {
            TransactionGenerationAttempt::Success(_) => None,
            TransactionGenerationAttempt::Error(error) => Some(error),
        }
    }
}
