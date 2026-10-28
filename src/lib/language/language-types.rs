//! CashAssembly language types.
//!
//! Port of libauth's `language/language-types.ts`.

use crate::vm::{AuthenticationInstruction, AuthenticationProgramStateCommon};

/// A range of source text, mirroring libauth's `Range`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    pub end_column: usize,
    pub end_line_number: usize,
    pub start_column: usize,
    pub start_line_number: usize,
}

/// A position in source text. `line` and `column` are one-based, `offset` is a
/// UTF-16 code unit offset (matching JavaScript string indexing).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourcePosition {
    pub column: usize,
    pub line: usize,
    pub offset: usize,
}

/// A source node with a start and end position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkedNode {
    pub end: SourcePosition,
    pub start: SourcePosition,
}

/// The name of a CashAssembly segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentName {
    BigIntLiteral,
    BinaryLiteral,
    Comment,
    Evaluation,
    HexLiteral,
    Identifier,
    Push,
    Script,
    Utf8Literal,
}

impl SegmentName {
    pub fn as_str(self) -> &'static str {
        match self {
            SegmentName::BigIntLiteral => "BigIntLiteral",
            SegmentName::BinaryLiteral => "BinaryLiteral",
            SegmentName::Comment => "Comment",
            SegmentName::Evaluation => "Evaluation",
            SegmentName::HexLiteral => "HexLiteral",
            SegmentName::Identifier => "Identifier",
            SegmentName::Push => "Push",
            SegmentName::Script => "Script",
            SegmentName::Utf8Literal => "UTF8Literal",
        }
    }
}

/// The value of a CashAssembly segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegmentValue {
    /// The contents of a `Script` segment.
    Script(Vec<Segment>),
    /// The inner `Script` of a `Push` segment (`<...>`).
    Push(Box<Segment>),
    /// The inner `Script` of an `Evaluation` segment (`$(...)`).
    Evaluation(Box<Segment>),
    /// The source text of a string segment (literal, identifier, or comment).
    Text(String),
}

/// A parsed CashAssembly segment. Mirrors libauth's
/// `CashAssemblyScriptSegment` (including `name`, `start`, `end`, and `value`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub end: SourcePosition,
    pub name: SegmentName,
    pub start: SourcePosition,
    pub value: SegmentValue,
}

impl Segment {
    pub fn children(&self) -> &[Segment] {
        match &self.value {
            SegmentValue::Script(children) => children,
            SegmentValue::Push(inner) | SegmentValue::Evaluation(inner) => inner.children(),
            SegmentValue::Text(_) => &[],
        }
    }

    /// The inner `Script` node of a `Push` or `Evaluation` segment.
    pub fn inner_script(&self) -> Option<&Segment> {
        match &self.value {
            SegmentValue::Push(inner) | SegmentValue::Evaluation(inner) => Some(inner),
            _ => None,
        }
    }

    pub fn text(&self) -> Option<&str> {
        match &self.value {
            SegmentValue::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn range(&self) -> Range {
        Range {
            end_column: self.end.column,
            end_line_number: self.end.line,
            start_column: self.start.column,
            start_line_number: self.start.line,
        }
    }
}

/// The result of parsing a CashAssembly script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseResult {
    Failure {
        expected: Vec<String>,
        index: SourcePosition,
    },
    Success(Segment),
}

/// The literal types which resolve directly to bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedSegmentLiteralType {
    BigIntLiteral,
    BinaryLiteral,
    HexLiteral,
    Utf8Literal,
}

impl ResolvedSegmentLiteralType {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolvedSegmentLiteralType::BigIntLiteral => "BigIntLiteral",
            ResolvedSegmentLiteralType::BinaryLiteral => "BinaryLiteral",
            ResolvedSegmentLiteralType::HexLiteral => "HexLiteral",
            ResolvedSegmentLiteralType::Utf8Literal => "UTF8Literal",
        }
    }
}

/// A literal resolved to bytecode (libauth's `ResolvedSegmentLiteralBytecode`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentLiteralBytecode {
    pub range: Range,
    pub literal: String,
    pub literal_type: ResolvedSegmentLiteralType,
    pub value: Vec<u8>,
}

/// An opcode identifier resolved to bytecode (libauth's
/// `ResolvedSegmentOpcodeBytecode`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentOpcodeBytecode {
    pub range: Range,
    pub opcode: String,
    pub value: Vec<u8>,
}

/// A script identifier resolved to bytecode (libauth's
/// `ResolvedSegmentScriptBytecode`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentScriptBytecode {
    pub range: Range,
    pub script: String,
    pub source: Box<CompilationResultSuccess>,
    pub value: Vec<u8>,
}

/// A variable identifier resolved to bytecode (libauth's
/// `ResolvedSegmentVariableBytecode`, which includes `ResolutionSignature`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentVariableBytecode {
    pub range: Range,
    pub signature: Option<SignatureInfo>,
    pub value: Vec<u8>,
    pub variable: String,
}

/// A segment resolved to bytecode (libauth's `ResolvedSegmentBytecode`).
#[derive(Clone, Debug)]
pub enum ResolvedSegmentBytecode {
    Literal(ResolvedSegmentLiteralBytecode),
    Opcode(ResolvedSegmentOpcodeBytecode),
    Script(ResolvedSegmentScriptBytecode),
    Variable(ResolvedSegmentVariableBytecode),
}

impl ResolvedSegmentBytecode {
    /// The range of the resolved segment.
    pub fn range(&self) -> Range {
        match self {
            ResolvedSegmentBytecode::Literal(segment) => segment.range,
            ResolvedSegmentBytecode::Opcode(segment) => segment.range,
            ResolvedSegmentBytecode::Script(segment) => segment.range,
            ResolvedSegmentBytecode::Variable(segment) => segment.range,
        }
    }

    /// The resolved bytecode.
    pub fn value(&self) -> &[u8] {
        match self {
            ResolvedSegmentBytecode::Literal(segment) => &segment.value,
            ResolvedSegmentBytecode::Opcode(segment) => &segment.value,
            ResolvedSegmentBytecode::Script(segment) => &segment.value,
            ResolvedSegmentBytecode::Variable(segment) => &segment.value,
        }
    }
}

/// A compilation error. When `missing_identifier` and `owning_entity` are set,
/// the error is recoverable by providing the referenced variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilationError {
    pub error: String,
    pub range: Range,
    pub missing_identifier: Option<String>,
    pub owning_entity: Option<String>,
}

impl CompilationError {
    pub fn is_recoverable(&self) -> bool {
        self.missing_identifier.is_some() && self.owning_entity.is_some()
    }
}

/// A resolved CashAssembly segment.
#[derive(Clone, Debug)]
pub enum ResolvedSegment {
    Bytecode(ResolvedSegmentBytecode),
    Comment(ResolvedSegmentComment),
    Error(ResolvedSegmentError),
    Evaluation(ResolvedSegmentEvaluation),
    Push(ResolvedSegmentPush),
}

impl ResolvedSegment {
    pub fn range(&self) -> Range {
        match self {
            ResolvedSegment::Bytecode(bytecode) => bytecode.range(),
            ResolvedSegment::Comment(segment) => segment.range,
            ResolvedSegment::Error(segment) => segment.range,
            ResolvedSegment::Evaluation(segment) => segment.range,
            ResolvedSegment::Push(segment) => segment.range,
        }
    }
}

/// A comment (libauth's `ResolvedSegmentComment`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentComment {
    pub range: Range,
    pub value: String,
}

/// A resolution error (libauth's `ResolvedSegmentError`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentError {
    pub range: Range,
    pub value: String,
    pub missing_identifier: Option<String>,
    pub owning_entity: Option<String>,
}

/// An evaluation (libauth's `ResolvedSegmentEvaluation`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentEvaluation<T = Vec<ResolvedSegment>> {
    pub range: Range,
    pub value: T,
}

/// A push (libauth's `ResolvedSegmentPush`).
#[derive(Clone, Debug)]
pub struct ResolvedSegmentPush<T = Vec<ResolvedSegment>> {
    pub range: Range,
    pub value: T,
}

/// A resolved script (libauth's `ResolvedScript`).
pub type ResolvedScript = Vec<ResolvedSegment>;

/// A node in a script reduction trace (libauth's `ScriptReductionTraceNode`).
#[derive(Clone, Debug)]
pub struct ScriptReductionTraceNode {
    pub bytecode: Vec<u8>,
    pub errors: Option<Vec<CompilationError>>,
    pub range: Range,
}

/// A reduction trace node with errors (libauth's
/// `ScriptReductionTraceErrorNode`).
#[derive(Clone, Debug)]
pub struct ScriptReductionTraceErrorNode {
    pub bytecode: Vec<u8>,
    pub errors: Vec<CompilationError>,
    pub range: Range,
}

/// A comment in a reduction trace (libauth's
/// `ScriptReductionTraceCommentNode`).
#[derive(Clone, Debug)]
pub struct ScriptReductionTraceCommentNode {
    pub bytecode: Vec<u8>,
    pub comment: String,
    pub errors: Option<Vec<CompilationError>>,
    pub range: Range,
}

/// A script in a reduction trace (libauth's
/// `ScriptReductionTraceScriptNode`).
#[derive(Clone, Debug)]
pub struct ScriptReductionTraceScriptNode {
    pub bytecode: Vec<u8>,
    pub errors: Option<Vec<CompilationError>>,
    pub range: Range,
    pub script: Vec<ScriptReductionTraceChildNode>,
}

/// A push in a reduction trace (libauth's `ScriptReductionTracePushNode`).
#[derive(Clone, Debug)]
pub struct ScriptReductionTracePushNode {
    pub bytecode: Vec<u8>,
    pub errors: Option<Vec<CompilationError>>,
    pub push: Box<ScriptReductionTraceScriptNode>,
    pub range: Range,
}

/// An evaluation in a reduction trace (libauth's
/// `ScriptReductionTraceEvaluationNode`).
#[derive(Clone, Debug)]
pub struct ScriptReductionTraceEvaluationNode {
    pub bytecode: Vec<u8>,
    pub errors: Option<Vec<CompilationError>>,
    pub range: Range,
    pub source: Box<ScriptReductionTraceScriptNode>,
    pub trace: Vec<AuthenticationProgramStateCommon>,
}

/// A child node of a {@link ScriptReductionTraceScriptNode} (libauth's
/// `ScriptReductionTraceChildNode`).
#[derive(Clone, Debug)]
pub enum ScriptReductionTraceChildNode {
    Comment(ScriptReductionTraceCommentNode),
    Error(ScriptReductionTraceErrorNode),
    Evaluation(ScriptReductionTraceEvaluationNode),
    Bytecode(ScriptReductionTraceNode),
    Push(ScriptReductionTracePushNode),
}

impl ScriptReductionTraceChildNode {
    pub fn bytecode(&self) -> &[u8] {
        match self {
            ScriptReductionTraceChildNode::Comment(node) => &node.bytecode,
            ScriptReductionTraceChildNode::Error(node) => &node.bytecode,
            ScriptReductionTraceChildNode::Evaluation(node) => &node.bytecode,
            ScriptReductionTraceChildNode::Bytecode(node) => &node.bytecode,
            ScriptReductionTraceChildNode::Push(node) => &node.bytecode,
        }
    }

    pub fn range(&self) -> Range {
        match self {
            ScriptReductionTraceChildNode::Comment(node) => node.range,
            ScriptReductionTraceChildNode::Error(node) => node.range,
            ScriptReductionTraceChildNode::Evaluation(node) => node.range,
            ScriptReductionTraceChildNode::Bytecode(node) => node.range,
            ScriptReductionTraceChildNode::Push(node) => node.range,
        }
    }

    pub fn errors(&self) -> Option<&[CompilationError]> {
        match self {
            ScriptReductionTraceChildNode::Error(node) => Some(&node.errors),
            ScriptReductionTraceChildNode::Comment(node) => node.errors.as_deref(),
            ScriptReductionTraceChildNode::Evaluation(node) => node.errors.as_deref(),
            ScriptReductionTraceChildNode::Bytecode(node) => node.errors.as_deref(),
            ScriptReductionTraceChildNode::Push(node) => node.errors.as_deref(),
        }
    }
}

/// The transformation applied to a compilation result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transform {
    P2sh20Locking,
    P2sh20Unlocking,
    P2sh32Locking,
    P2sh32Unlocking,
}

impl Transform {
    pub fn as_str(self) -> &'static str {
        match self {
            Transform::P2sh20Locking => "p2sh20-locking",
            Transform::P2sh20Unlocking => "p2sh20-unlocking",
            Transform::P2sh32Locking => "p2sh32-locking",
            Transform::P2sh32Unlocking => "p2sh32-unlocking",
        }
    }
}

/// A successful compilation result.
#[derive(Clone, Debug)]
pub struct CompilationResultSuccess {
    pub bytecode: Vec<u8>,
    pub parse: Segment,
    pub reduce: ScriptReductionTraceScriptNode,
    pub resolve: Vec<ResolvedSegment>,
    pub transformed: Option<Transform>,
}

/// The stage at which a compilation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilationErrorType {
    Parse,
    Reduce,
    Resolve,
}

impl CompilationErrorType {
    pub fn as_str(self) -> &'static str {
        match self {
            CompilationErrorType::Parse => "parse",
            CompilationErrorType::Reduce => "reduce",
            CompilationErrorType::Resolve => "resolve",
        }
    }
}

/// An unsuccessful compilation result.
#[derive(Clone, Debug)]
pub struct CompilationResultError {
    pub error_type: CompilationErrorType,
    pub errors: Vec<CompilationError>,
    pub parse: Option<Segment>,
    pub reduce: Option<ScriptReductionTraceScriptNode>,
    pub resolve: Option<Vec<ResolvedSegment>>,
}

/// The result of parsing, resolving, and reducing a script.
#[derive(Clone, Debug)]
pub enum CompilationResult {
    Success(Box<CompilationResultSuccess>),
    Error(CompilationResultError),
}

/// The type of an identifier resolution (`IdentifierResolutionType` in
/// libauth's `language-types`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierResolutionType {
    /// The identifier resolves to an opcode.
    Opcode,
    /// The identifier resolves to a template variable.
    Variable,
    /// The identifier resolves to an included script.
    Script,
}

impl IdentifierResolutionType {
    /// The serialized identifier type used by libauth.
    pub const fn text(self) -> &'static str {
        match self {
            Self::Opcode => "opcode",
            Self::Variable => "variable",
            Self::Script => "script",
        }
    }
}

/// libauth's `CompilationResultResolve`.
#[derive(Clone, Debug)]
pub struct CompilationResultResolve {
    pub parse: Segment,
    pub resolve: Vec<ResolvedSegment>,
}

/// libauth's `CompilationResultReduce`.
#[derive(Clone, Debug)]
pub struct CompilationResultReduce {
    pub parse: Segment,
    pub reduce: ScriptReductionTraceScriptNode,
    pub resolve: Vec<ResolvedSegment>,
}

/// libauth's `ResolutionSignature`.
#[derive(Clone, Debug, Default)]
pub struct ResolutionSignature {
    pub signature: Option<SignatureInfo>,
}

/// libauth's `ResolutionDebug`.
#[derive(Default)]
pub struct ResolutionDebug {
    pub debug: Option<Box<dyn std::any::Any>>,
}

/// libauth's `InstructionAggregation`.
#[derive(Clone, Debug)]
pub struct InstructionAggregation {
    pub instructions: Vec<AuthenticationInstruction>,
    pub last_ip: usize,
    pub range: Range,
}

/// libauth's `InstructionAggregationSuccess`.
#[derive(Clone, Debug)]
pub struct InstructionAggregationSuccess {
    pub aggregations: Vec<InstructionAggregation>,
    pub success: bool,
}

/// libauth's `InstructionAggregationError`.
#[derive(Clone, Debug)]
pub struct InstructionAggregationError {
    pub aggregations: Vec<InstructionAggregation>,
    pub remaining_bytecode: Vec<u8>,
    pub remaining_range: Range,
    pub success: bool,
}

/// libauth's `TraceSample`.
#[derive(Clone, Debug)]
pub struct TraceSample<ProgramState = AuthenticationProgramStateCommon> {
    pub range: Range,
    pub state: ProgramState,
}

/// An instruction and the program state which resulted from its evaluation,
/// occurring within the range of a single reduction trace node (an element of
/// {@link EvaluationSample.internalStates}).
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationInternalState<ProgramState = AuthenticationProgramStateCommon> {
    pub instruction: AuthenticationInstruction,
    pub state: ProgramState,
}

/// An evaluation sample extracted from a script reduction trace: the range of
/// the evaluation, the instruction which was evaluated, the range in the source
/// script over which the instruction was defined, and the resulting state.
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationSample<ProgramState = AuthenticationProgramStateCommon> {
    /// The range of the evaluation node in which this sample was generated.
    ///
    /// This can be used to identify which evaluation produced this sample.
    pub evaluation_range: Range,
    /// The final instruction which was evaluated during this sample.
    ///
    /// Note, the first sample of any evaluation is the initial state, so it has
    /// no instruction.
    pub instruction: Option<AuthenticationInstruction>,
    /// An ordered array of instructions and program states which occurred
    /// within the range of a single reduction trace node before the final
    /// instruction and state (assigned to `instruction` and `state`,
    /// respectively).
    pub internal_states: Vec<EvaluationInternalState<ProgramState>>,
    /// An ordered array of program states which resulted from the evaluation of
    /// this sample's instruction in subsequent iterations (e.g. within an
    /// `OP_BEGIN ... OP_UNTIL` loop).
    pub iterations: Option<Vec<ProgramState>>,
    /// The range over which this sample was defined in the source script.
    pub range: Range,
    /// The program state after the evaluation of this sample's `instruction`.
    pub state: ProgramState,
}

/// libauth's `CashAssemblyScriptSegment`: the crate's [`Segment`] carries the
/// same name, start/end positions, and value.
pub type CashAssemblyScriptSegment = Segment;

/// A fatal compilation error (libauth's `CompilationErrorFatal`): a
/// {@link CompilationError} without `missingIdentifier` or `owningEntity`.
pub type CompilationErrorFatal = CompilationError;

/// A recoverable compilation error (libauth's `CompilationErrorRecoverable`): a
/// {@link CompilationError} with `missingIdentifier` and `owningEntity`.
pub type CompilationErrorRecoverable = CompilationError;

/// The properties shared by all compilation errors (libauth's
/// `CompilationResultErrorBase`).
pub type CompilationResultErrorBase = CompilationResultError;

/// A compilation that failed while parsing (libauth's
/// `CompilationResultParseError`, `errorType: 'parse'`).
pub type CompilationResultParseError = CompilationResultError;

/// A compilation that failed while resolving identifiers (libauth's
/// `CompilationResultResolveError`, `errorType: 'resolve'`).
pub type CompilationResultResolveError = CompilationResultError;

/// A compilation that failed while reducing the resolved script (libauth's
/// `CompilationResultReduceError`, `errorType: 'reduce'`).
pub type CompilationResultReduceError = CompilationResultError;

/// A function that resolves a CashAssembly identifier (libauth's
/// `IdentifierResolutionFunction`).
pub type IdentifierResolutionFunction<'a> = dyn Fn(&str) -> IdentifierResolution + 'a;

/// The result of an {@link IdentifierResolutionFunction}: the resolved bytecode
/// (`status: true`) of an opcode, variable, or script, or an error
/// (`status: false`) of type {@link IdentifierResolutionErrorType}.
#[derive(Clone, Debug)]
pub enum IdentifierResolution {
    /// `{ bytecode, status: true, type: IdentifierResolutionType.opcode }`
    Opcode { bytecode: Vec<u8> },
    /// `{ bytecode, signature?, status: true, type: IdentifierResolutionType.variable }`
    Variable {
        bytecode: Vec<u8>,
        signature: Option<SignatureInfo>,
    },
    /// `{ bytecode, source, status: true, type: IdentifierResolutionType.script }`
    Script {
        bytecode: Vec<u8>,
        source: Box<CompilationResultSuccess>,
    },
    /// `{ error, entityOwnership?, recoverable, status: false, type: IdentifierResolutionErrorType.variable }`
    VariableError {
        entity_ownership: Option<String>,
        error: String,
        recoverable: bool,
    },
    /// `{ error, scriptId, status: false, type: IdentifierResolutionErrorType.script }`
    ScriptError { error: String, script_id: String },
    /// `{ error, status: false, type: IdentifierResolutionErrorType.unknown }`
    UnknownError { error: String },
}

/// The type of an unsuccessful identifier resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierResolutionErrorType {
    Unknown,
    Variable,
    Script,
}

/// The signature produced while resolving a variable (the value of
/// {@link ResolutionSignature.signature}): a data signature's `digest` and
/// `message`, or a transaction signature's signing `serialization`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureInfo {
    Data { digest: Vec<u8>, message: Vec<u8> },
    Serialization(Vec<u8>),
}
