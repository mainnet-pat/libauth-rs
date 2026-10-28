use std::collections::BTreeMap;
use std::rc::Rc;

use crate::crypto::{Ripemd160, Secp256k1, Sha256, Sha512};
use crate::engine::{
    WalletTemplateLockingType, WalletTemplateScenario, WalletTemplateTimeLockType,
    WalletTemplateVariable,
};
use crate::language::{CompilationResult, CompilationResultError, SignatureInfo};
use crate::runtime::json::Json;
use crate::vm::{AuthenticationProgramBch, AuthenticationProgramCommon, AuthenticationVirtualMachineBch, CompilationContextBch};

/// libauth's `CompilerOperationDebug`: the optional `debug` value (of an
/// unknown type) which may be returned by a compiler operation.
pub type CompilerOperationDebug = Option<Json>;

/// An error produced by a compiler operation (libauth's
/// `CompilerOperationErrorFatal` or, with `recoverable` set,
/// `CompilerOperationErrorRecoverable`).
#[derive(Clone, Debug, PartialEq)]
pub struct CompilerOperationError {
    pub debug: CompilerOperationDebug,
    pub error: String,
    /// If `true`, the error may be resolved by providing the missing data
    /// (e.g. a private key) in the compilation data.
    pub recoverable: bool,
}

/// A non-recoverable error produced by a compiler operation (a
/// {@link CompilerOperationError} without `recoverable`).
pub type CompilerOperationErrorFatal = CompilerOperationError;

/// An error which may be resolved by providing missing data (a
/// {@link CompilerOperationError} with `recoverable`).
pub type CompilerOperationErrorRecoverable = CompilerOperationError;

/// A successful compiler operation result, optionally including the signature
/// produced by the operation (libauth's `CompilerOperationSuccessGeneric`,
/// `CompilerOperationSuccessSignature`, or
/// `CompilerOperationSuccessDataSignature`).
#[derive(Clone, Debug, PartialEq)]
pub struct CompilerOperationSuccess {
    pub bytecode: Vec<u8>,
    pub debug: CompilerOperationDebug,
    pub signature: Option<SignatureInfo>,
}

/// A successful compiler operation result without a signature.
pub type CompilerOperationSuccessGeneric = CompilerOperationSuccess;

/// A successful compiler operation result with a signature
/// ({@link CompilerOperationSuccessSignature} or
/// {@link CompilerOperationSuccessDataSignature}).
pub type CompilerOperationSuccessSignatureType = CompilerOperationSuccess;

/// A successful compiler operation result with a transaction signature
/// (`signature.serialization`).
pub type CompilerOperationSuccessSignature = CompilerOperationSuccess;

/// A successful compiler operation result with a data signature
/// (`signature.digest` and `signature.message`).
pub type CompilerOperationSuccessDataSignature = CompilerOperationSuccess;

/// An unsuccessful compilation result which should be skipped (to attempt
/// another operation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompilerOperationSkip;

/// The result of a compiler operation (`status: 'error' | 'skip' | 'success'`).
#[derive(Clone, Debug, PartialEq)]
pub enum CompilerOperationResult {
    Error(CompilerOperationError),
    Skip(CompilerOperationSkip),
    Success(CompilerOperationSuccess),
}

/// A compiler operation method.
pub type CompilerOperation = Rc<dyn Fn(&str, &CompilationData, &CompilerConfiguration) -> CompilerOperationResult>;

/// The key operations common to the BCH compilers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerOperationsKeysCommon {
    EcdsaSignature,
    PublicKey,
}

/// Valid identifiers for full transaction signing serialization algorithms.
/// Each full serialization is double-sha256 hashed to produce the digest which
/// is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerOperationsSigningSerializationFull {
    FullAllOutputsAllUtxos,
    FullAllOutputsSingleInputInvalidAllUtxos,
    FullAllOutputsSingleInput,
    FullAllOutputs,
    FullCorrespondingOutputAllUtxos,
    FullCorrespondingOutputSingleInputInvalidAllUtxos,
    FullCorrespondingOutputSingleInput,
    FullCorrespondingOutput,
    FullDefault,
    FullNoOutputsAllUtxos,
    FullNoOutputsSingleInputInvalidAllUtxos,
    FullNoOutputsSingleInput,
    FullNoOutputs,
}

/// Valid identifiers for components of transaction signing serializations.
/// Components are combined in various orders to produce each of the valid
/// "full" signing serializations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerOperationsSigningSerializationComponent {
    CorrespondingOutputHash,
    CorrespondingOutput,
    CoveredBytecodeLength,
    CoveredBytecode,
    Locktime,
    OutpointIndex,
    OutpointTransactionHash,
    OutputValue,
    SequenceNumber,
    TransactionOutpointsHash,
    TransactionOutpoints,
    TransactionOutputsHash,
    TransactionOutputs,
    TransactionSequenceNumbersHash,
    TransactionSequenceNumbers,
    Version,
}

/// Valid identifiers indicating the components of transaction signing
/// serializations ({@link CompilerOperationsSigningSerializationComponent} or
/// {@link CompilerOperationsSigningSerializationFull}).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerOperationsSigningSerializationCommon {
    Component(CompilerOperationsSigningSerializationComponent),
    Full(CompilerOperationsSigningSerializationFull),
}

/// The operations of a compiler configuration for one variable type: either a
/// single operation (used for every operation identifier) or an object of
/// operations by operation identifier.
#[derive(Clone)]
pub enum CompilerOperationSet {
    Single(CompilerOperation),
    Multiple(BTreeMap<String, CompilerOperation>),
}

/// The `operations` of a {@link CompilerConfiguration}, by variable type.
#[derive(Clone, Default)]
pub struct CompilerOperations {
    pub hd_key: Option<CompilerOperationSet>,
    pub key: Option<CompilerOperationSet>,
    pub address_data: Option<CompilerOperationSet>,
    pub wallet_data: Option<CompilerOperationSet>,
    pub current_block_height: Option<CompilerOperationSet>,
    pub current_block_time: Option<CompilerOperationSet>,
    pub signing_serialization: Option<CompilerOperationSet>,
}

/// The full context required to compile a given CashAssembly Template script –
/// everything required for the compiler to understand the CompilationData and
/// generate the compiled bytecode (targeting a specific
/// {@link AuthenticationVirtualMachine}).
///
/// @remarks
/// A {@link CompilerConfiguration} must include a subset of the script's
/// {@link WalletTemplate} – all the variables and scripts referenced
/// (including children of children) by the script in question.
///
/// The context must also include an object mapping of opcode identifiers to the
/// bytecode they generate.
///
/// If keys are used, an implementation of `sha256` and `secp256k1` is
/// required. If the script requires evaluations during compilation, the
/// evaluating {@link AuthenticationVirtualMachine} must also be included.
#[derive(Clone, Default)]
pub struct CompilerConfiguration {
    /// A method that accepts the compiled bytecode contents of a CashAssembly
    /// evaluation and produces the equivalent {@link AuthenticationProgram} to
    /// be evaluated by the VM. This method is used internally to compute
    /// CashAssembly evaluations. See
    /// {@link createAuthenticationProgramEvaluationCommon} for details.
    pub create_authentication_program: Option<Rc<dyn Fn(&[u8]) -> AuthenticationProgramBch>>,
    /// An object mapping variable identifiers to the entity identifiers
    /// responsible for them. This is required for `HdKey` support, as each
    /// entity uses a single HD private key (provided in `hdKeys.hdPrivateKeys`)
    /// or HD public key (provided in `hdKeys.hdPublicKeys`) per compilation,
    /// and each `HdKey` variable is derived from this key.
    pub entity_ownership: Option<BTreeMap<String, String>>,
    /// An object mapping the script identifiers of locking scripts to their
    /// locking script type, either `standard`, `p2sh20`, or `p2sh32`.
    pub locking_script_types: Option<BTreeMap<String, WalletTemplateLockingType>>,
    /// An object mapping opcode identifiers to the bytecode they generate.
    pub opcodes: Option<BTreeMap<String, Vec<u8>>>,
    /// An object specifying the operations made available by this compiler
    /// configuration for each variable type.
    pub operations: Option<CompilerOperations>,
    /// An implementation of ripemd160 is required for any scripts which include
    /// `HdKey`s. This can be instantiated with {@link instantiateRipemd160}.
    pub ripemd160: Option<Ripemd160>,
    /// An object mapping scenario identifiers to the
    /// {@link WalletTemplateScenario}s they represent.
    pub scenarios: Option<BTreeMap<String, WalletTemplateScenario>>,
    /// An object mapping script identifiers to the text of script in CashAssembly.
    pub scripts: BTreeMap<String, String>,
    /// An implementation of secp256k1 is required for any scripts which include
    /// signatures. This can be instantiated with {@link instantiateSecp256k1}.
    pub secp256k1: Option<Secp256k1>,
    /// An implementation of sha256 is required for any scripts which include
    /// signatures. This can be instantiated with {@link instantiateSha256}.
    pub sha256: Option<Sha256>,
    /// An implementation of sha512 is required for any scripts which include
    /// `HdKey`s. This can be instantiated with {@link instantiateSha512}.
    pub sha512: Option<Sha512>,
    /// Only for use when recursively calling {@link compileScript} (e.g. in
    /// compiler operations).
    ///
    /// The "breadcrumb" path of script IDs currently being compiled, including
    /// the current script. (E.g. `["grandparentId", "parentId", "scriptId"]`)
    ///
    /// CashAssembly identifier resolution must be acyclic. To prevent an infinite
    /// loop, {@link IdentifierResolutionFunction}s must abort resolution if they
    /// encounter their own `id` while resolving another identifier. Likewise,
    /// child scripts being resolved by a parent script may not reference any
    /// script which is already in the process of being resolved.
    pub source_script_ids: Option<Vec<String>>,
    /// An object mapping the identifiers of unlocking scripts to the
    /// identifiers of the locking scripts they unlock. This is used to identify
    /// the `coveredBytecode` used in signing serializations, and it is required
    /// for all signature operations and many signing serialization operations.
    pub unlocking_scripts: Option<BTreeMap<String, String>>,
    /// An object mapping the identifiers of unlocking scripts to their
    /// `timeLockType`.
    ///
    /// The `timestamp` type indicates that the transaction's locktime is
    /// provided as a UNIX timestamp (the `locktime` value is greater than or
    /// equal to `500000000`).
    ///
    /// The `height` type indicates that the transaction's locktime is provided
    /// as a block height (the `locktime` value is less than `500000000`).
    ///
    /// See {@link WalletTemplateScriptUnlocking.timeLockType} for details.
    pub unlocking_script_time_lock_types: Option<BTreeMap<String, WalletTemplateTimeLockType>>,
    /// An object mapping template variable identifiers to the
    /// {@link WalletTemplateVariable} describing them.
    pub variables: Option<BTreeMap<String, WalletTemplateVariable>>,
    /// The {@link AuthenticationVirtualMachine} on which CashAssembly
    /// `evaluation` results will be computed.
    pub vm: Option<AuthenticationVirtualMachineBch>,
}

/// The `hdKeys` of a {@link CompilationData}.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CompilationDataHdKeys {
    /// The current address index to be used for this compilation. The
    /// `addressIndex` gets added to each HD key's `addressOffset` to calculate
    /// the dynamic index (`i`) used in each `privateDerivationPath` or
    /// `publicDerivationPath`.
    ///
    /// This is required for any compiler operation which requires derivation.
    /// Typically, the value is incremented by one for each address in a wallet.
    pub address_index: Option<f64>,
    /// A map of entity IDs to HD public keys. These HD public keys are used to
    /// derive public keys for each `HdKey` variable assigned to that entity
    /// (as specified in {@link CompilerConfiguration.entityOwnership})
    /// according to its `publicDerivationPath`.
    ///
    /// HD public keys may be encoded for either mainnet or testnet (the network
    /// information is ignored).
    ///
    /// If both an HD private key (in `hdPrivateKeys`) and HD public key (in
    /// `hdPublicKeys`) are provided for the same entity in the same compilation
    /// (not recommended), only the HD private key is used.
    pub hd_public_keys: Option<BTreeMap<String, String>>,
    /// A map of entity IDs to master HD private keys. These master HD private
    /// keys are used to derive each `HdKey` variable assigned to that entity
    /// (as specified in {@link CompilerConfiguration.entityOwnership})
    /// according to its `privateDerivationPath`.
    ///
    /// HD private keys may be encoded for either mainnet or testnet (the
    /// network information is ignored).
    ///
    /// If both an HD private key (in `hdPrivateKeys`) and HD public key (in
    /// `hdPublicKeys`) are provided for the same entity in the same compilation
    /// (not recommended), only the HD private key is used.
    pub hd_private_keys: Option<BTreeMap<String, String>>,
}

/// The `keys` of a {@link CompilationData}.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompilationDataKeys {
    /// A map of `Key` variable IDs to their private keys for this compilation.
    pub private_keys: Option<BTreeMap<String, Vec<u8>>>,
}

/// Data required at compilation time to generate the bytecode for a particular
/// CashAssembly Template script.
#[derive(Clone, Debug, PartialEq)]
pub struct CompilationData<CompilationContext = CompilationContextBch> {
    /// A map of full identifiers to pre-computed bytecode for this compilation.
    ///
    /// This is always used to provide bytecode for `AddressData` and
    /// `WalletData`, and it can also be used to provide public keys and
    /// signatures which have been pre-computed by other entities (e.g. when
    /// computing these would require access to private keys held by another
    /// entities).
    ///
    /// The provided `fullIdentifier` should match the complete identifier for
    /// each item, e.g. `some_wallet_data`, `variable_id.public_key`, or
    /// `variable_id.schnorr_signature.all_outputs`.
    ///
    /// All `AddressData` and `WalletData` variables must be provided via
    /// `bytecode`, and pre-computed results for operations of other variable
    /// types (e.g. `key.public_key`) may also be provided via this property.
    ///
    /// Because the bytecode is provided directly to the compiler, it is not
    /// evaluated by the compiler (e.g. as a pushed script).
    pub bytecode: Option<BTreeMap<String, Vec<u8>>>,
    /// The current block height at address creation time.
    pub current_block_height: Option<f64>,
    /// The current MTP block time as a UNIX timestamp at address creation time.
    ///
    /// Note, this is never a current timestamp, but rather the median timestamp
    /// of the last 11 blocks. It is therefore approximately one hour in the
    /// past.
    ///
    /// Every block has a precise MTP block time, much like a block height. See
    /// BIP113 for details.
    pub current_block_time: Option<f64>,
    /// An object describing the settings used for `HdKey` variables in this
    /// compilation.
    pub hd_keys: Option<CompilationDataHdKeys>,
    /// An object describing the settings used for `Key` variables in this
    /// compilation.
    pub keys: Option<CompilationDataKeys>,
    /// The {@link CompilationContext} expected by this particular compiler for
    /// any operations used in the compilation.
    pub compilation_context: Option<CompilationContext>,
}

impl<CompilationContext> Default for CompilationData<CompilationContext> {
    fn default() -> Self {
        CompilationData {
            bytecode: None,
            current_block_height: None,
            current_block_time: None,
            hd_keys: None,
            keys: None,
            compilation_context: None,
        }
    }
}

/// Any compiler configuration (libauth's `AnyCompilerConfiguration`, a
/// {@link CompilerConfiguration} accepting any operation identifiers).
pub type AnyCompilerConfiguration = CompilerConfiguration;

/// A {@link CompilerConfiguration} for which the `operations` are ignored.
pub type AnyCompilerConfigurationIgnoreOperations = CompilerConfiguration;

/// The result of a bytecode generation: the bytecode, or the error type and
/// errors of the failed compilation.
#[derive(Clone, Debug)]
pub enum BytecodeGenerationResult {
    /// libauth's `{ bytecode, success: true }`.
    Success { bytecode: Vec<u8> },
    /// libauth's `CompilationResultError` (with only `errorType` and `errors`
    /// populated, as by libauth's non-debug `generateBytecode`).
    Error(CompilationResultError),
}

/// A fully-generated authentication scenario: the compilation data and the
/// resulting authentication program.
#[derive(Clone, Debug, PartialEq)]
pub struct Scenario {
    pub data: CompilationData,
    pub program: AuthenticationProgramCommon,
}

/// A scenario generation result which includes all compilation information for
/// the scripts under test (in the scenario's "slot"s). This allows
/// testing tools to extract the compilations for debugging purposes.
#[derive(Clone, Debug)]
pub struct ScenarioGenerationDebuggingResult {
    /// The locking script compilation result (if successful, the locking
    /// script is used as the `lockingBytecode` of the source output under
    /// test). `None` if the source output under test uses literal bytecode
    /// (libauth returns the literal bytecode in place of a compilation).
    pub locking_compilation: Option<CompilationResult>,
    /// The generated scenario, or an error message describing why the scenario
    /// could not be generated.
    pub scenario: Result<Scenario, String>,
    /// The unlocking script compilation result (`None` if no inputs were
    /// compiled, or the input under test uses literal bytecode).
    pub unlocking_compilation: Option<CompilationResult>,
}

/// A compiler: an object with methods for bytecode and scenario generation
/// using the provided {@link CompilerConfiguration}.
///
/// libauth's `generateBytecode` and `generateScenario` return a debugging
/// result when called with `debug: true`; Rust expresses each mode as its own
/// method (`generate_bytecode`/`generate_bytecode_debug` and
/// `generate_scenario`/`generate_scenario_debug`).
#[derive(Clone)]
pub struct Compiler {
    pub configuration: CompilerConfiguration,
}
