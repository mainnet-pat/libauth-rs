//! Wallet template types.
//!
//! Port of libauth's `engine/types/template-types.ts`. A [`WalletTemplate`]
//! describes a wallet protocol's locking and unlocking scripts, the entities
//! that generate them, the variables they require, and scenarios used for
//! transaction estimation and script testing.
//!
//! Field doc comments note the original (wire) property names, which are
//! camelCase in JSON and snake_case on the Rust structs.

use std::collections::BTreeMap;

use crate::message::NonFungibleTokenCapability;

/// A set of locking scripts, unlocking scripts, and other information required
/// to use a certain wallet protocol.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplate {
    /// The URI identifying the JSON Schema used by this template. Wire name:
    /// `$schema`.
    pub schema: Option<String>,
    /// An optionally multi-line, human-readable description for this template.
    /// Wire name: `description`.
    pub description: Option<String>,
    /// A map of entity identifiers to entity definitions. Wire name:
    /// `entities`.
    pub entities: BTreeMap<String, WalletTemplateEntity>,
    /// A single-line, Title Case, human-readable name for this template.
    /// Wire name: `name`.
    pub name: Option<String>,
    /// A map of scenario identifiers to scenario definitions. Wire name:
    /// `scenarios`.
    pub scenarios: Option<BTreeMap<String, WalletTemplateScenario>>,
    /// A map of script identifiers to script definitions. Wire name:
    /// `scripts`.
    pub scripts: BTreeMap<String, WalletTemplateScriptDefinition>,
    /// The authentication virtual machine versions supported by this
    /// template. Wire name: `supported`.
    pub supported: Vec<AuthenticationVirtualMachineIdentifier>,
    /// A number identifying the format of this template; currently only `0`
    /// is allowed. Wire name: `version`.
    pub version: Option<u8>,
}

/// Allowable identifiers for authentication virtual machine versions.
///
/// Identifiers use the format `CODE_YYYY_MM`; the `_SPEC` suffix indicates a
/// custom, not-yet-deployed VM version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticationVirtualMachineIdentifier {
    /// `BCH_2020_05`
    Bch2020_05,
    /// `BCH_2021_05`
    Bch2021_05,
    /// `BCH_2022_05`
    Bch2022_05,
    /// `BCH_2023_05`
    Bch2023_05,
    /// `BCH_2024_05`
    Bch2024_05,
    /// `BCH_2025_05`
    Bch2025_05,
    /// `BCH_2026_05`
    Bch2026_05,
    /// `BCH_2027_05`
    Bch2027_05,
    /// `BCH_2028_05`
    Bch2028_05,
    /// `BCH_2029_05`
    Bch2029_05,
    /// `BCH_2030_05`
    Bch2030_05,
    /// `BCH_SPEC`
    BchSpec,
    /// `BSV_2020_02`
    Bsv2020_02,
    /// `BSV_SPEC`
    BsvSpec,
    /// `BTC_2017_08`
    Btc2017_08,
    /// `BTC_SPEC`
    BtcSpec,
    /// `XEC_2020_05`
    Xec2020_05,
    /// `XEC_SPEC`
    XecSpec,
}

impl AuthenticationVirtualMachineIdentifier {
    /// The exact identifier text used in template JSON.
    pub const fn text(self) -> &'static str {
        match self {
            AuthenticationVirtualMachineIdentifier::Bch2020_05 => "BCH_2020_05",
            AuthenticationVirtualMachineIdentifier::Bch2021_05 => "BCH_2021_05",
            AuthenticationVirtualMachineIdentifier::Bch2022_05 => "BCH_2022_05",
            AuthenticationVirtualMachineIdentifier::Bch2023_05 => "BCH_2023_05",
            AuthenticationVirtualMachineIdentifier::Bch2024_05 => "BCH_2024_05",
            AuthenticationVirtualMachineIdentifier::Bch2025_05 => "BCH_2025_05",
            AuthenticationVirtualMachineIdentifier::Bch2026_05 => "BCH_2026_05",
            AuthenticationVirtualMachineIdentifier::Bch2027_05 => "BCH_2027_05",
            AuthenticationVirtualMachineIdentifier::Bch2028_05 => "BCH_2028_05",
            AuthenticationVirtualMachineIdentifier::Bch2029_05 => "BCH_2029_05",
            AuthenticationVirtualMachineIdentifier::Bch2030_05 => "BCH_2030_05",
            AuthenticationVirtualMachineIdentifier::BchSpec => "BCH_SPEC",
            AuthenticationVirtualMachineIdentifier::Bsv2020_02 => "BSV_2020_02",
            AuthenticationVirtualMachineIdentifier::BsvSpec => "BSV_SPEC",
            AuthenticationVirtualMachineIdentifier::Btc2017_08 => "BTC_2017_08",
            AuthenticationVirtualMachineIdentifier::BtcSpec => "BTC_SPEC",
            AuthenticationVirtualMachineIdentifier::Xec2020_05 => "XEC_2020_05",
            AuthenticationVirtualMachineIdentifier::XecSpec => "XEC_SPEC",
        }
    }
}

/// An object describing the configuration for a particular entity within a
/// wallet template.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateEntity {
    /// An optionally multi-line, human-readable description for this entity.
    /// Wire name: `description`.
    pub description: Option<String>,
    /// A single-line, Title Case, human-readable name for this entity. Wire
    /// name: `name`.
    pub name: Option<String>,
    /// The identifiers of each script the entity must be capable of
    /// generating; defaults to all scripts in the template. Wire name:
    /// `scripts`.
    pub scripts: Option<Vec<String>>,
    /// A map of variable identifiers to definitions of the variables this
    /// entity must provide. Wire name: `variables`.
    pub variables: Option<BTreeMap<String, WalletTemplateVariable>>,
}

/// An object defining the data to use while compiling a scenario.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenarioData {
    /// A map of full identifiers to CashAssembly scripts that compile to each
    /// identifier's value for this scenario. Wire name: `bytecode`.
    pub bytecode: Option<BTreeMap<String, String>>,
    /// The current block height at the scenario's "address creation time".
    /// Wire name: `currentBlockHeight`.
    pub current_block_height: Option<f64>,
    /// The current Median Time-Past block time, as a UNIX timestamp in
    /// seconds, at the scenario's "address creation time". Wire name:
    /// `currentBlockTime`.
    pub current_block_time: Option<f64>,
    /// Settings used for `HdKey` variables in this scenario. Wire name:
    /// `hdKeys`.
    pub hd_keys: Option<WalletTemplateScenarioDataHdKeys>,
    /// Settings used for `Key` variables in this scenario. Wire name:
    /// `keys`.
    pub keys: Option<WalletTemplateScenarioDataKeys>,
}

/// The `hdKeys` settings of a [`WalletTemplateScenarioData`].
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenarioDataHdKeys {
    /// The current address index, added to each `HdKey`'s `addressOffset`;
    /// defaults to `0`. Wire name: `addressIndex`.
    pub address_index: Option<f64>,
    /// A map of entity identifiers to HD public keys. Wire name:
    /// `hdPublicKeys`.
    pub hd_public_keys: Option<BTreeMap<String, String>>,
    /// A map of entity identifiers to master HD private keys. Wire name:
    /// `hdPrivateKeys`.
    pub hd_private_keys: Option<BTreeMap<String, String>>,
}

/// The `keys` settings of a [`WalletTemplateScenarioData`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateScenarioDataKeys {
    /// A map of `Key` variable identifiers to 32-byte, hex-encoded private
    /// keys. Wire name: `privateKeys`.
    pub private_keys: Option<BTreeMap<String, String>>,
}

/// A bytecode configuration in a wallet template scenario.
///
/// The TypeScript type is a union of a hexadecimal-encoded string and an
/// object describing the required compilation.
#[derive(Clone, Debug, PartialEq)]
pub enum WalletTemplateScenarioBytecode {
    /// Hexadecimal-encoded bytecode.
    Hex(String),
    /// A script/overrides compilation definition.
    Definition(WalletTemplateScenarioBytecodeDefinition),
}

/// An object describing the compilation of a scenario's bytecode.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenarioBytecodeDefinition {
    /// The identifier of the script to compile; `Copy` (the default) is
    /// replaced with the identifier of the locking or unlocking script under
    /// test. Wire name: `script`.
    pub script: Option<WalletTemplateScenarioBytecodeScript>,
    /// Scenario data extending the scenario's top-level `data` during
    /// compilation. Wire name: `overrides`.
    pub overrides: Option<WalletTemplateScenarioData>,
}

/// The `script` property of a [`WalletTemplateScenarioBytecodeDefinition`]:
/// either a script identifier or the literal `["copy"]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletTemplateScenarioBytecodeScript {
    /// `["copy"]`: the locking or unlocking script under test.
    Copy,
    /// A specific script identifier.
    Id(String),
}

/// An example input used to define a scenario for a wallet template.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenarioInput {
    /// The index of the output spent by this input. Wire name:
    /// `outpointIndex`.
    pub outpoint_index: Option<f64>,
    /// The 32-byte, hex-encoded, big-endian transaction hash spent by this
    /// input. Wire name: `outpointTransactionHash`.
    pub outpoint_transaction_hash: Option<String>,
    /// The positive, 32-bit unsigned sequence number for this input. Wire
    /// name: `sequenceNumber`.
    pub sequence_number: Option<f64>,
    /// The unlocking bytecode for this input: either `["slot"]` or a bytecode
    /// definition. Wire name: `unlockingBytecode`.
    pub unlocking_bytecode: Option<WalletTemplateScenarioUnlockingBytecode>,
}

/// The `unlockingBytecode` of a [`WalletTemplateScenarioInput`].
#[derive(Clone, Debug, PartialEq)]
pub enum WalletTemplateScenarioUnlockingBytecode {
    /// `["slot"]`: the input under test.
    Slot,
    /// A bytecode definition or hexadecimal-encoded bytecode.
    Bytecode(WalletTemplateScenarioBytecode),
}

/// The `lockingBytecode` of a [`WalletTemplateScenarioOutput`].
///
/// The TypeScript conditional type only permits the `["slot"]` member when
/// `IsSourceOutput` is `true`; the const parameter is retained here, but
/// `Slot` is only meaningful for source outputs.
#[derive(Clone, Debug, PartialEq)]
pub enum WalletTemplateScenarioOutputLockingBytecode<const IS_SOURCE_OUTPUT: bool> {
    /// `["slot"]`: the source output in which the locking script under test is
    /// placed.
    Slot,
    /// A bytecode definition or hexadecimal-encoded locking bytecode.
    Bytecode(WalletTemplateScenarioBytecode),
}

/// An `valueSatoshis` definition: either a `number` or a hexadecimal-encoded
/// string (for values beyond `Number.MAX_SAFE_INTEGER`).
#[derive(Clone, Debug, PartialEq)]
pub enum WalletTemplateScenarioValueSatoshis {
    /// A satoshi value.
    Number(f64),
    /// A 16-character, hexadecimal-encoded uint64.
    Hex(String),
}

/// The fungible token amount of a [`WalletTemplateScenarioToken`]: either a
/// `number` or a decimal string (for amounts beyond `Number.MAX_SAFE_INTEGER`).
#[derive(Clone, Debug, PartialEq)]
pub enum WalletTemplateScenarioTokenAmount {
    /// A token amount.
    Number(f64),
    /// A decimal-encoded token amount.
    Decimal(String),
}

/// The `token.nft` property of a [`WalletTemplateScenarioToken`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateScenarioNft {
    /// The capability of this non-fungible token; defaults to `none`. Wire
    /// name: `capability`.
    pub capability: Option<NonFungibleTokenCapability>,
    /// The hex-encoded commitment contents; defaults to `""`. Wire name:
    /// `commitment`.
    pub commitment: Option<String>,
}

/// The `token` property of a [`WalletTemplateScenarioOutput`].
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenarioToken {
    /// The number of fungible tokens held in this output; defaults to `0`.
    /// Wire name: `amount`.
    pub amount: Option<WalletTemplateScenarioTokenAmount>,
    /// The 32-byte, hex-encoded, big-endian token category ID. Wire name:
    /// `category`.
    pub category: Option<String>,
    /// The non-fungible token held by this output. Wire name: `nft`.
    pub nft: Option<WalletTemplateScenarioNft>,
}

/// An example output used to define a scenario for a wallet template.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenarioOutput<const IS_SOURCE_OUTPUT: bool> {
    /// The locking bytecode used to encumber this output. Wire name:
    /// `lockingBytecode`.
    pub locking_bytecode: Option<WalletTemplateScenarioOutputLockingBytecode<IS_SOURCE_OUTPUT>>,
    /// The value of the output in satoshis; defaults to `0`. Wire name:
    /// `valueSatoshis`.
    pub value_satoshis: Option<WalletTemplateScenarioValueSatoshis>,
    /// The CashToken contents of this output, if any. Wire name: `token`.
    pub token: Option<WalletTemplateScenarioToken>,
}

/// A transaction output used to define a wallet template scenario
/// transaction (a [`WalletTemplateScenarioOutput`] with `IsSourceOutput` set
/// to `false`).
pub type WalletTemplateScenarioTransactionOutput = WalletTemplateScenarioOutput<false>;

/// A source output used by a wallet template scenario (a
/// [`WalletTemplateScenarioOutput`] with `IsSourceOutput` set to `true`).
pub type WalletTemplateScenarioSourceOutput = WalletTemplateScenarioOutput<true>;

/// The `transaction` property of a [`WalletTemplateScenario`].
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenarioTransaction {
    /// The list of inputs to use when generating the transaction. Wire name:
    /// `inputs`.
    pub inputs: Option<Vec<WalletTemplateScenarioInput>>,
    /// The locktime to use, from `0` to `4294967295`; defaults to `0`. Wire
    /// name: `locktime`.
    pub locktime: Option<f64>,
    /// The list of outputs to use when generating the transaction. Wire name:
    /// `outputs`.
    pub outputs: Option<Vec<WalletTemplateScenarioTransactionOutput>>,
    /// The transaction version, from `0` to `4294967295`; defaults to `2`.
    /// Wire name: `version`.
    pub version: Option<f64>,
}

/// An object describing the configuration for a particular scenario within a
/// wallet template.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateScenario {
    /// The data to use while compiling this scenario, extending the `extends`
    /// parent's data. Wire name: `data`.
    pub data: Option<WalletTemplateScenarioData>,
    /// An optionally multi-line, human-readable description for this
    /// scenario. Wire name: `description`.
    pub description: Option<String>,
    /// The identifier of the scenario this scenario extends; defaults to the
    /// default scenario. Wire name: `extends`.
    pub extends: Option<String>,
    /// A single-line, Title Case, human-readable name for this scenario.
    /// Wire name: `name`.
    pub name: Option<String>,
    /// The transaction within which this scenario should be evaluated. Wire
    /// name: `transaction`.
    pub transaction: Option<WalletTemplateScenarioTransaction>,
    /// The list of source outputs to use when generating the compilation
    /// context for this scenario. Wire name: `sourceOutputs`.
    pub source_outputs: Option<Vec<WalletTemplateScenarioSourceOutput>>,
}

/// The `timeLockType` expected by a wallet template unlocking script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletTemplateTimeLockType {
    /// The transaction's locktime is a block height (less than `500000000`).
    /// Literal: `height`.
    Height,
    /// The transaction's locktime is a UNIX timestamp (greater than or equal
    /// to `500000000`). Literal: `timestamp`.
    Timestamp,
}

impl WalletTemplateTimeLockType {
    /// The exact time lock type identifier used in template JSON.
    pub const fn text(self) -> &'static str {
        match self {
            WalletTemplateTimeLockType::Height => "height",
            WalletTemplateTimeLockType::Timestamp => "timestamp",
        }
    }
}

/// The `lockingType` of a wallet template locking script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletTemplateLockingType {
    /// Produce scripts in the P2SH20 "redeem script" format. Literal:
    /// `p2sh20`.
    P2sh20,
    /// Produce scripts in the P2SH32 "redeem script" format. Literal:
    /// `p2sh32`.
    P2sh32,
    /// Produce standard (non-P2SH) locking bytecode. Literal: `standard`.
    Standard,
}

impl WalletTemplateLockingType {
    /// The exact locking type identifier used in template JSON.
    pub const fn text(self) -> &'static str {
        match self {
            WalletTemplateLockingType::P2sh20 => "p2sh20",
            WalletTemplateLockingType::P2sh32 => "p2sh32",
            WalletTemplateLockingType::Standard => "standard",
        }
    }
}

/// An object describing the configuration for a particular script within a
/// wallet template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateScript {
    /// A single-line, human-readable name for this script. Wire name: `name`.
    pub name: Option<String>,
    /// The script definition in CashAssembly. Wire name: `script`.
    pub script: String,
}

/// A wallet template unlocking script (a [`WalletTemplateScript`] extended
/// with unlocking-script properties).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateScriptUnlocking {
    /// A single-line, human-readable name for this script. Wire name: `name`.
    pub name: Option<String>,
    /// The script definition in CashAssembly. Wire name: `script`.
    pub script: String,
    /// The minimum input age required for this unlocking script to become
    /// valid. Wire name: `ageLock`.
    pub age_lock: Option<String>,
    /// The identifier of the scenario to use when compiling an estimated
    /// transaction. Wire name: `estimate`.
    pub estimate: Option<String>,
    /// Scenario identifiers that result in bytecode that fails program
    /// verification. Wire name: `fails`.
    pub fails: Option<Vec<String>>,
    /// Scenario identifiers that result in a compilation error. Wire name:
    /// `invalid`.
    pub invalid: Option<Vec<String>>,
    /// Scenario identifiers that result in bytecode that passes program
    /// verification. Wire name: `passes`.
    pub passes: Option<Vec<String>>,
    /// The expected type of time locks in this script. Wire name:
    /// `timeLockType`.
    pub time_lock_type: Option<WalletTemplateTimeLockType>,
    /// The identifier of the locking script that can be unlocked by this
    /// script. Wire name: `unlocks`.
    pub unlocks: String,
}

/// A wallet template locking script (a [`WalletTemplateScript`] extended with
/// locking-script properties).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateScriptLocking {
    /// A single-line, human-readable name for this script. Wire name: `name`.
    pub name: Option<String>,
    /// The script definition in CashAssembly. Wire name: `script`.
    pub script: String,
    /// The P2SH20/P2SH32/standard locking behavior of this script. Wire name:
    /// `lockingType`.
    pub locking_type: WalletTemplateLockingType,
}

/// A wallet template tested script (a [`WalletTemplateScript`] extended with
/// test definitions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateScriptTested {
    /// A single-line, human-readable name for this script. Wire name: `name`.
    pub name: Option<String>,
    /// The script definition in CashAssembly. Wire name: `script`.
    pub script: String,
    /// If `true`, the script is wrapped in a push statement for testing;
    /// defaults to `false`. Wire name: `pushed`.
    pub pushed: Option<bool>,
    /// A map of test identifiers to tests of this script. Wire name: `tests`.
    pub tests: BTreeMap<String, WalletTemplateScriptTest>,
}

/// A test of a [`WalletTemplateScriptTested`] script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateScriptTest {
    /// The script to evaluate after the script being tested. Wire name:
    /// `check`.
    pub check: String,
    /// A single-line, Title Case, human-readable name for this test. Wire
    /// name: `name`.
    pub name: Option<String>,
    /// Scenario identifiers that result in bytecode that fails program
    /// verification. Wire name: `fails`.
    pub fails: Option<Vec<String>>,
    /// Scenario identifiers that result in a compilation error. Wire name:
    /// `invalid`.
    pub invalid: Option<Vec<String>>,
    /// Scenario identifiers that result in bytecode that passes program
    /// verification. Wire name: `passes`.
    pub passes: Option<Vec<String>>,
    /// A script to evaluate before the script being tested. Wire name:
    /// `setup`.
    pub setup: Option<String>,
}

/// A wallet template script entry: the union of [`WalletTemplateScript`],
/// [`WalletTemplateScriptLocking`], [`WalletTemplateScriptTested`], and
/// [`WalletTemplateScriptUnlocking`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletTemplateScriptDefinition {
    /// A script with only a name and definition.
    Script(WalletTemplateScript),
    /// A locking script.
    Locking(WalletTemplateScriptLocking),
    /// A tested script.
    Tested(WalletTemplateScriptTested),
    /// An unlocking script.
    Unlocking(WalletTemplateScriptUnlocking),
}

/// The base properties of a wallet template variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateVariableBase {
    /// A single-line, human-readable description for this variable. Wire name:
    /// `description`.
    pub description: Option<String>,
    /// A single-line, Title Case, human-readable name for this variable.
    /// Wire name: `name`.
    pub name: Option<String>,
    /// The variable's type identifier. Wire name: `type`.
    pub r#type: String,
}

/// The base properties of a wallet template key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateKeyBase {
    /// If `true`, this key should never be used to sign two different
    /// messages; defaults to `false`. Wire name: `neverSignTwice`.
    pub never_sign_twice: Option<bool>,
}

/// The variable type identifiers of wallet template variables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletTemplateVariableType {
    /// `AddressData`
    AddressData,
    /// `HdKey`
    HdKey,
    /// `Key`
    Key,
    /// `WalletData`
    WalletData,
}

impl WalletTemplateVariableType {
    /// The exact variable type identifier used in template JSON.
    pub const fn text(self) -> &'static str {
        match self {
            WalletTemplateVariableType::AddressData => "AddressData",
            WalletTemplateVariableType::HdKey => "HdKey",
            WalletTemplateVariableType::Key => "Key",
            WalletTemplateVariableType::WalletData => "WalletData",
        }
    }
}

/// A hierarchical-deterministic key variable.
///
/// Flattens the TypeScript
/// `WalletTemplateKeyBase & WalletTemplateVariableBase & { ... }` intersection.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletTemplateHdKey {
    /// A single-line, human-readable description for this HD key. Wire name:
    /// `description`.
    pub description: Option<String>,
    /// A single-line, Title Case, human-readable name for this HD key. Wire
    /// name: `name`.
    pub name: Option<String>,
    /// The variable type; must be `HdKey`. Wire name: `type`.
    pub r#type: WalletTemplateVariableType,
    /// See [`WalletTemplateKeyBase::never_sign_twice`]. Wire name:
    /// `neverSignTwice`.
    pub never_sign_twice: Option<bool>,
    /// The offset added to the compilation's `addressIndex` when deriving
    /// this key. Wire name: `addressOffset`.
    pub address_offset: Option<f64>,
    /// The fixed path used to derive the entity's HD public key from its
    /// provided HD private key. Wire name: `hdPublicKeyDerivationPath`.
    pub hd_public_key_derivation_path: Option<String>,
    /// The relative or absolute path used to derive this key from the owning
    /// entity's HD private key. Wire name: `privateDerivationPath`.
    pub private_derivation_path: Option<String>,
    /// The relative path used to derive this key's public key from the owning
    /// entity's HD public key. Wire name: `publicDerivationPath`.
    pub public_derivation_path: Option<String>,
}

/// A key variable providing fine-grained control over key generation and
/// mapping.
///
/// Flattens the TypeScript
/// `WalletTemplateKeyBase & WalletTemplateVariableBase & { ... }` intersection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateKey {
    /// A single-line, human-readable description for this key. Wire name:
    /// `description`.
    pub description: Option<String>,
    /// A single-line, Title Case, human-readable name for this key. Wire
    /// name: `name`.
    pub name: Option<String>,
    /// The variable type; must be `Key`. Wire name: `type`.
    pub r#type: WalletTemplateVariableType,
    /// See [`WalletTemplateKeyBase::never_sign_twice`]. Wire name:
    /// `neverSignTwice`.
    pub never_sign_twice: Option<bool>,
}

/// A static, wallet-lifetime data variable.
///
/// Flattens the TypeScript `WalletTemplateVariableBase & { ... }` intersection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateWalletData {
    /// A single-line, human-readable description for this wallet data. Wire
    /// name: `description`.
    pub description: Option<String>,
    /// A single-line, Title Case, human-readable name for this wallet data.
    /// Wire name: `name`.
    pub name: Option<String>,
    /// The variable type; must be `WalletData`. Wire name: `type`.
    pub r#type: WalletTemplateVariableType,
}

/// An address-specific data variable.
///
/// Flattens the TypeScript `WalletTemplateVariableBase & { ... }` intersection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTemplateAddressData {
    /// A single-line, human-readable description for this address data. Wire
    /// name: `description`.
    pub description: Option<String>,
    /// A single-line, Title Case, human-readable name for this address data.
    /// Wire name: `name`.
    pub name: Option<String>,
    /// The variable type; must be `AddressData`. Wire name: `type`.
    pub r#type: WalletTemplateVariableType,
}

/// A wallet template variable: the union of [`WalletTemplateAddressData`],
/// [`WalletTemplateHdKey`], [`WalletTemplateKey`], and
/// [`WalletTemplateWalletData`].
#[derive(Clone, Debug, PartialEq)]
pub enum WalletTemplateVariable {
    /// An `AddressData` variable.
    AddressData(WalletTemplateAddressData),
    /// An `HdKey` variable.
    HdKey(WalletTemplateHdKey),
    /// A `Key` variable.
    Key(WalletTemplateKey),
    /// A `WalletData` variable.
    WalletData(WalletTemplateWalletData),
}

impl WalletTemplateVariable {
    /// The variable's `type` identifier.
    pub const fn variable_type(&self) -> WalletTemplateVariableType {
        match self {
            WalletTemplateVariable::AddressData(_) => WalletTemplateVariableType::AddressData,
            WalletTemplateVariable::HdKey(_) => WalletTemplateVariableType::HdKey,
            WalletTemplateVariable::Key(_) => WalletTemplateVariableType::Key,
            WalletTemplateVariable::WalletData(_) => WalletTemplateVariableType::WalletData,
        }
    }
}

// Conversions between wallet templates and JSON. In libauth, a template is a
// plain object (interchangeable with its JSON); in this port, `TryFrom<&Json>`
// types a JSON value (see `importWalletTemplate`) and `From<&_> for Json`
// produces the equivalent JSON (with keys in sorted order).

use crate::runtime::json::typed::{
    array, boolean, from_f64, from_map, from_number, from_string, from_strings, map, number, object,
    optional, properties, required, string, strings,
};
use crate::runtime::json::Json;

fn variable_type_from_json(json: &Json) -> Result<WalletTemplateVariableType, String> {
    use WalletTemplateVariableType as Type;
    [Type::AddressData, Type::HdKey, Type::Key, Type::WalletData]
        .into_iter()
        .find(|candidate| json.as_str() == Some(candidate.text()))
        .ok_or_else(|| format!("Unknown variable type: {json}."))
}

impl TryFrom<&Json> for WalletTemplateVariable {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let r#type = variable_type_from_json(
            json.get("type")
                .ok_or_else(|| format!("Variable: missing property \"type\" in {json}."))?,
        )?;
        Ok(match r#type {
            WalletTemplateVariableType::AddressData | WalletTemplateVariableType::WalletData => {
                let p = properties(json, &["description", "name", "type"], "Variable")?;
                let description = optional(&p, "description", string)?;
                let name = optional(&p, "name", string)?;
                if r#type == WalletTemplateVariableType::AddressData {
                    WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                        description,
                        name,
                        r#type,
                    })
                } else {
                    WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                        description,
                        name,
                        r#type,
                    })
                }
            }
            WalletTemplateVariableType::Key => {
                let p = properties(json, &["description", "name", "neverSignTwice", "type"], "Key")?;
                WalletTemplateVariable::Key(WalletTemplateKey {
                    description: optional(&p, "description", string)?,
                    name: optional(&p, "name", string)?,
                    never_sign_twice: optional(&p, "neverSignTwice", boolean)?,
                    r#type,
                })
            }
            WalletTemplateVariableType::HdKey => {
                let p = properties(
                    json,
                    &[
                        "addressOffset",
                        "description",
                        "hdPublicKeyDerivationPath",
                        "name",
                        "neverSignTwice",
                        "privateDerivationPath",
                        "publicDerivationPath",
                        "type",
                    ],
                    "HdKey",
                )?;
                WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                    address_offset: optional(&p, "addressOffset", number)?,
                    description: optional(&p, "description", string)?,
                    hd_public_key_derivation_path: optional(&p, "hdPublicKeyDerivationPath", string)?,
                    name: optional(&p, "name", string)?,
                    never_sign_twice: optional(&p, "neverSignTwice", boolean)?,
                    private_derivation_path: optional(&p, "privateDerivationPath", string)?,
                    public_derivation_path: optional(&p, "publicDerivationPath", string)?,
                    r#type,
                })
            }
        })
    }
}

impl From<&WalletTemplateVariable> for Json {
    fn from(variable: &WalletTemplateVariable) -> Json {
        let text = |value: &Option<String>| value.as_deref().map(from_string);
        match variable {
            WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                description,
                name,
                r#type,
            })
            | WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                description,
                name,
                r#type,
            }) => object(vec![
                ("description", text(description)),
                ("name", text(name)),
                ("type", Some(from_string(r#type.text()))),
            ]),
            WalletTemplateVariable::Key(key) => object(vec![
                ("description", text(&key.description)),
                ("name", text(&key.name)),
                ("neverSignTwice", key.never_sign_twice.map(Json::Bool)),
                ("type", Some(from_string(key.r#type.text()))),
            ]),
            WalletTemplateVariable::HdKey(key) => object(vec![
                ("addressOffset", key.address_offset.map(from_f64)),
                ("description", text(&key.description)),
                ("hdPublicKeyDerivationPath", text(&key.hd_public_key_derivation_path)),
                ("name", text(&key.name)),
                ("neverSignTwice", key.never_sign_twice.map(Json::Bool)),
                ("privateDerivationPath", text(&key.private_derivation_path)),
                ("publicDerivationPath", text(&key.public_derivation_path)),
                ("type", Some(from_string(key.r#type.text()))),
            ]),
        }
    }
}

impl TryFrom<&Json> for WalletTemplateEntity {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["description", "name", "scripts", "variables"], "Entity")?;
        Ok(WalletTemplateEntity {
            description: optional(&p, "description", string)?,
            name: optional(&p, "name", string)?,
            scripts: optional(&p, "scripts", strings)?,
            variables: optional(&p, "variables", |value| map(value, |value| WalletTemplateVariable::try_from(value)))?,
        })
    }
}

impl From<&WalletTemplateEntity> for Json {
    fn from(entity: &WalletTemplateEntity) -> Json {
        object(vec![
            ("description", entity.description.as_deref().map(from_string)),
            ("name", entity.name.as_deref().map(from_string)),
            ("scripts", entity.scripts.as_deref().map(from_strings)),
            ("variables", entity.variables.as_ref().map(|variables| from_map(variables, |value| Json::from(value)))),
        ])
    }
}

fn string_map(json: &Json) -> Result<BTreeMap<String, String>, String> {
    map(json, string)
}

fn from_string_map(value: &BTreeMap<String, String>) -> Json {
    from_map(value, |value| from_string(value))
}

impl TryFrom<&Json> for WalletTemplateScenarioData {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(
            json,
            &["bytecode", "currentBlockHeight", "currentBlockTime", "hdKeys", "keys"],
            "Scenario data",
        )?;
        Ok(WalletTemplateScenarioData {
            bytecode: optional(&p, "bytecode", string_map)?,
            current_block_height: optional(&p, "currentBlockHeight", number)?,
            current_block_time: optional(&p, "currentBlockTime", number)?,
            hd_keys: optional(&p, "hdKeys", |value| {
                let p = properties(value, &["addressIndex", "hdPrivateKeys", "hdPublicKeys"], "HD keys")?;
                Ok(WalletTemplateScenarioDataHdKeys {
                    address_index: optional(&p, "addressIndex", number)?,
                    hd_private_keys: optional(&p, "hdPrivateKeys", string_map)?,
                    hd_public_keys: optional(&p, "hdPublicKeys", string_map)?,
                })
            })?,
            keys: optional(&p, "keys", |value| {
                let p = properties(value, &["privateKeys"], "Keys")?;
                Ok(WalletTemplateScenarioDataKeys {
                    private_keys: optional(&p, "privateKeys", string_map)?,
                })
            })?,
        })
    }
}

impl From<&WalletTemplateScenarioData> for Json {
    fn from(data: &WalletTemplateScenarioData) -> Json {
        object(vec![
            ("bytecode", data.bytecode.as_ref().map(from_string_map)),
            ("currentBlockHeight", data.current_block_height.map(from_f64)),
            ("currentBlockTime", data.current_block_time.map(from_f64)),
            (
                "hdKeys",
                data.hd_keys.as_ref().map(|hd_keys| {
                    object(vec![
                        ("addressIndex", hd_keys.address_index.map(from_f64)),
                        ("hdPrivateKeys", hd_keys.hd_private_keys.as_ref().map(from_string_map)),
                        ("hdPublicKeys", hd_keys.hd_public_keys.as_ref().map(from_string_map)),
                    ])
                }),
            ),
            (
                "keys",
                data.keys
                    .as_ref()
                    .map(|keys| object(vec![("privateKeys", keys.private_keys.as_ref().map(from_string_map))])),
            ),
        ])
    }
}

/// Returns `true` for `["slot"]`.
fn is_slot(json: &Json) -> bool {
    matches!(json.as_array(), Some([item]) if item.as_str() == Some("slot"))
}

fn slot() -> Json {
    Json::Array(vec![from_string("slot")])
}

impl TryFrom<&Json> for WalletTemplateScenarioBytecode {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        if let Some(hex) = json.as_str() {
            return Ok(WalletTemplateScenarioBytecode::Hex(hex.to_string()));
        }
        let p = properties(json, &["overrides", "script"], "Scenario bytecode")?;
        Ok(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
            overrides: optional(&p, "overrides", |value| WalletTemplateScenarioData::try_from(value))?,
            script: optional(&p, "script", |value| match value.as_str() {
                Some(id) => Ok(WalletTemplateScenarioBytecodeScript::Id(id.to_string())),
                None if strings(value)? == ["copy"] => Ok(WalletTemplateScenarioBytecodeScript::Copy),
                None => Err(format!("Expected a script ID or [\"copy\"], received {value}.")),
            })?,
        }))
    }
}

impl From<&WalletTemplateScenarioBytecode> for Json {
    fn from(bytecode: &WalletTemplateScenarioBytecode) -> Json {
        match bytecode {
            WalletTemplateScenarioBytecode::Hex(hex) => from_string(hex),
            WalletTemplateScenarioBytecode::Definition(definition) => object(vec![
                ("overrides", definition.overrides.as_ref().map(|value| Json::from(value))),
                (
                    "script",
                    definition.script.as_ref().map(|script| match script {
                        WalletTemplateScenarioBytecodeScript::Copy => Json::Array(vec![from_string("copy")]),
                        WalletTemplateScenarioBytecodeScript::Id(id) => from_string(id),
                    }),
                ),
            ]),
        }
    }
}

impl<const IS_SOURCE_OUTPUT: bool> TryFrom<&Json> for WalletTemplateScenarioOutput<IS_SOURCE_OUTPUT> {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["lockingBytecode", "token", "valueSatoshis"], "Scenario output")?;
        Ok(WalletTemplateScenarioOutput {
            locking_bytecode: optional(&p, "lockingBytecode", |value| {
                Ok(if is_slot(value) {
                    WalletTemplateScenarioOutputLockingBytecode::Slot
                } else {
                    WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::try_from(
                        value,
                    )?)
                })
            })?,
            token: optional(&p, "token", |value| {
                let p = properties(value, &["amount", "category", "nft"], "Scenario token")?;
                Ok(WalletTemplateScenarioToken {
                    amount: optional(&p, "amount", |value| {
                        Ok(match value.as_str() {
                            Some(amount) => WalletTemplateScenarioTokenAmount::Decimal(amount.to_string()),
                            None => WalletTemplateScenarioTokenAmount::Number(number(value)?),
                        })
                    })?,
                    category: optional(&p, "category", string)?,
                    nft: optional(&p, "nft", |value| {
                        let p = properties(value, &["capability", "commitment"], "Scenario NFT")?;
                        Ok(WalletTemplateScenarioNft {
                            capability: optional(&p, "capability", |value| {
                                use NonFungibleTokenCapability as Capability;
                                [Capability::None, Capability::Mutable, Capability::Minting]
                                    .into_iter()
                                    .find(|candidate| value.as_str() == Some(candidate.as_str()))
                                    .ok_or_else(|| format!("Unknown NFT capability: {value}."))
                            })?,
                            commitment: optional(&p, "commitment", string)?,
                        })
                    })?,
                })
            })?,
            value_satoshis: optional(&p, "valueSatoshis", |value| {
                Ok(match value.as_str() {
                    Some(hex) => WalletTemplateScenarioValueSatoshis::Hex(hex.to_string()),
                    None => WalletTemplateScenarioValueSatoshis::Number(number(value)?),
                })
            })?,
        })
    }
}

impl<const IS_SOURCE_OUTPUT: bool> From<&WalletTemplateScenarioOutput<IS_SOURCE_OUTPUT>> for Json {
    fn from(output: &WalletTemplateScenarioOutput<IS_SOURCE_OUTPUT>) -> Json {
        object(vec![
            (
                "lockingBytecode",
                output.locking_bytecode.as_ref().map(|locking_bytecode| match locking_bytecode {
                    WalletTemplateScenarioOutputLockingBytecode::Slot => slot(),
                    WalletTemplateScenarioOutputLockingBytecode::Bytecode(bytecode) => Json::from(bytecode),
                }),
            ),
            (
                "token",
                output.token.as_ref().map(|token| {
                    object(vec![
                        (
                            "amount",
                            token.amount.as_ref().map(|amount| match amount {
                                WalletTemplateScenarioTokenAmount::Number(amount) => from_f64(*amount),
                                WalletTemplateScenarioTokenAmount::Decimal(amount) => from_string(amount),
                            }),
                        ),
                        ("category", token.category.as_deref().map(from_string)),
                        (
                            "nft",
                            token.nft.as_ref().map(|nft| {
                                object(vec![
                                    ("capability", nft.capability.map(|capability| from_string(capability.as_str()))),
                                    ("commitment", nft.commitment.as_deref().map(from_string)),
                                ])
                            }),
                        ),
                    ])
                }),
            ),
            (
                "valueSatoshis",
                output.value_satoshis.as_ref().map(|value| match value {
                    WalletTemplateScenarioValueSatoshis::Number(value) => from_f64(*value),
                    WalletTemplateScenarioValueSatoshis::Hex(hex) => from_string(hex),
                }),
            ),
        ])
    }
}

impl TryFrom<&Json> for WalletTemplateScenarioInput {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(
            json,
            &["outpointIndex", "outpointTransactionHash", "sequenceNumber", "unlockingBytecode"],
            "Scenario input",
        )?;
        Ok(WalletTemplateScenarioInput {
            outpoint_index: optional(&p, "outpointIndex", number)?,
            outpoint_transaction_hash: optional(&p, "outpointTransactionHash", string)?,
            sequence_number: optional(&p, "sequenceNumber", number)?,
            unlocking_bytecode: optional(&p, "unlockingBytecode", |value| {
                Ok(if is_slot(value) {
                    WalletTemplateScenarioUnlockingBytecode::Slot
                } else {
                    WalletTemplateScenarioUnlockingBytecode::Bytecode(WalletTemplateScenarioBytecode::try_from(value)?)
                })
            })?,
        })
    }
}

impl From<&WalletTemplateScenarioInput> for Json {
    fn from(input: &WalletTemplateScenarioInput) -> Json {
        object(vec![
            ("outpointIndex", input.outpoint_index.map(from_f64)),
            ("outpointTransactionHash", input.outpoint_transaction_hash.as_deref().map(from_string)),
            ("sequenceNumber", input.sequence_number.map(from_f64)),
            (
                "unlockingBytecode",
                input.unlocking_bytecode.as_ref().map(|bytecode| match bytecode {
                    WalletTemplateScenarioUnlockingBytecode::Slot => slot(),
                    WalletTemplateScenarioUnlockingBytecode::Bytecode(bytecode) => Json::from(bytecode),
                }),
            ),
        ])
    }
}

impl TryFrom<&Json> for WalletTemplateScenario {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(
            json,
            &["data", "description", "extends", "name", "sourceOutputs", "transaction"],
            "Scenario",
        )?;
        Ok(WalletTemplateScenario {
            data: optional(&p, "data", |value| WalletTemplateScenarioData::try_from(value))?,
            description: optional(&p, "description", string)?,
            extends: optional(&p, "extends", string)?,
            name: optional(&p, "name", string)?,
            source_outputs: optional(&p, "sourceOutputs", |value| array(value, |value| WalletTemplateScenarioOutput::try_from(value)))?,
            transaction: optional(&p, "transaction", |value| {
                let p = properties(value, &["inputs", "locktime", "outputs", "version"], "Scenario transaction")?;
                Ok(WalletTemplateScenarioTransaction {
                    inputs: optional(&p, "inputs", |value| array(value, |value| WalletTemplateScenarioInput::try_from(value)))?,
                    locktime: optional(&p, "locktime", number)?,
                    outputs: optional(&p, "outputs", |value| array(value, |value| WalletTemplateScenarioOutput::try_from(value)))?,
                    version: optional(&p, "version", number)?,
                })
            })?,
        })
    }
}

impl From<&WalletTemplateScenario> for Json {
    fn from(scenario: &WalletTemplateScenario) -> Json {
        object(vec![
            ("data", scenario.data.as_ref().map(|value| Json::from(value))),
            ("description", scenario.description.as_deref().map(from_string)),
            ("extends", scenario.extends.as_deref().map(from_string)),
            ("name", scenario.name.as_deref().map(from_string)),
            (
                "sourceOutputs",
                scenario
                    .source_outputs
                    .as_ref()
                    .map(|outputs| Json::Array(outputs.iter().map(|value| Json::from(value)).collect())),
            ),
            (
                "transaction",
                scenario.transaction.as_ref().map(|transaction| {
                    object(vec![
                        (
                            "inputs",
                            transaction
                                .inputs
                                .as_ref()
                                .map(|inputs| Json::Array(inputs.iter().map(|value| Json::from(value)).collect())),
                        ),
                        ("locktime", transaction.locktime.map(from_f64)),
                        (
                            "outputs",
                            transaction
                                .outputs
                                .as_ref()
                                .map(|outputs| Json::Array(outputs.iter().map(|value| Json::from(value)).collect())),
                        ),
                        ("version", transaction.version.map(from_f64)),
                    ])
                }),
            ),
        ])
    }
}

fn find_text<T: Copy>(candidates: &[T], text: impl Fn(T) -> &'static str, json: &Json, kind: &str) -> Result<T, String> {
    candidates
        .iter()
        .copied()
        .find(|candidate| json.as_str() == Some(text(*candidate)))
        .ok_or_else(|| format!("Unknown {kind}: {json}."))
}

/// Like libauth's `walletTemplateToCompilerConfiguration`, a script with
/// `unlocks` is an unlocking script, one with `lockingType` a locking script,
/// and one with `tests` a tested script.
impl TryFrom<&Json> for WalletTemplateScriptDefinition {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let has = |key: &str| json.get(key).is_some();
        if has("unlocks") {
            let p = properties(
                json,
                &["ageLock", "estimate", "fails", "invalid", "name", "passes", "script", "timeLockType", "unlocks"],
                "Unlocking script",
            )?;
            return Ok(WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                age_lock: optional(&p, "ageLock", string)?,
                estimate: optional(&p, "estimate", string)?,
                fails: optional(&p, "fails", strings)?,
                invalid: optional(&p, "invalid", strings)?,
                name: optional(&p, "name", string)?,
                passes: optional(&p, "passes", strings)?,
                script: string(required(&p, "script", "Unlocking script")?)?,
                time_lock_type: optional(&p, "timeLockType", |value| {
                    use WalletTemplateTimeLockType as Type;
                    find_text(&[Type::Height, Type::Timestamp], Type::text, value, "time lock type")
                })?,
                unlocks: string(required(&p, "unlocks", "Unlocking script")?)?,
            }));
        }
        if has("lockingType") {
            let p = properties(json, &["lockingType", "name", "script"], "Locking script")?;
            use WalletTemplateLockingType as Type;
            return Ok(WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                locking_type: find_text(
                    &[Type::P2sh20, Type::P2sh32, Type::Standard],
                    Type::text,
                    required(&p, "lockingType", "Locking script")?,
                    "locking type",
                )?,
                name: optional(&p, "name", string)?,
                script: string(required(&p, "script", "Locking script")?)?,
            }));
        }
        if has("tests") {
            let p = properties(json, &["name", "pushed", "script", "tests"], "Tested script")?;
            return Ok(WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: optional(&p, "name", string)?,
                pushed: optional(&p, "pushed", boolean)?,
                script: string(required(&p, "script", "Tested script")?)?,
                tests: map(required(&p, "tests", "Tested script")?, |test| {
                    let p = properties(test, &["check", "fails", "invalid", "name", "passes", "setup"], "Script test")?;
                    Ok(WalletTemplateScriptTest {
                        check: string(required(&p, "check", "Script test")?)?,
                        fails: optional(&p, "fails", strings)?,
                        invalid: optional(&p, "invalid", strings)?,
                        name: optional(&p, "name", string)?,
                        passes: optional(&p, "passes", strings)?,
                        setup: optional(&p, "setup", string)?,
                    })
                })?,
            }));
        }
        let p = properties(json, &["name", "script"], "Script")?;
        Ok(WalletTemplateScriptDefinition::Script(WalletTemplateScript {
            name: optional(&p, "name", string)?,
            script: string(required(&p, "script", "Script")?)?,
        }))
    }
}

impl From<&WalletTemplateScriptDefinition> for Json {
    fn from(script: &WalletTemplateScriptDefinition) -> Json {
        let text = |value: &Option<String>| value.as_deref().map(from_string);
        let texts = |value: &Option<Vec<String>>| value.as_deref().map(from_strings);
        match script {
            WalletTemplateScriptDefinition::Script(script) => object(vec![
                ("name", text(&script.name)),
                ("script", Some(from_string(&script.script))),
            ]),
            WalletTemplateScriptDefinition::Locking(script) => object(vec![
                ("lockingType", Some(from_string(script.locking_type.text()))),
                ("name", text(&script.name)),
                ("script", Some(from_string(&script.script))),
            ]),
            WalletTemplateScriptDefinition::Unlocking(script) => object(vec![
                ("ageLock", text(&script.age_lock)),
                ("estimate", text(&script.estimate)),
                ("fails", texts(&script.fails)),
                ("invalid", texts(&script.invalid)),
                ("name", text(&script.name)),
                ("passes", texts(&script.passes)),
                ("script", Some(from_string(&script.script))),
                ("timeLockType", script.time_lock_type.map(|value| from_string(value.text()))),
                ("unlocks", Some(from_string(&script.unlocks))),
            ]),
            WalletTemplateScriptDefinition::Tested(script) => object(vec![
                ("name", text(&script.name)),
                ("pushed", script.pushed.map(Json::Bool)),
                ("script", Some(from_string(&script.script))),
                (
                    "tests",
                    Some(from_map(&script.tests, |test| {
                        object(vec![
                            ("check", Some(from_string(&test.check))),
                            ("fails", texts(&test.fails)),
                            ("invalid", texts(&test.invalid)),
                            ("name", text(&test.name)),
                            ("passes", texts(&test.passes)),
                            ("setup", text(&test.setup)),
                        ])
                    })),
                ),
            ]),
        }
    }
}

impl TryFrom<&Json> for WalletTemplate {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(
            json,
            &["$schema", "description", "entities", "name", "scenarios", "scripts", "supported", "version"],
            "Wallet template",
        )?;
        use AuthenticationVirtualMachineIdentifier as Vm;
        let vms = [
            Vm::Bch2020_05,
            Vm::Bch2021_05,
            Vm::Bch2022_05,
            Vm::Bch2023_05,
            Vm::Bch2024_05,
            Vm::Bch2025_05,
            Vm::Bch2026_05,
            Vm::Bch2027_05,
            Vm::Bch2028_05,
            Vm::Bch2029_05,
            Vm::Bch2030_05,
            Vm::BchSpec,
            Vm::Bsv2020_02,
            Vm::BsvSpec,
            Vm::Btc2017_08,
            Vm::BtcSpec,
            Vm::Xec2020_05,
            Vm::XecSpec,
        ];
        Ok(WalletTemplate {
            schema: optional(&p, "$schema", string)?,
            description: optional(&p, "description", string)?,
            entities: map(required(&p, "entities", "Wallet template")?, |value| WalletTemplateEntity::try_from(value))?,
            name: optional(&p, "name", string)?,
            scenarios: optional(&p, "scenarios", |value| map(value, |value| WalletTemplateScenario::try_from(value)))?,
            scripts: map(required(&p, "scripts", "Wallet template")?, |value| WalletTemplateScriptDefinition::try_from(value))?,
            supported: array(required(&p, "supported", "Wallet template")?, |value| {
                find_text(&vms, Vm::text, value, "virtual machine")
            })?,
            version: optional(&p, "version", |value| match number(value)? {
                version if version == 0.0 => Ok(0),
                _ => Err(format!("Expected 0, received {value}.")),
            })?,
        })
    }
}

impl From<&WalletTemplate> for Json {
    fn from(template: &WalletTemplate) -> Json {
        object(vec![
            ("$schema", template.schema.as_deref().map(from_string)),
            ("description", template.description.as_deref().map(from_string)),
            ("entities", Some(from_map(&template.entities, |value| Json::from(value)))),
            ("name", template.name.as_deref().map(from_string)),
            ("scenarios", template.scenarios.as_ref().map(|scenarios| from_map(scenarios, |value| Json::from(value)))),
            ("scripts", Some(from_map(&template.scripts, |value| Json::from(value)))),
            (
                "supported",
                Some(Json::Array(template.supported.iter().map(|vm| from_string(vm.text())).collect())),
            ),
            ("version", template.version.map(from_number)),
        ])
    }
}
