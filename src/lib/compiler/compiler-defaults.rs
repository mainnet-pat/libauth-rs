/// Default values used by the compiler.
pub struct CompilerDefaults;

#[allow(non_upper_case_globals)]
impl CompilerDefaults {
    /// The `addressIndex` used by the default scenario `data`.
    pub const defaultScenarioAddressIndex: f64 = 0.0;
    /// The value of `lockingBytecode` and `unlockingBytecode` when generating a
    /// default scenario for which no locking or unlocking script is provided.
    pub const defaultScenarioBytecode: &'static str = "";
    /// The value of `currentBlockHeight` in the default authentication template
    /// scenario. This is the height of the second mined block after the genesis
    /// block: `000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd`.
    ///
    /// This default value was chosen to be low enough to simplify the debugging
    /// of block height offsets while remaining differentiated from `0` and `1`,
    /// which are used both as boolean return values and for control flow.
    pub const defaultScenarioCurrentBlockHeight: f64 = 2.0;
    /// The value of `currentBlockTime` in the default authentication template
    /// scenario. This is the Median Time-Past block time (BIP113) of block `2`
    /// (the block used in `defaultScenarioCurrentBlockHeight`).
    pub const defaultScenarioCurrentBlockTime: f64 = 1231469665.0;
    /// The default `outpointTransactionHash` of inputs in scenarios.
    pub const defaultScenarioInputOutpointTransactionHash: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    /// The default `category` of tokens in scenarios.
    pub const defaultScenarioOutputTokenCategory: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000002";
    /// The default `sequenceNumber` of inputs in scenarios.
    pub const defaultScenarioInputSequenceNumber: f64 = 0.0;
    /// The default `lockingBytecode` of outputs in scenarios.
    pub const defaultScenarioOutputLockingBytecode: &'static str = "6a076c696261757468";
    /// The default `valueSatoshis` of outputs in scenarios.
    pub const defaultScenarioOutputValueSatoshis: f64 = 0.0;
    /// The default `locktime` of scenario transactions.
    pub const defaultScenarioTransactionLocktime: f64 = 0.0;
    /// The default `version` of scenario transactions.
    pub const defaultScenarioTransactionVersion: f64 = 2.0;
    /// If unset, each `HdKey` uses an `addressOffset` of `0`.
    pub const hdKeyAddressOffset: f64 = 0.0;
    /// If unset, each `HdKey` uses this `hdPublicKeyDerivationPath`.
    pub const hdKeyHdPublicKeyDerivationPath: &'static str = "";
    /// If unset, each `HdKey` uses this `privateDerivationPath`.
    pub const hdKeyPrivateDerivationPath: &'static str = "i";
    /// The prefix used to refer to other scenario bytecode scripts from within a
    /// bytecode script. See {@link WalletTemplateScenarioData.bytecode} for
    /// details.
    pub const scenarioBytecodeScriptPrefix: &'static str = "_scenario.";
}
