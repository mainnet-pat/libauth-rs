use crate::format::format_error;
use crate::vm::AuthenticationProgramStateError;

pub struct AuthenticationErrorCommon;

#[allow(non_upper_case_globals)]
impl AuthenticationErrorCommon {
    pub const calledReserved: &'static str = "Program called an unassigned, reserved operation.";
    pub const calledReturn: &'static str = "Program called an OP_RETURN operation.";
    pub const calledUpgradableNop: &'static str = "Program called a disallowed upgradable non-operation (OP_NOP1-OP_NOP10).";
    pub const checkSequenceUnavailable: &'static str = "Program called an OP_CHECKSEQUENCEVERIFY operation, but OP_CHECKSEQUENCEVERIFY requires transaction version 2 or higher.";
    pub const disabledOpcode: &'static str = "Program contains a disabled opcode.";
    pub const divisionByZero: &'static str = "Program attempted to divide a number by zero.";
    pub const emptyAlternateStack: &'static str = "Tried to read from an empty alternate stack.";
    pub const emptyStack: &'static str = "Tried to read from an empty stack.";
    pub const exceededMaximumBytecodeLengthLocking: &'static str = "The provided locking bytecode exceeds the maximum bytecode length.";
    pub const exceededMaximumBytecodeLengthUnlocking: &'static str = "The provided unlocking bytecode exceeds the maximum bytecode length.";
    pub const exceededMaximumVmNumberByteLength: &'static str = "Program attempted an OP_BIN2NUM operation on a byte sequence that cannot be encoded within the maximum VM Number length.";
    pub const exceededMaximumControlStackDepth: &'static str = "Program exceeded the maximum control stack depth.";
    pub const exceededMaximumSignatureCheckCount: &'static str = "Program exceeded the maximum signature check count.";
    pub const exceededMaximumStackDepth: &'static str = "Program exceeded the maximum stack depth.";
    pub const exceededMaximumStackItemLength: &'static str = "Program attempted to push a stack item that exceeded the maximum stack item length.";
    pub const exceededMaximumOperationCount: &'static str = "Program exceeded the maximum operation count (201 operations).";
    pub const exceedsMaximumMultisigPublicKeyCount: &'static str = "Program called an OP_CHECKMULTISIG that exceeds the maximum public key count (20 public keys).";
    pub const failedVerify: &'static str = "Program failed an OP_VERIFY operation.";
    pub const invalidStackIndex: &'static str = "Tried to read from an invalid stack index.";
    pub const incompatibleLocktimeType: &'static str = "Program called an OP_CHECKLOCKTIMEVERIFY operation with an incompatible locktime type. The transaction locktime and required locktime must both refer to either a block height or a block time.";
    pub const incompatibleSequenceType: &'static str = "Program called an OP_CHECKSEQUENCEVERIFY operation with an incompatible sequence type flag. The input sequence number and required sequence number must both use the same sequence locktime type.";
    pub const insufficientLength: &'static str = "Program called an OP_NUM2BIN operation with an insufficient byte length to re-encode the provided number.";
    pub const insufficientPublicKeys: &'static str = "Program called an OP_CHECKMULTISIG operation that requires signatures from more public keys than are provided.";
    pub const invalidCheckBitsValue: &'static str = "Program called an OP_CHECKMULTISIG operation with an invalid CheckBits value.";
    pub const invalidCheckBitsSignatureCount: &'static str = "Program called an OP_CHECKMULTISIG operation with a CheckBits value configuring validation for an incorrect number of signatures.";
    pub const invalidNaturalNumber: &'static str = "Invalid input: the key/signature count inputs for OP_CHECKMULTISIG require a natural number (n > 0).";
    pub const invalidPublicKeyEncoding: &'static str = "Encountered an improperly encoded public key.";
    pub const invalidVmNumber: &'static str = "Invalid input: this operation requires a valid VM Number.";
    pub const invalidSignatureEncoding: &'static str = "Encountered an improperly encoded signature.";
    pub const invalidSplitIndex: &'static str = "Program called an OP_SPLIT operation with an invalid index.";
    pub const invalidTransactionInputIndex: &'static str = "Program attempted to read from an invalid transaction input index.";
    pub const invalidTransactionOutputIndex: &'static str = "Program attempted to read from an invalid transaction output index.";
    pub const invalidTransactionUtxoIndex: &'static str = "Program attempted to read from an invalid transaction UTXO index.";
    pub const locktimeDisabled: &'static str = "Program called an OP_CHECKLOCKTIMEVERIFY operation, but locktime is disabled for this transaction.";
    pub const mismatchedBitwiseOperandLength: &'static str = "Program attempted a bitwise operation on operands of different lengths.";
    pub const malformedLockingBytecode: &'static str = "The provided locking bytecode is malformed.";
    pub const malformedP2shBytecode: &'static str = "Redeem bytecode was malformed prior to P2SH evaluation.";
    pub const malformedPush: &'static str = "Program must be long enough to push the requested number of bytes.";
    pub const malformedUnlockingBytecode: &'static str = "The provided unlocking bytecode is malformed.";
    pub const negativeLocktime: &'static str = "Program called an OP_CHECKLOCKTIMEVERIFY or OP_CHECKSEQUENCEVERIFY operation with a negative locktime.";
    pub const nonEmptyControlStackLockingBytecode: &'static str = "The locking bytecode completed with a non-empty control stack.";
    pub const nonEmptyControlStackRedeemBytecode: &'static str = "The redeem bytecode completed with a non-empty control stack.";
    pub const nonEmptyControlStackUnlockingBytecode: &'static str = "The unlocking bytecode completed with a non-empty control stack.";
    pub const nonMinimalPush: &'static str = "Push operations must use the smallest possible encoding.";
    pub const nonNullSignatureFailure: &'static str = "Program failed a signature verification with a non-null signature (violating the \"NULLFAIL\" rule).";
    pub const nonSchnorrSizedSignatureInSchnorrMultiSig: &'static str = "Program used a non schnorr-sized signature (65 bytes) in a schnorr OP_CHECKMULTISIG operation.";
    pub const overflowsVmNumberRange: &'static str = "Program attempted an arithmetic operation which exceeds the range of VM Numbers.";
    pub const requiresCleanStackLockingBytecode: &'static str = "Non-P2SH locking bytecode completed evaluation with an unexpected number of items on the stack (must be exactly 1).";
    pub const requiresCleanStackRedeemBytecode: &'static str = "P2SH redeem bytecode completed evaluation with an unexpected number of items on the stack (must be exactly 1).";
    pub const requiresPushOnly: &'static str = "Unlocking bytecode may contain only push operations in version 1 and 2 transactions.";
    pub const schnorrSizedSignatureInEcdsaMultiSig: &'static str = "Program used a schnorr-sized signature (65 bytes) in a legacy-mode (ECDSA) OP_CHECKMULTISIG operation.";
    pub const tokenValidationExcessiveCommitmentLength: &'static str = "Transaction violates token validation: excessive token commitment length.";
    pub const tokenValidationInvalidMintingToken: &'static str = "Transaction violates token validation: the transaction outputs include a minting token that is not substantiated by the transaction inputs.";
    pub const tokenValidationExcessiveAmount: &'static str = "Transaction violates token validation: the transaction outputs include a sum of fungible tokens for a category exceeding the maximum fungible token amount.";
    pub const tokenValidationInvalidFungibleMint: &'static str = "Transaction violates token validation: the transaction creates new fungible tokens for a category without a matching genesis input.";
    pub const tokenValidationOutputsExceedInputs: &'static str = "Transaction violates token validation: the sum of fungible tokens in the transaction outputs exceed that of the transaction inputs for a category.";
    pub const tokenValidationExcessiveMutableTokens: &'static str = "Transaction violates token validation: the transaction creates more mutable tokens than are available for a category without a matching minting token.";
    pub const tokenValidationExcessiveImmutableTokens: &'static str = "Transaction violates token validation: the transaction creates an immutable token for a category without a matching minting token or sufficient mutable tokens.";
    pub const unexpectedElse: &'static str = "Encountered an OP_ELSE outside of an OP_IF ... OP_ENDIF block.";
    pub const unexpectedEndIf: &'static str = "Encountered an OP_ENDIF that is not following a matching OP_IF.";
    pub const unknownOpcode: &'static str = "Called an unknown opcode.";
    pub const unmatchedSequenceDisable: &'static str = "Program called an OP_CHECKSEQUENCEVERIFY operation requiring the disable flag, but the input's sequence number is missing the disable flag.";
    pub const unmatchedP2shRedeemBytecode: &'static str = "The P2SH redeem bytecode provided in this input does not match the hash required by the locking bytecode.";
    pub const unsatisfiedLocktime: &'static str = "Program called an OP_CHECKLOCKTIMEVERIFY operation that requires a locktime greater than the transaction's locktime.";
    pub const unsatisfiedSequenceNumber: &'static str = "Program called an OP_CHECKSEQUENCEVERIFY operation that requires a sequence number greater than the input's sequence number.";
    pub const unsuccessfulEvaluation: &'static str = "Unsuccessful evaluation: completed with a non-truthy value on top of the stack.";
    pub const verifyFailedExcessiveLength: &'static str = "Unable to verify transaction: excessive byte length.";
    pub const verifyFailedInsufficientLength: &'static str = "Unable to verify transaction: insufficient byte length.";
    pub const verifyFailedMismatchedSourceOutputs: &'static str = "Unable to verify transaction: a single spent output must be provided for each transaction input.";
    pub const verifyFailedNoInputs: &'static str = "Unable to verify transaction: transactions must have at least one input.";
    pub const verifyFailedNoOutputs: &'static str = "Unable to verify transaction: transactions must have at least one output.";
    pub const verifyFailedInputsExceedMaxMoney: &'static str = "Unable to verify transaction: the sum of source output values exceeds the maximum possible satoshi value.";
    pub const verifyFailedOutputsExceedInputs: &'static str = "Unable to verify transaction: the sum of transaction output values exceeds the sum of transaction inputs.";
    pub const verifyFailedOutputsExceedMaxMoney: &'static str = "Unable to verify transaction: the sum of transaction output values exceeds the maximum possible satoshi value.";
    pub const verifyFailedDuplicateSourceOutputs: &'static str = "Unable to verify transaction: the transaction attempts to spend the same outpoint in multiple inputs.";
    pub const verifyFailedInvalidVersion: &'static str = "Unable to verify transaction: transaction version must be either 1 or 2.";
    pub const verifyFailedExcessiveSigChecks: &'static str = "Unable to verify transaction: excessive cumulative signature check count.";
    pub const verifyStandardFailedExcessiveLength: &'static str = "Unable to verify standard transaction: transaction exceeds maximum standard byte length.";
    pub const verifyStandardFailedNonstandardOutput: &'static str = "Unable to verify standard transaction: standard transactions may only create standard output types.";
    pub const verifyStandardFailedNonstandardSourceOutput: &'static str = "Unable to verify standard transaction: standard transactions may only spend standard output types.";
    pub const verifyStandardFailedDustOutput: &'static str = "Unable to verify standard transaction: standard transactions may not have dust outputs.";
    pub const verifyStandardFailedExcessiveDataCarrierBytes: &'static str = "Unable to verify standard transaction: excessive data carrier bytes.";
    pub const verifyStandardFailedExcessiveUnlockingBytecodeLength: &'static str = "Unable to verify standard transaction: excessive unlocking bytecode length.";
    pub const verifyStandardFailedNonPushUnlockingBytecode: &'static str = "Unable to verify standard transaction: unlocking bytecode must only include push operations.";
}

/// Apply an error to a program state, returning the program state with the
/// error. If the program state already has an error, the existing error is
/// retained (the first error encountered is the one reported).
pub fn apply_error(
    state: &mut AuthenticationProgramStateError,
    error_type: &str,
    error_details: Option<&str>,
) {
    if state.error.is_none() {
        state.error = Some(format_error(error_type, error_details));
    }
}
