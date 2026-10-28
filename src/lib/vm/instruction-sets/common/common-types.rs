use crate::message::{Input, Output, TransactionCommon};
use crate::vm::{
    apply_error, execution_is_active, AuthenticationErrorCommon, AuthenticationProgramStateCommon,
};

/// The operation performed for undefined opcodes: an "unknown opcode" error
/// (if execution is active).
pub fn undefined_operation(state: &mut AuthenticationProgramStateCommon) {
    if execution_is_active(state) {
        apply_error(state, AuthenticationErrorCommon::unknownOpcode, None);
    }
}

/// The context in which a compilation occurs: the transaction, the index of
/// the input being compiled, and the source outputs spent by the transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilationContext<TransactionType> {
    /// The index of the input for which the compilation is occurring.
    pub input_index: usize,
    /// An array of the source outputs spent by the transaction.
    pub source_outputs: Vec<Output>,
    /// The transaction in which the compilation is occurring.
    pub transaction: TransactionType,
}

/// A {@link CompilationContext} for a {@link TransactionCommon} in which the
/// unlocking bytecode of each input may be undefined.
pub type CompilationContextCommon = CompilationContext<TransactionCommon<Input<Option<Vec<u8>>>>>;

const SHA256_HASH_LENGTH: usize = 32;

/// Create an "empty" {@link CompilationContextCommon} for testing: one input
/// with an undefined unlocking bytecode and one empty output (each defaulting
/// to a maximum `valueSatoshis`).
pub fn create_compilation_context_common_testing(
    source_outputs: Option<Vec<Output>>,
    inputs: Option<Vec<Input<Option<Vec<u8>>>>>,
    locktime: Option<u32>,
    version: Option<u32>,
    outputs: Option<Vec<Output>>,
) -> CompilationContextCommon {
    CompilationContext {
        input_index: 0,
        source_outputs: source_outputs.unwrap_or_else(|| {
            vec![Output {
                locking_bytecode: Vec::new(),
                token: None,
                value_satoshis: 0xffff_ffff_ffff_ffff,
            }]
        }),
        transaction: TransactionCommon {
            inputs: inputs.unwrap_or_else(|| {
                vec![Input {
                    outpoint_index: 0,
                    outpoint_transaction_hash: vec![1; SHA256_HASH_LENGTH],
                    sequence_number: 0,
                    unlocking_bytecode: None,
                }]
            }),
            locktime: locktime.unwrap_or(0),
            outputs: outputs.unwrap_or_else(|| {
                vec![Output {
                    locking_bytecode: Vec::new(),
                    token: None,
                    value_satoshis: 0xffff_ffff_ffff_ffff,
                }]
            }),
            version: version.unwrap_or(0),
        },
    }
}
