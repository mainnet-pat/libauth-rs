use crate::crypto::{hash256, Sha256};
use crate::format::{big_int_to_compact_uint, flatten_bin_array, number_to_bin_uint32_le, value_satoshis_to_bin};
use crate::message::{
    encode_token_prefix, encode_transaction_input_sequence_numbers_for_signing,
    encode_transaction_outpoints, encode_transaction_output,
    encode_transaction_outputs_for_signing, Input, TransactionCommon,
};
use crate::vm::CompilationContext;

/// A.K.A. `SIGHASH_`
pub struct SigningSerializationFlag;

#[allow(non_upper_case_globals)]
impl SigningSerializationFlag {
    /// A.K.A. `SIGHASH_ALL`
    pub const allOutputs: u8 = 0x01;
    /// A.K.A. `SIGHASH_NONE`
    pub const noOutputs: u8 = 0x02;
    /// A.K.A. `SIGHASH_SINGLE`
    pub const correspondingOutput: u8 = 0x03;
    /// A.K.A. `SIGHASH_UTXOS`
    pub const utxos: u8 = 0x20;
    /// A.K.A. `SIGHASH_FORKID`
    pub const forkId: u8 = 0x40;
    /// A.K.A. `ANYONE_CAN_PAY`
    pub const singleInput: u8 = 0x80;
}

/// The signing serialization types supported by the BCH VM.
pub struct SigningSerializationType;

#[allow(non_upper_case_globals)]
impl SigningSerializationType {
    pub const allOutputs: u8 = SigningSerializationFlag::allOutputs | SigningSerializationFlag::forkId;
    pub const allOutputsAllUtxos: u8 = SigningSerializationFlag::allOutputs
        | SigningSerializationFlag::utxos
        | SigningSerializationFlag::forkId;
    pub const allOutputsSingleInput: u8 = SigningSerializationFlag::allOutputs
        | SigningSerializationFlag::singleInput
        | SigningSerializationFlag::forkId;
    pub const correspondingOutput: u8 =
        SigningSerializationFlag::correspondingOutput | SigningSerializationFlag::forkId;
    pub const correspondingOutputAllUtxos: u8 = SigningSerializationFlag::correspondingOutput
        | SigningSerializationFlag::utxos
        | SigningSerializationFlag::forkId;
    pub const correspondingOutputSingleInput: u8 = SigningSerializationFlag::correspondingOutput
        | SigningSerializationFlag::singleInput
        | SigningSerializationFlag::forkId;
    pub const noOutputs: u8 = SigningSerializationFlag::noOutputs | SigningSerializationFlag::forkId;
    pub const noOutputsAllUtxos: u8 = SigningSerializationFlag::noOutputs
        | SigningSerializationFlag::utxos
        | SigningSerializationFlag::forkId;
    pub const noOutputsSingleInput: u8 = SigningSerializationFlag::noOutputs
        | SigningSerializationFlag::singleInput
        | SigningSerializationFlag::forkId;
}

pub use self::SigningSerializationType as SigningSerializationTypeBch;

/// @deprecated Alias of `SigningSerializationTypeBch` for
/// backwards-compatibility.
pub use self::SigningSerializationTypeBch as SigningSerializationTypeBCH;

const MASK_5_BITS: u8 = 0b11111;
const SHA256_HASH_BYTE_LENGTH: usize = 32;

/// The first byte of the signing serialization type (as in JavaScript, a
/// missing byte behaves as `0` in bitwise operations).
fn first_byte(signing_serialization_type: &[u8]) -> u8 {
    signing_serialization_type.first().copied().unwrap_or(0)
}

fn matches_flag(signing_serialization_type: &[u8], flag: u8) -> bool {
    (first_byte(signing_serialization_type) & flag) != 0
}

fn equals(signing_serialization_type: &[u8], flag: u8) -> bool {
    (first_byte(signing_serialization_type) & MASK_5_BITS) == flag
}

fn should_serialize_single_input(signing_serialization_type: &[u8]) -> bool {
    matches_flag(signing_serialization_type, SigningSerializationFlag::singleInput)
}

fn should_serialize_corresponding_output(signing_serialization_type: &[u8]) -> bool {
    equals(signing_serialization_type, SigningSerializationFlag::correspondingOutput)
}

fn should_serialize_no_outputs(signing_serialization_type: &[u8]) -> bool {
    equals(signing_serialization_type, SigningSerializationFlag::noOutputs)
}

fn should_serialize_utxos(signing_serialization_type: &[u8]) -> bool {
    matches_flag(signing_serialization_type, SigningSerializationFlag::utxos)
}

fn empty_hash() -> Vec<u8> {
    vec![0; SHA256_HASH_BYTE_LENGTH]
}

/// Return the proper `hashPrevouts` value for a given a signing serialization
/// type.
/// @param signingSerializationType - the signing serialization type to test
/// @param transactionOutpoints - see
/// {@link generateSigningSerializationComponentsBch}
/// @param sha256 - an implementation of sha256 (defaults to the internal
/// instance)
pub fn hash_prevouts(
    signing_serialization_type: &[u8],
    transaction_outpoints: &[u8],
    sha256: Option<&Sha256>,
) -> Vec<u8> {
    if should_serialize_single_input(signing_serialization_type) {
        empty_hash()
    } else {
        hash256(transaction_outpoints, sha256)
    }
}

/// Return the proper `hashUtxos` value for a given a signing serialization
/// type.
/// @param signingSerializationType - the signing serialization type to test
/// @param transactionUtxos - see {@link generateSigningSerializationComponentsBch}
/// @param sha256 - an implementation of sha256 (defaults to the internal
/// instance)
pub fn hash_utxos(
    signing_serialization_type: &[u8],
    transaction_utxos: &[u8],
    sha256: Option<&Sha256>,
) -> Vec<u8> {
    if should_serialize_utxos(signing_serialization_type) {
        hash256(transaction_utxos, sha256)
    } else {
        Vec::new()
    }
}

/// Return the proper `hashSequence` value for a given a signing serialization
/// type.
/// @param signingSerializationType - the signing serialization type to test
/// @param transactionSequenceNumbers - see
/// {@link generateSigningSerializationComponentsBch}
/// @param sha256 - an implementation of sha256 (defaults to the internal
/// instance)
pub fn hash_sequence(
    signing_serialization_type: &[u8],
    transaction_sequence_numbers: &[u8],
    sha256: Option<&Sha256>,
) -> Vec<u8> {
    if !should_serialize_single_input(signing_serialization_type)
        && !should_serialize_corresponding_output(signing_serialization_type)
        && !should_serialize_no_outputs(signing_serialization_type)
    {
        hash256(transaction_sequence_numbers, sha256)
    } else {
        empty_hash()
    }
}

/// Return the proper `hashOutputs` value for a given a signing serialization
/// type.
/// @param signingSerializationType - the signing serialization type to test
/// @param transactionOutputs - see
/// {@link generateSigningSerializationComponentsBch}
/// @param correspondingOutput - see
/// {@link generateSigningSerializationComponentsBch}
/// @param sha256 - an implementation of sha256 (defaults to the internal
/// instance)
pub fn hash_outputs(
    corresponding_output: Option<&[u8]>,
    signing_serialization_type: &[u8],
    transaction_outputs: &[u8],
    sha256: Option<&Sha256>,
) -> Vec<u8> {
    if !should_serialize_corresponding_output(signing_serialization_type)
        && !should_serialize_no_outputs(signing_serialization_type)
    {
        return hash256(transaction_outputs, sha256);
    }
    if should_serialize_corresponding_output(signing_serialization_type) {
        return match corresponding_output {
            None => empty_hash(),
            Some(corresponding_output) => hash256(corresponding_output, sha256),
        };
    }
    empty_hash()
}

/// Encode the signing serialization for a particular transaction input
/// following the BIP143-like algorithm used by the BCH VM (with
/// `SIGHASH_UTXOS` support).
///
/// The components are those of libauth's options object (see
/// [`generate_signing_serialization_components_bch`]) in destructuring order;
/// `fork_id` defaults to `0x000000`, and `sha256` defaults to the internal
/// instance.
#[allow(clippy::too_many_arguments)]
pub fn encode_signing_serialization_bch(
    corresponding_output: Option<&[u8]>,
    covered_bytecode: &[u8],
    fork_id: Option<&[u8]>,
    locktime: u32,
    outpoint_index: u32,
    outpoint_transaction_hash: &[u8],
    output_token_prefix: &[u8],
    output_value: &[u8],
    sequence_number: u32,
    signing_serialization_type: &[u8],
    transaction_outpoints: &[u8],
    transaction_outputs: &[u8],
    transaction_sequence_numbers: &[u8],
    transaction_utxos: &[u8],
    version: u32,
    sha256: Option<&Sha256>,
) -> Vec<u8> {
    let fork_id = fork_id.unwrap_or(&[0, 0, 0]);
    let mut outpoint_transaction_hash = outpoint_transaction_hash.to_vec();
    outpoint_transaction_hash.reverse();
    flatten_bin_array(&[
        number_to_bin_uint32_le(version),
        hash_prevouts(signing_serialization_type, transaction_outpoints, sha256),
        hash_utxos(signing_serialization_type, transaction_utxos, sha256),
        hash_sequence(signing_serialization_type, transaction_sequence_numbers, sha256),
        outpoint_transaction_hash,
        number_to_bin_uint32_le(outpoint_index),
        output_token_prefix.to_vec(),
        big_int_to_compact_uint(covered_bytecode.len() as u64),
        covered_bytecode.to_vec(),
        output_value.to_vec(),
        number_to_bin_uint32_le(sequence_number),
        hash_outputs(corresponding_output, signing_serialization_type, transaction_outputs, sha256),
        number_to_bin_uint32_le(locktime),
        signing_serialization_type.to_vec(),
        fork_id.to_vec(),
    ])
}

/// @deprecated Alias of `encodeSigningSerializationBch` for
/// backwards-compatibility.
pub use self::encode_signing_serialization_bch as encode_signing_serialization_BCH;

/// The signing serialization components which are shared between all of the
/// inputs in a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningSerializationTransactionComponentsBch {
    /// A time or block height at which the transaction is considered valid
    /// (and can be added to the block chain). This allows signers to create
    /// time-locked transactions that may only become valid in the future.
    pub locktime: u32,
    /// A.K.A. the serialization for `hashPrevouts`
    ///
    /// The signing serialization of all input outpoints. (See BIP143 or
    /// Bitcoin Cash's Replay Protected Sighash spec for details.)
    pub transaction_outpoints: Vec<u8>,
    /// The signing serialization of output amounts and locking bytecode values.
    /// (See BIP143 or Bitcoin Cash's Replay Protected Sighash spec for details.)
    pub transaction_outputs: Vec<u8>,
    /// A.K.A. the serialization for `hashSequence`
    ///
    /// The signing serialization of all input sequence numbers. (See BIP143 or
    /// Bitcoin Cash's Replay Protected Sighash spec for details.)
    pub transaction_sequence_numbers: Vec<u8>,
    /// The signing serialization of all UTXOs spent by the transaction's
    /// inputs (concatenated in input order).
    pub transaction_utxos: Vec<u8>,
    /// The version number of the transaction.
    pub version: u32,
}

/// @deprecated Alias of `SigningSerializationTransactionComponentsBch` for
/// backwards-compatibility.
pub type SigningSerializationTransactionComponentsBCH = SigningSerializationTransactionComponentsBch;

/// All signing serialization components for a particular transaction input
/// (the {@link SigningSerializationTransactionComponentsBch} and the
/// input-specific components).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningSerializationComponentsBch {
    /// The encoded output with the same index as this input (or `None` if no
    /// such output exists).
    pub corresponding_output: Option<Vec<u8>>,
    pub locktime: u32,
    /// The index (within the previous transaction) of the outpoint being spent
    /// by this input.
    pub outpoint_index: u32,
    /// The hash/ID of the transaction from which the outpoint being spent by
    /// this input originated.
    pub outpoint_transaction_hash: Vec<u8>,
    /// The token prefix encoding of the outpoint being spent by this input.
    pub output_token_prefix: Vec<u8>,
    /// The 8-byte `Uint64LE`-encoded value of the outpoint in satoshis (see
    /// {@link bigIntToBinUint64LE}).
    pub output_value: Vec<u8>,
    /// The `sequenceNumber` associated with the input being validated. See
    /// {@link Input.sequenceNumber} for details.
    pub sequence_number: u32,
    pub transaction_outpoints: Vec<u8>,
    pub transaction_outputs: Vec<u8>,
    pub transaction_sequence_numbers: Vec<u8>,
    pub transaction_utxos: Vec<u8>,
    pub version: u32,
}

/// @deprecated Alias of `SigningSerializationComponentsBch` for
/// backwards-compatibility.
pub type SigningSerializationComponentsBCH = SigningSerializationComponentsBch;

/// Given a {@link CompilationContextBch}, generate the signing serialization
/// components for the input being compiled (`context.inputIndex`).
///
/// Generic over the input bytecode type so that both compilation contexts
/// (with possibly-undefined unlocking bytecode) and authentication programs
/// are accepted, as in libauth.
pub fn generate_signing_serialization_components_bch<Bytecode>(
    context: &CompilationContext<TransactionCommon<Input<Bytecode>>>,
) -> SigningSerializationComponentsBch {
    let input = &context.transaction.inputs[context.input_index];
    let source_output = &context.source_outputs[context.input_index];
    SigningSerializationComponentsBch {
        corresponding_output: context
            .transaction
            .outputs
            .get(context.input_index)
            .map(encode_transaction_output),
        locktime: context.transaction.locktime,
        outpoint_index: input.outpoint_index,
        outpoint_transaction_hash: input.outpoint_transaction_hash.clone(),
        output_token_prefix: encode_token_prefix(source_output.token.as_ref()),
        output_value: value_satoshis_to_bin(source_output.value_satoshis),
        sequence_number: input.sequence_number,
        transaction_outpoints: encode_transaction_outpoints(&context.transaction.inputs),
        transaction_outputs: encode_transaction_outputs_for_signing(&context.transaction.outputs),
        transaction_sequence_numbers: encode_transaction_input_sequence_numbers_for_signing(
            &context.transaction.inputs,
        ),
        transaction_utxos: encode_transaction_outputs_for_signing(&context.source_outputs),
        version: context.transaction.version,
    }
}

/// @deprecated Alias of `generateSigningSerializationComponentsBch` for
/// backwards-compatibility.
pub use self::generate_signing_serialization_components_bch as generate_signing_serialization_components_BCH;

/// Generate the encoded signing serialization for a particular input in the
/// provided compilation context (`sha256` defaults to the internal instance).
pub fn generate_signing_serialization_bch<Bytecode>(
    context: &CompilationContext<TransactionCommon<Input<Bytecode>>>,
    covered_bytecode: &[u8],
    signing_serialization_type: &[u8],
    sha256: Option<&Sha256>,
) -> Vec<u8> {
    let components = generate_signing_serialization_components_bch(context);
    encode_signing_serialization_bch(
        components.corresponding_output.as_deref(),
        covered_bytecode,
        None,
        components.locktime,
        components.outpoint_index,
        &components.outpoint_transaction_hash,
        &components.output_token_prefix,
        &components.output_value,
        components.sequence_number,
        signing_serialization_type,
        &components.transaction_outpoints,
        &components.transaction_outputs,
        &components.transaction_sequence_numbers,
        &components.transaction_utxos,
        components.version,
        sha256,
    )
}

/// @deprecated Alias of `generateSigningSerializationBch` for
/// backwards-compatibility.
pub use self::generate_signing_serialization_bch as generate_signing_serialization_BCH;

/// Return `true` if the provided signing serialization type does not set the
/// `SIGHASH_FORKID` flag (i.e. the legacy, pre-fork algorithm would be used).
///
/// @param signingSerializationType - the 32-bit number indicating the signing
/// serialization algorithm to use
pub fn is_legacy_signing_serialization(signing_serialization_type: i64) -> bool {
    // JavaScript bitwise operators work on 32-bit integers.
    let signing_serialization_type = signing_serialization_type as i32;
    let fork_value = signing_serialization_type >> 8;
    let new_fork_value = (fork_value ^ 0xdead) | 0x00ff_0000;
    let sighash_type = (new_fork_value << 8) | (signing_serialization_type & 0xff);
    (sighash_type & SigningSerializationFlag::forkId as i32) == 0
}
