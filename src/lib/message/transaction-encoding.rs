use crate::crypto::{hash256, Sha256};
use crate::format::{
    big_int_to_compact_uint, bin_to_hex, flatten_bin_array, format_error, number_to_bin_uint32_le,
    read_compact_uint_minimal, read_item_count, read_multiple, value_satoshis_to_bin,
    MaybeReadResult, ReadPosition, ReadResult,
};

use super::read_components::{
    read_bytes, read_compact_uint_prefixed_bin, read_remaining_bytes, read_uint32_le,
    read_uint64_le,
};
use super::transaction_types::{Input, Nft, NonFungibleTokenCapability, Output, Token, TransactionCommon};

const OUTPOINT_TRANSACTION_HASH_LENGTH: usize = 32;

/// Encode a single input for inclusion in an encoded transaction.
///
/// @param input - the input to encode
pub fn encode_transaction_input(input: &Input) -> Vec<u8> {
    let mut outpoint_transaction_hash = input.outpoint_transaction_hash.clone();
    outpoint_transaction_hash.reverse();
    flatten_bin_array(&[
        outpoint_transaction_hash,
        number_to_bin_uint32_le(input.outpoint_index),
        big_int_to_compact_uint(input.unlocking_bytecode.len() as u64),
        input.unlocking_bytecode.clone(),
        number_to_bin_uint32_le(input.sequence_number),
    ])
}

/// Errors produced while decoding a transaction.
pub struct TransactionDecodingError;

impl TransactionDecodingError {
    pub const transaction: &'static str = "Error reading transaction.";
    pub const endsWithUnexpectedBytes: &'static str = "Error decoding transaction: the provided input includes unexpected bytes after the encoded transaction.";
    pub const input: &'static str = "Error reading transaction input.";
    pub const inputs: &'static str = "Error reading transaction inputs.";
    pub const output: &'static str = "Error reading transaction output.";
    pub const outputs: &'static str = "Error reading transaction outputs.";
    pub const outputsEndWithUnexpectedBytes: &'static str = "Error decoding transaction outputs: the provided serialization includes unexpected bytes after the encoded transaction outputs.";
    pub const lockingBytecodeLength: &'static str = "Error reading locking bytecode length.";
}

/// Read a transaction {@link Input} from the provided {@link ReadPosition},
/// returning either an error message (as a string) or an object containing the
/// {@link Input} and the next {@link ReadPosition}.
pub fn read_transaction_input(position: ReadPosition<'_>) -> MaybeReadResult<'_, Input> {
    let input_read = read_multiple(
        position,
        (
            read_bytes(OUTPOINT_TRANSACTION_HASH_LENGTH),
            read_uint32_le,
            read_compact_uint_prefixed_bin,
            read_uint32_le,
        ),
    )
    .map_err(|error| format_error(TransactionDecodingError::input, Some(&error)))?;
    let ReadResult {
        position: next_position,
        result: (mut outpoint_transaction_hash, outpoint_index, unlocking_bytecode, sequence_number),
    } = input_read;
    outpoint_transaction_hash.reverse();
    Ok(ReadResult {
        position: next_position,
        result: Input {
            outpoint_index,
            outpoint_transaction_hash,
            sequence_number,
            unlocking_bytecode,
        },
    })
}

/// Encode a set of {@link Input}s for inclusion in an encoded transaction
/// including the prefixed number of inputs.
///
/// Format: [CompactUint: input count] [encoded inputs]
///
/// @param inputs - the set of inputs to encode
pub fn encode_transaction_inputs(inputs: &[Input]) -> Vec<u8> {
    let mut parts = vec![big_int_to_compact_uint(inputs.len() as u64)];
    parts.extend(inputs.iter().map(encode_transaction_input));
    flatten_bin_array(&parts)
}

/// Read a set of transaction {@link Input}s beginning at {@link ReadPosition}.
/// A CompactUint will be read to determine the number of inputs, and that
/// number of transaction inputs will be read and returned. Returns either an
/// error message (as a string) or an object containing the array of inputs and
/// the next {@link ReadPosition}.
pub fn read_transaction_inputs(position: ReadPosition<'_>) -> MaybeReadResult<'_, Vec<Input>> {
    read_item_count(position, read_transaction_input)
        .map_err(|error| format_error(TransactionDecodingError::inputs, Some(&error)))
}

const PREFIX_TOKEN: u8 = 0xef;
const HAS_AMOUNT: u8 = 0b0001_0000;
const HAS_NFT: u8 = 0b0010_0000;
const HAS_COMMITMENT_LENGTH: u8 = 0b0100_0000;
const RESERVED_BIT: u8 = 0b1000_0000;
const TOKEN_BITFIELD_INDEX: usize = 33;
const MINIMUM_PREFIX_LENGTH: usize = 34;
const TOKEN_FORMAT_MASK: u8 = 0xf0;
const NFT_CAPABILITY_MASK: u8 = 0x0f;
const MAXIMUM_CAPABILITY: u8 = 2;

const MAXIMUM_TOKEN_AMOUNT: u64 = 9_223_372_036_854_775_807;

/// Map a non-fungible token capability's number (as encoded in a token prefix)
/// to its label.
pub const nftCapabilityNumberToLabel: [NonFungibleTokenCapability; 3] = [
    NonFungibleTokenCapability::None,
    NonFungibleTokenCapability::Mutable,
    NonFungibleTokenCapability::Minting,
];

/// Map a non-fungible token capability's label to its number (as encoded in a
/// token prefix).
pub static nftCapabilityLabelToNumber: std::sync::LazyLock<std::collections::BTreeMap<NonFungibleTokenCapability, u8>> =
    std::sync::LazyLock::new(|| {
        std::collections::BTreeMap::from([
            (NonFungibleTokenCapability::None, 0),
            (NonFungibleTokenCapability::Mutable, 1),
            (NonFungibleTokenCapability::Minting, 2),
        ])
    });

/// Errors produced while decoding a token prefix.
pub struct CashTokenDecodingError;

impl CashTokenDecodingError {
    pub const invalidPrefix: &'static str = "Error reading token prefix.";
    pub const insufficientLength: &'static str = "Invalid token prefix: insufficient length.";
    pub const reservedBit: &'static str = "Invalid token prefix: reserved bit is set.";
    pub const invalidCapability: &'static str =
        "Invalid token prefix: capability must be none (0), mutable (1), or minting (2).";
    pub const commitmentWithoutNft: &'static str =
        "Invalid token prefix: commitment requires an NFT.";
    pub const capabilityWithoutNft: &'static str =
        "Invalid token prefix: capability requires an NFT.";
    pub const commitmentLengthZero: &'static str =
        "Invalid token prefix: if encoded, commitment length must be greater than 0.";
    pub const invalidCommitment: &'static str =
        "Invalid token prefix: invalid non-fungible token commitment.";
    pub const invalidAmountEncoding: &'static str =
        "Invalid token prefix: invalid fungible token amount encoding.";
    pub const zeroAmount: &'static str =
        "Invalid token prefix: if encoded, fungible token amount must be greater than 0.";
    pub const excessiveAmount: &'static str =
        "Invalid token prefix: exceeds maximum fungible token amount of 9223372036854775807.";
    pub const noTokens: &'static str = "Invalid token prefix: must encode at least one token.";
}

/// Read a token amount from the provided {@link ReadPosition}, returning
/// either an error message (as a string) or an object containing the value and
/// the next {@link ReadPosition}.
pub fn read_token_amount(position: ReadPosition<'_>) -> MaybeReadResult<'_, u64> {
    let amount_read = read_compact_uint_minimal(position).map_err(|error| {
        format_error(CashTokenDecodingError::invalidAmountEncoding, Some(&error))
    })?;
    if amount_read.result > MAXIMUM_TOKEN_AMOUNT {
        return Err(format_error(
            CashTokenDecodingError::excessiveAmount,
            Some(&format!("Encoded amount: {}", amount_read.result)),
        ));
    }
    if amount_read.result == 0 {
        return Err(format_error(CashTokenDecodingError::zeroAmount, None));
    }
    Ok(amount_read)
}

/// Attempt to read a transaction {@link Output}'s token prefix from the
/// provided {@link ReadPosition}, returning either an error message (as a
/// string) or an object containing the (optional) token information and the
/// next {@link ReadPosition}.
///
/// Rather than using this function directly, most applications should
/// use {@link readLockingBytecodeWithPrefix}.
pub fn read_token_prefix(position: ReadPosition<'_>) -> MaybeReadResult<'_, Option<Token>> {
    let ReadPosition { bin, index } = position;
    if bin.get(index) != Some(&PREFIX_TOKEN) {
        return Ok(ReadResult {
            position,
            result: None,
        });
    }
    if bin.len() < index + MINIMUM_PREFIX_LENGTH {
        return Err(format_error(
            CashTokenDecodingError::insufficientLength,
            Some(&format!(
                "The minimum possible length is {MINIMUM_PREFIX_LENGTH}. Missing bytes: {}",
                MINIMUM_PREFIX_LENGTH - (bin.len() - index)
            )),
        ));
    }
    let mut category = bin[index + 1..index + TOKEN_BITFIELD_INDEX].to_vec();
    category.reverse();
    let token_bitfield = bin[index + TOKEN_BITFIELD_INDEX];
    let prefix_structure = token_bitfield & TOKEN_FORMAT_MASK;
    if prefix_structure & RESERVED_BIT != 0 {
        return Err(format_error(
            CashTokenDecodingError::reservedBit,
            Some(&format!("Bitfield: 0b{token_bitfield:b}")),
        ));
    }
    let nft_capability_int = token_bitfield & NFT_CAPABILITY_MASK;
    if nft_capability_int > MAXIMUM_CAPABILITY {
        return Err(format_error(
            CashTokenDecodingError::invalidCapability,
            Some(&format!("Capability value: {nft_capability_int}")),
        ));
    }
    let capability = nftCapabilityNumberToLabel[nft_capability_int as usize];
    let has_nft = prefix_structure & HAS_NFT != 0;
    let has_commitment_length = prefix_structure & HAS_COMMITMENT_LENGTH != 0;
    if has_commitment_length && !has_nft {
        return Err(format_error(
            CashTokenDecodingError::commitmentWithoutNft,
            Some(&format!("Bitfield: 0b{token_bitfield:b}")),
        ));
    }
    let has_amount = prefix_structure & HAS_AMOUNT != 0;
    let next_position = ReadPosition {
        bin,
        index: index + TOKEN_BITFIELD_INDEX + 1,
    };
    if has_nft {
        let commitment_read = if has_commitment_length {
            read_compact_uint_prefixed_bin(next_position).map_err(|error| {
                format_error(CashTokenDecodingError::invalidCommitment, Some(&error))
            })?
        } else {
            ReadResult {
                position: next_position,
                result: Vec::new(),
            }
        };
        if has_commitment_length && commitment_read.result.is_empty() {
            return Err(format_error(CashTokenDecodingError::commitmentLengthZero, None));
        }
        let amount_read = if has_amount {
            read_token_amount(commitment_read.position)?
        } else {
            ReadResult {
                position: commitment_read.position,
                result: 0,
            }
        };
        return Ok(ReadResult {
            position: amount_read.position,
            result: Some(Token {
                amount: amount_read.result,
                category,
                nft: Some(Nft {
                    capability,
                    commitment: commitment_read.result,
                }),
            }),
        });
    }
    if capability != NonFungibleTokenCapability::None {
        return Err(format_error(
            CashTokenDecodingError::capabilityWithoutNft,
            Some(&format!("Bitfield: 0b{token_bitfield:b}")),
        ));
    }
    if !has_amount {
        return Err(format_error(
            CashTokenDecodingError::noTokens,
            Some(&format!("Bitfield: 0b{token_bitfield:b}")),
        ));
    }
    let amount_read = read_token_amount(next_position)?;
    Ok(ReadResult {
        position: amount_read.position,
        result: Some(Token {
            amount: amount_read.result,
            category,
            nft: None,
        }),
    })
}

/// Read the locking bytecode and token information from a transaction
/// {@link Output}, beginning at the `CompactUint` prefix of the "locking
/// bytecode" field. Returns either an error message (as a string) or an object
/// containing the locking bytecode, the (optional) token information, and the
/// next {@link ReadPosition}.
#[doc(hidden)]
fn read_remaining_bytes_infallible(position: ReadPosition<'_>) -> MaybeReadResult<'_, Vec<u8>> {
    Ok(read_remaining_bytes(position))
}

pub fn read_locking_bytecode_with_prefix(
    position: ReadPosition<'_>,
) -> MaybeReadResult<'_, (Vec<u8>, Option<Token>)> {
    let bytecode_read = read_compact_uint_prefixed_bin(position).map_err(|error| {
        format_error(TransactionDecodingError::lockingBytecodeLength, Some(&error))
    })?;
    let ReadResult {
        result: contents,
        position: next_position,
    } = bytecode_read;
    let contents_read = read_multiple(
        ReadPosition {
            bin: &contents,
            index: 0,
        },
        (read_token_prefix, read_remaining_bytes_infallible),
    )
    .map_err(|error| format_error(CashTokenDecodingError::invalidPrefix, Some(&error)))?;
    let (token, locking_bytecode) = contents_read.result;
    Ok(ReadResult {
        position: next_position,
        result: (locking_bytecode, token),
    })
}

/// Read a transaction {@link Output} from the provided {@link ReadPosition},
/// returning either an error message (as a string) or an object containing the
/// {@link Output} and the next {@link ReadPosition}.
pub fn read_transaction_output(position: ReadPosition<'_>) -> MaybeReadResult<'_, Output> {
    let output_read = read_multiple(position, (read_uint64_le, read_locking_bytecode_with_prefix))
        .map_err(|error| format_error(TransactionDecodingError::output, Some(&error)))?;
    let ReadResult {
        position: next_position,
        result: (value_satoshis, (locking_bytecode, token)),
    } = output_read;
    Ok(ReadResult {
        position: next_position,
        result: Output {
            locking_bytecode,
            token,
            value_satoshis,
        },
    })
}

/// Encode a token prefix for the provided token information. Returns an empty
/// `Uint8Array` if the output has no token (or if the token amount is zero
/// without an NFT).
pub fn encode_token_prefix(token: Option<&Token>) -> Vec<u8> {
    let Some(token) = token else {
        return Vec::new();
    };
    if token.nft.is_none() && token.amount < 1 {
        return Vec::new();
    }
    let has_nft = if token.nft.is_none() { 0 } else { HAS_NFT };
    let capability_int = token
        .nft
        .as_ref()
        .map_or(0, |nft| nftCapabilityLabelToNumber[&nft.capability]);
    let has_commitment_length = match &token.nft {
        Some(nft) if !nft.commitment.is_empty() => HAS_COMMITMENT_LENGTH,
        _ => 0,
    };
    let has_amount = if token.amount > 0 { HAS_AMOUNT } else { 0 };
    let token_bitfield = has_nft | has_commitment_length | has_amount | capability_int;
    let mut category = token.category.clone();
    category.reverse();
    let mut parts = vec![vec![PREFIX_TOKEN], category, vec![token_bitfield]];
    if has_commitment_length != 0 {
        let commitment = &token.nft.as_ref().expect("an NFT with a commitment").commitment;
        parts.push(big_int_to_compact_uint(commitment.len() as u64));
        parts.push(commitment.clone());
    }
    if has_amount != 0 {
        parts.push(big_int_to_compact_uint(token.amount));
    }
    flatten_bin_array(&parts)
}

/// Encode a single {@link Output} for inclusion in an encoded transaction.
///
/// @param output - the output to encode
pub fn encode_transaction_output(output: &Output) -> Vec<u8> {
    let locking_bytecode_field = flatten_bin_array(&[
        encode_token_prefix(output.token.as_ref()),
        output.locking_bytecode.clone(),
    ]);
    flatten_bin_array(&[
        value_satoshis_to_bin(output.value_satoshis),
        big_int_to_compact_uint(locking_bytecode_field.len() as u64),
        locking_bytecode_field,
    ])
}

/// Read a set of transaction {@link Output}s beginning at {@link ReadPosition}.
/// A CompactUint will be read to determine the number of outputs, and that
/// number of transaction outputs will be read and returned. Returns either an
/// error message (as a string) or an object containing the array of outputs
/// and the next {@link ReadPosition}.
pub fn read_transaction_outputs(position: ReadPosition<'_>) -> MaybeReadResult<'_, Vec<Output>> {
    read_item_count(position, read_transaction_output)
        .map_err(|error| format_error(TransactionDecodingError::outputs, Some(&error)))
}

/// Decode a CompactUint-prefixed series of transaction {@link Output}s,
/// requiring that the provided encoding contains no trailing bytes.
pub fn decode_transaction_outputs(bin: &[u8]) -> Result<Vec<Output>, String> {
    let outputs_read = read_transaction_outputs(ReadPosition { bin, index: 0 })?;
    if outputs_read.position.index != bin.len() {
        return Err(format_error(
            TransactionDecodingError::outputsEndWithUnexpectedBytes,
            Some(&format!(
                "Last encoded transaction output ends at index {}, leaving {} remaining byte(s).",
                outputs_read.position.index as i64 - 1,
                bin.len() - outputs_read.position.index
            )),
        ));
    }
    Ok(outputs_read.result)
}

/// Encode a set of {@link Output}s for inclusion in an encoded transaction
/// including the prefixed number of outputs. Note, this encoding differs from
/// {@link encodeTransactionOutputsForSigning} (used for signing serializations).
///
/// Format: [CompactUint: output count] [encoded outputs]
///
/// @param outputs - the set of outputs to encode
pub fn encode_transaction_outputs(outputs: &[Output]) -> Vec<u8> {
    let mut parts = vec![big_int_to_compact_uint(outputs.len() as u64)];
    parts.extend(outputs.iter().map(encode_transaction_output));
    flatten_bin_array(&parts)
}

/// Read a version 1 or 2 transaction beginning at {@link ReadPosition},
/// returning either an error message (as a string) or an object containing the
/// {@link TransactionCommon} and the next {@link ReadPosition}. Rather than
/// using this function directly, most applications should
/// use {@link decodeTransactionCommon}.
pub fn read_transaction_common(position: ReadPosition<'_>) -> MaybeReadResult<'_, TransactionCommon> {
    let transaction_read = read_multiple(
        position,
        (read_uint32_le, read_transaction_inputs, read_transaction_outputs, read_uint32_le),
    )
    .map_err(|error| format_error(TransactionDecodingError::transaction, Some(&error)))?;
    let ReadResult {
        position: next_position,
        result: (version, inputs, outputs, locktime),
    } = transaction_read;
    Ok(ReadResult {
        position: next_position,
        result: TransactionCommon {
            inputs,
            locktime,
            outputs,
            version,
        },
    })
}

/// An alias of {@link readTransactionCommon}.
pub use self::read_transaction_common as read_transaction;

/// Read a transaction {@link Output} from the provided {@link ReadPosition}
/// without support for CashTokens, returning either an error message (as a
/// string) or an object containing the {@link Output} and the next
/// {@link ReadPosition}.
///
/// Note: this function is only useful for decoding pre-CashTokens transactions;
/// most applications should use {@link readTransactionOutput}.
pub fn read_transaction_output_non_token_aware(
    pos: ReadPosition<'_>,
) -> MaybeReadResult<'_, Output> {
    let output_read = read_multiple(pos, (read_uint64_le, read_compact_uint_prefixed_bin))
        .map_err(|error| format_error(TransactionDecodingError::output, Some(&error)))?;
    let ReadResult {
        position: next_position,
        result: (value_satoshis, locking_bytecode),
    } = output_read;
    Ok(ReadResult {
        position: next_position,
        result: Output {
            locking_bytecode,
            token: None,
            value_satoshis,
        },
    })
}

/// Read a set of transaction {@link Output}s beginning at {@link ReadPosition}
/// without support for CashTokens. A CompactUint will be read to determine the
/// number of outputs, and that number of transaction outputs will be read and
/// returned. Returns either an error message (as a string) or an object
/// containing the array of outputs and the next {@link ReadPosition}.
///
/// Note: this function is only useful for decoding pre-CashTokens transactions;
/// most applications should use {@link readTransactionOutputs}.
pub fn read_transaction_outputs_non_token_aware(
    pos: ReadPosition<'_>,
) -> MaybeReadResult<'_, Vec<Output>> {
    read_item_count(pos, read_transaction_output_non_token_aware)
        .map_err(|error| format_error(TransactionDecodingError::outputs, Some(&error)))
}

/// Read a version 1 or 2 transaction beginning at {@link ReadPosition}
/// without support for CashTokens, returning either an error message (as a
/// string) or an object containing the {@link TransactionCommon} and the next
/// {@link ReadPosition}.
///
/// Note: this function is only useful for decoding pre-CashTokens transactions;
/// most applications should use {@link readTransactionCommon}.
pub fn read_transaction_non_token_aware(
    position: ReadPosition<'_>,
) -> MaybeReadResult<'_, TransactionCommon> {
    let transaction_read = read_multiple(
        position,
        (
            read_uint32_le,
            read_transaction_inputs,
            read_transaction_outputs_non_token_aware,
            read_uint32_le,
        ),
    )
    .map_err(|error| format_error(TransactionDecodingError::transaction, Some(&error)))?;
    let ReadResult {
        position: next_position,
        result: (version, inputs, outputs, locktime),
    } = transaction_read;
    Ok(ReadResult {
        position: next_position,
        result: TransactionCommon {
            inputs,
            locktime,
            outputs,
            version,
        },
    })
}

/// Decode a {@link TransactionCommon} according to the version 1/2 P2P
/// network transaction format.
///
/// This method checks that the provided input includes no trailing bytes; if
/// unexpected trailing bytes are present, an error is returned.
///
/// @param bin - the encoded transaction to decode
pub fn decode_transaction_common(bin: &[u8]) -> Result<TransactionCommon, String> {
    let transaction_read = read_transaction_common(ReadPosition { bin, index: 0 })?;
    if transaction_read.position.index != bin.len() {
        return Err(format_error(
            TransactionDecodingError::endsWithUnexpectedBytes,
            Some(&format!(
                "Encoded transaction ends at index {}, leaving {} remaining bytes.",
                transaction_read.position.index as i64 - 1,
                bin.len() - transaction_read.position.index
            )),
        ));
    }
    Ok(transaction_read.result)
}

/// An alias of {@link decodeTransactionCommon}.
pub use self::decode_transaction_common as decode_transaction_bch;

/// An alias of {@link decodeTransactionBch}.
pub use self::decode_transaction_bch as decode_transaction;

/// @deprecated Alias of `decodeTransactionBch` for backwards-compatibility.
pub use self::decode_transaction_bch as decode_transaction_BCH;

/// Decode a {@link TransactionCommon} from a trusted source according to the
/// version 1/2 P2P network transaction format.
///
/// Note: this method panics on invalid input. Most applications should instead
/// use {@link decodeTransactionCommon}.
///
/// @param bin - the encoded transaction to decode
pub fn decode_transaction_unsafe_common(bin: &[u8]) -> TransactionCommon {
    match decode_transaction_common(bin) {
        Ok(transaction) => transaction,
        Err(error) => panic!("{error}"),
    }
}

/// An alias of {@link decodeTransactionUnsafeCommon}.
pub use self::decode_transaction_unsafe_common as decode_transaction_unsafe_bch;

/// An alias of {@link decodeTransactionUnsafeBch}.
pub use self::decode_transaction_unsafe_bch as decode_transaction_unsafe;

/// @deprecated Alias of `decodeTransactionUnsafeBch` for backwards-compatibility.
pub use self::decode_transaction_unsafe_bch as decode_transaction_unsafe_BCH;

/// Encode a {@link TransactionCommon} using the standard P2P network format.
///
/// Note, this method assumes the provided transaction is valid.
///
/// @param tx - the transaction to encode
pub fn encode_transaction_common(tx: &TransactionCommon) -> Vec<u8> {
    flatten_bin_array(&[
        number_to_bin_uint32_le(tx.version),
        encode_transaction_inputs(&tx.inputs),
        encode_transaction_outputs(&tx.outputs),
        number_to_bin_uint32_le(tx.locktime),
    ])
}

/// An alias of {@link encodeTransactionCommon}.
pub use self::encode_transaction_common as encode_transaction_bch;

/// An alias of {@link encodeTransactionBch}.
pub use self::encode_transaction_bch as encode_transaction;

/// @deprecated Alias of `encodeTransactionBch` for backwards-compatibility.
pub use self::encode_transaction_bch as encode_transaction_BCH;

/// Compute a transaction hash (A.K.A. "transaction ID" or "TXID") from an
/// encoded transaction in P2P network message order. This is the byte order
/// typically used within bitcoin wire protocols.
///
/// @param transaction - the encoded transaction
/// @param sha256 - an implementation of sha256
pub fn hash_transaction_p2p_order(transaction: &[u8], sha256: Option<&Sha256>) -> Vec<u8> {
    hash256(transaction, sha256)
}

/// Compute a transaction hash (A.K.A. "transaction ID" or "TXID") from an
/// encoded transaction in user interface byte order. This is the byte order
/// typically used by block explorers, wallets, and RPCs.
///
/// @param transaction - the encoded transaction
/// @param sha256 - an implementation of sha256
pub fn hash_transaction_ui_order(transaction: &[u8], sha256: Option<&Sha256>) -> Vec<u8> {
    let mut hash = hash_transaction_p2p_order(transaction, sha256);
    hash.reverse();
    hash
}

/// Derive a standard identifier from a serialized data structure.
///
/// @remarks
/// By convention, Bitcoin transaction and block identifiers are derived by
/// double-sha256 hashing their serialized form, and then reversing the byte
/// order. (The result of each hash is a big-endian number, but it is converted
/// to little-endian for display.)
///
/// @param transaction - the serialized transaction from which to derive the
/// identifier
pub fn hash_transaction(transaction: &[u8]) -> String {
    bin_to_hex(&hash_transaction_ui_order(transaction, None))
}

/// Get the hash of all outpoints in a series of inputs. (For use in
/// `hashTransactionOutpoints`.)
///
/// @param inputs - the series of inputs from which to extract the outpoints
pub fn encode_transaction_outpoints<Bytecode>(inputs: &[Input<Bytecode>]) -> Vec<u8> {
    flatten_bin_array(
        &inputs
            .iter()
            .map(|input| {
                let mut outpoint_transaction_hash = input.outpoint_transaction_hash.clone();
                outpoint_transaction_hash.reverse();
                flatten_bin_array(&[
                    outpoint_transaction_hash,
                    number_to_bin_uint32_le(input.outpoint_index),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

/// Encode an array of transaction {@link Output}s for use in transaction
/// signing serializations. Note, this encoding differs from
/// {@link encodeTransactionOutputs} (used for encoding full transactions).
///
/// @param outputs - the array of outputs to encode
pub fn encode_transaction_outputs_for_signing(outputs: &[Output]) -> Vec<u8> {
    flatten_bin_array(&outputs.iter().map(encode_transaction_output).collect::<Vec<_>>())
}

/// Encode an array of input sequence numbers for use in transaction signing
/// serializations.
///
/// @param inputs - the array of inputs from which to extract the sequence
/// numbers
pub fn encode_transaction_input_sequence_numbers_for_signing<Bytecode>(
    inputs: &[Input<Bytecode>],
) -> Vec<u8> {
    flatten_bin_array(
        &inputs
            .iter()
            .map(|input| number_to_bin_uint32_le(input.sequence_number))
            .collect::<Vec<_>>(),
    )
}
