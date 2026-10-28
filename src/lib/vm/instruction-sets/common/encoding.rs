use crate::vm::ConsensusCommon;

struct Asn1;

impl Asn1 {
    const SEQUENCE_TAG_TYPE: u8 = 0x30;
    const INTEGER_TAG_TYPE: u8 = 0x02;
}

struct Der;

impl Der {
    const MINIMUM_LENGTH: usize = 8;
    const MAXIMUM_LENGTH: usize = 72;
    const SEQUENCE_TAG_INDEX: usize = 0;
    const SEQUENCE_LENGTH_INDEX: usize = 1;
    const R_TAG_INDEX: usize = 2;
    const R_LENGTH_INDEX: usize = 3;
    const R_VALUE_INDEX: usize = 4;
    const SEQUENCE_TAG_BYTE: usize = 1;
    const SEQUENCE_LENGTH_BYTE: usize = 1;
    const INTEGER_TAG_BYTE: usize = 1;
    const INTEGER_LENGTH_BYTE: usize = 1;
    const SEQUENCE_METADATA_BYTES: usize = Der::SEQUENCE_TAG_BYTE + Der::SEQUENCE_LENGTH_BYTE;
    const INTEGER_METADATA_BYTES: usize = Der::INTEGER_TAG_BYTE + Der::INTEGER_LENGTH_BYTE;
    const MINIMUM_S_VALUE_BYTES: usize = 1;
    const MINIMUM_NON_R_VALUE_BYTES: usize = Der::SEQUENCE_METADATA_BYTES
        + Der::INTEGER_METADATA_BYTES
        + Der::INTEGER_METADATA_BYTES
        + Der::MINIMUM_S_VALUE_BYTES;
}

const MASK_NEGATIVE: u8 = 0x80;

fn is_negative(value: Option<&u8>) -> bool {
    value.is_some_and(|value| (value & MASK_NEGATIVE) != 0)
}

fn has_unnecessary_padding(length: usize, first_byte: Option<&u8>, second_byte: Option<&u8>) -> bool {
    length > 1 && first_byte == Some(&0) && !is_negative(second_byte)
}

fn is_valid_integer(signature: &[u8], tag_index: usize, length: usize, value_index: usize) -> bool {
    signature.get(tag_index) == Some(&Asn1::INTEGER_TAG_TYPE)
        && length != 0
        && !is_negative(signature.get(value_index))
        && !has_unnecessary_padding(length, signature.get(value_index), signature.get(value_index + 1))
}

/// Validate a DER-encoded signature.
///
/// @remarks
/// This function is consensus-critical since BIP66, but differs from the BIP66
/// specification in that it does not validate the existence of a signing
/// serialization type byte at the end of the signature (to support
/// OP_CHECKDATASIG). To validate a bitcoin-encoded signature (including null
/// signatures), use {@link isValidSignatureEncodingBchTransaction}.
///
/// @privateRemarks
/// From the Bitcoin ABC C++ implementation:
///
/// Format: `0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]`
/// total-length: 1-byte length descriptor of everything that follows,
/// excluding the sighash byte.
/// R-length: 1-byte length descriptor of the R value that follows.
/// R: arbitrary-length big-endian encoded R value. It must use the
/// shortest possible encoding for a positive integers (which means no null
/// bytes at the start, except a single one when the next byte has its highest
/// bit set).
/// S-length: 1-byte length descriptor of the S value that follows.
/// S: arbitrary-length big-endian encoded S value. The same rules apply.
pub fn is_valid_signature_encoding_der(signature: &[u8]) -> bool {
    let correct_length_range =
        signature.len() > Der::MINIMUM_LENGTH && signature.len() < Der::MAXIMUM_LENGTH;
    let correct_sequence_tag_type =
        signature.get(Der::SEQUENCE_TAG_INDEX) == Some(&Asn1::SEQUENCE_TAG_TYPE);
    let correct_sequence_length = signature
        .get(Der::SEQUENCE_LENGTH_INDEX)
        .is_some_and(|length| *length as isize == signature.len() as isize - Der::SEQUENCE_METADATA_BYTES as isize);
    let Some(&r_length) = signature.get(Der::R_LENGTH_INDEX) else {
        return false;
    };
    let r_length = r_length as usize;
    let consistent_r_length =
        r_length as isize <= signature.len() as isize - Der::MINIMUM_NON_R_VALUE_BYTES as isize;
    let r_is_valid = is_valid_integer(signature, Der::R_TAG_INDEX, r_length, Der::R_VALUE_INDEX);
    let s_tag_index = Der::R_VALUE_INDEX + r_length;
    let s_length_index = s_tag_index + 1;
    let Some(&s_length) = signature.get(s_length_index) else {
        return false;
    };
    let s_length = s_length as usize;
    let s_value_index = s_length_index + 1;
    let consistent_s_length = s_value_index + s_length == signature.len();
    let s_is_valid = is_valid_integer(signature, s_tag_index, s_length, s_value_index);
    correct_length_range
        && correct_sequence_tag_type
        && correct_sequence_length
        && consistent_r_length
        && r_is_valid
        && consistent_s_length
        && s_is_valid
}

/// Validate the encoding of a transaction signature, including a signing
/// serialization type byte (A.K.A. "sighash" byte).
///
/// @param transactionSignature - the full transaction signature
pub fn is_valid_signature_encoding_bch_transaction(
    transaction_signature: &[u8],
    valid_signing_serialization_types: &[u8],
) -> bool {
    transaction_signature.is_empty()
        || (valid_signing_serialization_types
            .contains(&transaction_signature[transaction_signature.len() - 1])
            && (transaction_signature.len() == ConsensusCommon::schnorrSignatureLength + 1
                || is_valid_signature_encoding_der(
                    &transaction_signature[..transaction_signature.len() - 1],
                )))
}

/// Split a bitcoin-encoded signature into a signature and signing serialization
/// type (returned as `(signature, signingSerializationType)`).
///
/// While a bitcoin-encoded signature only includes a single byte to encode the
/// signing serialization type, a 3-byte forkId can be appended to the signing
/// serialization to provide replay-protection between different forks. (See
/// Bitcoin Cash's Replay Protected Sighash spec for details.)
///
/// @param encodedSignature - a signature that passes
/// {@link isValidSignatureEncodingBchTransaction}
pub fn decode_bitcoin_signature(encoded_signature: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let split = encoded_signature.len().saturating_sub(1);
    (
        encoded_signature[..split].to_vec(),
        encoded_signature[split..].to_vec(),
    )
}
