use std::rc::Rc;

use crate::crypto::{hash256, Ripemd160, Secp256k1, Sha1, Sha256};
use crate::format::bin_to_hex;
use crate::runtime::bigint::BigInt;
use crate::runtime::number::number_to_string;
use crate::vm::{
    apply_error, boolean_to_vm_number, combine_operations, decode_bitcoin_signature,
    encode_authentication_instructions, generate_signing_serialization_bch,
    increment_hash_digest_iterations, is_valid_public_key_encoding,
    is_valid_signature_encoding_bch_transaction, is_valid_signature_encoding_der,
    length_to_hash_digest_iteration_count, op_verify, push_to_stack, use_one_stack_item,
    use_one_vm_number, use_three_stack_items, use_two_stack_items, AuthenticationErrorCommon,
    AuthenticationProgramStateCommon, AuthenticationProgramStateSignedMessage, ConsensusCommon,
    Operation, SigningSerializationTypesBch,
};

fn default_ripemd160(ripemd160: Option<Ripemd160>) -> Ripemd160 {
    ripemd160.unwrap_or_else(|| crate::crypto::ripemd160.clone())
}

fn default_sha1(sha1: Option<Sha1>) -> Sha1 {
    sha1.unwrap_or_else(|| crate::crypto::sha1.clone())
}

fn default_sha256(sha256: Option<Sha256>) -> Sha256 {
    sha256.unwrap_or_else(|| crate::crypto::sha256.clone())
}

fn default_secp256k1(secp256k1: Option<Secp256k1>) -> Secp256k1 {
    secp256k1.unwrap_or_else(|| crate::crypto::secp256k1.clone())
}

/// `ripemd160` defaults to the internal instance.
pub fn op_ripemd160(ripemd160: Option<Ripemd160>) -> Operation {
    let ripemd160 = default_ripemd160(ripemd160);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_stack_item(state, |next_state, [value]| {
            increment_hash_digest_iterations(next_state, value.len(), false, |final_state| {
                push_to_stack(final_state, vec![ripemd160.hash(&value)], None);
            });
        });
    })
}

/// `sha1` defaults to the internal instance.
pub fn op_sha1(sha1: Option<Sha1>) -> Operation {
    let sha1 = default_sha1(sha1);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_stack_item(state, |next_state, [value]| {
            increment_hash_digest_iterations(next_state, value.len(), false, |final_state| {
                push_to_stack(final_state, vec![sha1.hash(&value)], None);
            });
        });
    })
}

/// `sha256` defaults to the internal instance.
pub fn op_sha256(sha256: Option<Sha256>) -> Operation {
    let sha256 = default_sha256(sha256);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_stack_item(state, |next_state, [value]| {
            increment_hash_digest_iterations(next_state, value.len(), false, |final_state| {
                push_to_stack(final_state, vec![sha256.hash(&value)], None);
            });
        });
    })
}

/// `ripemd160` and `sha256` default to the internal instances.
pub fn op_hash160(ripemd160: Option<Ripemd160>, sha256: Option<Sha256>) -> Operation {
    let ripemd160 = default_ripemd160(ripemd160);
    let sha256 = default_sha256(sha256);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_stack_item(state, |next_state, [value]| {
            increment_hash_digest_iterations(next_state, value.len(), true, |final_state| {
                push_to_stack(final_state, vec![ripemd160.hash(&sha256.hash(&value))], None);
            });
        });
    })
}

/// `sha256` defaults to the internal instance.
pub fn op_hash256(sha256: Option<Sha256>) -> Operation {
    let sha256 = default_sha256(sha256);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_one_stack_item(state, |next_state, [value]| {
            increment_hash_digest_iterations(next_state, value.len(), true, |final_state| {
                push_to_stack(final_state, vec![hash256(&value, Some(&sha256))], None);
            });
        });
    })
}

pub fn op_code_separator(state: &mut AuthenticationProgramStateCommon) {
    state.last_code_separator = state.ip;
}

fn covered_bytecode(state: &AuthenticationProgramStateCommon) -> Vec<u8> {
    let start = usize::try_from(state.last_code_separator + 1).unwrap_or(0);
    encode_authentication_instructions(&state.instructions[start.min(state.instructions.len())..])
}

/// `secp256k1` and `sha256` default to the internal instances.
pub fn op_check_sig(secp256k1: Option<Secp256k1>, sha256: Option<Sha256>) -> Operation {
    let secp256k1 = default_secp256k1(secp256k1);
    let sha256 = default_sha256(sha256);
    Rc::new(move |s: &mut AuthenticationProgramStateCommon| {
        use_two_stack_items(s, |state, [bitcoin_encoded_signature, public_key]| {
            if !is_valid_public_key_encoding(&public_key) {
                apply_error(state, AuthenticationErrorCommon::invalidPublicKeyEncoding, None);
                return;
            }
            if !is_valid_signature_encoding_bch_transaction(
                &bitcoin_encoded_signature,
                SigningSerializationTypesBch,
            ) {
                let details = format!(
                    "Transaction signature (including signing serialization): {}",
                    bin_to_hex(&bitcoin_encoded_signature)
                );
                apply_error(state, AuthenticationErrorCommon::invalidSignatureEncoding, Some(&details));
                return;
            }
            if bitcoin_encoded_signature.is_empty() {
                push_to_stack(state, vec![boolean_to_vm_number(false)], None);
                return;
            }
            let covered_bytecode = covered_bytecode(state);
            let (signature, signing_serialization_type) =
                decode_bitcoin_signature(&bitcoin_encoded_signature);
            let serialization = generate_signing_serialization_bch(
                &state.program,
                &covered_bytecode,
                &signing_serialization_type,
                Some(&sha256),
            );
            let digest = hash256(&serialization, Some(&sha256));
            state.metrics.signature_check_count += 1.0;
            let double_hashed = 1;
            state.metrics.hash_digest_iterations +=
                (double_hashed + length_to_hash_digest_iteration_count(serialization.len())) as f64;
            state
                .signed_messages
                .push(AuthenticationProgramStateSignedMessage::Serialization {
                    digest: digest.clone(),
                    serialization,
                });
            let use_schnorr = signature.len() == ConsensusCommon::schnorrSignatureLength;
            let success = if use_schnorr {
                secp256k1.verify_signature_schnorr(&signature, &public_key, &digest)
            } else {
                secp256k1.verify_signature_der_low_s(&signature, &public_key, &digest)
            };
            if success {
                push_to_stack(state, vec![boolean_to_vm_number(success)], None);
            } else {
                let details =
                    format!("Algorithm used: {}.", if use_schnorr { "Schnorr" } else { "ECDSA" });
                apply_error(state, AuthenticationErrorCommon::nonNullSignatureFailure, Some(&details));
            }
        });
    })
}

const MULTISIG_MAXIMUM_PUBLIC_KEYS: f64 = 20.0;
const MULTISIG_BINARY: u32 = 2;

/// Return the number of `1` bits in the number `n`.
/// @param n - the number
pub fn count_bits(n: &BigInt) -> usize {
    n.to_string_radix(MULTISIG_BINARY)
        .chars()
        .filter(|character| *character != '0')
        .count()
}

/// The errors which can occur when decoding a CheckBits bitfield.
pub struct BitfieldDecodeError;

#[allow(non_upper_case_globals)]
impl BitfieldDecodeError {
    pub const invalidBitfieldSize: &'static str =
        "BitfieldDecode error: bitfield exceeds maximum length (32 bits).";
    pub const bitsSetBeyondExpectedRange: &'static str =
        "BitfieldDecode error: the decoded bitfield includes bits set beyond the expected range.";
}

/// Decode a non-null `OP_CHECKMULTISIG` bitfield (A.K.A. `CheckBits`)
/// representing the positions of public keys against which the provided
/// signatures must be verified.
/// @param bin - the stack item from which to decode the bitfield
/// @param expectedBitLength - the number of bits expected
pub fn decode_bitfield(bin: &[u8], expected_bit_length: usize) -> Result<BigInt, String> {
    let expected_bitfield_length = (expected_bit_length + 7) / 8;
    if bin.len() != expected_bitfield_length {
        return Err(crate::format::format_error(
            BitfieldDecodeError::invalidBitfieldSize,
            Some(&format!(
                "Bitfield length: {}, expected length: {expected_bitfield_length}.",
                bin.len()
            )),
        ));
    }
    let mut bitfield = BigInt::zero();
    for (i, byte) in bin.iter().enumerate().take(expected_bitfield_length) {
        bitfield = bitfield.bitor(&BigInt::from_u64(*byte as u64).shl(8 * i as u64));
    }
    let mask = BigInt::from_u64(1)
        .shl(expected_bit_length as u64)
        .sub(&BigInt::from_u64(1));
    if bitfield.bitand(&mask) != bitfield {
        return Err(crate::format::format_error(
            BitfieldDecodeError::bitsSetBeyondExpectedRange,
            Some(&format!("Bitfield: {bitfield}, expected bit length: {expected_bit_length}.")),
        ));
    }
    Ok(bitfield)
}

/// Remove and return the last `count` items of `stack` (JavaScript's
/// `stack.splice(-count)`, which removes every item if `count` exceeds the
/// stack depth).
fn splice_last(stack: &mut Vec<Vec<u8>>, count: usize) -> Vec<Vec<u8>> {
    let start = stack.len().saturating_sub(count);
    stack.split_off(start)
}

/// The multisig evaluation following the removal of the public keys and
/// signatures: the dummy value selects Schnorr (non-empty CheckBits) or
/// legacy ECDSA mode.
#[allow(clippy::too_many_arguments)]
fn evaluate_multisig(
    final_state: &mut AuthenticationProgramStateCommon,
    dummy_value: Vec<u8>,
    public_keys: &[Vec<u8>],
    signatures: &[Vec<u8>],
    required_approving_public_keys: usize,
    secp256k1: &Secp256k1,
    sha256: &Sha256,
) {
    let covered_bytecode = if !signatures.is_empty() {
        covered_bytecode(final_state)
    } else {
        Vec::new()
    };
    let one = BigInt::from_u64(1);
    if !dummy_value.is_empty() {
        let check_bits = match decode_bitfield(&dummy_value, public_keys.len()) {
            Err(error) => {
                apply_error(final_state, AuthenticationErrorCommon::invalidCheckBitsValue, Some(&error));
                return;
            }
            Ok(check_bits) => check_bits,
        };
        let bit_count = count_bits(&check_bits);
        if bit_count != signatures.len() {
            let details = format!(
                "CheckBits signatures configured: {bit_count}; signatures required: {}.",
                signatures.len()
            );
            apply_error(
                final_state,
                AuthenticationErrorCommon::invalidCheckBitsSignatureCount,
                Some(&details),
            );
            return;
        }
        let mut i_key = 0_usize;
        for bitcoin_encoded_signature in signatures {
            if check_bits.shr(i_key as u64).is_zero() {
                apply_error(final_state, "Expected to be unreachable: unexpected end of bitfield.", None);
                return;
            }
            while check_bits.shr(i_key as u64).bitand(&one).is_zero() {
                i_key += 1;
            }
            if i_key >= public_keys.len() {
                apply_error(
                    final_state,
                    "Expected to be unreachable: more set bits than available public keys.",
                    None,
                );
                return;
            }
            let public_key = &public_keys[i_key];
            if !is_valid_public_key_encoding(public_key) {
                let details = format!("Provided public key: {}", bin_to_hex(public_key));
                apply_error(final_state, AuthenticationErrorCommon::invalidPublicKeyEncoding, Some(&details));
                return;
            }
            if !is_valid_signature_encoding_bch_transaction(
                bitcoin_encoded_signature,
                SigningSerializationTypesBch,
            ) {
                let details = format!(
                    "Transaction signature (including signing serialization type): {}",
                    bin_to_hex(bitcoin_encoded_signature)
                );
                apply_error(final_state, AuthenticationErrorCommon::invalidSignatureEncoding, Some(&details));
                return;
            }
            let (signature, signing_serialization_type) =
                decode_bitcoin_signature(bitcoin_encoded_signature);
            let serialization = generate_signing_serialization_bch(
                &final_state.program,
                &covered_bytecode,
                &signing_serialization_type,
                Some(sha256),
            );
            let digest = hash256(&serialization, Some(sha256));
            final_state.metrics.signature_check_count += 1.0;
            let double_hashed = 1;
            final_state.metrics.hash_digest_iterations +=
                (double_hashed + length_to_hash_digest_iteration_count(serialization.len())) as f64;
            final_state
                .signed_messages
                .push(AuthenticationProgramStateSignedMessage::Serialization {
                    digest: digest.clone(),
                    serialization,
                });
            if signature.len() != ConsensusCommon::schnorrSignatureLength {
                let details = format!("Provided signature: {}", bin_to_hex(&signature));
                apply_error(
                    final_state,
                    AuthenticationErrorCommon::nonSchnorrSizedSignatureInSchnorrMultiSig,
                    Some(&details),
                );
                return;
            }
            let success = secp256k1.verify_signature_schnorr(&signature, public_key, &digest);
            if !success {
                let details = format!(
                    "Algorithm used: 'Schnorr'. CheckBits: {}.",
                    check_bits.to_string_radix(MULTISIG_BINARY)
                );
                apply_error(final_state, AuthenticationErrorCommon::nonNullSignatureFailure, Some(&details));
                return;
            }
            i_key += 1;
        }
        if !check_bits.shr(i_key as u64).is_zero() {
            apply_error(
                final_state,
                "Expected to be unreachable: unexpected bits set after processing all signatures.",
                None,
            );
            return;
        }
        push_to_stack(final_state, vec![boolean_to_vm_number(true)], None);
        return;
    }

    let mut approving_public_keys = 0_usize;
    let mut remaining_signatures = signatures.len();
    let mut remaining_public_keys = public_keys.len();
    while remaining_signatures > 0
        && remaining_public_keys > 0
        && approving_public_keys + remaining_public_keys >= remaining_signatures
        && approving_public_keys != required_approving_public_keys
    {
        let public_key = &public_keys[remaining_public_keys - 1];
        let bitcoin_encoded_signature = &signatures[remaining_signatures - 1];
        if !is_valid_public_key_encoding(public_key) {
            let details = format!("Provided public key: {}", bin_to_hex(public_key));
            apply_error(final_state, AuthenticationErrorCommon::invalidPublicKeyEncoding, Some(&details));
            return;
        }
        if !is_valid_signature_encoding_bch_transaction(
            bitcoin_encoded_signature,
            SigningSerializationTypesBch,
        ) {
            let details = format!(
                "Transaction signature (including signing serialization type): {}",
                bin_to_hex(bitcoin_encoded_signature)
            );
            apply_error(final_state, AuthenticationErrorCommon::invalidSignatureEncoding, Some(&details));
            return;
        }
        if bitcoin_encoded_signature.is_empty() {
            remaining_signatures -= 1;
            continue;
        }
        let (signature, signing_serialization_type) =
            decode_bitcoin_signature(bitcoin_encoded_signature);
        let serialization = generate_signing_serialization_bch(
            &final_state.program,
            &covered_bytecode,
            &signing_serialization_type,
            Some(sha256),
        );
        let digest = hash256(&serialization, Some(sha256));
        let double_hashed = 1;
        final_state.metrics.hash_digest_iterations +=
            (double_hashed + length_to_hash_digest_iteration_count(serialization.len())) as f64;
        final_state
            .signed_messages
            .push(AuthenticationProgramStateSignedMessage::Serialization {
                digest: digest.clone(),
                serialization,
            });
        if signature.len() == ConsensusCommon::schnorrSignatureLength {
            let details = format!("Provided signature: {}", bin_to_hex(&signature));
            apply_error(
                final_state,
                AuthenticationErrorCommon::schnorrSizedSignatureInEcdsaMultiSig,
                Some(&details),
            );
            return;
        }
        let signed = secp256k1.verify_signature_der_low_s(&signature, public_key, &digest);
        if signed {
            approving_public_keys += 1;
            remaining_signatures -= 1;
        }
        remaining_public_keys -= 1;
    }
    let success = approving_public_keys == required_approving_public_keys;
    let all_signatures_are_null = signatures.iter().all(Vec::is_empty);
    if !all_signatures_are_null {
        final_state.metrics.signature_check_count += public_keys.len() as f64;
        if !success {
            apply_error(final_state, AuthenticationErrorCommon::nonNullSignatureFailure, None);
            return;
        }
    }
    push_to_stack(final_state, vec![boolean_to_vm_number(success)], None);
}

/// `enforce_operation_limit` defaults to `true`; `secp256k1` and `sha256`
/// default to the internal instances.
pub fn op_check_multi_sig(
    secp256k1: Option<Secp256k1>,
    sha256: Option<Sha256>,
    enforce_operation_limit: Option<bool>,
) -> Operation {
    let enforce_operation_limit = enforce_operation_limit.unwrap_or(true);
    let secp256k1 = default_secp256k1(secp256k1);
    let sha256 = default_sha256(sha256);
    Rc::new(move |s: &mut AuthenticationProgramStateCommon| {
        use_one_vm_number(
            s,
            |state, [public_keys_value]| {
                let potential_public_keys = public_keys_value.to_number();
                if potential_public_keys < 0.0 {
                    let details = format!(
                        "Indicated public key count: {}.",
                        number_to_string(potential_public_keys)
                    );
                    apply_error(state, AuthenticationErrorCommon::invalidNaturalNumber, Some(&details));
                    return;
                }
                if potential_public_keys > MULTISIG_MAXIMUM_PUBLIC_KEYS {
                    let details = format!(
                        "Indicated public key count: {}.",
                        number_to_string(potential_public_keys)
                    );
                    apply_error(
                        state,
                        AuthenticationErrorCommon::exceedsMaximumMultisigPublicKeyCount,
                        Some(&details),
                    );
                    return;
                }
                let potential_public_keys = potential_public_keys as usize;
                let public_keys = if potential_public_keys > 0 {
                    splice_last(&mut state.stack, potential_public_keys)
                } else {
                    Vec::new()
                };
                state.operation_count += potential_public_keys;
                if enforce_operation_limit
                    && state.operation_count > ConsensusCommon::maximumOperationCount
                {
                    apply_error(state, AuthenticationErrorCommon::exceededMaximumOperationCount, None);
                    return;
                }
                use_one_vm_number(
                    state,
                    |next_state, [approving_keys]| {
                        let required_approving_public_keys = approving_keys.to_number();
                        if required_approving_public_keys < 0.0 {
                            let details = format!(
                                "Indicated signature count: {}.",
                                number_to_string(required_approving_public_keys)
                            );
                            apply_error(
                                next_state,
                                AuthenticationErrorCommon::invalidNaturalNumber,
                                Some(&details),
                            );
                            return;
                        }
                        if required_approving_public_keys > potential_public_keys as f64 {
                            let details = format!(
                                "Indicated signature count: {}.",
                                number_to_string(required_approving_public_keys)
                            );
                            apply_error(
                                next_state,
                                AuthenticationErrorCommon::insufficientPublicKeys,
                                Some(&details),
                            );
                            return;
                        }
                        let required_approving_public_keys = required_approving_public_keys as usize;
                        let signatures = if required_approving_public_keys > 0 {
                            splice_last(&mut next_state.stack, required_approving_public_keys)
                        } else {
                            Vec::new()
                        };
                        use_one_stack_item(next_state, |final_state, [dummy_value]| {
                            evaluate_multisig(
                                final_state,
                                dummy_value,
                                &public_keys,
                                &signatures,
                                required_approving_public_keys,
                                &secp256k1,
                                &sha256,
                            );
                        });
                    },
                    None,
                    None,
                );
            },
            None,
            None,
        );
    })
}

/// `secp256k1` and `sha256` default to the internal instances.
pub fn op_check_sig_verify(secp256k1: Option<Secp256k1>, sha256: Option<Sha256>) -> Operation {
    combine_operations(op_check_sig(secp256k1, sha256), Rc::new(op_verify))
}

pub fn op_check_multi_sig_verify(
    enforce_operation_limit: bool,
    secp256k1: Secp256k1,
    sha256: Sha256,
) -> Operation {
    combine_operations(
        op_check_multi_sig(Some(secp256k1), Some(sha256), Some(enforce_operation_limit)),
        Rc::new(op_verify),
    )
}

/// Validate the encoding of a raw signature – a signature without a signing
/// serialization type byte (A.K.A. "sighash" byte).
///
/// @param signature - the raw signature
pub fn is_valid_signature_encoding_bch_raw(signature: &[u8]) -> bool {
    signature.is_empty()
        || signature.len() == ConsensusCommon::schnorrSignatureLength
        || is_valid_signature_encoding_der(signature)
}

pub fn op_check_data_sig(secp256k1: Secp256k1, sha256: Sha256) -> Operation {
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        use_three_stack_items(state, |next_state, [signature, message, public_key]| {
            if !is_valid_signature_encoding_bch_raw(&signature) {
                let details = format!("Data signature: {}", bin_to_hex(&signature));
                apply_error(next_state, AuthenticationErrorCommon::invalidSignatureEncoding, Some(&details));
                return;
            }
            if !is_valid_public_key_encoding(&public_key) {
                let details = format!("Provided public key: {}", bin_to_hex(&public_key));
                apply_error(next_state, AuthenticationErrorCommon::invalidPublicKeyEncoding, Some(&details));
                return;
            }
            if signature.is_empty() {
                push_to_stack(next_state, vec![boolean_to_vm_number(false)], None);
                return;
            }
            let digest = sha256.hash(&message);
            next_state.metrics.signature_check_count += 1.0;
            next_state.metrics.hash_digest_iterations +=
                length_to_hash_digest_iteration_count(message.len()) as f64;
            next_state
                .signed_messages
                .push(AuthenticationProgramStateSignedMessage::Message {
                    digest: digest.clone(),
                    message,
                });
            let use_schnorr = signature.len() == ConsensusCommon::schnorrSignatureLength;
            let success = if use_schnorr {
                secp256k1.verify_signature_schnorr(&signature, &public_key, &digest)
            } else {
                secp256k1.verify_signature_der_low_s(&signature, &public_key, &digest)
            };
            if success {
                push_to_stack(next_state, vec![boolean_to_vm_number(success)], None);
            } else {
                apply_error(next_state, AuthenticationErrorCommon::nonNullSignatureFailure, None);
            }
        });
    })
}

/// `secp256k1` and `sha256` default to the internal instances.
pub fn op_check_data_sig_verify(secp256k1: Option<Secp256k1>, sha256: Option<Sha256>) -> Operation {
    combine_operations(
        op_check_data_sig(default_secp256k1(secp256k1), default_sha256(sha256)),
        Rc::new(op_verify),
    )
}

pub fn op_reverse_bytes(state: &mut AuthenticationProgramStateCommon) {
    use_one_stack_item(state, |next_state, [mut item]| {
        item.reverse();
        push_to_stack(next_state, vec![item], None);
    });
}
