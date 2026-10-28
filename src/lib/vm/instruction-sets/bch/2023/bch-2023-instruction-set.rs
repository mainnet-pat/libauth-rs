use std::collections::BTreeMap;
use std::rc::Rc;

use crate::address::{is_pay_to_script_hash20, is_pay_to_script_hash32};
use crate::crypto::{Ripemd160, Secp256k1, Sha1, Sha256};
use crate::format::{bin_to_hex, format_error};
use crate::message::encode_transaction_bch;
use crate::vm::{
    apply_error, authentication_instructions_are_malformed, conditionally_evaluate,
    create_op_0_not_equal, create_op_1_add, create_op_1_sub, create_op_abs,
    create_op_active_bytecode, create_op_add, create_op_bin2_num, create_op_bool_and,
    create_op_bool_or, create_op_cat, create_op_div, create_op_greater_than,
    create_op_greater_than_or_equal, create_op_input_bytecode, create_op_less_than,
    create_op_less_than_or_equal, create_op_max, create_op_min, create_op_mod, create_op_mul,
    create_op_negate, create_op_not, create_op_num2_bin, create_op_num_equal,
    create_op_num_equal_verify, create_op_num_not_equal, create_op_output_bytecode,
    create_op_sub, create_op_utxo_bytecode, create_op_within, decode_authentication_instructions,
    disabled_operation, disassemble_authentication_instruction_malformed,
    get_dust_threshold, increment_operation_count, is_arbitrary_data_output, is_dust_output,
    is_push_only, is_simple_multisig, is_standard_output_bytecode_2023,
    is_standard_utxo_bytecode_2023, is_witness_program, map_over_operations,
    maximum_signature_check_count, op_2_drop, op_2_dup, op_2_over, op_2_rot, op_2_swap,
    op_3_dup, op_and, op_check_data_sig, op_check_data_sig_verify, op_check_lock_time_verify,
    op_check_multi_sig, op_check_multi_sig_verify, op_check_sequence_verify, op_check_sig,
    op_check_sig_verify, op_code_separator, op_depth, op_drop, op_dup, op_else, op_end_if,
    op_equal, op_equal_verify, op_from_alt_stack, op_hash160, op_hash256, op_if, op_if_dup,
    op_input_index, op_input_sequence_number, op_nip, op_nop, op_nop_disallowed, op_not_if,
    op_or, op_outpoint_index, op_outpoint_tx_hash, op_output_token_amount,
    op_output_token_category, op_output_token_commitment, op_output_value, op_over, op_pick,
    op_return, op_reverse_bytes, op_ripemd160, op_roll, op_rot, op_sha1, op_sha256, op_size,
    op_split, op_swap, op_to_alt_stack, op_tuck, op_tx_input_count, op_tx_locktime,
    op_tx_output_count, op_tx_version, op_utxo_token_amount, op_utxo_token_category,
    op_utxo_token_commitment, op_utxo_value, op_verify, op_xor, push_number_operation,
    push_operation, reserved_operation, stack_item_is_truthy, undefined_operation,
    verify_transaction_tokens, AuthenticationErrorCommon, AuthenticationInstruction,
    AuthenticationInstructionMaybeMalformed, AuthenticationInstructionsMaybeMalformed,
    AuthenticationProgramBch, AuthenticationProgramStateBch,
    AuthenticationProgramStateMetrics, ConsensusBch2023, InstructionSet,
    InstructionSetEvaluation, InstructionSetOperationMapping, InstructionSetVerification,
    Operation, OpcodesBch2023, ResolvedTransactionBch,
};

const SATOSHIS_PER_COIN: u128 = 100_000_000;
const MAX_COINS: u128 = 21_000_000;
const MAX_MONEY: u128 = MAX_COINS * SATOSHIS_PER_COIN;

/// Convert decoded instructions into authentication instructions (omitting a
/// final malformed instruction, which is reported separately).
fn instructions_of(instructions: AuthenticationInstructionsMaybeMalformed) -> Vec<AuthenticationInstruction> {
    instructions
        .into_iter()
        .filter_map(|instruction| match instruction {
            AuthenticationInstructionMaybeMalformed::Instruction(instruction) => Some(instruction),
            AuthenticationInstructionMaybeMalformed::Malformed(_) => None,
        })
        .collect()
}

/// The description of the final (malformed) instruction in a list of
/// malformed instructions.
fn describe_malformed(instructions: &AuthenticationInstructionsMaybeMalformed) -> String {
    match instructions.last() {
        Some(AuthenticationInstructionMaybeMalformed::Malformed(instruction)) => format!(
            "Malformed instruction: {}.",
            disassemble_authentication_instruction_malformed(OpcodesBch2023::MEMBERS, instruction)
        ),
        _ => unreachable!("the final instruction is malformed"),
    }
}

/// Create the initial program state for a phase of evaluation:
/// `{ ...stateInitialize(program), ...stateOverride, instructions, program, stack }`.
fn initialize_phase(
    program: &AuthenticationProgramBch,
    evaluation: &InstructionSetEvaluation<'_, AuthenticationProgramBch, AuthenticationProgramStateBch>,
    instructions: Vec<AuthenticationInstruction>,
    metrics: Option<AuthenticationProgramStateMetrics>,
    stack: Vec<Vec<u8>>,
) -> AuthenticationProgramStateBch {
    let mut state = (evaluation.state_initialize)(program);
    if let Some(state_override) = evaluation.state_override {
        state_override(&mut state);
    }
    state.instructions = Rc::new(instructions);
    if let Some(metrics) = metrics {
        state.metrics = metrics;
    }
    state.stack = stack;
    state
}

/// create an instance of the BCH 2023 virtual machine instruction set.
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
///
/// The remaining parameters (libauth's second, object parameter) default to
/// `ConsensusBch2023` and the internal crypto instances.
#[allow(clippy::too_many_lines)]
pub fn create_instruction_set_bch_2023(
    standard: Option<bool>,
    consensus: Option<ConsensusBch2023>,
    ripemd160: Option<Ripemd160>,
    secp256k1: Option<Secp256k1>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
) -> InstructionSet<ResolvedTransactionBch, AuthenticationProgramBch, AuthenticationProgramStateBch> {
    let standard = standard.unwrap_or(true);
    let consensus = consensus.unwrap_or(ConsensusBch2023);
    let ripemd160 = ripemd160.unwrap_or_else(|| crate::crypto::ripemd160.clone());
    let secp256k1 = secp256k1.unwrap_or_else(|| crate::crypto::secp256k1.clone());
    let sha1 = sha1.unwrap_or_else(|| crate::crypto::sha1.clone());
    let sha256 = sha256.unwrap_or_else(|| crate::crypto::sha256.clone());
    let conditionally_push = push_operation(Some(consensus.maximum_stack_item_length));
    let op = |operation: fn(&mut AuthenticationProgramStateBch)| -> Operation { Rc::new(operation) };
    let ce = conditionally_evaluate;

    let mut operations: InstructionSetOperationMapping = BTreeMap::new();
    // OP_0 through OP_PUSHDATA_4
    for opcode in OpcodesBch2023::OP_0..=OpcodesBch2023::OP_PUSHDATA_4 {
        operations.insert(opcode, Rc::clone(&conditionally_push));
    }
    operations.insert(OpcodesBch2023::OP_1NEGATE, ce(push_number_operation(-1)));
    operations.insert(OpcodesBch2023::OP_RESERVED, ce(op(reserved_operation)));
    // OP_1 through OP_16
    for (number, opcode) in (OpcodesBch2023::OP_1..=OpcodesBch2023::OP_16).enumerate() {
        operations.insert(opcode, ce(push_number_operation(number as i64 + 1)));
    }

    let mut counted: InstructionSetOperationMapping = BTreeMap::from([
        (OpcodesBch2023::OP_NOP, ce(op(op_nop))),
        (OpcodesBch2023::OP_VER, ce(op(reserved_operation))),
        (OpcodesBch2023::OP_IF, op(op_if)),
        (OpcodesBch2023::OP_NOTIF, op(op_not_if)),
        (OpcodesBch2023::OP_VERIF, op(reserved_operation)),
        (OpcodesBch2023::OP_VERNOTIF, op(reserved_operation)),
        (OpcodesBch2023::OP_ELSE, op(op_else)),
        (OpcodesBch2023::OP_ENDIF, op(op_end_if)),
        (OpcodesBch2023::OP_VERIFY, ce(op(op_verify))),
        (OpcodesBch2023::OP_RETURN, ce(op(op_return))),
        (OpcodesBch2023::OP_TOALTSTACK, ce(op(op_to_alt_stack))),
        (OpcodesBch2023::OP_FROMALTSTACK, ce(op(op_from_alt_stack))),
        (OpcodesBch2023::OP_2DROP, ce(op(op_2_drop))),
        (OpcodesBch2023::OP_2DUP, ce(op(op_2_dup))),
        (OpcodesBch2023::OP_3DUP, ce(op(op_3_dup))),
        (OpcodesBch2023::OP_2OVER, ce(op(op_2_over))),
        (OpcodesBch2023::OP_2ROT, ce(op(op_2_rot))),
        (OpcodesBch2023::OP_2SWAP, ce(op(op_2_swap))),
        (OpcodesBch2023::OP_IFDUP, ce(op(op_if_dup))),
        (OpcodesBch2023::OP_DEPTH, ce(op(op_depth))),
        (OpcodesBch2023::OP_DROP, ce(op(op_drop))),
        (OpcodesBch2023::OP_DUP, ce(op(op_dup))),
        (OpcodesBch2023::OP_NIP, ce(op(op_nip))),
        (OpcodesBch2023::OP_OVER, ce(op(op_over))),
        (OpcodesBch2023::OP_PICK, ce(op(op_pick))),
        (OpcodesBch2023::OP_ROLL, ce(op(op_roll))),
        (OpcodesBch2023::OP_ROT, ce(op(op_rot))),
        (OpcodesBch2023::OP_SWAP, ce(op(op_swap))),
        (OpcodesBch2023::OP_TUCK, ce(op(op_tuck))),
        (OpcodesBch2023::OP_CAT, ce(create_op_cat(Some(consensus.maximum_stack_item_length)))),
        (OpcodesBch2023::OP_SPLIT, ce(op(op_split))),
        (OpcodesBch2023::OP_NUM2BIN, ce(create_op_num2_bin(Some(consensus.maximum_stack_item_length)))),
        (
            OpcodesBch2023::OP_BIN2NUM,
            ce(create_op_bin2_num(
                Some(consensus.maximum_stack_item_length),
                Some(consensus.maximum_vm_number_byte_length),
            )),
        ),
        (OpcodesBch2023::OP_SIZE, ce(op(op_size))),
        (OpcodesBch2023::OP_INVERT, op(disabled_operation)),
        (OpcodesBch2023::OP_AND, ce(op(op_and))),
        (OpcodesBch2023::OP_OR, ce(op(op_or))),
        (OpcodesBch2023::OP_XOR, ce(op(op_xor))),
        (OpcodesBch2023::OP_EQUAL, ce(op(op_equal))),
        (OpcodesBch2023::OP_EQUALVERIFY, ce(op(op_equal_verify))),
        (OpcodesBch2023::OP_RESERVED1, ce(op(reserved_operation))),
        (OpcodesBch2023::OP_RESERVED2, ce(op(reserved_operation))),
    ]);
    let maximum_vm_number_byte_length = Some(consensus.maximum_vm_number_byte_length);
    counted.extend([
        (OpcodesBch2023::OP_1ADD, ce(create_op_1_add(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_1SUB, ce(create_op_1_sub(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_2MUL, op(disabled_operation)),
        (OpcodesBch2023::OP_2DIV, op(disabled_operation)),
        (OpcodesBch2023::OP_NEGATE, ce(create_op_negate(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_ABS, ce(create_op_abs(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_NOT, ce(create_op_not(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_0NOTEQUAL, ce(create_op_0_not_equal(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_ADD, ce(create_op_add(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_SUB, ce(create_op_sub(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_MUL, ce(create_op_mul(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_DIV, ce(create_op_div(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_MOD, ce(create_op_mod(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_LSHIFT, op(disabled_operation)),
        (OpcodesBch2023::OP_RSHIFT, op(disabled_operation)),
        (OpcodesBch2023::OP_BOOLAND, ce(create_op_bool_and(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_BOOLOR, ce(create_op_bool_or(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_NUMEQUAL, ce(create_op_num_equal(maximum_vm_number_byte_length))),
        (
            OpcodesBch2023::OP_NUMEQUALVERIFY,
            ce(create_op_num_equal_verify(maximum_vm_number_byte_length)),
        ),
        (OpcodesBch2023::OP_NUMNOTEQUAL, ce(create_op_num_not_equal(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_LESSTHAN, ce(create_op_less_than(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_GREATERTHAN, ce(create_op_greater_than(maximum_vm_number_byte_length))),
        (
            OpcodesBch2023::OP_LESSTHANOREQUAL,
            ce(create_op_less_than_or_equal(maximum_vm_number_byte_length)),
        ),
        (
            OpcodesBch2023::OP_GREATERTHANOREQUAL,
            ce(create_op_greater_than_or_equal(maximum_vm_number_byte_length)),
        ),
        (OpcodesBch2023::OP_MIN, ce(create_op_min(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_MAX, ce(create_op_max(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_WITHIN, ce(create_op_within(maximum_vm_number_byte_length))),
        (OpcodesBch2023::OP_RIPEMD160, ce(op_ripemd160(Some(ripemd160.clone())))),
        (OpcodesBch2023::OP_SHA1, ce(op_sha1(Some(sha1.clone())))),
        (OpcodesBch2023::OP_SHA256, ce(op_sha256(Some(sha256.clone())))),
        (
            OpcodesBch2023::OP_HASH160,
            ce(op_hash160(Some(ripemd160.clone()), Some(sha256.clone()))),
        ),
        (OpcodesBch2023::OP_HASH256, ce(op_hash256(Some(sha256.clone())))),
        (OpcodesBch2023::OP_CODESEPARATOR, ce(op(op_code_separator))),
        (
            OpcodesBch2023::OP_CHECKSIG,
            ce(op_check_sig(Some(secp256k1.clone()), Some(sha256.clone()))),
        ),
        (
            OpcodesBch2023::OP_CHECKSIGVERIFY,
            ce(op_check_sig_verify(Some(secp256k1.clone()), Some(sha256.clone()))),
        ),
        (
            OpcodesBch2023::OP_CHECKMULTISIG,
            ce(op_check_multi_sig(Some(secp256k1.clone()), Some(sha256.clone()), Some(true))),
        ),
        (
            OpcodesBch2023::OP_CHECKMULTISIGVERIFY,
            ce(op_check_multi_sig_verify(true, secp256k1.clone(), sha256.clone())),
        ),
    ]);
    let nop = if standard { op_nop_disallowed } else { op_nop::<AuthenticationProgramStateBch> };
    counted.extend([
        (OpcodesBch2023::OP_NOP1, ce(op(nop))),
        (OpcodesBch2023::OP_CHECKLOCKTIMEVERIFY, ce(op(op_check_lock_time_verify))),
        (OpcodesBch2023::OP_CHECKSEQUENCEVERIFY, ce(op(op_check_sequence_verify))),
        (OpcodesBch2023::OP_NOP4, ce(op(nop))),
        (OpcodesBch2023::OP_NOP5, ce(op(nop))),
        (OpcodesBch2023::OP_NOP6, ce(op(nop))),
        (OpcodesBch2023::OP_NOP7, ce(op(nop))),
        (OpcodesBch2023::OP_NOP8, ce(op(nop))),
        (OpcodesBch2023::OP_NOP9, ce(op(nop))),
        (OpcodesBch2023::OP_NOP10, ce(op(nop))),
    ]);
    counted.extend([
        (
            OpcodesBch2023::OP_CHECKDATASIG,
            ce(op_check_data_sig(secp256k1.clone(), sha256.clone())),
        ),
        (
            OpcodesBch2023::OP_CHECKDATASIGVERIFY,
            ce(op_check_data_sig_verify(Some(secp256k1.clone()), Some(sha256.clone()))),
        ),
        (OpcodesBch2023::OP_REVERSEBYTES, ce(op(op_reverse_bytes))),
        (OpcodesBch2023::OP_INPUTINDEX, ce(op(op_input_index))),
        (
            OpcodesBch2023::OP_ACTIVEBYTECODE,
            ce(create_op_active_bytecode(Some(consensus.maximum_stack_item_length))),
        ),
        (OpcodesBch2023::OP_TXVERSION, ce(op(op_tx_version))),
        (OpcodesBch2023::OP_TXINPUTCOUNT, ce(op(op_tx_input_count))),
        (OpcodesBch2023::OP_TXOUTPUTCOUNT, ce(op(op_tx_output_count))),
        (OpcodesBch2023::OP_TXLOCKTIME, ce(op(op_tx_locktime))),
        (OpcodesBch2023::OP_UTXOVALUE, ce(op(op_utxo_value))),
        (
            OpcodesBch2023::OP_UTXOBYTECODE,
            ce(create_op_utxo_bytecode(Some(consensus.maximum_stack_item_length))),
        ),
        (OpcodesBch2023::OP_OUTPOINTTXHASH, ce(op(op_outpoint_tx_hash))),
        (OpcodesBch2023::OP_OUTPOINTINDEX, ce(op(op_outpoint_index))),
        (
            OpcodesBch2023::OP_INPUTBYTECODE,
            ce(create_op_input_bytecode(Some(consensus.maximum_stack_item_length))),
        ),
        (OpcodesBch2023::OP_INPUTSEQUENCENUMBER, ce(op(op_input_sequence_number))),
        (OpcodesBch2023::OP_OUTPUTVALUE, ce(op(op_output_value))),
        (
            OpcodesBch2023::OP_OUTPUTBYTECODE,
            ce(create_op_output_bytecode(Some(consensus.maximum_stack_item_length))),
        ),
        (OpcodesBch2023::OP_UTXOTOKENCATEGORY, ce(op(op_utxo_token_category))),
        (OpcodesBch2023::OP_UTXOTOKENCOMMITMENT, ce(op(op_utxo_token_commitment))),
        (OpcodesBch2023::OP_UTXOTOKENAMOUNT, ce(op(op_utxo_token_amount))),
        (OpcodesBch2023::OP_OUTPUTTOKENCATEGORY, ce(op(op_output_token_category))),
        (OpcodesBch2023::OP_OUTPUTTOKENCOMMITMENT, ce(op(op_output_token_commitment))),
        (OpcodesBch2023::OP_OUTPUTTOKENAMOUNT, ce(op(op_output_token_amount))),
    ]);
    operations.extend(map_over_operations(&[&increment_operation_count], counted));

    let evaluate = Rc::new(
        move |program: &AuthenticationProgramBch,
              evaluation: &InstructionSetEvaluation<'_, AuthenticationProgramBch, AuthenticationProgramStateBch>|
              -> AuthenticationProgramStateBch {
            let unlocking_bytecode = &program.transaction.inputs[program.input_index].unlocking_bytecode;
            let locking_bytecode = &program.source_outputs[program.input_index].locking_bytecode;
            let unlocking_instructions = decode_authentication_instructions(unlocking_bytecode);
            let locking_instructions = decode_authentication_instructions(locking_bytecode);
            let mut initial_state = initialize_phase(
                program,
                evaluation,
                instructions_of(unlocking_instructions.clone()),
                None,
                Vec::new(),
            );
            if unlocking_bytecode.len() > consensus.maximum_bytecode_length {
                let details = format!(
                    "Maximum bytecode length: {} bytes. Unlocking bytecode length: {} bytes.",
                    consensus.maximum_bytecode_length,
                    unlocking_bytecode.len()
                );
                apply_error(
                    &mut initial_state,
                    AuthenticationErrorCommon::exceededMaximumBytecodeLengthUnlocking,
                    Some(&details),
                );
                return initial_state;
            }
            if authentication_instructions_are_malformed(&unlocking_instructions) {
                let details = describe_malformed(&unlocking_instructions);
                apply_error(
                    &mut initial_state,
                    AuthenticationErrorCommon::malformedUnlockingBytecode,
                    Some(&details),
                );
                return initial_state;
            }
            if !is_push_only(unlocking_bytecode) {
                apply_error(&mut initial_state, AuthenticationErrorCommon::requiresPushOnly, None);
                return initial_state;
            }
            if locking_bytecode.len() > consensus.maximum_bytecode_length {
                let details = format!(
                    "Maximum bytecode length: {} bytes. Locking bytecode length: {} bytes.",
                    consensus.maximum_bytecode_length,
                    locking_bytecode.len()
                );
                apply_error(
                    &mut initial_state,
                    AuthenticationErrorCommon::exceededMaximumBytecodeLengthLocking,
                    Some(&details),
                );
                return initial_state;
            }
            if authentication_instructions_are_malformed(&locking_instructions) {
                let details = describe_malformed(&locking_instructions);
                apply_error(
                    &mut initial_state,
                    AuthenticationErrorCommon::malformedLockingBytecode,
                    Some(&details),
                );
                return initial_state;
            }
            let mut unlocking_result = (evaluation.state_evaluate)(initial_state);
            if unlocking_result.error.is_some() {
                return unlocking_result;
            }
            if !unlocking_result.control_stack.is_empty() {
                let details = format!(
                    "Remaining control stack depth: {}.",
                    unlocking_result.control_stack.len()
                );
                apply_error(
                    &mut unlocking_result,
                    AuthenticationErrorCommon::nonEmptyControlStackUnlockingBytecode,
                    Some(&details),
                );
                return unlocking_result;
            }
            let mut locking_result = (evaluation.state_evaluate)(initialize_phase(
                program,
                evaluation,
                instructions_of(locking_instructions),
                Some(unlocking_result.metrics.clone()),
                unlocking_result.stack.clone(),
            ));
            if locking_result.error.is_some() {
                return locking_result;
            }
            if !locking_result.control_stack.is_empty() {
                let details = format!(
                    "Remaining control stack depth: {}.",
                    locking_result.control_stack.len()
                );
                apply_error(
                    &mut locking_result,
                    AuthenticationErrorCommon::nonEmptyControlStackLockingBytecode,
                    Some(&details),
                );
                return locking_result;
            }
            let p2sh20 = is_pay_to_script_hash20(locking_bytecode);
            let p2sh32 = is_pay_to_script_hash32(locking_bytecode);
            if !p2sh20 && !p2sh32 {
                if locking_result.stack.len() != 1 {
                    let details = format!("Remaining stack depth: {}.", locking_result.stack.len());
                    apply_error(
                        &mut locking_result,
                        AuthenticationErrorCommon::requiresCleanStackLockingBytecode,
                        Some(&details),
                    );
                }
                return locking_result;
            }
            let top = locking_result.stack.last().cloned().unwrap_or_default();
            if !stack_item_is_truthy(&top) {
                let details = format!("Top stack item: \"{}\".", bin_to_hex(&top));
                apply_error(
                    &mut locking_result,
                    AuthenticationErrorCommon::unmatchedP2shRedeemBytecode,
                    Some(&details),
                );
                return locking_result;
            }
            let mut p2sh_stack = unlocking_result.stack.clone();
            let p2sh_script = p2sh_stack.pop().unwrap_or_default();
            if p2sh20 && p2sh_stack.is_empty() && is_witness_program(&p2sh_script) {
                return locking_result;
            }
            let p2sh_instructions = decode_authentication_instructions(&p2sh_script);
            let mut p2sh_result = if authentication_instructions_are_malformed(&p2sh_instructions) {
                let mut result = locking_result;
                result.error = Some(AuthenticationErrorCommon::malformedP2shBytecode.to_string());
                result
            } else {
                (evaluation.state_evaluate)(initialize_phase(
                    program,
                    evaluation,
                    instructions_of(p2sh_instructions),
                    Some(locking_result.metrics.clone()),
                    p2sh_stack,
                ))
            };
            if !p2sh_result.control_stack.is_empty() {
                let details = format!(
                    "Remaining control stack depth: {}.",
                    p2sh_result.control_stack.len()
                );
                apply_error(
                    &mut p2sh_result,
                    AuthenticationErrorCommon::nonEmptyControlStackRedeemBytecode,
                    Some(&details),
                );
                return p2sh_result;
            }
            if p2sh_result.stack.len() != 1 {
                let details = format!("Remaining stack depth: {}.", p2sh_result.stack.len());
                apply_error(
                    &mut p2sh_result,
                    AuthenticationErrorCommon::requiresCleanStackRedeemBytecode,
                    Some(&details),
                );
                return p2sh_result;
            }
            p2sh_result
        },
    );

    let every = Rc::new(move |state: &mut AuthenticationProgramStateBch| {
        let unlocking_bytecode_length =
            state.program.transaction.inputs[state.program.input_index].unlocking_bytecode.len();
        state.metrics.maximum_signature_check_count =
            maximum_signature_check_count(unlocking_bytecode_length) as f64;
        if standard && state.metrics.signature_check_count > state.metrics.maximum_signature_check_count {
            let details = format!(
                "Maximum signature check count: {}; signature check count following operation: {}.",
                state.metrics.maximum_signature_check_count, state.metrics.signature_check_count
            );
            apply_error(
                state,
                AuthenticationErrorCommon::exceededMaximumSignatureCheckCount,
                Some(&details),
            );
            return;
        }
        if state.stack.len() + state.alternate_stack.len() > consensus.maximum_stack_depth {
            let details = format!("Maximum stack depth: {}.", consensus.maximum_stack_depth);
            apply_error(state, AuthenticationErrorCommon::exceededMaximumStackDepth, Some(&details));
            return;
        }
        if state.operation_count > consensus.maximum_operation_count {
            apply_error(state, AuthenticationErrorCommon::exceededMaximumOperationCount, None);
        }
    });

    let initialize = Rc::new(move |program: &AuthenticationProgramBch| -> AuthenticationProgramStateBch {
        let unlocking_bytecode_length =
            program.transaction.inputs[program.input_index].unlocking_bytecode.len();
        let density_control_length =
            (consensus.density_control_base_length + unlocking_bytecode_length) as f64;
        let maximum_iterations_per_byte = if standard {
            consensus.hash_digest_iterations_per_byte_standard
        } else {
            consensus.hash_digest_iterations_per_byte_nonstandard
        };
        AuthenticationProgramStateBch {
            alternate_stack: Vec::new(),
            control_stack: Vec::new(),
            error: None,
            function_count: 0,
            function_table: BTreeMap::new(),
            instructions: Rc::new(Vec::new()),
            ip: 0,
            last_code_separator: -1,
            metrics: AuthenticationProgramStateMetrics {
                arithmetic_cost: 0.0,
                defined_functions: 0.0,
                density_control_length,
                evaluated_instruction_count: 0.0,
                hash_digest_iterations: 0.0,
                maximum_hash_digest_iterations: (maximum_iterations_per_byte * density_control_length).floor(),
                maximum_operation_cost: (density_control_length * consensus.operation_cost_budget_per_byte)
                    .floor(),
                maximum_signature_check_count: maximum_signature_check_count(unlocking_bytecode_length) as f64,
                operation_cost: 0.0,
                signature_check_count: 0.0,
                stack_pushed_bytes: 0.0,
                max_memory_usage: None,
            },
            operation_count: 0,
            program: Rc::new(program.clone()),
            signed_messages: Vec::new(),
            stack: Vec::new(),
        }
    });

    let success = Rc::new(|state: &AuthenticationProgramStateBch| -> Result<(), String> {
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        match state.stack.last() {
            Some(top) if stack_item_is_truthy(top) => Ok(()),
            top => Err(format_error(
                AuthenticationErrorCommon::unsuccessfulEvaluation,
                Some(&match top {
                    None => "Stack is empty.".to_string(),
                    Some(top) => format!("Top stack item: \"{}\".", bin_to_hex(top)),
                }),
            )),
        }
    });

    let verify = Rc::new(
        move |resolved_transaction: &ResolvedTransactionBch,
              verification: &InstructionSetVerification<'_, AuthenticationProgramBch, AuthenticationProgramStateBch>|
              -> Result<(), String> {
            let ResolvedTransactionBch {
                source_outputs,
                transaction,
            } = resolved_transaction;
            if transaction.inputs.is_empty() {
                return Err(format_error(AuthenticationErrorCommon::verifyFailedNoInputs, None));
            }
            if transaction.outputs.is_empty() {
                return Err(format_error(AuthenticationErrorCommon::verifyFailedNoOutputs, None));
            }
            if transaction.inputs.len() != source_outputs.len() {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedMismatchedSourceOutputs,
                    Some(&format!(
                        "Transaction input count: {}; source outputs count: {}.",
                        transaction.inputs.len(),
                        source_outputs.len()
                    )),
                ));
            }
            let transaction_length_bytes = encode_transaction_bch(transaction).len();
            if transaction_length_bytes < consensus.minimum_transaction_length_bytes {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedInsufficientLength,
                    Some(&format!(
                        "The transaction is {transaction_length_bytes} bytes, but transactions must be no smaller than {} bytes to prevent an exploit of the transaction Merkle tree design.",
                        consensus.minimum_transaction_length_bytes
                    )),
                ));
            }
            if transaction_length_bytes > consensus.maximum_transaction_length_bytes {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedExcessiveLength,
                    Some(&format!(
                        "Transaction exceeds maximum byte length: the transaction is {transaction_length_bytes} bytes, but the maximum transaction size is {} bytes.",
                        consensus.maximum_transaction_length_bytes
                    )),
                ));
            }
            let input_value: u128 = source_outputs
                .iter()
                .map(|utxo| utxo.value_satoshis as u128)
                .sum();
            let output_value: u128 = transaction
                .outputs
                .iter()
                .map(|output| output.value_satoshis as u128)
                .sum();
            if input_value > MAX_MONEY {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedInputsExceedMaxMoney,
                    Some(&format!(
                        "Maximum supply in satoshis: {MAX_MONEY}, cumulative input value: {input_value}."
                    )),
                ));
            }
            if output_value > MAX_MONEY {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedOutputsExceedMaxMoney,
                    Some(&format!(
                        "Maximum supply in satoshis: {MAX_MONEY}, cumulative output value: {output_value}."
                    )),
                ));
            }
            if output_value > input_value {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedOutputsExceedInputs,
                    Some(&format!(
                        "Cumulative input value: {input_value}, cumulative output value: {output_value}."
                    )),
                ));
            }
            let outpoint_list: Vec<String> = transaction
                .inputs
                .iter()
                .map(|input| {
                    format!(
                        "outpointTransactionHash: {}, outpointIndex: {}",
                        bin_to_hex(&input.outpoint_transaction_hash),
                        input.outpoint_index
                    )
                })
                .collect();
            let first_duplicate = outpoint_list.iter().enumerate().find(|(index, outpoint)| {
                outpoint_list.iter().rposition(|other| other == *outpoint) != Some(*index)
            });
            if let Some((_, first_duplicate)) = first_duplicate {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedDuplicateSourceOutputs,
                    Some(first_duplicate),
                ));
            }
            if transaction.version < consensus.minimum_consensus_version
                || transaction.version > consensus.maximum_consensus_version
            {
                return Err(format_error(
                    AuthenticationErrorCommon::verifyFailedInvalidVersion,
                    Some(&format!("Encoded version number: {}.", transaction.version)),
                ));
            }
            if standard {
                if transaction_length_bytes > consensus.maximum_standard_transaction_size {
                    return Err(format_error(
                        AuthenticationErrorCommon::verifyStandardFailedExcessiveLength,
                        Some(&format!(
                            "This transaction is {transaction_length_bytes} bytes, but the maximum standard transaction size is {} bytes.",
                            consensus.maximum_standard_transaction_size
                        )),
                    ));
                }
                for (index, output) in source_outputs.iter().enumerate() {
                    if consensus.maximum_standard_locking_bytecode_length == -1 {
                        if !is_standard_utxo_bytecode_2023(&output.locking_bytecode) {
                            return Err(format_error(
                                AuthenticationErrorCommon::verifyStandardFailedNonstandardSourceOutput,
                                Some(&format!(
                                    "Source output {index} is non-standard: locking bytecode does not match a standard pattern: P2PKH, P2PK, P2SH, P2MS, or arbitrary data (OP_RETURN)."
                                )),
                            ));
                        }
                    } else if output.locking_bytecode.len() as i64
                        > consensus.maximum_standard_locking_bytecode_length
                        && is_simple_multisig(&output.locking_bytecode).is_none()
                    {
                        return Err(format_error(
                            AuthenticationErrorCommon::verifyStandardFailedNonstandardSourceOutput,
                            Some(&format!(
                                "Source output {index} is non-standard: locking bytecode length of {} exceeds the maximum standard locking bytecode length of {}.",
                                output.locking_bytecode.len(),
                                consensus.maximum_standard_locking_bytecode_length
                            )),
                        ));
                    }
                }
                let mut total_arbitrary_data_bytes = 0;
                for (index, output) in transaction.outputs.iter().enumerate() {
                    let data_carrier = is_arbitrary_data_output(&output.locking_bytecode);
                    if data_carrier {
                        total_arbitrary_data_bytes += output.locking_bytecode.len() + 1;
                    }
                    let p2s_is_standard = consensus.maximum_standard_locking_bytecode_length != -1;
                    if !p2s_is_standard && !is_standard_output_bytecode_2023(&output.locking_bytecode) {
                        return Err(format_error(
                            AuthenticationErrorCommon::verifyStandardFailedNonstandardOutput,
                            Some(&format!(
                                "Transaction output {index} is non-standard: locking bytecode does not match a standard pattern: P2PKH, P2PK, P2SH, P2MS, or arbitrary data (OP_RETURN)."
                            )),
                        ));
                    }
                    if p2s_is_standard
                        && output.locking_bytecode.len() as i64
                            > consensus.maximum_standard_locking_bytecode_length
                        && !data_carrier
                    {
                        return Err(format_error(
                            AuthenticationErrorCommon::verifyStandardFailedNonstandardOutput,
                            Some(&format!(
                                "Transaction output {index} is non-standard: locking bytecode length of {} exceeds the maximum standard locking bytecode length of {} and does not match the standard arbitrary data pattern (OP_RETURN).",
                                output.locking_bytecode.len(),
                                consensus.maximum_standard_locking_bytecode_length
                            )),
                        ));
                    }
                    if is_dust_output(output, None) {
                        return Err(format_error(
                            AuthenticationErrorCommon::verifyStandardFailedDustOutput,
                            Some(&format!(
                                "Transaction output {index} must have a value of at least {} satoshis. Current value: {}",
                                get_dust_threshold(output, None),
                                output.value_satoshis
                            )),
                        ));
                    }
                }
                if total_arbitrary_data_bytes > consensus.maximum_data_carrier_bytes {
                    return Err(format_error(
                        AuthenticationErrorCommon::verifyStandardFailedExcessiveDataCarrierBytes,
                        Some(&format!(
                            "Standard transactions may carry no more than {} bytes in arbitrary data outputs; this transaction includes {total_arbitrary_data_bytes} bytes of arbitrary data.",
                            consensus.maximum_data_carrier_bytes
                        )),
                    ));
                }
                for (index, input) in transaction.inputs.iter().enumerate() {
                    if input.unlocking_bytecode.len() > consensus.maximum_standard_unlocking_bytecode_length {
                        return Err(format_error(
                            AuthenticationErrorCommon::verifyStandardFailedExcessiveUnlockingBytecodeLength,
                            Some(&format!(
                                "The maximum standard unlocking bytecode length is {} bytes, but the unlocking bytecode at input index {index} is {} bytes.",
                                consensus.maximum_standard_unlocking_bytecode_length,
                                input.unlocking_bytecode.len()
                            )),
                        ));
                    }
                    if !is_push_only(&input.unlocking_bytecode) {
                        return Err(format_error(
                            AuthenticationErrorCommon::verifyStandardFailedNonPushUnlockingBytecode,
                            Some(&format!(
                                "The unlocking bytecode at input index {index} contains non-push operations."
                            )),
                        ));
                    }
                }
            }
            verify_transaction_tokens(
                transaction,
                source_outputs,
                consensus.maximum_token_commitment_length,
            )?;
            let mut cumulative_sig_checks = 0.0;
            for input_index in 0..transaction.inputs.len() {
                let state = (verification.evaluate)(&AuthenticationProgramBch {
                    input_index,
                    source_outputs: source_outputs.clone(),
                    transaction: transaction.clone(),
                });
                cumulative_sig_checks += state.metrics.signature_check_count;
                if cumulative_sig_checks > consensus.maximum_transaction_signature_checks as f64 {
                    return Err(format_error(
                        AuthenticationErrorCommon::verifyFailedExcessiveSigChecks,
                        Some(&format!(
                            "Transaction exceeded the per-transaction maximum of {} signature checks while evaluating input index {input_index} of {}.",
                            consensus.maximum_transaction_signature_checks,
                            transaction.inputs.len()
                        )),
                    ));
                }
                if let Err(result) = (verification.success)(&state) {
                    return Err(format!(
                        "Unable to verify transaction: error in evaluating input index {input_index}: {result}"
                    ));
                }
            }
            Ok(())
        },
    );

    InstructionSet {
        r#continue: Rc::new(|state: &mut AuthenticationProgramStateBch| {
            state.error.is_none() && state.ip < state.instructions.len() as isize
        }),
        evaluate,
        every: Some(every),
        initialize,
        operations,
        success,
        undefined: Rc::new(undefined_operation),
        verify,
    }
}

/// See {@link createInstructionSetBch2023}.
pub use self::create_instruction_set_bch_2023 as create_instruction_set_bch;
