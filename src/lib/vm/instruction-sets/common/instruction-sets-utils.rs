use std::collections::BTreeMap;

use crate::address::{
    is_pay_to_public_key, is_pay_to_public_key_hash, is_pay_to_script_hash20,
    is_pay_to_script_hash32,
};
use crate::format::{
    bin_to_hex, flatten_bin_array, number_to_bin_uint16_le, number_to_bin_uint32_le, ReadPosition,
};
use crate::message::{encode_transaction_output, Output};
use crate::runtime::bigint::BigInt;
use crate::vm::{
    AuthenticationInstruction, AuthenticationInstructionMalformed,
    AuthenticationInstructionMaybeMalformed, AuthenticationInstructionOperation,
    AuthenticationInstructionPush, AuthenticationInstructionPushMalformedData,
    AuthenticationInstructionPushMalformedLength, AuthenticationInstructionsMaybeMalformed,
    OpcodesBchSpec, OpcodesBtc,
};

/// A type guard to determine if the provided instruction is malformed.
pub fn authentication_instruction_is_malformed(
    instruction: &AuthenticationInstructionMaybeMalformed,
) -> bool {
    matches!(instruction, AuthenticationInstructionMaybeMalformed::Malformed(_))
}

/// A type guard to determine if the final instruction in the provided list of
/// instructions is malformed. (Only the final instruction can be malformed.)
pub fn authentication_instructions_are_malformed(
    instructions: &[AuthenticationInstructionMaybeMalformed],
) -> bool {
    instructions
        .last()
        .is_some_and(authentication_instruction_is_malformed)
}

/// A type guard to determine if all of the provided instructions are push
/// instructions.
pub fn authentication_instructions_are_push_instructions(
    instructions: &[AuthenticationInstruction],
) -> bool {
    instructions
        .iter()
        .all(|instruction| matches!(instruction, AuthenticationInstruction::Push(_)))
}

struct CommonPushOpcodes;

impl CommonPushOpcodes {
    const OP_0: u8 = 0x00;
    const OP_PUSHDATA_1: u8 = 0x4c;
    const OP_PUSHDATA_2: u8 = 0x4d;
    const OP_PUSHDATA_4: u8 = 0x4e;
}

const UINT8_BYTES: u8 = 1;
const UINT16_BYTES: u8 = 2;
const UINT32_BYTES: u8 = 4;

/// Decode a little endian number of `length` (`1`, `2`, or `4`) bytes from
/// `position`.
pub fn read_little_endian_number(position: ReadPosition<'_>, length: u8) -> u32 {
    let ReadPosition { bin, index } = position;
    match length {
        UINT8_BYTES => bin[index] as u32,
        UINT16_BYTES => u16::from_le_bytes([bin[index], bin[index + 1]]) as u32,
        _ => u32::from_le_bytes([bin[index], bin[index + 1], bin[index + 2], bin[index + 3]]),
    }
}

/// Returns the number of bytes used to indicate the length of the push in
/// this operation (`0`, `1`, `2`, or `4`).
pub fn opcode_to_push_length(opcode: u8) -> u8 {
    match opcode {
        CommonPushOpcodes::OP_PUSHDATA_1 => UINT8_BYTES,
        CommonPushOpcodes::OP_PUSHDATA_2 => UINT16_BYTES,
        CommonPushOpcodes::OP_PUSHDATA_4 => UINT32_BYTES,
        _ => 0,
    }
}

/// Decode one instruction from the provided virtual machine bytecode,
/// returning the decoded instruction and the position following it.
///
/// If the final instruction is a push which extends beyond the end of the
/// bytecode, it is returned as a malformed instruction.
pub fn read_authentication_instruction(
    position: ReadPosition<'_>,
) -> (AuthenticationInstructionMaybeMalformed, ReadPosition<'_>) {
    let ReadPosition { bin, index } = position;
    let opcode = bin[index];
    if opcode > CommonPushOpcodes::OP_PUSHDATA_4 {
        return (
            AuthenticationInstructionMaybeMalformed::Instruction(
                AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode }),
            ),
            ReadPosition { bin, index: index + 1 },
        );
    }
    let length_bytes = opcode_to_push_length(opcode);
    if length_bytes != 0 && index + length_bytes as usize >= bin.len() {
        let slice_start = index + 1;
        let slice_end = slice_start + length_bytes as usize;
        return (
            AuthenticationInstructionMaybeMalformed::Malformed(
                AuthenticationInstructionMalformed::PushMalformedLength(
                    AuthenticationInstructionPushMalformedLength {
                        expected_length_bytes: length_bytes,
                        length: bin[slice_start.min(bin.len())..slice_end.min(bin.len())].to_vec(),
                        opcode,
                    },
                ),
            ),
            ReadPosition { bin, index: slice_end },
        );
    }
    let data_bytes = if length_bytes == 0 {
        opcode as usize
    } else {
        read_little_endian_number(ReadPosition { bin, index: index + 1 }, length_bytes) as usize
    };
    let data_start = index + 1 + length_bytes as usize;
    let data_end = data_start + data_bytes;
    let data = bin[data_start.min(bin.len())..data_end.min(bin.len())].to_vec();
    let instruction = if data_end > bin.len() {
        AuthenticationInstructionMaybeMalformed::Malformed(
            AuthenticationInstructionMalformed::PushMalformedData(
                AuthenticationInstructionPushMalformedData {
                    data,
                    expected_data_bytes: data_end - data_start,
                    opcode,
                },
            ),
        )
    } else {
        AuthenticationInstructionMaybeMalformed::Instruction(AuthenticationInstruction::Push(
            AuthenticationInstructionPush { data, opcode },
        ))
    };
    (instruction, ReadPosition { bin, index: data_end })
}

/// Clone an authentication instruction.
pub fn clone_authentication_instruction(
    instruction: &AuthenticationInstruction,
) -> AuthenticationInstruction {
    instruction.clone()
}

/// Decode authentication virtual machine bytecode (`lockingBytecode` or
/// `unlockingBytecode`) into {@link AuthenticationInstructionsMaybeMalformed}.
/// The method {@link authenticationInstructionsAreMalformed} can be used to
/// determine if these instructions include a malformed instruction.
pub fn decode_authentication_instructions(bytecode: &[u8]) -> AuthenticationInstructionsMaybeMalformed {
    let mut instructions = Vec::new();
    let mut i = 0;
    while i < bytecode.len() {
        let (instruction, position) =
            read_authentication_instruction(ReadPosition { bin: bytecode, index: i });
        i = position.index;
        instructions.push(instruction);
    }
    instructions
}

/// Look up an opcode name in an opcode enum (`opcodes[opcode]`): as in a
/// TypeScript enum object, the last member with the value wins.
fn opcode_name<'a>(opcodes: &[(&'a str, u8)], opcode: u8) -> Option<&'a str> {
    opcodes
        .iter()
        .rev()
        .find(|(_, value)| *value == opcode)
        .map(|(name, _)| *name)
}

fn is_multi_word_push(opcode: u8) -> bool {
    opcode != CommonPushOpcodes::OP_0
}

fn format_asm_push_hex(data: &[u8]) -> String {
    if data.is_empty() {
        String::new()
    } else {
        format!("0x{}", bin_to_hex(data))
    }
}

fn format_missing_bytes_asm(missing: usize) -> String {
    format!("[missing {missing} byte{}]", if missing == 1 { "" } else { "s" })
}

fn is_push_data(push_opcode: u8) -> bool {
    push_opcode >= CommonPushOpcodes::OP_PUSHDATA_1
}

/// Disassemble a malformed authentication instruction into a string
/// description.
pub fn disassemble_authentication_instruction_malformed(
    opcodes: &[(&str, u8)],
    instruction: &AuthenticationInstructionMalformed,
) -> String {
    let name = opcode_name(opcodes, instruction.opcode()).unwrap_or("OP_UNKNOWN");
    let description = match instruction {
        AuthenticationInstructionMalformed::PushMalformedLength(instruction) => format!(
            "{}{}",
            format_asm_push_hex(&instruction.length),
            format_missing_bytes_asm(instruction.expected_length_bytes as usize - instruction.length.len())
        ),
        AuthenticationInstructionMalformed::PushMalformedData(instruction) => format!(
            "{}{}{}",
            if is_push_data(instruction.opcode) {
                format!("{} ", instruction.expected_data_bytes)
            } else {
                String::new()
            },
            format_asm_push_hex(&instruction.data),
            format_missing_bytes_asm(instruction.expected_data_bytes - instruction.data.len())
        ),
    };
    format!("{name} {description}")
}

/// Disassemble a properly-formed authentication instruction into a string
/// description.
pub fn disassemble_authentication_instruction(
    opcodes: &[(&str, u8)],
    instruction: &AuthenticationInstruction,
) -> String {
    let name = opcode_name(opcodes, instruction.opcode()).unwrap_or("OP_UNKNOWN");
    match instruction {
        AuthenticationInstruction::Push(push) if is_multi_word_push(push.opcode) => format!(
            "{name} {}{}",
            if is_push_data(push.opcode) {
                format!("{} ", push.data.len())
            } else {
                String::new()
            },
            format_asm_push_hex(&push.data)
        ),
        _ => name.to_string(),
    }
}

/// Disassemble a single {@link AuthenticationInstructionMaybeMalformed} into
/// its ASM representation.
pub fn disassemble_authentication_instruction_maybe_malformed(
    opcodes: &[(&str, u8)],
    instruction: &AuthenticationInstructionMaybeMalformed,
) -> String {
    match instruction {
        AuthenticationInstructionMaybeMalformed::Malformed(instruction) => {
            disassemble_authentication_instruction_malformed(opcodes, instruction)
        }
        AuthenticationInstructionMaybeMalformed::Instruction(instruction) => {
            disassemble_authentication_instruction(opcodes, instruction)
        }
    }
}

/// Disassemble an array of {@link AuthenticationInstructionMaybeMalformed}
/// (including potential malformed instructions) into its ASM representation.
pub fn disassemble_authentication_instructions_maybe_malformed(
    opcodes: &[(&str, u8)],
    instructions: &[AuthenticationInstructionMaybeMalformed],
) -> String {
    instructions
        .iter()
        .map(|instruction| disassemble_authentication_instruction_maybe_malformed(opcodes, instruction))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Disassemble authentication bytecode into a lossless ASM representation.
/// (All push operations are represented with the same opcodes used in the
/// bytecode, even when non-minimally encoded.)
pub fn disassemble_bytecode(opcodes: &[(&str, u8)], bytecode: &[u8]) -> String {
    disassemble_authentication_instructions_maybe_malformed(
        opcodes,
        &decode_authentication_instructions(bytecode),
    )
}

/// Disassemble BCH authentication bytecode into its ASM representation.
pub fn disassemble_bytecode_bch(bytecode: &[u8]) -> String {
    disassemble_authentication_instructions_maybe_malformed(
        OpcodesBchSpec::MEMBERS,
        &decode_authentication_instructions(bytecode),
    )
}

/// @deprecated Alias of `disassembleBytecodeBch` for backwards-compatibility.
pub use self::disassemble_bytecode_bch as disassemble_bytecode_BCH;

/// Disassemble BTC authentication bytecode into its ASM representation.
pub fn disassemble_bytecode_btc(bytecode: &[u8]) -> String {
    disassemble_authentication_instructions_maybe_malformed(
        OpcodesBtc::MEMBERS,
        &decode_authentication_instructions(bytecode),
    )
}

/// @deprecated Alias of `disassembleBytecodeBtc` for backwards-compatibility.
pub use self::disassemble_bytecode_btc as disassemble_bytecode_BTC;

/// Create an object where each key is an opcode identifier and each value is
/// the bytecode value (`Uint8Array`) it represents.
pub fn generate_bytecode_map(opcodes: &[(&str, u8)]) -> BTreeMap<String, Vec<u8>> {
    opcodes
        .iter()
        .map(|(name, value)| (name.to_string(), vec![*value]))
        .collect()
}

fn get_instruction_length_bytes(instruction: &AuthenticationInstructionPush) -> Vec<u8> {
    let expected_length = opcode_to_push_length(instruction.opcode);
    match expected_length {
        UINT8_BYTES => vec![instruction.data.len() as u8],
        UINT16_BYTES => number_to_bin_uint16_le(instruction.data.len() as u16),
        _ => number_to_bin_uint32_le(instruction.data.len() as u32),
    }
}

/// Re-encode a valid authentication instruction.
pub fn encode_authentication_instruction(instruction: &AuthenticationInstruction) -> Vec<u8> {
    let mut encoded = vec![instruction.opcode()];
    if let AuthenticationInstruction::Push(push) = instruction {
        if is_push_data(push.opcode) {
            encoded.extend(get_instruction_length_bytes(push));
        }
        encoded.extend_from_slice(&push.data);
    }
    encoded
}

/// Re-encode a malformed authentication instruction.
pub fn encode_authentication_instruction_malformed(
    instruction: &AuthenticationInstructionMalformed,
) -> Vec<u8> {
    let opcode = instruction.opcode();
    match instruction {
        AuthenticationInstructionMalformed::PushMalformedLength(instruction) => {
            flatten_bin_array(&[vec![opcode], instruction.length.clone()])
        }
        AuthenticationInstructionMalformed::PushMalformedData(instruction) => {
            if is_push_data(opcode) {
                let length = match opcode {
                    CommonPushOpcodes::OP_PUSHDATA_1 => vec![instruction.expected_data_bytes as u8],
                    CommonPushOpcodes::OP_PUSHDATA_2 => {
                        number_to_bin_uint16_le(instruction.expected_data_bytes as u16)
                    }
                    _ => number_to_bin_uint32_le(instruction.expected_data_bytes as u32),
                };
                return flatten_bin_array(&[vec![opcode], length, instruction.data.clone()]);
            }
            flatten_bin_array(&[vec![opcode], instruction.data.clone()])
        }
    }
}

/// Re-encode a potentially-malformed authentication instruction.
pub fn encode_authentication_instruction_maybe_malformed(
    instruction: &AuthenticationInstructionMaybeMalformed,
) -> Vec<u8> {
    match instruction {
        AuthenticationInstructionMaybeMalformed::Malformed(instruction) => {
            encode_authentication_instruction_malformed(instruction)
        }
        AuthenticationInstructionMaybeMalformed::Instruction(instruction) => {
            encode_authentication_instruction(instruction)
        }
    }
}

/// Re-encode an array of valid authentication instructions.
pub fn encode_authentication_instructions(instructions: &[AuthenticationInstruction]) -> Vec<u8> {
    flatten_bin_array(
        &instructions
            .iter()
            .map(encode_authentication_instruction)
            .collect::<Vec<_>>(),
    )
}

/// Re-encode an array of authentication instructions which may end with a
/// malformed instruction.
pub fn encode_authentication_instructions_maybe_malformed(
    instructions: &[AuthenticationInstructionMaybeMalformed],
) -> Vec<u8> {
    flatten_bin_array(
        &instructions
            .iter()
            .map(encode_authentication_instruction_maybe_malformed)
            .collect::<Vec<_>>(),
    )
}

/// The errors which can be returned when decoding a VM Number.
pub struct VmNumberError;

#[allow(non_upper_case_globals)]
impl VmNumberError {
    pub const outOfRange: &'static str = "Failed to decode VM Number: overflows VM Number range.";
    pub const requiresMinimal: &'static str =
        "Failed to decode VM Number: the number is not minimally-encoded.";
}

/// Test if the result of {@link vmNumberToBigInt} is a {@link VmNumberError}.
pub fn is_vm_number_error(value: &Result<BigInt, String>) -> bool {
    matches!(value, Err(error) if error == VmNumberError::outOfRange || error == VmNumberError::requiresMinimal)
}

const VM_NUMBER_SIGN_BYTE: u8 = 0x80;

/// Decode a VM Number (A.K.A. "Script Number") into a `bigint`, returning a
/// {@link VmNumberError} if the encoding is invalid.
///
/// `maximum_vm_number_byte_length` defaults to `0` (no maximum) and
/// `require_minimal_encoding` defaults to `true`.
pub fn vm_number_to_big_int(
    bytes: &[u8],
    maximum_vm_number_byte_length: Option<usize>,
    require_minimal_encoding: Option<bool>,
) -> Result<BigInt, String> {
    let maximum_vm_number_byte_length = maximum_vm_number_byte_length.unwrap_or(0);
    let require_minimal_encoding = require_minimal_encoding.unwrap_or(true);
    if bytes.is_empty() {
        return Ok(BigInt::zero());
    }
    if maximum_vm_number_byte_length != 0 && bytes.len() > maximum_vm_number_byte_length {
        return Err(VmNumberError::outOfRange.to_string());
    }
    let most_significant_byte = bytes[bytes.len() - 1];
    let all_but_the_sign_bit = 0b0111_1111;
    let just_the_sign_bit = 0b1000_0000;
    if require_minimal_encoding
        && (most_significant_byte & all_but_the_sign_bit) == 0
        && (bytes.len() <= 1 || (bytes[bytes.len() - 2] & just_the_sign_bit) == 0)
    {
        return Err(VmNumberError::requiresMinimal.to_string());
    }
    let negative = (most_significant_byte & VM_NUMBER_SIGN_BYTE) != 0;
    if !negative {
        return Ok(BigInt::from_bytes_le(bytes));
    }
    let mut magnitude = bytes.to_vec();
    let last = magnitude.len() - 1;
    magnitude[last] &= !VM_NUMBER_SIGN_BYTE;
    Ok(BigInt::from_bytes_le(&magnitude).negate())
}

/// Convert a `bigint` into the VM Number format (A.K.A. "Script Number").
pub fn big_int_to_vm_number(integer: &BigInt) -> Vec<u8> {
    if integer.is_zero() {
        return Vec::new();
    }
    let is_negative = integer.is_negative();
    let mut bytes = integer.to_bytes_le();
    let sign_flipping_byte = 0x80;
    let last = bytes.len() - 1;
    if (bytes[last] & sign_flipping_byte) > 0 {
        bytes.push(if is_negative { sign_flipping_byte } else { 0x00 });
    } else if is_negative {
        bytes[last] |= sign_flipping_byte;
    }
    bytes
}

/// Determine if a stack item is "truthy" in the same way as C++ boolean
/// conversion (zero and negative zero of any length are falsy).
pub fn stack_item_is_truthy(item: &[u8]) -> bool {
    let sign_flipping_byte = 0x80;
    for (i, byte) in item.iter().enumerate() {
        if *byte != 0 {
            if i == item.len() - 1 && *byte == sign_flipping_byte {
                return false;
            }
            return true;
        }
    }
    false
}

/// Convert a boolean into VM Number format (the type used to express
/// boolean values emitted by several operations).
pub fn boolean_to_vm_number(value: bool) -> Vec<u8> {
    if value {
        big_int_to_vm_number(&BigInt::from_u64(1))
    } else {
        big_int_to_vm_number(&BigInt::zero())
    }
}

struct Opcodes;

impl Opcodes {
    const OP_0: u8 = 0x00;
    const OP_1NEGATE: u8 = 0x4f;
    const OP_RESERVED: u8 = 0x50;
    const OP_1: u8 = 0x51;
    const OP_16: u8 = 0x60;
    const OP_RETURN: u8 = 0x6a;
    const OP_CHECKMULTISIG: u8 = 0xae;
}

/// Returns true if the provided opcode is a push operation (`OP_0` through
/// `OP_16`, including `OP_1NEGATE` and `OP_RESERVED`).
pub fn is_push_operation(opcode: u8) -> bool {
    opcode <= Opcodes::OP_16
}

/// Test if the provided bytecode contains only push operations. (Malformed
/// final pushes are considered push operations.)
pub fn is_push_only(bytecode: &[u8]) -> bool {
    decode_authentication_instructions(bytecode)
        .iter()
        .all(|instruction| is_push_operation(instruction.opcode()))
}

/// Test if the provided bytecode is entirely push instructions (and not
/// malformed): unlike {@link isPushOnly}, `OP_1NEGATE`, `OP_RESERVED`, and
/// `OP_1` through `OP_16` are rejected.
pub fn is_push_only_accurate(bytecode: &[u8]) -> bool {
    let instructions = decode_authentication_instructions(bytecode);
    if authentication_instructions_are_malformed(&instructions) {
        return false;
    }
    let instructions: Vec<AuthenticationInstruction> = instructions
        .into_iter()
        .filter_map(|instruction| match instruction {
            AuthenticationInstructionMaybeMalformed::Instruction(instruction) => Some(instruction),
            AuthenticationInstructionMaybeMalformed::Malformed(_) => None,
        })
        .collect();
    authentication_instructions_are_push_instructions(&instructions)
}

/// Test if the provided locking bytecode is an arbitrary data output (an
/// `OP_RETURN` followed only by push operations).
pub fn is_arbitrary_data_output(locking_bytecode: &[u8]) -> bool {
    !locking_bytecode.is_empty()
        && locking_bytecode[0] == Opcodes::OP_RETURN
        && is_push_only(&locking_bytecode[1..])
}

struct Dust;

impl Dust {
    const P2PKH_INPUT_LENGTH: usize = 148;
    const MINIMUM_FEE_MULTIPLE: u64 = 3;
    const STANDARD_DUST_RELAY_FEE: u64 = 1000;
    const BYTES_PER_KB: u64 = 1000;
}

/// Given a length and a fee rate (in satoshis per kilobyte), get the minimum
/// fee: the fee is never less than 1 satoshi for a non-empty length.
pub fn get_minimum_fee(length: u64, fee_rate_sats_per_kb: u64) -> u64 {
    if length < 1 {
        return 0;
    }
    let truncated = (length as u128 * fee_rate_sats_per_kb as u128) / Dust::BYTES_PER_KB as u128;
    if truncated == 0 {
        1
    } else {
        u64::try_from(truncated).unwrap_or(u64::MAX)
    }
}

/// Given the encoded length of an output, get the dust threshold: the
/// minimum value an output may have to be considered standard.
///
/// `dust_relay_fee_sat_per_kb` defaults to `1000`.
pub fn get_dust_threshold_for_length(output_length: usize, dust_relay_fee_sat_per_kb: Option<u64>) -> u64 {
    let dust_relay_fee_sat_per_kb = dust_relay_fee_sat_per_kb.unwrap_or(Dust::STANDARD_DUST_RELAY_FEE);
    let expected_total_length = output_length + Dust::P2PKH_INPUT_LENGTH;
    Dust::MINIMUM_FEE_MULTIPLE
        .saturating_mul(get_minimum_fee(expected_total_length as u64, dust_relay_fee_sat_per_kb))
}

/// Get the dust threshold of an output: the minimum value it may have to be
/// considered standard. (Arbitrary data outputs have a threshold of `0`.)
///
/// `dust_relay_fee_sat_per_kb` defaults to `1000`.
pub fn get_dust_threshold(output: &Output, dust_relay_fee_sat_per_kb: Option<u64>) -> u64 {
    if is_arbitrary_data_output(&output.locking_bytecode) {
        return 0;
    }
    let encoded_output_length = encode_transaction_output(output).len();
    get_dust_threshold_for_length(encoded_output_length, dust_relay_fee_sat_per_kb)
}

/// Test if an output is considered dust (its value is less than its dust
/// threshold).
///
/// `dust_relay_fee_sat_per_kb` defaults to `1000`.
pub fn is_dust_output(output: &Output, dust_relay_fee_sat_per_kb: Option<u64>) -> bool {
    output.value_satoshis < get_dust_threshold(output, dust_relay_fee_sat_per_kb)
}

struct PublicKey;

impl PublicKey {
    const UNCOMPRESSED_BYTE_LENGTH: usize = 65;
    const UNCOMPRESSED_HEADER_BYTE: u8 = 0x04;
    const UNCOMPRESSED_HEADER_BYTE_LEGACY_EVEN_Y: u8 = 0x06;
    const UNCOMPRESSED_HEADER_BYTE_LEGACY_ODD_Y: u8 = 0x07;
    const COMPRESSED_BYTE_LENGTH: usize = 33;
    const COMPRESSED_HEADER_BYTE_EVEN: u8 = 0x02;
    const COMPRESSED_HEADER_BYTE_ODD: u8 = 0x03;
}

/// Test if the provided public key is a validly-encoded uncompressed public
/// key (65 bytes, with a `0x04` header).
pub fn is_valid_uncompressed_public_key_encoding(public_key: &[u8]) -> bool {
    public_key.len() == PublicKey::UNCOMPRESSED_BYTE_LENGTH
        && public_key[0] == PublicKey::UNCOMPRESSED_HEADER_BYTE
}

/// Test if the provided public key is a validly-encoded compressed public
/// key (33 bytes, with a `0x02` or `0x03` header).
pub fn is_valid_compressed_public_key_encoding(public_key: &[u8]) -> bool {
    public_key.len() == PublicKey::COMPRESSED_BYTE_LENGTH
        && (public_key[0] == PublicKey::COMPRESSED_HEADER_BYTE_EVEN
            || public_key[0] == PublicKey::COMPRESSED_HEADER_BYTE_ODD)
}

/// Test if the provided public key is validly-encoded (compressed or
/// uncompressed).
pub fn is_valid_public_key_encoding(public_key: &[u8]) -> bool {
    is_valid_compressed_public_key_encoding(public_key)
        || is_valid_uncompressed_public_key_encoding(public_key)
}

/// Test if the provided public key is encoded in a form considered standard
/// prior to the 2026 upgrade (including the legacy "hybrid" uncompressed
/// headers, `0x06` and `0x07`).
pub fn is_standardness_public_key_encoding_pre2026(public_key: &[u8]) -> bool {
    let header = public_key.first().copied();
    if public_key.len() == PublicKey::COMPRESSED_BYTE_LENGTH {
        return header == Some(PublicKey::COMPRESSED_HEADER_BYTE_EVEN)
            || header == Some(PublicKey::COMPRESSED_HEADER_BYTE_ODD);
    }
    if public_key.len() == PublicKey::UNCOMPRESSED_BYTE_LENGTH {
        return header == Some(PublicKey::UNCOMPRESSED_HEADER_BYTE)
            || header == Some(PublicKey::UNCOMPRESSED_HEADER_BYTE_LEGACY_EVEN_Y)
            || header == Some(PublicKey::UNCOMPRESSED_HEADER_BYTE_LEGACY_ODD_Y);
    }
    false
}

/// Get the number pushed by a "push number" opcode (`OP_0`, `OP_1NEGATE`, or
/// `OP_1` through `OP_16`), or `None` (libauth's `false`) for any other
/// opcode.
pub fn push_number_opcode_to_number(opcode: u8) -> Option<i32> {
    if opcode == Opcodes::OP_0 {
        return Some(0);
    }
    if opcode == Opcodes::OP_1NEGATE {
        return Some(-1);
    }
    if !(Opcodes::OP_1..=Opcodes::OP_16).contains(&opcode) {
        return None;
    }
    Some(opcode as i32 - Opcodes::OP_RESERVED as i32)
}

const MULTISIG_MINIMUM_INSTRUCTIONS: usize = 4;
const MULTISIG_MAXIMUM_STANDARD_N: i32 = 3;

/// Parse a "simple" multisig locking bytecode (`m` public keys `n`
/// `OP_CHECKMULTISIG`, with standard public key encodings), returning
/// `(m, n, publicKeys)` or `None` (libauth's `false`).
pub fn is_simple_multisig(locking_bytecode: &[u8]) -> Option<(i32, i32, Vec<Vec<u8>>)> {
    let instructions = decode_authentication_instructions(locking_bytecode);
    if authentication_instructions_are_malformed(&instructions) {
        return None;
    }
    let last_index = instructions.len().checked_sub(1)?;
    if instructions.len() < MULTISIG_MINIMUM_INSTRUCTIONS
        || instructions[last_index].opcode() != Opcodes::OP_CHECKMULTISIG
    {
        return None;
    }
    let m = push_number_opcode_to_number(instructions[0].opcode());
    let n = push_number_opcode_to_number(instructions[last_index - 1].opcode());
    let (Some(m), Some(n)) = (m, n) else {
        return None;
    };
    let mut public_keys = Vec::new();
    for instruction in &instructions[1..instructions.len() - 2] {
        match instruction {
            AuthenticationInstructionMaybeMalformed::Instruction(AuthenticationInstruction::Push(
                push,
            )) => public_keys.push(push.data.clone()),
            _ => return None,
        }
    }
    if public_keys
        .iter()
        .any(|key| !is_standardness_public_key_encoding_pre2026(key))
    {
        return None;
    }
    Some((m, n, public_keys))
}

/// Test if the provided locking bytecode is a standard bare multisig (at most
/// 3 public keys).
pub fn is_standard_multisig(locking_bytecode: &[u8]) -> bool {
    let Some((m, n, _)) = is_simple_multisig(locking_bytecode) else {
        return false;
    };
    !(n < 1 || n > MULTISIG_MAXIMUM_STANDARD_N || m < 1 || m > n)
}

/// Test if the provided locking bytecode is a standard output type prior to
/// the 2023 upgrade (P2PKH, P2SH20, P2PK, arbitrary data, or standard bare
/// multisig).
pub fn is_standard_output_bytecode_pre2023(locking_bytecode: &[u8]) -> bool {
    is_pay_to_public_key_hash(locking_bytecode)
        || is_pay_to_script_hash20(locking_bytecode)
        || is_pay_to_public_key(locking_bytecode)
        || is_arbitrary_data_output(locking_bytecode)
        || is_standard_multisig(locking_bytecode)
}

/// Test if the provided locking bytecode is a standard output type following
/// the 2023 upgrade (adding P2SH32).
pub fn is_standard_output_bytecode_2023(locking_bytecode: &[u8]) -> bool {
    is_standard_output_bytecode_pre2023(locking_bytecode) || is_pay_to_script_hash32(locking_bytecode)
}

/// Test if the provided locking bytecode is a standard UTXO type (spendable
/// by a standard transaction) following the 2023 upgrade.
pub fn is_standard_utxo_bytecode_2023(locking_bytecode: &[u8]) -> bool {
    is_pay_to_public_key_hash(locking_bytecode)
        || is_pay_to_script_hash20(locking_bytecode)
        || is_pay_to_public_key(locking_bytecode)
        || is_arbitrary_data_output(locking_bytecode)
        || is_simple_multisig(locking_bytecode).is_some()
        || is_pay_to_script_hash32(locking_bytecode)
}

struct SegWit;

impl SegWit {
    const MINIMUM_LENGTH: usize = 4;
    const MAXIMUM_LENGTH: usize = 42;
    const OP_0: u8 = 0;
    const OP_1: u8 = 81;
    const OP_16: u8 = 96;
    const VERSION_AND_LENGTH_BYTES: usize = 2;
}

/// Test a stack item for the SegWit Recovery Rules activated in
/// `BCH_2019_05`: is it a witness program?
pub fn is_witness_program(bytecode: &[u8]) -> bool {
    let correct_length =
        bytecode.len() >= SegWit::MINIMUM_LENGTH && bytecode.len() <= SegWit::MAXIMUM_LENGTH;
    let valid_version_push = bytecode.first() == Some(&SegWit::OP_0)
        || bytecode
            .first()
            .is_some_and(|first| *first >= SegWit::OP_1 && *first <= SegWit::OP_16);
    let correct_length_byte = bytecode
        .get(1)
        .is_some_and(|length| *length as usize + SegWit::VERSION_AND_LENGTH_BYTES == bytecode.len());
    correct_length && valid_version_push && correct_length_byte
}
