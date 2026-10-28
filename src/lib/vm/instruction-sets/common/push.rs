use std::rc::Rc;

use crate::format::{number_to_bin_uint16_le, number_to_bin_uint32_le};
use crate::runtime::bigint::BigInt;
use crate::vm::{
    apply_error, big_int_to_vm_number, execution_is_active, push_to_stack,
    AuthenticationErrorCommon, AuthenticationInstruction, AuthenticationProgramStateCommon,
    ConsensusCommon, Operation,
};

struct PushOperationConstants;

impl PushOperationConstants {
    const OP_0: u8 = 0;
    /// OP_PUSHBYTES_75
    const MAXIMUM_PUSH_BYTE_OPERATION_SIZE: usize = 0x4b;
    const OP_PUSHDATA_1: u8 = 0x4c;
    const OP_PUSHDATA_2: u8 = 0x4d;
    const OP_PUSHDATA_4: u8 = 0x4e;
    /// OP_1 through OP_16
    const PUSH_NUMBER_OPCODES_OFFSET: u8 = 0x50;
    const PUSH_NUMBER_OPCODES: u8 = 16;
    const NEGATIVE_ONE: u8 = 0x81;
    const OP_1NEGATE: u8 = 79;
    /// 256 - 1
    const MAXIMUM_PUSH_DATA_1_SIZE: usize = 255;
    /// Math.pow(2, 16) - 1
    const MAXIMUM_PUSH_DATA_2_SIZE: usize = 65535;
    /// Math.pow(2, 32) - 1
    const MAXIMUM_PUSH_DATA_4_SIZE: usize = 4_294_967_295;
}

/// Returns the minimal bytecode required to push the provided `data` to the
/// stack.
///
/// @remarks
/// This method conservatively encodes a `Uint8Array` as a data push. For VM
/// Numbers that can be pushed using a single opcode (-1 through 16), the
/// equivalent bytecode value is returned. Other `data` values will be prefixed
/// with the proper opcode and push length bytes (if necessary) to create the
/// minimal push instruction.
///
/// Note, while some single-byte VM Number pushes will be minimally-encoded by
/// this method, all larger inputs will be encoded as-is (it cannot be assumed
/// that inputs are intended to be used as VM Numbers).
pub fn encode_data_push(data: &[u8]) -> Vec<u8> {
    if data.len() <= PushOperationConstants::MAXIMUM_PUSH_BYTE_OPERATION_SIZE {
        if data.is_empty() {
            return vec![0];
        }
        if data.len() == 1 {
            if data[0] != 0 && data[0] <= PushOperationConstants::PUSH_NUMBER_OPCODES {
                return vec![data[0] + PushOperationConstants::PUSH_NUMBER_OPCODES_OFFSET];
            }
            if data[0] == PushOperationConstants::NEGATIVE_ONE {
                return vec![PushOperationConstants::OP_1NEGATE];
            }
            return vec![1, data[0]];
        }
        return [&[data.len() as u8], data].concat();
    }
    if data.len() <= PushOperationConstants::MAXIMUM_PUSH_DATA_1_SIZE {
        return [&[PushOperationConstants::OP_PUSHDATA_1, data.len() as u8], data].concat();
    }
    if data.len() <= PushOperationConstants::MAXIMUM_PUSH_DATA_2_SIZE {
        return [
            &[PushOperationConstants::OP_PUSHDATA_2][..],
            &number_to_bin_uint16_le(data.len() as u16),
            data,
        ]
        .concat();
    }
    [
        &[PushOperationConstants::OP_PUSHDATA_4][..],
        &number_to_bin_uint32_le(data.len() as u32),
        data,
    ]
    .concat()
}

/// Returns true if the provided `data` is minimally-encoded by the provided
/// `opcode`.
pub fn is_minimal_data_push(opcode: u8, data: &[u8]) -> bool {
    if data.is_empty() {
        return opcode == PushOperationConstants::OP_0;
    }
    if data.len() == 1 {
        let byte = data[0];
        if (1..=PushOperationConstants::PUSH_NUMBER_OPCODES).contains(&byte) {
            return opcode == byte + PushOperationConstants::PUSH_NUMBER_OPCODES_OFFSET;
        }
        if byte == PushOperationConstants::NEGATIVE_ONE {
            return opcode == PushOperationConstants::OP_1NEGATE;
        }
    }
    if data.len() <= PushOperationConstants::MAXIMUM_PUSH_BYTE_OPERATION_SIZE {
        return opcode as usize == data.len();
    }
    if data.len() <= PushOperationConstants::MAXIMUM_PUSH_DATA_1_SIZE {
        return opcode == PushOperationConstants::OP_PUSHDATA_1;
    }
    if data.len() <= PushOperationConstants::MAXIMUM_PUSH_DATA_2_SIZE {
        return opcode == PushOperationConstants::OP_PUSHDATA_2;
    }
    if data.len() <= PushOperationConstants::MAXIMUM_PUSH_DATA_4_SIZE {
        return opcode == PushOperationConstants::OP_PUSHDATA_4;
    }
    false
}

/// Create the push operation: push the data of the current instruction to the
/// stack (if execution is active), failing if the item exceeds
/// `maximum_stack_item_length` (default:
/// `ConsensusCommon.maximumStackItemLength`, even within an unexecuted branch)
/// or the push is not minimally encoded.
pub fn push_operation(maximum_stack_item_length: Option<usize>) -> Operation {
    let maximum_stack_item_length =
        maximum_stack_item_length.unwrap_or(ConsensusCommon::maximumStackItemLength);
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        let instructions = Rc::clone(&state.instructions);
        let AuthenticationInstruction::Push(instruction) = &instructions[state.ip as usize] else {
            unreachable!("push operations are only assigned to push opcodes");
        };
        if instruction.data.len() > maximum_stack_item_length {
            let details = format!(
                "Maximum stack item length: {maximum_stack_item_length} bytes. Item length: {} bytes.",
                instruction.data.len()
            );
            apply_error(state, AuthenticationErrorCommon::exceededMaximumStackItemLength, Some(&details));
            return;
        }
        if !execution_is_active(state) {
            return;
        }
        if is_minimal_data_push(instruction.opcode, &instruction.data) {
            let data = instruction.data.clone();
            push_to_stack(state, vec![data], None);
        } else {
            apply_error(state, AuthenticationErrorCommon::nonMinimalPush, None);
        }
    })
}

/// @param number - the number that is pushed to the stack by this operation.
/// @returns an operation that pushes a number to the stack.
pub fn push_number_operation(number: i64) -> Operation {
    let value = big_int_to_vm_number(&BigInt::from_i64(number));
    Rc::new(move |state: &mut AuthenticationProgramStateCommon| {
        push_to_stack(state, vec![value.clone()], None);
    })
}
