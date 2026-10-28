use crate::format::hex_to_bin;
use crate::message::{encode_transaction_common, hash_transaction_p2p_order, Input, Output};
use crate::vm::{AuthenticationProgramBch, TransactionBch};

/// Create an {@link AuthenticationProgramBch} (with a funding and a spending
/// transaction) for testing the provided locking and unlocking bytecode.
pub fn create_test_authentication_program_bch(
    locking_bytecode: Vec<u8>,
    value_satoshis: u64,
    unlocking_bytecode: Vec<u8>,
) -> AuthenticationProgramBch {
    let test_funding_transaction: TransactionBch = TransactionBch {
        inputs: vec![Input {
            outpoint_index: 0xffff_ffff,
            outpoint_transaction_hash: hex_to_bin(
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            sequence_number: 0xffff_ffff,
            unlocking_bytecode: vec![0, 0],
        }],
        locktime: 0,
        outputs: vec![Output {
            locking_bytecode,
            token: None,
            value_satoshis,
        }],
        version: 1,
    };
    let test_spending_transaction: TransactionBch = TransactionBch {
        inputs: vec![Input {
            outpoint_index: 0,
            outpoint_transaction_hash: hash_transaction_p2p_order(
                &encode_transaction_common(&test_funding_transaction),
                None,
            ),
            sequence_number: 0xffff_ffff,
            unlocking_bytecode,
        }],
        locktime: 0,
        outputs: vec![Output {
            locking_bytecode: Vec::new(),
            token: None,
            value_satoshis,
        }],
        version: 1,
    };
    AuthenticationProgramBch {
        input_index: 0,
        source_outputs: test_funding_transaction.outputs,
        transaction: test_spending_transaction,
    }
}
