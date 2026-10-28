//! Port of `vm/instruction-sets/xec/xec.spec.ts`.

use libauth::{
    create_virtual_machine_xec, decode_transaction_common, hex_to_bin, Output,
    ResolvedTransactionCommon,
};

const P2SH_MULTISIG_TRANSACTION_HEX: &str = "0200000001600a1b6b0563bbd5b9bef124ff634600df774559da6c51e34a6b97a178be233401000000fc0047304402205e7d56c4e7854f9c672977d6606dd2f0af5494b8e61108e2a92fc920bf8049fc022065262675b0e1a3850d88bd3c56e0eb5fb463d9cdbe49f2f625da5c0f82c765304147304402200d167d5ed77fa169346d295f6fb742e80ae391f0ae086d42b99152bdb23edf4102202c8b85c2583b07b66485b88cacdd14f680bd3aa3f3f12e9f63bc02b4d1cc6d15414c6952210349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e465882102a438b1662aec9c35f85794600e1d2d3683a43cbb66307cf825fc4486b84695452103d9fffac162e9e15aecbe4f937b951815ccb4f940c850fff9ee52fa70805ae7de53ae000000000100000000000000000d6a0b68656c6c6f20776f726c6400000000";

/// The same transaction with version `1` (invalidating its signatures).
const INVALID_INPUT_TRANSACTION_HEX: &str = "0100000001600a1b6b0563bbd5b9bef124ff634600df774559da6c51e34a6b97a178be233401000000fc0047304402205e7d56c4e7854f9c672977d6606dd2f0af5494b8e61108e2a92fc920bf8049fc022065262675b0e1a3850d88bd3c56e0eb5fb463d9cdbe49f2f625da5c0f82c765304147304402200d167d5ed77fa169346d295f6fb742e80ae391f0ae086d42b99152bdb23edf4102202c8b85c2583b07b66485b88cacdd14f680bd3aa3f3f12e9f63bc02b4d1cc6d15414c6952210349c17cce8a460f013fdcd286f90f7b0330101d0f3ab4ced44a5a3db764e465882102a438b1662aec9c35f85794600e1d2d3683a43cbb66307cf825fc4486b84695452103d9fffac162e9e15aecbe4f937b951815ccb4f940c850fff9ee52fa70805ae7de53ae000000000100000000000000000d6a0b68656c6c6f20776f726c6400000000";

fn p2sh_source_output(value_satoshis: u64) -> Output {
    Output {
        locking_bytecode: hex_to_bin("a9147ff682419764f7d0e6df75884c28334b9729864387"),
        token: None,
        value_satoshis,
    }
}

#[test]
fn verify_transaction() {
    let vm = create_virtual_machine_xec(None);
    let value_satoshis = 10000;
    let transaction = match decode_transaction_common(&hex_to_bin(P2SH_MULTISIG_TRANSACTION_HEX)) {
        Err(transaction) => panic!("{transaction}"),
        Ok(transaction) => transaction,
    };

    let source_outputs = vec![p2sh_source_output(value_satoshis)];

    let result = vm.verify(&ResolvedTransactionCommon {
        source_outputs,
        transaction,
    });
    assert_eq!(result, Ok(()), "{result:?}");
}

#[test]
fn verify_transaction_() {
    let vm = create_virtual_machine_xec(None);
    let value_satoshis = 10000;
    let transaction = match decode_transaction_common(&hex_to_bin(P2SH_MULTISIG_TRANSACTION_HEX)) {
        Err(transaction) => panic!("{transaction}"),
        Ok(transaction) => transaction,
    };

    let source_outputs = vec![p2sh_source_output(value_satoshis)];

    let result = vm.verify(&ResolvedTransactionCommon {
        source_outputs,
        transaction,
    });
    assert_eq!(result, Ok(()), "{result:?}");
}

#[test]
fn verify_transaction_incorrect_spent_outputs_length() {
    let vm = create_virtual_machine_xec(None);
    let transaction = match decode_transaction_common(&hex_to_bin(P2SH_MULTISIG_TRANSACTION_HEX)) {
        Err(transaction) => panic!("{transaction}"),
        Ok(transaction) => transaction,
    };

    let source_outputs: Vec<Output> = vec![];

    let result = vm.verify(&ResolvedTransactionCommon {
        source_outputs,
        transaction,
    });
    assert_eq!(
        result,
        Err("Unable to verify transaction: a single spent output must be provided for each transaction input. Transaction input count: 1; source outputs count: 0.".to_string()),
        "{result:?}"
    );
}

#[test]
fn verify_transaction_invalid_input() {
    let vm = create_virtual_machine_xec(None);
    let value_satoshis = 10000;
    let transaction = match decode_transaction_common(&hex_to_bin(INVALID_INPUT_TRANSACTION_HEX)) {
        Err(transaction) => panic!("{transaction}"),
        Ok(transaction) => transaction,
    };

    let source_outputs = vec![p2sh_source_output(value_satoshis)];

    let result = vm.verify(&ResolvedTransactionCommon {
        source_outputs,
        transaction,
    });
    assert_eq!(
        result,
        Err("Unable to verify transaction: error in evaluating input index 0: Program failed a signature verification with a non-null signature (violating the \"NULLFAIL\" rule).".to_string()),
        "{result:?}"
    );
}
