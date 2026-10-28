//! Port of `transaction/generate-transaction.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "../compiler/compiler-bch/compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;
#[path = "transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use libauth::runtime::json::{parse_json, Json};
use libauth::{
    decode_transaction, generate_transaction, hex_to_bin, import_wallet_template, locking_bytecode_to_cash_address,
    wallet_template_to_compiler_bch, BytecodeGenerationResult, CashAddressNetworkPrefix, CashAddressResult,
    CompilationData, CompilationDataKeys, CompilationDirectiveLocking, CompilationDirectiveUnlocking, InputTemplate,
    InputUnlockingBytecode, OutputLockingBytecode, OutputTemplate, TransactionGenerationAttempt,
    TransactionGenerationSuccess, TransactionTemplateFixed,
};

use compiler_bch_e2e_spec_helper::privateKeyM0;

/// libauth's `maybeP2pkhTemplate: unknown` (an untyped object).
static maybeP2pkhTemplate: LazyLock<Json> = LazyLock::new(|| {
    parse_json(
        r#"{
  "entities": {
    "ownerEntity": {
      "name": "Owner",
      "scripts": ["lock", "unlock"],
      "variables": {
        "owner": {
          "description": "The private key that controls this wallet.",
          "name": "Owner's Key",
          "type": "Key"
        }
      }
    }
  },
  "scripts": {
    "celebrate": {
      "script": "OP_RETURN <\"hello world\">"
    },
    "lock": {
      "lockingType": "standard",
      "name": "P2PKH Lock",
      "script": "OP_DUP\nOP_HASH160 <$( <owner.public_key> OP_HASH160\n)> OP_EQUALVERIFY\nOP_CHECKSIG"
    },
    "unlock": {
      "name": "Unlock",
      "script": "<owner.schnorr_signature.all_outputs>\n<owner.public_key>",
      "unlocks": "lock"
    }
  },
  "supported": ["BCH_2022_05"]
}"#,
    )
    .expect("valid JSON")
});

#[test]
fn create_compiler_bch_generate_transaction() {
    let p2pkh_template = match import_wallet_template(&maybeP2pkhTemplate) {
        Err(error) => panic!("{error}"),
        Ok(template) => template,
    };

    let p2pkh = wallet_template_to_compiler_bch(&p2pkh_template, None);
    let locking_bytecode = p2pkh.generate_bytecode(
        &CompilationData {
            keys: Some(CompilationDataKeys {
                private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
            }),
            ..Default::default()
        },
        "lock",
    );

    let locking_bytecode = match locking_bytecode {
        BytecodeGenerationResult::Error(error) => panic!("{:?}", error.errors),
        BytecodeGenerationResult::Success { bytecode } => bytecode,
    };

    assert_eq!(
        locking_bytecode_to_cash_address(
            Some(CashAddressNetworkPrefix::Testnet.as_str()),
            &locking_bytecode,
            None
        ),
        Ok(CashAddressResult {
            address: "bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x".to_string(),
        })
    );

    let utxo_outpoint_transaction_hash = hex_to_bin("68127de83d2ab77d7f5fd8d2ac6181d94473c0cbb2d0776084bf28884f6ecd77");

    let value_satoshis = 1000000;
    let result = generate_transaction(&TransactionTemplateFixed {
        inputs: vec![InputTemplate {
            outpoint_index: 1,
            outpoint_transaction_hash: utxo_outpoint_transaction_hash,
            sequence_number: 0,
            unlocking_bytecode: InputUnlockingBytecode::Compilation(CompilationDirectiveUnlocking {
                compiler: p2pkh.clone(),
                data: Some(CompilationData {
                    keys: Some(CompilationDataKeys {
                        private_keys: Some(BTreeMap::from([("owner".to_string(), privateKeyM0.clone())])),
                    }),
                    ..Default::default()
                }),
                script: "unlock".to_string(),
                token: None,
                value_satoshis,
            }),
        }],
        locktime: 0,
        outputs: vec![OutputTemplate {
            locking_bytecode: OutputLockingBytecode::Compilation(CompilationDirectiveLocking {
                compiler: p2pkh,
                data: None,
                script: "celebrate".to_string(),
            }),
            token: None,
            value_satoshis: 0,
        }],
        version: 2,
    });

    if let TransactionGenerationAttempt::Error(error) = &result {
        panic!("{:?}", error.errors);
    }

    assert_eq!(
        format!("{result:?}"),
        format!(
            "{:?}",
            TransactionGenerationAttempt::Success(TransactionGenerationSuccess {
                transaction: decode_transaction(&hex_to_bin(
                    "020000000177cd6e4f8828bf846077d0b2cbc07344d98161acd2d85f7f7db72a3de87d1268010000006441f87a1dc0fb4a30443fdfcc678e713d99cffb963bd52b497377e81abe2cc2b5ac6e9837fab0a23f4d05fd06b80e7673a68bfa8d2f66b7ec5537e88696d7bae1b841210376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5000000000100000000000000000d6a0b68656c6c6f20776f726c6400000000"
                ))
                .unwrap(),
            })
        )
    );
}
