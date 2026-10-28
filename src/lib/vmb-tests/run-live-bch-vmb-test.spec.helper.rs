//! Port of `vmb-tests/run-live-bch-vmb-test.spec.helper.ts`
//! (`cargo run --release --example run-live-bch-vmb-test -- <command> ...`).

// libauth names its constants in camelCase; keep those names.
#![allow(non_upper_case_globals)]

// TODO: finish this simple wallet CLI

use std::collections::BTreeMap;

use libauth::address::{
    cash_address_to_locking_bytecode, locking_bytecode_to_base58_address, locking_bytecode_to_cash_address,
    Base58AddressEncodingResult, Base58AddressNetwork,
};
use libauth::compiler::{
    cash_assembly_to_bin, create_compiler_bch, hd_private_key_to_p2pkh_cash_address,
    hd_private_key_to_p2pkh_locking_bytecode, wallet_template_to_compiler_configuration,
};
use libauth::engine::{
    AuthenticationVirtualMachineIdentifier, WalletTemplate, WalletTemplateEntity, WalletTemplateHdKey,
    WalletTemplateLockingType, WalletTemplateScenario, WalletTemplateScenarioBytecode,
    WalletTemplateScenarioBytecodeDefinition, WalletTemplateScenarioBytecodeScript, WalletTemplateScenarioData,
    WalletTemplateScenarioDataHdKeys, WalletTemplateScenarioInput, WalletTemplateScenarioOutput,
    WalletTemplateScenarioOutputLockingBytecode, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioUnlockingBytecode, WalletTemplateScenarioValueSatoshis, WalletTemplateScriptDefinition,
    WalletTemplateScriptLocking, WalletTemplateScriptUnlocking, WalletTemplateVariable, WalletTemplateVariableType,
};
use libauth::format::{assert_success, bin_to_hex, bins_are_equal, hex_to_bin, is_hex, stringify};
use libauth::key::{
    derive_hd_private_node_from_seed, encode_hd_private_key, hd_private_key_to_identifier, DecodedHdKey, HdKeyNetwork,
    HdPrivateNode,
};
use libauth::language::{stringify_debug_trace_summary, summarize_debug_trace};
use libauth::message::{decode_transaction_unsafe, encode_transaction, hash_transaction, Output};
use libauth::runtime::crypto::get_random_values;
use libauth::runtime::json::Json;
use libauth::vm::{create_virtual_machine_bch_2025, AuthenticationProgramCommon, ResolvedTransactionCommon};

const usageInfo: &str = "
Usage:

# Generate an HD private key
============================
Command: cargo run --example run-live-bch-vmb-test -- private [optional-hex-encoded-seed]

Generate a new private key to use when funding tests. To provide entropy from another source, a hex-encoded seed can optionally be provided. A seed should include between 16 bytes and 64 bytes of entropy (recommended: 32 bytes).


# Generate a funding address
============================
Command: cargo run --example run-live-bch-vmb-test -- address <prefix> <hd_private_key> [optional-address-index]
   E.g.: cargo run --example run-live-bch-vmb-test -- address bitcoincash xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta

To generate an address, provide the CashAddress prefix and the xprv of the HD key to use when generating the funding transaction. Typical prefixes are: bitcoincash, bchtest, bchreg


# Generate the transaction(s)
====================
Command: cargo run --example run-live-bch-vmb-test -- generate <hd_private_key> <transaction_hex>
   E.g.: cargo run --example run-live-bch-vmb-test -- generate xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta 020000...

For <transaction_hex>, provide the full, encoded funding transaction. The generate command will use the first output paying to index 0 of the provided address.
";

const defaultSeedLength: usize = 32;
const fundingAddressIndex: f64 = 0.0;

/// `stringify(output)`: libauth marks `Uint8Array`s and `bigint`s in the output.
fn output_to_json(output: &Output) -> Json {
    let bytes = |bin: &[u8]| Json::String(format!("<Uint8Array: 0x{}>", bin_to_hex(bin)));
    let bigint = |value: u64| Json::String(format!("<bigint: {value}n>"));
    let mut entries = vec![("lockingBytecode".to_string(), bytes(&output.locking_bytecode))];
    if let Some(token) = &output.token {
        let mut token_entries = vec![
            ("amount".to_string(), bigint(token.amount)),
            ("category".to_string(), bytes(&token.category)),
        ];
        if let Some(nft) = &token.nft {
            token_entries.push((
                "nft".to_string(),
                Json::Object(vec![
                    ("capability".to_string(), Json::String(nft.capability.as_str().to_string())),
                    ("commitment".to_string(), bytes(&nft.commitment)),
                ]),
            ));
        }
        entries.push(("token".to_string(), Json::Object(token_entries)));
    }
    entries.push(("valueSatoshis".to_string(), bigint(output.value_satoshis)));
    Json::Object(entries)
}

fn exit(code: i32) -> ! {
    std::process::exit(code)
}

fn bytecode_script(script: &str) -> WalletTemplateScenarioBytecode {
    WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
        script: Some(WalletTemplateScenarioBytecodeScript::Id(script.to_string())),
        overrides: None,
    })
}

#[allow(clippy::too_many_lines)]
fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (arg1, arg2, arg3) = (arguments.first(), arguments.get(1), arguments.get(2));

    let Some(arg1) = arg1 else {
        println!("{usageInfo}");
        exit(0);
    };

    if arg1 == "private" {
        if let Some(arg2) = arg2 {
            if !is_hex(arg2) {
                println!("Seed must be hex encoded. To use a random seed, omit this option.");
                exit(1);
            }
        }
        let seed = match arg2 {
            None => {
                let mut seed = vec![0; defaultSeedLength];
                assert_success(get_random_values(&mut seed), None);
                seed
            }
            Some(arg2) => hex_to_bin(arg2),
        };

        let HdPrivateNode::Valid(node) = derive_hd_private_node_from_seed(&seed, None, None, None) else {
            panic!("The seed derives an invalid HD private node.");
        };
        let hd_private_key = assert_success(
            encode_hd_private_key(&DecodedHdKey { network: HdKeyNetwork::Mainnet, node }, None),
            None,
        )
        .hd_private_key;
        println!(
            "
Derived a new HD private key from seed: {}

HD private key: {hd_private_key}

To use it, run: cargo run --example run-live-bch-vmb-test -- address <prefix> <hd_private_key> [index]

For <prefix> provide the CashAddress prefix to use. Typical prefixes are: bitcoincash, bchtest, bchreg
For [index], optionally provide an address index to use (default: 0)

E.g. for a mainnet address:
cargo run --example run-live-bch-vmb-test -- address bitcoincash {hd_private_key}
  ",
            bin_to_hex(&seed)
        );

        exit(0);
    }

    if arg1 == "address" {
        let (Some(arg2), Some(arg3)) = (arg2, arg3) else {
            println!("Required arguments for \"address\": <prefix> <hd_private_key>");
            println!("{usageInfo}");
            exit(1);
        };
        let key_id = match hd_private_key_to_identifier(arg3, None) {
            Ok(key_id) => key_id,
            Err(error) => {
                println!("\n {error}");
                exit(1);
            }
        };
        let address = assert_success(
            hd_private_key_to_p2pkh_cash_address(fundingAddressIndex, arg3, Some(arg2), None, None),
            None,
        )
        .address;
        let bytecode = assert_success(cash_address_to_locking_bytecode(&address), None).bytecode;
        let Base58AddressEncodingResult::Address(legacy_address) =
            locking_bytecode_to_base58_address(&bytecode, Some(Base58AddressNetwork::Mainnet), None)
        else {
            panic!("a P2PKH locking bytecode");
        };
        let Base58AddressEncodingResult::Address(copay_address) =
            locking_bytecode_to_base58_address(&bytecode, Some(Base58AddressNetwork::CopayBch), None)
        else {
            panic!("a P2PKH locking bytecode");
        };
        println!(
            "
Derived address index {fundingAddressIndex} from key ID: {}.

Send funds to this address:
{address}

(Legacy format: {legacy_address}, Copay legacy format: {copay_address})

When the funding transaction has been created, run the \"generate\" command:
cargo run --example run-live-bch-vmb-test -- generate {arg3} <transaction_hex>

For <transaction_hex>, provide the full, encoded funding transaction. The generate command will use the first output paying to index 0 of the provided address.
",
            bin_to_hex(&key_id)
        );
        exit(0);
    }

    if arg1 != "generate" {
        println!("Unknown command: {arg1}");
        println!("{usageInfo}");
        exit(1);
    }
    let (Some(arg2), Some(arg3)) = (arg2, arg3) else {
        println!("Required arguments for \"generate\": <hd_private_key> <transaction_hex>");
        println!("{usageInfo}");
        exit(1);
    };

    let hd_private_key = arg2.as_str();
    if let Err(error) = hd_private_key_to_identifier(arg2, None) {
        println!("\n {error}");
        exit(1);
    }
    let funding_transaction_bin = hex_to_bin(arg3);
    let funding_tx_id = hash_transaction(&funding_transaction_bin);
    let funding_transaction = decode_transaction_unsafe(&funding_transaction_bin);
    let funding_locking_bytecode = assert_success(
        hd_private_key_to_p2pkh_locking_bytecode(fundingAddressIndex, hd_private_key, None),
        None,
    );
    let funding_address = assert_success(
        locking_bytecode_to_cash_address(Some("bitcoincash"), &funding_locking_bytecode, None),
        None,
    )
    .address;
    let Some(funding_utxo_index) = funding_transaction
        .outputs
        .iter()
        .position(|output| bins_are_equal(&output.locking_bytecode, &funding_locking_bytecode))
    else {
        println!(
            "The provided funding transaction does not have an output which pays to address index {fundingAddressIndex} of the provided HD private key. Is this the correct transaction?
Expected locking bytecode: {}
CashAddress: {funding_address}
",
            bin_to_hex(&funding_locking_bytecode)
        );
        exit(1);
    };
    let funding_utxo = funding_transaction.outputs[funding_utxo_index].clone();

    println!("Funding UTXO: {}", stringify(&output_to_json(&funding_utxo), None));

    // let outputAddress = 'bitcoincash:qq2pq6z974lrdq8s0zkrl79efs3xap98fqvz9f30fl';
    let output_address = "bchtest:qrz7khw7pml90zzgzrf7ttdp934d56sxkyxgwhre99";
    if let Err(error) = cash_address_to_locking_bytecode(output_address) {
        println!("The output address \"{output_address}\" is invalid: {error}");
        exit(1);
    }

    let funding_utxo_value = funding_utxo.value_satoshis as f64;
    let setup_size_bytes = 183.0;
    let setup_output_value = funding_utxo_value - setup_size_bytes;
    let test_size_bytes = 106.0;
    let final_output_value = setup_output_value - test_size_bytes;

    let setup_tx_id = "bec7a1507cc76495f005dcc71652cbb388c9adb10da7acdf89caa56c0c45da9e";
    let setup_utxo_index: u32 = 0;

    let final_output_bytecode = bin_to_hex(&assert_success(cash_assembly_to_bin("OP_RETURN <\"BigInt\">"), None));
    let data = || WalletTemplateScenarioData {
        bytecode: None,
        current_block_height: None,
        current_block_time: None,
        hd_keys: Some(WalletTemplateScenarioDataHdKeys {
            address_index: None,
            hd_public_keys: None,
            hd_private_keys: Some(BTreeMap::from([("owner".to_string(), hd_private_key.to_string())])),
        }),
        keys: None,
    };
    let scenario = |source_value: f64,
                    outpoint_index: f64,
                    outpoint_transaction_hash: &str,
                    output: WalletTemplateScenarioOutput<false>| WalletTemplateScenario {
        data: Some(data()),
        description: None,
        extends: None,
        name: None,
        source_outputs: Some(vec![WalletTemplateScenarioOutput {
            locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
            value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(source_value)),
            token: None,
        }]),
        transaction: Some(WalletTemplateScenarioTransaction {
            inputs: Some(vec![WalletTemplateScenarioInput {
                outpoint_index: Some(outpoint_index),
                outpoint_transaction_hash: Some(outpoint_transaction_hash.to_string()),
                sequence_number: None,
                unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
            }]),
            locktime: None,
            outputs: Some(vec![output]),
            version: None,
        }),
    };
    let unlocking = |name: Option<&str>, script: &str, unlocks: &str| {
        WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
            age_lock: None,
            estimate: None,
            fails: None,
            invalid: None,
            name: name.map(str::to_string),
            passes: None,
            script: script.to_string(),
            time_lock_type: None,
            unlocks: unlocks.to_string(),
        })
    };
    let configuration = wallet_template_to_compiler_configuration(&WalletTemplate {
        schema: None,
        description: None,
        entities: BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateEntity {
                description: None,
                name: None,
                scripts: None,
                variables: Some(BTreeMap::from([(
                    "key".to_string(),
                    WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                        address_offset: None,
                        description: None,
                        hd_public_key_derivation_path: None,
                        name: None,
                        never_sign_twice: None,
                        private_derivation_path: None,
                        public_derivation_path: None,
                        r#type: WalletTemplateVariableType::HdKey,
                    }),
                )])),
            },
        )]),
        name: None,
        scenarios: Some(BTreeMap::from([
            (
                "setupTx".to_string(),
                scenario(
                    funding_utxo_value,
                    funding_utxo_index as f64,
                    &funding_tx_id,
                    WalletTemplateScenarioOutput {
                        locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(bytecode_script(
                            "testLock",
                        ))),
                        value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(setup_output_value)),
                        token: None,
                    },
                ),
            ),
            (
                "testSpend".to_string(),
                scenario(
                    setup_output_value,
                    f64::from(setup_utxo_index),
                    setup_tx_id,
                    WalletTemplateScenarioOutput {
                        locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                            WalletTemplateScenarioBytecode::Hex(final_output_bytecode.clone()),
                        )),
                        value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(final_output_value)),
                        token: None,
                    },
                ),
            ),
        ])),
        scripts: BTreeMap::from([
            (
                "p2pkhLock".to_string(),
                WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                    locking_type: WalletTemplateLockingType::Standard,
                    name: Some("P2PKH Lock".to_string()),
                    script: "OP_DUP\nOP_HASH160 <$(<key.public_key> OP_HASH160\n)> OP_EQUALVERIFY\nOP_CHECKSIG"
                        .to_string(),
                }),
            ),
            (
                "p2pkhUnlock".to_string(),
                unlocking(Some("Unlock"), "<key.schnorr_signature.all_outputs>\n<key.public_key>", "p2pkhLock"),
            ),
            (
                "testLock".to_string(),
                WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                    locking_type: WalletTemplateLockingType::P2sh20,
                    name: None,
                    script: "<0xffffffffffffffff> OP_MUL <0x0100000000000000ffffffffffffff3f> OP_EQUAL".to_string(),
                }),
            ),
            ("testUnlock".to_string(), unlocking(None, "<0xffffffffffffffff>", "testLock")),
        ]),
        supported: vec![
            AuthenticationVirtualMachineIdentifier::Bch2023_05,
            AuthenticationVirtualMachineIdentifier::Bch2025_05,
        ],
        version: None,
    });
    let compiler = create_compiler_bch(configuration);
    let setup_tx = match compiler.generate_scenario_debug(None, Some("setupTx"), Some("p2pkhUnlock")) {
        Ok(setup_tx) => setup_tx,
        Err(error) => {
            println!("Error while generating setupTransaction: {error}");
            exit(1);
        }
    };
    let setup_scenario = match setup_tx.scenario {
        Ok(scenario) => scenario,
        Err(error) => {
            println!("Error while generating setupTransaction.scenario - {error}");
            exit(1);
        }
    };

    let vm = create_virtual_machine_bch_2025(Some(true));
    let first_program = ResolvedTransactionCommon {
        source_outputs: vec![funding_utxo.clone()],
        transaction: setup_scenario.program.transaction.clone(),
    };
    if let Err(test_first_tx) = vm.verify(&first_program) {
        println!("First transaction is invalid: {test_first_tx}");
        let trace = vm.debug(
            &AuthenticationProgramCommon {
                input_index: funding_utxo_index,
                source_outputs: first_program.source_outputs.clone(),
                transaction: first_program.transaction.clone(),
            },
            None,
        );
        println!("{}", stringify_debug_trace_summary(&summarize_debug_trace(&trace), None, None, None));
        exit(1);
    }

    let encoded_setup_tx = encode_transaction(&setup_scenario.program.transaction);
    let new_setup_tx_id = hash_transaction(&encoded_setup_tx);

    if new_setup_tx_id != setup_tx_id {
        eprintln!("Update \"setupTxId\" to: {new_setup_tx_id}");
        exit(1);
    }

    if setup_size_bytes != encoded_setup_tx.len() as f64 {
        eprintln!("Set \"setupSizeBytes\" to the new value: {}", encoded_setup_tx.len());
        exit(1);
    }

    println!(
        "
First TX ID: {setup_tx_id}
Hex: {}
",
        bin_to_hex(&encoded_setup_tx)
    );

    let second_tx = match compiler.generate_scenario_debug(None, Some("testSpend"), Some("testUnlock")) {
        Ok(second_tx) => second_tx,
        Err(error) => {
            println!("Error while generating setupTransaction: {error}");
            exit(1);
        }
    };
    let second_scenario = match second_tx.scenario {
        Ok(scenario) => scenario,
        Err(error) => {
            println!("Error while generating setupTransaction.scenario - {error}");
            exit(1);
        }
    };

    let setup_utxo = setup_scenario.program.transaction.outputs[setup_utxo_index as usize].clone();

    println!("Setup UTXO: {}", stringify(&output_to_json(&setup_utxo), None));

    let second_program = ResolvedTransactionCommon {
        source_outputs: vec![setup_utxo],
        transaction: second_scenario.program.transaction.clone(),
    };

    let encoded_second_tx = encode_transaction(&second_scenario.program.transaction);
    // (libauth hashes the setup transaction here.)
    let second_tx_id = hash_transaction(&encoded_setup_tx);

    println!(
        "
  Second TX ID: {second_tx_id}
  Hex: {}
  ",
        bin_to_hex(&encoded_second_tx)
    );

    println!("verifying second transaction:");

    let test_second_tx = vm.verify(&second_program);

    let trace = vm.debug(
        &AuthenticationProgramCommon {
            input_index: setup_utxo_index as usize,
            source_outputs: second_program.source_outputs.clone(),
            transaction: second_program.transaction.clone(),
        },
        None,
    );
    println!("{}", stringify_debug_trace_summary(&summarize_debug_trace(&trace), None, None, None));

    if let Err(test_second_tx) = test_second_tx {
        println!("Second transaction is invalid: {test_second_tx}");
        exit(1);
    }

    if test_size_bytes != encoded_second_tx.len() as f64 {
        eprintln!("Set \"testSizeBytes\" to the new value: {}", encoded_second_tx.len());
        exit(1);
    }
}
