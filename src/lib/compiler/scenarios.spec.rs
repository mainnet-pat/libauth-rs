//! Port of `compiler/scenarios.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "../transaction/transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    create_compiler_bch, extend_scenario_definition, extend_scenario_definition_data,
    extended_scenario_definition_to_compilation_data, generate_default_scenario_definition, generate_extended_scenario,
    hex_to_bin, import_wallet_template, sha256, sha512, walletTemplateP2pkh, walletTemplateP2pkhNonHd,
    wallet_template_to_compiler_bch, wallet_template_to_compiler_configuration, AuthenticationProgramCommon,
    AuthenticationVirtualMachineIdentifier, CompilationData, CompilationDataHdKeys, CompilationDataKeys,
    CompilerConfiguration, ExtendedScenarioDefinition, Input, Output, Scenario, TransactionCommon, WalletTemplate,
    WalletTemplateAddressData, WalletTemplateEntity, WalletTemplateHdKey, WalletTemplateKey, WalletTemplateLockingType,
    WalletTemplateScenario, WalletTemplateScenarioBytecode, WalletTemplateScenarioBytecodeDefinition,
    WalletTemplateScenarioBytecodeScript, WalletTemplateScenarioData, WalletTemplateScenarioDataHdKeys,
    WalletTemplateScenarioDataKeys, WalletTemplateScenarioInput, WalletTemplateScenarioOutput,
    WalletTemplateScenarioOutputLockingBytecode, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioUnlockingBytecode, WalletTemplateScenarioValueSatoshis, WalletTemplateScript,
    WalletTemplateScriptDefinition, WalletTemplateScriptLocking, WalletTemplateScriptTest, WalletTemplateScriptTested,
    WalletTemplateScriptUnlocking, WalletTemplateVariable, WalletTemplateVariableType,
};

use transaction_e2e_spec_helper::cashChannelsJson;

/// libauth's `{}` as `data`.
fn empty_scenario_data() -> WalletTemplateScenarioData {
    WalletTemplateScenarioData {
        bytecode: None,
        current_block_height: None,
        current_block_time: None,
        hd_keys: None,
        keys: None,
    }
}

/// libauth's `{}` as a scenario.
fn empty_scenario() -> WalletTemplateScenario {
    WalletTemplateScenario {
        data: None,
        description: None,
        extends: None,
        name: None,
        source_outputs: None,
        transaction: None,
    }
}

/// The `expectScenarioGenerationResult` macro (`test.macro`) as a plain
/// function. `template_overrides` and `configuration_overrides` receive the
/// macro's base template/configuration and return the TS spread result
/// (`{ ...base, ...overrides }`); libauth's `Scenario | string` result is a
/// `Result<Scenario, String>`.
fn expect_scenario_generation_result(
    scenario_id: Option<&str>,
    unlocking_script_id: Option<&str>,
    template_overrides: impl FnOnce(WalletTemplate) -> WalletTemplate,
    expected_result: Result<Scenario, String>,
    configuration_overrides: Option<fn(CompilerConfiguration) -> CompilerConfiguration>,
) {
    let configuration = wallet_template_to_compiler_configuration(&template_overrides(WalletTemplate {
        schema: None,
        description: None,
        entities: BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateEntity {
                description: None,
                name: None,
                scripts: None,
                variables: Some(BTreeMap::from([
                    (
                        "another".to_string(),
                        WalletTemplateVariable::Key(WalletTemplateKey {
                            description: None,
                            name: None,
                            never_sign_twice: None,
                            r#type: WalletTemplateVariableType::Key,
                        }),
                    ),
                    (
                        "key1".to_string(),
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
                    ),
                    (
                        "var1".to_string(),
                        WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                            description: None,
                            name: None,
                            r#type: WalletTemplateVariableType::AddressData,
                        }),
                    ),
                ])),
            },
        )]),
        name: None,
        scenarios: None,
        scripts: BTreeMap::from([
            (
                "compileTimeAssert".to_string(),
                WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                    name: Some("Var1 Padded".to_string()),
                    pushed: Some(true),
                    script: "$(<var1> OP_DUP <0> OP_GREATERTHAN OP_VERIFY OP_DUP <0xff7f> OP_LESSTHANOREQUAL OP_VERIFY <2> OP_NUM2BIN)".to_string(),
                    tests: BTreeMap::from([(
                        "is_within_range".to_string(),
                        WalletTemplateScriptTest {
                            check: "OP_SIZE <2> OP_EQUALVERIFY OP_BIN2NUM <var1> OP_EQUAL".to_string(),
                            fails: None,
                            invalid: Some(vec!["above".to_string(), "below".to_string()]),
                            name: Some("Is Within Range".to_string()),
                            passes: Some(vec!["within".to_string()]),
                            setup: None,
                        },
                    )]),
                }),
            ),
            (
                "p2pkhLock".to_string(),
                WalletTemplateScriptDefinition::Script(WalletTemplateScript {
                    name: None,
                    script: "OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG".to_string(),
                }),
            ),
            (
                "p2pkhUnlock".to_string(),
                WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                    age_lock: None,
                    estimate: None,
                    fails: None,
                    invalid: None,
                    name: None,
                    passes: None,
                    script: "<key1.schnorr_signature.all_outputs> <key1.public_key>".to_string(),
                    time_lock_type: None,
                    unlocks: "p2pkhLock".to_string(),
                }),
            ),
            (
                "p2sh20Lock".to_string(),
                WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                    locking_type: WalletTemplateLockingType::P2sh20,
                    name: None,
                    script: "<var1> OP_DROP OP_DROP OP_1".to_string(),
                }),
            ),
            (
                "p2sh20Unlock".to_string(),
                WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                    age_lock: None,
                    estimate: None,
                    fails: None,
                    invalid: None,
                    name: None,
                    passes: None,
                    script: "<key1.schnorr_signature.all_outputs>".to_string(),
                    time_lock_type: None,
                    unlocks: "p2sh20Lock".to_string(),
                }),
            ),
        ]),
        supported: vec![AuthenticationVirtualMachineIdentifier::Bch2020_05],
        version: Some(0),
    }));

    let compiler = create_compiler_bch(match configuration_overrides {
        Some(overrides) => overrides(configuration),
        None => configuration,
    });

    let scenario = compiler.generate_scenario(None, scenario_id, unlocking_script_id);

    assert_eq!(
        scenario, expected_result,
        "- \nResult: {scenario:#?}\n\nExpected:\n {expected_result:#?}\n"
    );
}

// generateDefaultScenarioDefinition: empty
#[test]
fn generate_default_scenario_definition_empty() {
    let scenario = generate_default_scenario_definition(&CompilerConfiguration::default());
    assert_eq!(
        scenario,
        Ok(ExtendedScenarioDefinition {
            data: WalletTemplateScenarioData {
                bytecode: None,
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: None,
                keys: None,
            },
            source_outputs: vec![WalletTemplateScenarioOutput {
                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
                token: None,
                value_satoshis: None,
            }],
            transaction: WalletTemplateScenarioTransaction {
                inputs: Some(vec![WalletTemplateScenarioInput {
                    outpoint_index: None,
                    outpoint_transaction_hash: None,
                    sequence_number: None,
                    unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
                }]),
                locktime: Some(0.0),
                outputs: Some(vec![WalletTemplateScenarioOutput {
                    locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                        WalletTemplateScenarioBytecode::Hex("6a076c696261757468".to_string())
                    )),
                    token: None,
                    value_satoshis: None,
                }]),
                version: Some(2.0),
            },
        }),
    );
}

// generateDefaultScenarioDefinition: missing sha256
#[test]
fn generate_default_scenario_definition_missing_sha256() {
    let scenario = generate_default_scenario_definition(&CompilerConfiguration {
        sha512: Some(sha512.clone()),
        variables: Some(BTreeMap::from([(
            "key".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: Some("The private key that controls this wallet.".to_string()),
                hd_public_key_derivation_path: None,
                name: Some("Key".to_string()),
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        ..Default::default()
    });
    assert_eq!(
        scenario,
        Err("An implementations of \"sha256\" is required to generate defaults for HD keys, but the \"sha256\" property is not included in this compiler configuration.".to_string()),
    );
}

// generateDefaultScenarioDefinition: missing sha512
#[test]
fn generate_default_scenario_definition_missing_sha512() {
    let scenario = generate_default_scenario_definition(&CompilerConfiguration {
        sha256: Some(sha256.clone()),
        variables: Some(BTreeMap::from([(
            "key".to_string(),
            WalletTemplateVariable::HdKey(WalletTemplateHdKey {
                address_offset: None,
                description: Some("The private key that controls this wallet.".to_string()),
                hd_public_key_derivation_path: None,
                name: Some("Key".to_string()),
                never_sign_twice: None,
                private_derivation_path: None,
                public_derivation_path: None,
                r#type: WalletTemplateVariableType::HdKey,
            }),
        )])),
        ..Default::default()
    });
    assert_eq!(
        scenario,
        Err("An implementations of \"sha512\" is required to generate defaults for HD keys, but the \"sha512\" property is not included in this compiler configuration.".to_string()),
    );
}

// extendScenarioDefinitionData: empty
#[test]
fn extend_scenario_definition_data_empty() {
    let extended = extend_scenario_definition_data(&empty_scenario_data(), &empty_scenario_data());
    assert_eq!(extended, empty_scenario_data());
}

// extendScenarioDefinitionData: 1
#[test]
fn extend_scenario_definition_data_1() {
    let extended = extend_scenario_definition_data(
        &WalletTemplateScenarioData {
            bytecode: None,
            current_block_height: None,
            current_block_time: None,
            hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                address_index: None,
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("b".to_string(), "(hd public key)".to_string())])),
            }),
            keys: None,
        },
        &WalletTemplateScenarioData {
            bytecode: Some(BTreeMap::from([("test".to_string(), "<\"abc\">".to_string())])),
            current_block_height: None,
            current_block_time: None,
            hd_keys: None,
            keys: None,
        },
    );
    assert_eq!(
        extended,
        WalletTemplateScenarioData {
            bytecode: Some(BTreeMap::from([("test".to_string(), "<\"abc\">".to_string())])),
            current_block_height: None,
            current_block_time: None,
            hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                address_index: None,
                hd_private_keys: None,
                hd_public_keys: Some(BTreeMap::from([("b".to_string(), "(hd public key)".to_string())])),
            }),
            keys: None,
        },
    );
}

// extendScenarioDefinition: empty
#[test]
fn extend_scenario_definition_empty() {
    let extended = extend_scenario_definition(&empty_scenario(), &empty_scenario());
    assert_eq!(extended, empty_scenario());
}

// extendScenarioDefinition: default
#[test]
fn extend_scenario_definition_default() {
    let scenario_parent = generate_default_scenario_definition(&CompilerConfiguration::default()).unwrap();
    let extended = extend_scenario_definition(&scenario_parent, &empty_scenario());
    assert_eq!(
        extended,
        ExtendedScenarioDefinition {
            data: WalletTemplateScenarioData {
                bytecode: None,
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: None,
                keys: None,
            },
            source_outputs: vec![WalletTemplateScenarioOutput {
                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
                token: None,
                value_satoshis: None,
            }],
            transaction: WalletTemplateScenarioTransaction {
                inputs: Some(vec![WalletTemplateScenarioInput {
                    outpoint_index: None,
                    outpoint_transaction_hash: None,
                    sequence_number: None,
                    unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
                }]),
                locktime: Some(0.0),
                outputs: Some(vec![WalletTemplateScenarioOutput {
                    locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                        WalletTemplateScenarioBytecode::Hex("6a076c696261757468".to_string())
                    )),
                    token: None,
                    value_satoshis: None,
                }]),
                version: Some(2.0),
            },
        },
    );
}

// extendScenarioDefinition: complex extend
#[test]
fn extend_scenario_definition_complex_extend() {
    let extended = extend_scenario_definition(
        &WalletTemplateScenario {
            source_outputs: Some(vec![WalletTemplateScenarioOutput {
                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                    WalletTemplateScenarioBytecode::Hex("".to_string()),
                )),
                token: None,
                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
            }]),
            transaction: Some(WalletTemplateScenarioTransaction {
                inputs: Some(vec![WalletTemplateScenarioInput {
                    outpoint_index: None,
                    outpoint_transaction_hash: None,
                    sequence_number: None,
                    unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
                }]),
                locktime: Some(0.0),
                outputs: Some(vec![WalletTemplateScenarioOutput {
                    locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                        WalletTemplateScenarioBytecode::Hex("".to_string()),
                    )),
                    token: None,
                    value_satoshis: None,
                }]),
                version: Some(2.0),
            }),
            ..empty_scenario()
        },
        &WalletTemplateScenario {
            data: Some(WalletTemplateScenarioData {
                bytecode: Some(BTreeMap::from([("a".to_string(), "beef".to_string())])),
                current_block_height: None,
                current_block_time: None,
                hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                    address_index: Some(1.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "entity1".to_string(),
                        "(hd private key)".to_string(),
                    )])),
                    hd_public_keys: Some(BTreeMap::from([("entity2".to_string(), "(hd public key)".to_string())])),
                }),
                keys: Some(WalletTemplateScenarioDataKeys {
                    private_keys: Some(BTreeMap::from([("key".to_string(), "(key)".to_string())])),
                }),
            }),
            description: None,
            extends: None,
            name: None,
            source_outputs: None,
            transaction: Some(WalletTemplateScenarioTransaction {
                inputs: None,
                locktime: None,
                outputs: None,
                version: None,
            }),
        },
    );
    assert_eq!(
        extended,
        WalletTemplateScenario {
            data: Some(WalletTemplateScenarioData {
                bytecode: Some(BTreeMap::from([("a".to_string(), "beef".to_string())])),
                current_block_height: None,
                current_block_time: None,
                hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                    address_index: Some(1.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "entity1".to_string(),
                        "(hd private key)".to_string()
                    )])),
                    hd_public_keys: Some(BTreeMap::from([("entity2".to_string(), "(hd public key)".to_string())])),
                }),
                keys: Some(WalletTemplateScenarioDataKeys {
                    private_keys: Some(BTreeMap::from([("key".to_string(), "(key)".to_string())])),
                }),
            }),
            source_outputs: Some(vec![WalletTemplateScenarioOutput {
                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                    WalletTemplateScenarioBytecode::Hex("".to_string())
                )),
                token: None,
                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
            }]),
            transaction: Some(WalletTemplateScenarioTransaction {
                inputs: Some(vec![WalletTemplateScenarioInput {
                    outpoint_index: None,
                    outpoint_transaction_hash: None,
                    sequence_number: None,
                    unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
                }]),
                locktime: Some(0.0),
                outputs: Some(vec![WalletTemplateScenarioOutput {
                    locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                        WalletTemplateScenarioBytecode::Hex("".to_string())
                    )),
                    token: None,
                    value_satoshis: None,
                }]),
                version: Some(2.0),
            }),
            ..empty_scenario()
        },
    );
}

// extendScenarioDefinition: complex extend (2)
#[test]
fn extend_scenario_definition_complex_extend_2() {
    let extended = extend_scenario_definition(
        &WalletTemplateScenario {
            data: Some(WalletTemplateScenarioData {
                bytecode: Some(BTreeMap::from([("a".to_string(), "beef".to_string())])),
                current_block_height: None,
                current_block_time: None,
                hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                    address_index: Some(1.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "entity1".to_string(),
                        "(hd private key)".to_string(),
                    )])),
                    hd_public_keys: Some(BTreeMap::from([("entity2".to_string(), "(hd public key)".to_string())])),
                }),
                keys: Some(WalletTemplateScenarioDataKeys {
                    private_keys: Some(BTreeMap::from([("key".to_string(), "(key)".to_string())])),
                }),
            }),
            ..empty_scenario()
        },
        &WalletTemplateScenario {
            data: Some(WalletTemplateScenarioData {
                bytecode: None,
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: None,
                keys: None,
            }),
            description: None,
            extends: None,
            name: None,
            source_outputs: Some(vec![WalletTemplateScenarioOutput {
                locking_bytecode: None,
                token: None,
                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
            }]),
            transaction: None,
        },
    );
    assert_eq!(
        extended,
        WalletTemplateScenario {
            data: Some(WalletTemplateScenarioData {
                bytecode: Some(BTreeMap::from([("a".to_string(), "beef".to_string())])),
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                    address_index: Some(1.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "entity1".to_string(),
                        "(hd private key)".to_string()
                    )])),
                    hd_public_keys: Some(BTreeMap::from([("entity2".to_string(), "(hd public key)".to_string())])),
                }),
                keys: Some(WalletTemplateScenarioDataKeys {
                    private_keys: Some(BTreeMap::from([("key".to_string(), "(key)".to_string())])),
                }),
            }),
            source_outputs: Some(vec![WalletTemplateScenarioOutput {
                locking_bytecode: None,
                token: None,
                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
            }]),
            ..empty_scenario()
        }
    );
}

// generateExtendedScenario: unknown scenario identifier
#[test]
fn generate_extended_scenario_unknown_scenario_identifier() {
    let extended = generate_extended_scenario(&CompilerConfiguration::default(), Some("unknown"), None);
    assert_eq!(
        extended,
        Err("Cannot extend scenario \"unknown\": a scenario with the identifier unknown is not included in this compiler configuration.".to_string()),
    );
}

// extendedScenarioDefinitionToCompilationData: empty
#[test]
fn extended_scenario_definition_to_compilation_data_empty() {
    let extended = extended_scenario_definition_to_compilation_data(&WalletTemplateScenario {
        data: Some(empty_scenario_data()),
        ..empty_scenario()
    });
    assert_eq!(extended, CompilationData::default());
}

// extendedScenarioDefinitionToCompilationData: empty hdKeys
#[test]
fn extended_scenario_definition_to_compilation_data_empty_hd_keys() {
    let extended = extended_scenario_definition_to_compilation_data(&WalletTemplateScenario {
        data: Some(WalletTemplateScenarioData {
            hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                address_index: None,
                hd_private_keys: None,
                hd_public_keys: None,
            }),
            ..empty_scenario_data()
        }),
        ..empty_scenario()
    });
    assert_eq!(
        extended,
        CompilationData {
            hd_keys: Some(CompilationDataHdKeys::default()),
            ..Default::default()
        }
    );
}

// generateDefaultScenarioDefinition: walletTemplateP2pkhNonHd
#[test]
fn generate_default_scenario_definition_wallet_template_p2pkh_non_hd() {
    let configuration = wallet_template_to_compiler_configuration(&walletTemplateP2pkhNonHd);
    let scenario = generate_default_scenario_definition(&configuration);

    assert_eq!(
        scenario,
        Ok(ExtendedScenarioDefinition {
            data: WalletTemplateScenarioData {
                bytecode: None,
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: None,
                keys: Some(WalletTemplateScenarioDataKeys {
                    private_keys: Some(BTreeMap::from([(
                        "key".to_string(),
                        "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
                    )])),
                }),
            },
            source_outputs: vec![WalletTemplateScenarioOutput {
                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
                token: None,
                value_satoshis: None,
            }],
            transaction: WalletTemplateScenarioTransaction {
                inputs: Some(vec![WalletTemplateScenarioInput {
                    outpoint_index: None,
                    outpoint_transaction_hash: None,
                    sequence_number: None,
                    unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
                }]),
                locktime: Some(0.0),
                outputs: Some(vec![WalletTemplateScenarioOutput {
                    locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(
                        WalletTemplateScenarioBytecode::Hex("6a076c696261757468".to_string())
                    )),
                    token: None,
                    value_satoshis: None,
                }]),
                version: Some(2.0),
            },
        }),
    );
}

// generateDefaultScenarioDefinition: walletTemplateP2pkh
#[test]
fn generate_default_scenario_definition_wallet_template_p2pkh() {
    let configuration = CompilerConfiguration {
        sha256: Some(sha256.clone()),
        sha512: Some(sha512.clone()),
        ..wallet_template_to_compiler_configuration(&walletTemplateP2pkh)
    };
    let scenario = generate_default_scenario_definition(&configuration);
    assert_eq!(
        scenario,
        Ok(ExtendedScenarioDefinition {
            data: WalletTemplateScenarioData {
                bytecode: None,
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                    address_index: Some(0.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "owner".to_string(),
                        "xprv9s21ZrQH143K3w1RdaeDYJjQpiA1vmm3MBNbpFyRGCP8wf7CvY3rgfLGGpw8YBgb7PitSoXBnRRyAYo8fm24T5to52JAv9mgbvXc82Z3EH3".to_string(),
                    )])),
                    hd_public_keys: None,
                }),
                keys: None,
            },
            source_outputs: vec![WalletTemplateScenarioOutput {
                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
                token: None,
                value_satoshis: None,
            }],
            transaction: WalletTemplateScenarioTransaction {
                inputs: Some(vec![WalletTemplateScenarioInput {
                    outpoint_index: None,
                    outpoint_transaction_hash: None,
                    sequence_number: None,
                    unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
                }]),
                locktime: Some(0.0),
                outputs: Some(vec![WalletTemplateScenarioOutput {
                    locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Hex("6a076c696261757468".to_string()))),
                    token: None,
                    value_satoshis: None,
                }]),
                version: Some(2.0),
            },
        }),
    );
}

// generateScenario: deep extend
#[test]
fn generate_scenario_deep_extend() {
    expect_scenario_generation_result(
        Some("c"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([
                (
                    "a".to_string(),
                    WalletTemplateScenario {
                        data: Some(WalletTemplateScenarioData {
                            bytecode: Some(BTreeMap::from([("var1".to_string(), "0x010203".to_string())])),
                            current_block_height: None,
                            current_block_time: None,
                            hd_keys: None,
                            keys: None,
                        }),
                        description: None,
                        extends: None,
                        name: None,
                        source_outputs: None,
                        transaction: None,
                    },
                ),
                (
                    "b".to_string(),
                    WalletTemplateScenario {
                        data: Some(WalletTemplateScenarioData {
                            bytecode: None,
                            current_block_height: None,
                            current_block_time: None,
                            hd_keys: None,
                            keys: Some(WalletTemplateScenarioDataKeys {
                                private_keys: Some(BTreeMap::from([(
                                    "another".to_string(),
                                    "00000000000000000000000000000000000000000000000000000000000000ff".to_string(),
                                )])),
                            }),
                        }),
                        description: None,
                        extends: Some("a".to_string()),
                        name: None,
                        source_outputs: None,
                        transaction: None,
                    },
                ),
                (
                    "c".to_string(),
                    WalletTemplateScenario {
                        data: None,
                        description: None,
                        extends: Some("b".to_string()),
                        name: None,
                        source_outputs: None,
                        transaction: None,
                    },
                ),
            ])),
            ..template
        },
        Ok(Scenario {
            data: CompilationData {
                bytecode: Some(BTreeMap::from([("var1".to_string(), hex_to_bin("010203"))])),
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(CompilationDataHdKeys {
                    address_index: Some(0.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "owner".to_string(),
                        "xprv9s21ZrQH143K3Dfym3ZPsqraXhUokyNALDNHuaDZo14vDW86EpWxTq7ypGDgHCsZNCzsMtJb6xSDWEKmGYfGUZ1edNXGmfxNVaK5aNpBVMJ".to_string(),
                    )])),
                    hd_public_keys: None,
                }),
                keys: Some(CompilationDataKeys {
                    private_keys: Some(BTreeMap::from([(
                        "another".to_string(),
                        hex_to_bin("00000000000000000000000000000000000000000000000000000000000000ff"),
                    )])),
                }),
                ..Default::default()
            },
            program: AuthenticationProgramCommon {
                input_index: 0,
                source_outputs: vec![Output {
                    locking_bytecode: hex_to_bin("a9147ab197d4888698145e7a0af625f8181a95604cd887"),
                    token: None,
                    value_satoshis: 0,
                }],
                transaction: TransactionCommon {
                    inputs: vec![Input {
                        outpoint_index: 0,
                        outpoint_transaction_hash: hex_to_bin(
                            "0000000000000000000000000000000000000000000000000000000000000001",
                        ),
                        sequence_number: 0,
                        unlocking_bytecode: hex_to_bin(
                            "41fd8c2293325a5e85ba2683aa41a3ad483a3917db24b512c396b696a5ccf023ffdbf3883a589271ff90589f0bcbc1ab69b966257df71c0dba78aea4e4064c5c00410703010203757551",
                        ),
                    }],
                    locktime: 0,
                    outputs: vec![Output {
                        locking_bytecode: hex_to_bin("6a076c696261757468"),
                        token: None,
                        value_satoshis: 0,
                    }],
                    version: 2,
                },
            },
        }),
        None,
    );
}

// generateScenario: cyclical extend
#[test]
fn generate_scenario_cyclical_extend() {
    expect_scenario_generation_result(
        Some("c"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([
                (
                    "a".to_string(),
                    WalletTemplateScenario {
                        data: None,
                        description: None,
                        extends: Some("c".to_string()),
                        name: None,
                        source_outputs: None,
                        transaction: None,
                    },
                ),
                (
                    "b".to_string(),
                    WalletTemplateScenario {
                        data: None,
                        description: None,
                        extends: Some("a".to_string()),
                        name: None,
                        source_outputs: None,
                        transaction: None,
                    },
                ),
                (
                    "c".to_string(),
                    WalletTemplateScenario {
                        data: None,
                        description: None,
                        extends: Some("b".to_string()),
                        name: None,
                        source_outputs: None,
                        transaction: None,
                    },
                ),
            ])),
            ..template
        },
        Err("Cannot generate scenario \"c\": Cannot extend scenario \"c\": scenario \"c\" extends itself. Scenario inheritance path: c → b → a".to_string()),
        None,
    );
}

// generateScenario: no scenarios
#[test]
fn generate_scenario_no_scenarios() {
    expect_scenario_generation_result(
        Some("does_not_exist"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: None,
            ..template
        },
        Err("Cannot generate scenario \"does_not_exist\": a scenario definition with the identifier does_not_exist is not included in this compiler configuration.".to_string()),
        None,
    );
}

// generateScenario: unknown scenario ID
#[test]
fn generate_scenario_unknown_scenario_id() {
    expect_scenario_generation_result(
        Some("does_not_exist"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "another".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: None,
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"does_not_exist\": a scenario definition with the identifier does_not_exist is not included in this compiler configuration.".to_string()),
        None,
    );
}

// generateScenario: invalid bytecode value
#[test]
fn generate_scenario_invalid_bytecode_value() {
    expect_scenario_generation_result(
        Some("a"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: Some(WalletTemplateScenarioData {
                        bytecode: Some(BTreeMap::from([("var1".to_string(), "invalid".to_string())])),
                        current_block_height: None,
                        current_block_time: None,
                        hd_keys: None,
                        keys: None,
                    }),
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: None,
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"a\". Compilation error while generating bytecode for \"var1\": [1, 1] Unknown identifier \"invalid\".".to_string()),
        None,
    );
}

// generateScenario: no scenario ID
#[test]
fn generate_scenario_no_scenario_id() {
    expect_scenario_generation_result(
        None,
        Some("p2pkhUnlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: None,
                },
            )])),
            ..template
        },
        Ok(Scenario {
            data: CompilationData {
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(CompilationDataHdKeys {
                    address_index: Some(0.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "owner".to_string(),
                        "xprv9s21ZrQH143K3Dfym3ZPsqraXhUokyNALDNHuaDZo14vDW86EpWxTq7ypGDgHCsZNCzsMtJb6xSDWEKmGYfGUZ1edNXGmfxNVaK5aNpBVMJ".to_string(),
                    )])),
                    hd_public_keys: None,
                }),
                keys: Some(CompilationDataKeys {
                    private_keys: Some(BTreeMap::from([(
                        "another".to_string(),
                        hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001"),
                    )])),
                }),
                ..Default::default()
            },
            program: AuthenticationProgramCommon {
                input_index: 0,
                source_outputs: vec![Output {
                    locking_bytecode: hex_to_bin("76a9141431b2926e6c7953f3dc3f2c5c19fe2d2dc57cfc88ac"),
                    token: None,
                    value_satoshis: 0,
                }],
                transaction: TransactionCommon {
                    inputs: vec![Input {
                        outpoint_index: 0,
                        outpoint_transaction_hash: hex_to_bin(
                            "0000000000000000000000000000000000000000000000000000000000000001",
                        ),
                        sequence_number: 0,
                        unlocking_bytecode: hex_to_bin(
                            "4133afdb65a3c9d2b50f32bc0d6750473425b3c21b138c66596182f072cc2f49d956b71e0183f1aa5620616405ebff584a1e3d4584e9c83b3cd8cc669295db73f641210309c64e4fbc61f4ddc950eb0acff2047850b864d6fb8198070a946cda5d72e5ba",
                        ),
                    }],
                    locktime: 0,
                    outputs: vec![Output {
                        locking_bytecode: hex_to_bin("6a076c696261757468"),
                        token: None,
                        value_satoshis: 0,
                    }],
                    version: 2,
                },
            },
        }),
        None,
    );
}

// generateScenario: no unlocking script ID, no scenario ID
#[test]
fn generate_scenario_no_unlocking_script_id_no_scenario_id() {
    expect_scenario_generation_result(
        None,
        None,
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: None,
                },
            )])),
            ..template
        },
        Ok(Scenario {
            data: CompilationData {
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(CompilationDataHdKeys {
                    address_index: Some(0.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "owner".to_string(),
                        "xprv9s21ZrQH143K3Dfym3ZPsqraXhUokyNALDNHuaDZo14vDW86EpWxTq7ypGDgHCsZNCzsMtJb6xSDWEKmGYfGUZ1edNXGmfxNVaK5aNpBVMJ".to_string(),
                    )])),
                    hd_public_keys: None,
                }),
                keys: Some(CompilationDataKeys {
                    private_keys: Some(BTreeMap::from([(
                        "another".to_string(),
                        hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001"),
                    )])),
                }),
                ..Default::default()
            },
            program: AuthenticationProgramCommon {
                input_index: 0,
                source_outputs: vec![Output {
                    locking_bytecode: hex_to_bin(""),
                    token: None,
                    value_satoshis: 0,
                }],
                transaction: TransactionCommon {
                    inputs: vec![Input {
                        outpoint_index: 0,
                        outpoint_transaction_hash: hex_to_bin(
                            "0000000000000000000000000000000000000000000000000000000000000001",
                        ),
                        sequence_number: 0,
                        unlocking_bytecode: hex_to_bin(""),
                    }],
                    locktime: 0,
                    outputs: vec![Output {
                        locking_bytecode: hex_to_bin("6a076c696261757468"),
                        token: None,
                        value_satoshis: 0,
                    }],
                    version: 2,
                },
            },
        }),
        None,
    );
}

// generateScenario: mismatched source outputs and transaction inputs
#[test]
fn generate_scenario_mismatched_source_outputs_and_transaction_inputs() {
    expect_scenario_generation_result(
        Some("a"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: Some(WalletTemplateScenarioTransaction {
                        inputs: Some(vec![
                            WalletTemplateScenarioInput {
                                outpoint_index: None,
                                outpoint_transaction_hash: None,
                                sequence_number: None,
                                unlocking_bytecode: None,
                            },
                            WalletTemplateScenarioInput {
                                outpoint_index: None,
                                outpoint_transaction_hash: None,
                                sequence_number: None,
                                unlocking_bytecode: None,
                            },
                        ]),
                        locktime: None,
                        outputs: None,
                        version: None,
                    }),
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"a\": could not match source outputs with inputs - \"sourceOutputs\" must be the same length as \"transaction.inputs\".".to_string()),
        None,
    );
}

// generateScenario: ambiguous input under test
#[test]
fn generate_scenario_ambiguous_input_under_test() {
    expect_scenario_generation_result(
        Some("a"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: Some(WalletTemplateScenarioTransaction {
                        inputs: None,
                        locktime: None,
                        outputs: Some(vec![WalletTemplateScenarioOutput {
                            locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                overrides: None,
                                script: Some(WalletTemplateScenarioBytecodeScript::Id("unknown".to_string())),
                            }))),
                            token: None,
                            value_satoshis: None,
                        }]),
                        version: None,
                    }),
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"a\": Failed compilation of source output at index 0: Cannot resolve \"var1\" - the \"bytecode\" property was not provided in the compilation data. Failed compilation of transaction output at index 0: No script with an ID of \"unknown\" was provided in the compiler configuration.".to_string()),
        None,
    );
}

// generateScenario: no locking script
#[test]
fn generate_scenario_no_locking_script() {
    expect_scenario_generation_result(
        Some("a"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: Some(WalletTemplateScenarioTransaction {
                        inputs: None,
                        locktime: None,
                        outputs: Some(vec![WalletTemplateScenarioOutput {
                            locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                overrides: None,
                                script: None,
                            }))),
                            token: None,
                            value_satoshis: None,
                        }]),
                        version: None,
                    }),
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"a\" using unlocking script \"p2sh20Unlock\": the locking script unlocked by \"p2sh20Unlock\" is not provided in this compiler configuration.".to_string()),
        Some(|configuration| CompilerConfiguration {
            unlocking_scripts: None,
            ..configuration
        }),
    );
}

// generateScenario: no locking script, no specified unlocking script
// TS: `test.failing` (expected to fail).
#[should_panic]
#[test]
fn generate_scenario_no_locking_script_no_specified_unlocking_script() {
    expect_scenario_generation_result(
        Some("a"),
        None,
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: Some(WalletTemplateScenarioTransaction {
                        inputs: None,
                        locktime: None,
                        outputs: Some(vec![WalletTemplateScenarioOutput {
                            locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                overrides: None,
                                script: None,
                            }))),
                            token: None,
                            value_satoshis: None,
                        }]),
                        version: None,
                    }),
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"a\": Cannot generate locking bytecode for output 0: this output is set to use the script unlocked by the unlocking script under test, but an unlocking script ID was not provided for scenario generation.".to_string()),
        Some(|configuration| CompilerConfiguration {
            unlocking_scripts: None,
            ..configuration
        }),
    );
}

// generateScenario: simple transaction, locking bytecode override
#[test]
fn generate_scenario_simple_transaction_locking_bytecode_override() {
    expect_scenario_generation_result(
        Some("a"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: Some(WalletTemplateScenarioData {
                        bytecode: None,
                        current_block_height: Some(5.0),
                        current_block_time: None,
                        hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                            address_index: None,
                            hd_private_keys: None,
                            hd_public_keys: Some(BTreeMap::new()),
                        }),
                        keys: Some(WalletTemplateScenarioDataKeys {
                            private_keys: Some(BTreeMap::from([(
                                "another".to_string(),
                                "00000000000000000000000000000000000000000000000000000000000000ff".to_string(),
                            )])),
                        }),
                    }),
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: Some(vec![WalletTemplateScenarioOutput {
                        locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
                        token: None,
                        value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
                    }]),
                    transaction: Some(WalletTemplateScenarioTransaction {
                        inputs: None,
                        locktime: None,
                        outputs: Some(vec![
                            WalletTemplateScenarioOutput {
                                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                    overrides: Some(WalletTemplateScenarioData {
                                        bytecode: None,
                                        current_block_height: Some(9.0),
                                        current_block_time: None,
                                        hd_keys: None,
                                        keys: None,
                                    }),
                                    script: None,
                                }))),
                                token: None,
                                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
                            },
                            WalletTemplateScenarioOutput {
                                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                    overrides: Some(WalletTemplateScenarioData {
                                        bytecode: None,
                                        current_block_height: None,
                                        current_block_time: None,
                                        hd_keys: None,
                                        keys: None,
                                    }),
                                    script: None,
                                }))),
                                token: None,
                                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
                            },
                        ]),
                        version: Some(3.0),
                    }),
                },
            )])),
            scripts: BTreeMap::from([
                (
                    "p2sh20Lock".to_string(),
                    WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                        locking_type: WalletTemplateLockingType::Standard,
                        name: None,
                        script: "OP_DROP <current_block_height> OP_DROP OP_1".to_string(),
                    }),
                ),
                (
                    "p2sh20Unlock".to_string(),
                    WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                        age_lock: None,
                        estimate: None,
                        fails: None,
                        invalid: None,
                        name: None,
                        passes: None,
                        script: "<key1.schnorr_signature.all_outputs>".to_string(),
                        time_lock_type: None,
                        unlocks: "p2sh20Lock".to_string(),
                    }),
                ),
            ]),
            ..template
        },
        Ok(Scenario {
            data: CompilationData {
                current_block_height: Some(5.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(CompilationDataHdKeys {
                    address_index: Some(0.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "owner".to_string(),
                        "xprv9s21ZrQH143K3Dfym3ZPsqraXhUokyNALDNHuaDZo14vDW86EpWxTq7ypGDgHCsZNCzsMtJb6xSDWEKmGYfGUZ1edNXGmfxNVaK5aNpBVMJ".to_string(),
                    )])),
                    hd_public_keys: Some(BTreeMap::new()),
                }),
                keys: Some(CompilationDataKeys {
                    private_keys: Some(BTreeMap::from([(
                        "another".to_string(),
                        hex_to_bin("00000000000000000000000000000000000000000000000000000000000000ff"),
                    )])),
                }),
                ..Default::default()
            },
            program: AuthenticationProgramCommon {
                input_index: 0,
                source_outputs: vec![Output {
                    locking_bytecode: hex_to_bin("75557551"),
                    token: None,
                    value_satoshis: 0xffffffffffffffff,
                }],
                transaction: TransactionCommon {
                    inputs: vec![Input {
                        outpoint_index: 0,
                        outpoint_transaction_hash: hex_to_bin(
                            "0000000000000000000000000000000000000000000000000000000000000001",
                        ),
                        sequence_number: 0,
                        unlocking_bytecode: hex_to_bin(
                            "419f16a55d6a75256ed6618a12d058f13d3792a3970ea75f11f670a886341bbd9d6e48b9f0cc6ff5074a1b15dd2e398150d4dcc184af8aaecbdc26fb16d15d8b7441",
                        ),
                    }],
                    locktime: 0,
                    outputs: vec![
                        Output {
                            locking_bytecode: hex_to_bin("75597551"),
                            token: None,
                            value_satoshis: 0xffffffffffffffff,
                        },
                        Output {
                            locking_bytecode: hex_to_bin("75557551"),
                            token: None,
                            value_satoshis: 0xffffffffffffffff,
                        },
                    ],
                    version: 3,
                },
            },
        }),
        None,
    );
}

// generateScenario: complex transaction, locking bytecode variable override
#[test]
fn generate_scenario_complex_transaction_locking_bytecode_variable_override() {
    expect_scenario_generation_result(
        Some("a"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: Some(WalletTemplateScenarioData {
                        bytecode: Some(BTreeMap::from([("var1".to_string(), "0x010203".to_string())])),
                        current_block_height: None,
                        current_block_time: None,
                        hd_keys: None,
                        keys: None,
                    }),
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: Some(vec![
                        WalletTemplateScenarioOutput {
                            locking_bytecode: None,
                            token: None,
                            value_satoshis: None,
                        },
                        WalletTemplateScenarioOutput {
                            locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
                            token: None,
                            value_satoshis: None,
                        },
                    ]),
                    transaction: Some(WalletTemplateScenarioTransaction {
                        inputs: Some(vec![
                            WalletTemplateScenarioInput {
                                outpoint_index: Some(1.0),
                                outpoint_transaction_hash: Some("0000000000000000000000000000000000000000000000000000000000000001".to_string()),
                                sequence_number: Some(1.0),
                                unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Hex("beef".to_string()))),
                            },
                            WalletTemplateScenarioInput {
                                outpoint_index: None,
                                outpoint_transaction_hash: None,
                                sequence_number: None,
                                unlocking_bytecode: Some(WalletTemplateScenarioUnlockingBytecode::Slot),
                            },
                        ]),
                        locktime: Some(4294967295.0),
                        outputs: Some(vec![
                            WalletTemplateScenarioOutput {
                                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                    overrides: None,
                                    script: None,
                                }))),
                                token: None,
                                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(1000.0)),
                            },
                            WalletTemplateScenarioOutput {
                                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                    overrides: Some(WalletTemplateScenarioData {
                                        bytecode: None,
                                        current_block_height: Some(0.0),
                                        current_block_time: None,
                                        hd_keys: None,
                                        keys: None,
                                    }),
                                    script: None,
                                }))),
                                token: None,
                                value_satoshis: None,
                            },
                            WalletTemplateScenarioOutput {
                                locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                    overrides: Some(WalletTemplateScenarioData {
                                        bytecode: Some(BTreeMap::from([("var1".to_string(), "0x030405".to_string())])),
                                        current_block_height: None,
                                        current_block_time: None,
                                        hd_keys: None,
                                        keys: None,
                                    }),
                                    script: None,
                                }))),
                                token: None,
                                value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Hex("ffffffffffffffff".to_string())),
                            },
                        ]),
                        version: Some(3.0),
                    }),
                },
            )])),
            ..template
        },
        Ok(Scenario {
            data: CompilationData {
                bytecode: Some(BTreeMap::from([("var1".to_string(), hex_to_bin("010203"))])),
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(CompilationDataHdKeys {
                    address_index: Some(0.0),
                    hd_private_keys: Some(BTreeMap::from([(
                        "owner".to_string(),
                        "xprv9s21ZrQH143K3Dfym3ZPsqraXhUokyNALDNHuaDZo14vDW86EpWxTq7ypGDgHCsZNCzsMtJb6xSDWEKmGYfGUZ1edNXGmfxNVaK5aNpBVMJ".to_string(),
                    )])),
                    hd_public_keys: None,
                }),
                keys: Some(CompilationDataKeys {
                    private_keys: Some(BTreeMap::from([(
                        "another".to_string(),
                        hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001"),
                    )])),
                }),
                ..Default::default()
            },
            program: AuthenticationProgramCommon {
                input_index: 1,
                source_outputs: vec![
                    Output {
                        locking_bytecode: hex_to_bin("a9147ab197d4888698145e7a0af625f8181a95604cd887"),
                        token: None,
                        value_satoshis: 0,
                    },
                    Output {
                        locking_bytecode: hex_to_bin("a9147ab197d4888698145e7a0af625f8181a95604cd887"),
                        token: None,
                        value_satoshis: 0,
                    },
                ],
                transaction: TransactionCommon {
                    inputs: vec![
                        Input {
                            outpoint_index: 1,
                            outpoint_transaction_hash: hex_to_bin(
                                "0000000000000000000000000000000000000000000000000000000000000001",
                            ),
                            sequence_number: 1,
                            unlocking_bytecode: hex_to_bin("beef"),
                        },
                        Input {
                            outpoint_index: 1,
                            outpoint_transaction_hash: hex_to_bin(
                                "0000000000000000000000000000000000000000000000000000000000000001",
                            ),
                            sequence_number: 0,
                            unlocking_bytecode: hex_to_bin(
                                "41ceed7320920a9b4035bc4afbb6118635113595a46bd5d64ee3651bb2e88986177b677219e864d639a405c4d0ab28a103a8b3df0cf49b6a0f1cd8d6d95dd9aa71410703010203757551",
                            ),
                        },
                    ],
                    locktime: 4294967295,
                    outputs: vec![
                        Output {
                            locking_bytecode: hex_to_bin("a9147ab197d4888698145e7a0af625f8181a95604cd887"),
                            token: None,
                            value_satoshis: 1000,
                        },
                        Output {
                            locking_bytecode: hex_to_bin("a9147ab197d4888698145e7a0af625f8181a95604cd887"),
                            token: None,
                            value_satoshis: 0,
                        },
                        Output {
                            locking_bytecode: hex_to_bin("a9144e6f989ad736aaffd2f895768f274579722fc73b87"),
                            token: None,
                            value_satoshis: 0xffffffffffffffff,
                        },
                    ],
                    version: 3,
                },
            },
        }),
        None,
    );
}

// generateScenario: locking bytecode generation failure
#[test]
fn generate_scenario_locking_bytecode_generation_failure() {
    expect_scenario_generation_result(
        Some("a"),
        Some("p2sh20Unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "a".to_string(),
                WalletTemplateScenario {
                    data: None,
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: Some(WalletTemplateScenarioTransaction {
                        inputs: None,
                        locktime: None,
                        outputs: Some(vec![WalletTemplateScenarioOutput {
                            locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                                overrides: Some(WalletTemplateScenarioData {
                                    bytecode: Some(BTreeMap::from([("var1".to_string(), "broken".to_string())])),
                                    current_block_height: None,
                                    current_block_time: None,
                                    hd_keys: None,
                                    keys: None,
                                }),
                                script: None,
                            }))),
                            token: None,
                            value_satoshis: None,
                        }]),
                        version: None,
                    }),
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"a\": Failed compilation of source output at index 0: Cannot resolve \"var1\" - the \"bytecode\" property was not provided in the compilation data. Failed compilation of transaction output at index 0: Could not compile scenario \"data.bytecode\": Compilation error while generating bytecode for \"var1\": [1, 1] Unknown identifier \"broken\".".to_string()),
        None,
    );
}

// generateScenario: invalid scenario for tested script
#[test]
fn generate_scenario_invalid_scenario_for_tested_script() {
    expect_scenario_generation_result(
        Some("above"),
        Some("compileTimeAssert.is_within_range.unlock"),
        |template| WalletTemplate {
            scenarios: Some(BTreeMap::from([(
                "above".to_string(),
                WalletTemplateScenario {
                    data: Some(WalletTemplateScenarioData {
                        bytecode: Some(BTreeMap::from([("var1".to_string(), "32768".to_string())])),
                        current_block_height: None,
                        current_block_time: None,
                        hd_keys: None,
                        keys: None,
                    }),
                    description: None,
                    extends: None,
                    name: None,
                    source_outputs: None,
                    transaction: None,
                },
            )])),
            ..template
        },
        Err("Cannot generate scenario \"above\": Failed compilation of source output at index 0: Compilation error in resolved script \"compileTimeAssert\": [1, 1] Failed to reduce evaluation: Program failed an OP_VERIFY operation.".to_string()),
        None,
    );
}

// generateScenario: cash-channels-v1 - after_payment_time
#[test]
fn generate_scenario_cash_channels_v1_after_payment_time() {
    let template = match import_wallet_template(&cashChannelsJson) {
        Err(error) => panic!("{error}"),
        Ok(template) => template,
    };
    let compiler = wallet_template_to_compiler_bch(&template, None);
    let scenario = compiler.generate_scenario(None, Some("after_payment_time"), Some("execute_authorization"));
    assert_eq!(
        scenario,
        Ok(Scenario {
            data: CompilationData {
                bytecode: Some(BTreeMap::from([
                    ("authorized_amount".to_string(), hex_to_bin("e803")),
                    ("denominating_asset".to_string(), hex_to_bin("555344")),
                    ("maximum_authorized_satoshis".to_string(), hex_to_bin("0429")),
                    ("payment_number".to_string(), hex_to_bin("02")),
                    ("payment_satoshis".to_string(), hex_to_bin("1027")),
                    ("payment_time".to_string(), hex_to_bin("80bf345e")),
                ])),
                current_block_height: Some(2.0),
                current_block_time: Some(1231469665.0),
                hd_keys: Some(CompilationDataHdKeys {
                    address_index: Some(0.0),
                    hd_private_keys: None,
                    hd_public_keys: None,
                }),
                keys: Some(CompilationDataKeys {
                    private_keys: Some(BTreeMap::from([
                        (
                            "owner".to_string(),
                            hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001"),
                        ),
                        (
                            "rate_oracle".to_string(),
                            hex_to_bin("0000000000000000000000000000000000000000000000000000000000000003"),
                        ),
                        (
                            "receiver".to_string(),
                            hex_to_bin("0000000000000000000000000000000000000000000000000000000000000005"),
                        ),
                    ])),
                }),
                ..Default::default()
            },
            program: AuthenticationProgramCommon {
                input_index: 0,
                source_outputs: vec![Output {
                    locking_bytecode: hex_to_bin("a914582d988b353dbe4d34863606fc7fac13a026f30187"),
                    token: None,
                    value_satoshis: 20000,
                }],
                transaction: TransactionCommon {
                    inputs: vec![Input {
                        outpoint_index: 0,
                        outpoint_transaction_hash: hex_to_bin(
                            "0000000000000000000000000000000000000000000000000000000000000001",
                        ),
                        sequence_number: 0,
                        unlocking_bytecode: hex_to_bin(
                            "412f8a7bef0803cf707cd971e50c3d0ecd432f361d40b22dddb548972522c49cf7d4d55c8eea3ce2e69e6db08857ebd503fc0f0bfecc1ba2fc29fd48d51b5f5a9f414c6902000000d5a45bffe65ef500725b4bc16e60ba39910d364324f702be75ed825c1c78a50c8cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb9000000000000000000000000000000000000000000000000000000000000000100000000e24c4e210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817987c63766b56795f795779765c79a26958805779588057795880577958807e7e766b7e7e7e7cbbb16d6d5879020202004c92886c537958807e7c6c21022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4766b7ea9882102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9bb57795779815193528057797e7ea9011702a9147b01877e7e7e5579817b9458807c7e7c7eaa7c7e7e7e7e7e7e7ea86c7653797bad7b01407f757b7bba67ac6808204e00000000000004000000000880bf345e4100000000021027473045022100a42985db397f96f2dbec3846026c7e0d77a9de8e7a3239e6d241e1123e123e9602202bc889045417638a75ba423d567fa50a6f49ab9d23657dacdf09311db37b9be51477bf07ad61ce9c0ed3b026db9f6201a80a6afcec02042902e803035553440480bf345e473045022100f32fb0c45c9b0915455b6c8dbadb61f05f6b6e5cd74bce81e9fcadadbae466ba02207f7aa8052816478fc104d44b14161bbdc9011cadcc69b52f60337c0767e6622b514ce2210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817987c63766b56795f795779765c79a26958805779588057795880577958807e7e766b7e7e7e7cbbb16d6d5879020200886c537958807e7c6c21022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4766b7ea9882102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9bb57795779815193528057797e7ea9011702a9147b01877e7e7e5579817b9458807c7e7c7eaa7c7e7e7e7e7e7e7ea86c7653797bad7b01407f757b7bba67ac68",
                        ),
                    }],
                    locktime: 1580515200,
                    outputs: vec![Output {
                        locking_bytecode: hex_to_bin("a91456e3217f1b623d9d566ee2e648cf6c74ac6a9b1687"),
                        token: None,
                        value_satoshis: 10000,
                    }],
                    version: 2,
                },
            },
        }),
    );
}
