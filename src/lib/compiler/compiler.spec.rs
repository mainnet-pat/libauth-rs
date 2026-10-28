//! Port of `compiler/compiler.spec.ts`.
#![allow(non_upper_case_globals)]

use std::collections::BTreeMap;

use libauth::{
    create_compiler_common, hex_to_bin, walletTemplateP2pkh, walletTemplateP2pkhNonHd,
    wallet_template_to_compiler_configuration, AuthenticationVirtualMachineIdentifier, BytecodeGenerationResult,
    CompilationData, CompilerConfiguration, WalletTemplate, WalletTemplateAddressData, WalletTemplateEntity,
    WalletTemplateHdKey, WalletTemplateKey, WalletTemplateLockingType, WalletTemplateScript,
    WalletTemplateScriptDefinition, WalletTemplateScriptTest, WalletTemplateScriptTested, WalletTemplateVariable,
    WalletTemplateVariableType,
};

/// `t.deepEqual` for compiler configurations: `CompilerConfiguration`
/// implements neither `PartialEq` nor `Debug` (it holds functions, crypto
/// instances, and a VM), so every data property is compared, and each
/// function/instance property is compared by presence.
fn assert_configuration_eq(actual: &CompilerConfiguration, expected: &CompilerConfiguration) {
    assert_eq!(actual.entity_ownership, expected.entity_ownership, "entityOwnership");
    assert_eq!(
        actual.locking_script_types, expected.locking_script_types,
        "lockingScriptTypes"
    );
    assert_eq!(actual.opcodes, expected.opcodes, "opcodes");
    assert_eq!(actual.scenarios, expected.scenarios, "scenarios");
    assert_eq!(actual.scripts, expected.scripts, "scripts");
    assert_eq!(actual.source_script_ids, expected.source_script_ids, "sourceScriptIds");
    assert_eq!(actual.unlocking_scripts, expected.unlocking_scripts, "unlockingScripts");
    assert_eq!(
        actual.unlocking_script_time_lock_types, expected.unlocking_script_time_lock_types,
        "unlockingScriptTimeLockTypes"
    );
    assert_eq!(actual.variables, expected.variables, "variables");
    assert_eq!(
        actual.create_authentication_program.is_some(),
        expected.create_authentication_program.is_some(),
        "createAuthenticationProgram"
    );
    assert_eq!(actual.operations.is_some(), expected.operations.is_some(), "operations");
    assert_eq!(actual.ripemd160.is_some(), expected.ripemd160.is_some(), "ripemd160");
    assert_eq!(actual.secp256k1.is_some(), expected.secp256k1.is_some(), "secp256k1");
    assert_eq!(actual.sha256.is_some(), expected.sha256.is_some(), "sha256");
    assert_eq!(actual.sha512.is_some(), expected.sha512.is_some(), "sha512");
    assert_eq!(actual.vm.is_some(), expected.vm.is_some(), "vm");
}

fn strings(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[test]
fn create_compiler_common_() {
    let compiler = create_compiler_common(CompilerConfiguration {
        scripts: strings(&[("lock", "OP_DUP OP_HASH160 <some_public_key> OP_EQUALVERIFY OP_CHECKSIG")]),
        variables: Some(BTreeMap::from([(
            "some_public_key".to_string(),
            WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                description: None,
                name: None,
                r#type: WalletTemplateVariableType::AddressData,
            }),
        )])),
        ..Default::default()
    });
    let result_lock = compiler.generate_bytecode(
        &CompilationData {
            bytecode: Some(BTreeMap::from([(
                "some_public_key".to_string(),
                hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d"),
            )])),
            ..Default::default()
        },
        "lock",
    );
    assert_eq!(
        format!("{result_lock:?}"),
        format!(
            "{:?}",
            BytecodeGenerationResult::Success {
                bytecode: hex_to_bin("76a91415d16c84669ab46059313bf0747e781f1d13936d88ac"),
            }
        )
    );
}

#[test]
fn wallet_template_to_compiler_configuration_wallet_template_p2pkh_non_hd() {
    let configuration = wallet_template_to_compiler_configuration(&walletTemplateP2pkhNonHd);
    assert_configuration_eq(
        &configuration,
        &CompilerConfiguration {
            entity_ownership: Some(strings(&[("key", "owner")])),
            locking_script_types: Some(BTreeMap::from([(
                "lock".to_string(),
                WalletTemplateLockingType::Standard,
            )])),
            scripts: strings(&[
                (
                    "lock",
                    "OP_DUP\nOP_HASH160 <$(<key.public_key> OP_HASH160\n)> OP_EQUALVERIFY\nOP_CHECKSIG",
                ),
                ("unlock", "<key.schnorr_signature.all_outputs>\n<key.public_key>"),
            ]),
            unlocking_script_time_lock_types: Some(BTreeMap::new()),
            unlocking_scripts: Some(strings(&[("unlock", "lock")])),
            variables: Some(BTreeMap::from([(
                "key".to_string(),
                WalletTemplateVariable::Key(WalletTemplateKey {
                    description: Some("The private key that controls this wallet.".to_string()),
                    name: Some("Key".to_string()),
                    never_sign_twice: None,
                    r#type: WalletTemplateVariableType::Key,
                }),
            )])),
            ..Default::default()
        },
    );
}

#[test]
fn wallet_template_to_compiler_configuration_wallet_template_p2pkh() {
    let configuration = wallet_template_to_compiler_configuration(&walletTemplateP2pkh);
    assert_configuration_eq(
        &configuration,
        &CompilerConfiguration {
            entity_ownership: Some(strings(&[("key", "owner")])),
            locking_script_types: Some(BTreeMap::from([(
                "lock".to_string(),
                WalletTemplateLockingType::Standard,
            )])),
            scripts: strings(&[
                (
                    "lock",
                    "OP_DUP\nOP_HASH160 <$(<key.public_key> OP_HASH160\n)> OP_EQUALVERIFY\nOP_CHECKSIG",
                ),
                ("unlock", "<key.schnorr_signature.all_outputs>\n<key.public_key>"),
            ]),
            unlocking_script_time_lock_types: Some(BTreeMap::new()),
            unlocking_scripts: Some(strings(&[("unlock", "lock")])),
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
        },
    );
}

fn script_test(check: &str, setup: Option<&str>) -> WalletTemplateScriptTest {
    WalletTemplateScriptTest {
        check: check.to_string(),
        fails: None,
        invalid: None,
        name: None,
        passes: None,
        setup: setup.map(str::to_string),
    }
}

#[test]
fn wallet_template_to_compiler_configuration_virtualized_tests() {
    // libauth's template (cast `as WalletTemplate`) uses arrays for `tests`;
    // `Object.entries` of an array yields its indexes ("0", "1", ...) as keys.
    let configuration = wallet_template_to_compiler_configuration(&WalletTemplate {
        description: None,
        entities: BTreeMap::from([(
            "empty".to_string(),
            WalletTemplateEntity {
                description: None,
                name: None,
                scripts: None,
                variables: None,
            },
        )]),
        name: None,
        scenarios: None,
        schema: None,
        scripts: BTreeMap::from([
            (
                "add_two".to_string(),
                WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                    name: None,
                    pushed: None,
                    script: "<2> OP_ADD".to_string(),
                    tests: BTreeMap::from([
                        ("0".to_string(), script_test("<3> OP_EQUAL", Some("<1>"))),
                        ("1".to_string(), script_test("<4> OP_EQUAL", Some("<2>"))),
                    ]),
                }),
            ),
            (
                "message".to_string(),
                WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                    name: None,
                    pushed: Some(true),
                    script: "\"abc\"".to_string(),
                    tests: BTreeMap::from([("0".to_string(), script_test("<\"abc\"> OP_EQUAL", None))]),
                }),
            ),
            (
                "push_three".to_string(),
                WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                    name: None,
                    pushed: None,
                    script: "<3>".to_string(),
                    tests: BTreeMap::from([("0".to_string(), script_test("<3> OP_EQUAL", None))]),
                }),
            ),
            (
                "unrelated".to_string(),
                WalletTemplateScriptDefinition::Script(WalletTemplateScript {
                    name: None,
                    script: "<1>".to_string(),
                }),
            ),
        ]),
        supported: vec![AuthenticationVirtualMachineIdentifier::Bch2022_05],
        version: Some(0),
    });

    assert_configuration_eq(
        &configuration,
        &CompilerConfiguration {
            entity_ownership: Some(BTreeMap::new()),
            locking_script_types: Some(BTreeMap::from([
                ("add_two.0.lock".to_string(), WalletTemplateLockingType::P2sh20),
                ("add_two.1.lock".to_string(), WalletTemplateLockingType::P2sh20),
                ("message.0.lock".to_string(), WalletTemplateLockingType::P2sh20),
                ("push_three.0.lock".to_string(), WalletTemplateLockingType::P2sh20),
            ])),
            scripts: strings(&[
                ("add_two", "<2> OP_ADD"),
                ("add_two.0.check", "<3> OP_EQUAL"),
                ("add_two.0.lock", "add_two add_two.0.check"),
                ("add_two.0.unlock", "<1>"),
                ("add_two.1.check", "<4> OP_EQUAL"),
                ("add_two.1.lock", "add_two add_two.1.check"),
                ("add_two.1.unlock", "<2>"),
                ("message", "\"abc\""),
                ("message.0.check", "<\"abc\"> OP_EQUAL"),
                ("message.0.lock", "<message> message.0.check"),
                ("message.0.unlock", ""),
                ("push_three", "<3>"),
                ("push_three.0.check", "<3> OP_EQUAL"),
                ("push_three.0.lock", "push_three push_three.0.check"),
                ("push_three.0.unlock", ""),
                ("unrelated", "<1>"),
            ]),
            unlocking_script_time_lock_types: Some(BTreeMap::new()),
            unlocking_scripts: Some(strings(&[
                ("add_two.0.unlock", "add_two.0.lock"),
                ("add_two.1.unlock", "add_two.1.lock"),
                ("message.0.unlock", "message.0.lock"),
                ("push_three.0.unlock", "push_three.0.lock"),
            ])),
            variables: Some(BTreeMap::new()),
            ..Default::default()
        },
    );
}
