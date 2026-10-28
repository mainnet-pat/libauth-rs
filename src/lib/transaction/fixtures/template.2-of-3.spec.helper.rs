//! Port of `transaction/fixtures/template.2-of-3.spec.helper.ts`.
#![allow(dead_code, non_upper_case_globals)]

use std::collections::BTreeMap;
use std::sync::LazyLock;

use libauth::{
    AuthenticationVirtualMachineIdentifier, WalletTemplate, WalletTemplateEntity, WalletTemplateHdKey,
    WalletTemplateLockingType, WalletTemplateScriptDefinition, WalletTemplateScriptLocking,
    WalletTemplateScriptUnlocking, WalletTemplateVariable, WalletTemplateVariableType,
};

fn create_signer(name: &str, signer_index: &str, scripts: &[&str]) -> WalletTemplateEntity {
    WalletTemplateEntity {
        description: None,
        name: Some(name.to_string()),
        scripts: Some(
            ["lock"]
                .iter()
                .chain(scripts)
                .map(|script| script.to_string())
                .collect(),
        ),
        variables: Some(BTreeMap::from([(
            format!("key{signer_index}"),
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
    }
}

fn cosigner(name: &str, script: &str) -> WalletTemplateScriptDefinition {
    WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
        age_lock: None,
        estimate: None,
        fails: None,
        invalid: None,
        name: Some(name.to_string()),
        passes: None,
        script: script.to_string(),
        time_lock_type: None,
        unlocks: "lock".to_string(),
    })
}

/// 2-of-3 P2SH
/// This is a mostly-hard-coded 2-of-3 example. A more general function could be written to generate m-of-n wallets
pub static twoOfThree: LazyLock<WalletTemplate> = LazyLock::new(|| WalletTemplate {
    // libauth writes `...{ name: '2-of-3 Multisig' }` first, placing `name`
    // first in the generated JSON (see `generate-templates.spec.helper.rs`).
    name: Some("2-of-3 Multisig".to_string()),
    schema: Some("https://libauth.org/schemas/wallet-template-v0.schema.json".to_string()),
    description: None,
    entities: BTreeMap::from([
        (
            "signer_1".to_string(),
            create_signer("Signer 1", "1", &["1_and_2", "1_and_3"]),
        ),
        (
            "signer_2".to_string(),
            create_signer("Signer 2", "2", &["1_and_2", "2_and_3"]),
        ),
        (
            "signer_3".to_string(),
            create_signer("Signer 3", "3", &["1_and_3", "2_and_3"]),
        ),
    ]),
    scenarios: None,
    scripts: BTreeMap::from([
        (
            "1_and_2".to_string(),
            cosigner(
                "Cosigner 1 & 2",
                "OP_0\n<key1.ecdsa_signature.all_outputs>\n<key2.ecdsa_signature.all_outputs>",
            ),
        ),
        (
            "1_and_3".to_string(),
            cosigner(
                "Cosigner 1 & 3",
                "OP_0\n<key1.ecdsa_signature.all_outputs>\n<key3.ecdsa_signature.all_outputs>",
            ),
        ),
        (
            "2_and_3".to_string(),
            cosigner(
                "Cosigner 2 & 3",
                "OP_0\n<key2.ecdsa_signature.all_outputs>\n<key3.ecdsa_signature.all_outputs>",
            ),
        ),
        (
            "lock".to_string(),
            WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                locking_type: WalletTemplateLockingType::P2sh20,
                name: Some("2-of-3 Vault".to_string()),
                script: "OP_2\n<key1.public_key>\n<key2.public_key>\n<key3.public_key>\nOP_3\nOP_CHECKMULTISIG"
                    .to_string(),
            }),
        ),
    ]),
    supported: vec![
        AuthenticationVirtualMachineIdentifier::Bch2021_05,
        AuthenticationVirtualMachineIdentifier::Bch2022_05,
        AuthenticationVirtualMachineIdentifier::Bch2023_05,
        AuthenticationVirtualMachineIdentifier::Bch2024_05,
        AuthenticationVirtualMachineIdentifier::Bch2025_05,
        AuthenticationVirtualMachineIdentifier::Bch2026_05,
    ],
    version: None,
});
