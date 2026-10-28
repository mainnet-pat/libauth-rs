//! Port of `transaction/fixtures/template.sig-of-sig.spec.helper.ts`.
#![allow(dead_code, non_upper_case_globals)]

use std::collections::BTreeMap;
use std::sync::LazyLock;

use libauth::{
    AuthenticationVirtualMachineIdentifier, WalletTemplate, WalletTemplateEntity, WalletTemplateHdKey,
    WalletTemplateLockingType, WalletTemplateScript, WalletTemplateScriptDefinition, WalletTemplateScriptLocking,
    WalletTemplateScriptUnlocking, WalletTemplateVariable, WalletTemplateVariableType,
};

fn hd_key() -> WalletTemplateVariable {
    WalletTemplateVariable::HdKey(WalletTemplateHdKey {
        address_offset: None,
        description: None,
        hd_public_key_derivation_path: None,
        name: None,
        never_sign_twice: None,
        private_derivation_path: None,
        public_derivation_path: None,
        r#type: WalletTemplateVariableType::HdKey,
    })
}

pub static sigOfSig: LazyLock<WalletTemplate> = LazyLock::new(|| {
    WalletTemplate {
    // libauth writes `...{ name: 'Sig-of-Sig Vault (2-of-2)' }` first, placing
    // `name` first in the generated JSON (see `generate-templates.spec.helper.rs`).
    name: Some("Sig-of-Sig Vault (2-of-2)".to_string()),
    schema: None,
    description: Some("An unusual example of a template that must be signed in a specific order: Second Signer may only sign after First Signer. This construction could be useful in scenarios where a particular signing order must be guaranteed, e.g. proving that a \"most-responsible\" party only signed for a transaction knowing they were the final signer.".to_string()),
    entities: BTreeMap::from([
        (
            "signer_1".to_string(),
            WalletTemplateEntity {
                description: None,
                name: Some("First Signer".to_string()),
                scripts: None,
                variables: Some(BTreeMap::from([("first".to_string(), hd_key())])),
            },
        ),
        (
            "signer_2".to_string(),
            WalletTemplateEntity {
                description: None,
                name: Some("Second Signer".to_string()),
                scripts: None,
                variables: Some(BTreeMap::from([("second".to_string(), hd_key())])),
            },
        ),
    ]),
    scenarios: None,
    scripts: BTreeMap::from([
        (
            "first_signature".to_string(),
            WalletTemplateScriptDefinition::Script(WalletTemplateScript {
                name: None,
                script: "first.ecdsa_signature.all_outputs".to_string(),
            }),
        ),
        (
            "lock".to_string(),
            WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                locking_type: WalletTemplateLockingType::P2sh20,
                name: Some("Sig-of-Sig Vault".to_string()),
                script: "OP_2 OP_PICK <second.public_key> OP_CHECKDATASIGVERIFY OP_DUP OP_HASH160 <$(<first.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG".to_string(),
            }),
        ),
        (
            "spend".to_string(),
            WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                age_lock: None,
                estimate: None,
                fails: None,
                invalid: None,
                name: None,
                passes: None,
                script: "<first.ecdsa_signature.all_outputs> <first.public_key> <second.ecdsa_data_signature.first_signature>".to_string(),
                time_lock_type: None,
                unlocks: "lock".to_string(),
            }),
        ),
    ]),
    supported: vec![
        AuthenticationVirtualMachineIdentifier::Bch2021_05,
        AuthenticationVirtualMachineIdentifier::Bch2022_05,
    ],
    version: None,
}
});
