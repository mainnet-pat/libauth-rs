//! Port of `transaction/fixtures/template.2-of-2-recoverable.spec.helper.ts`.
#![allow(dead_code, non_upper_case_globals)]

use std::collections::BTreeMap;
use std::sync::LazyLock;

use libauth::{
    AuthenticationVirtualMachineIdentifier, CompilerDefaults, WalletTemplate, WalletTemplateEntity,
    WalletTemplateHdKey, WalletTemplateLockingType, WalletTemplateScenario, WalletTemplateScenarioData,
    WalletTemplateScenarioTransaction, WalletTemplateScriptDefinition, WalletTemplateScriptLocking,
    WalletTemplateScriptUnlocking, WalletTemplateTimeLockType, WalletTemplateVariable, WalletTemplateVariableType,
    WalletTemplateWalletData,
};

const secondsIn30Days: u64 = 2592000;

fn hd_key(name: &str) -> WalletTemplateVariable {
    WalletTemplateVariable::HdKey(WalletTemplateHdKey {
        address_offset: None,
        description: None,
        hd_public_key_derivation_path: None,
        name: Some(name.to_string()),
        never_sign_twice: None,
        private_derivation_path: None,
        public_derivation_path: None,
        r#type: WalletTemplateVariableType::HdKey,
    })
}

fn strings(values: &[&str]) -> Option<Vec<String>> {
    Some(values.iter().map(|value| value.to_string()).collect())
}

fn transaction(locktime: f64) -> WalletTemplateScenarioTransaction {
    WalletTemplateScenarioTransaction {
        inputs: None,
        locktime: Some(locktime),
        outputs: None,
        version: None,
    }
}

pub static twoOfTwoRecoverable: LazyLock<WalletTemplate> = LazyLock::new(|| {
    WalletTemplate {
    // libauth writes `...{ name: '2-of-2 Recoverable Vault' }` first, placing
    // `name` first in the generated JSON (see `generate-templates.spec.helper.rs`).
    name: Some("2-of-2 Recoverable Vault".to_string()),
    schema: Some("https://libauth.org/schemas/wallet-template-v0.schema.json".to_string()),
    description: Some("A 2-of-2 wallet, which after a specified delay, can be recovered by either of the original two keys and a signature from a trusted user (e.g. an attorney).\n\nIn this implementation, all wallet addresses become recoverable at the same time. To \"bump\" the recovery time to a later date, create a new wallet and transfer the funds.\n\nThis scheme is described in more detail in BIP-65.".to_string()),
    entities: BTreeMap::from([
        (
            "signer_1".to_string(),
            WalletTemplateEntity {
                description: Some("One of the two co-owners of this wallet. If Signer 1 is unable to sign, Signer 2 and Trusted Party can recover funds after the specified delay.".to_string()),
                name: Some("Signer 1".to_string()),
                scripts: strings(&["lock", "spend", "recover_1"]),
                variables: Some(BTreeMap::from([
                    (
                        "delay_seconds".to_string(),
                        WalletTemplateVariable::WalletData(WalletTemplateWalletData {
                            description: Some("The waiting period (from the time the wallet is created) after which the Trusted Party can assist with delayed recoveries. The delay is measured in seconds, e.g. 1 day is 86400, 30 days is 2592000.".to_string()),
                            name: Some("Recovery Delay (Seconds)".to_string()),
                            r#type: WalletTemplateVariableType::WalletData,
                        }),
                    ),
                    ("first".to_string(), hd_key("Signer 1's HdKey")),
                ])),
            },
        ),
        (
            "signer_2".to_string(),
            WalletTemplateEntity {
                description: Some("One of the two co-owners of this wallet. If Signer 2 is unable to sign, Signer 1 and Trusted Party can recover funds after the specified delay.".to_string()),
                name: Some("Signer 2".to_string()),
                scripts: strings(&["lock", "spend", "recover_2"]),
                variables: Some(BTreeMap::from([("second".to_string(), hd_key("Signer 2's HdKey"))])),
            },
        ),
        (
            "trusted_party".to_string(),
            WalletTemplateEntity {
                description: Some("A trusted party, like a lawyer or trusted employee. If either signer is unable to sign, after the specified delay, Trusted Party can help to recover funds by co-signing on that signer's behalf.".to_string()),
                name: Some("Trusted Party".to_string()),
                scripts: strings(&["lock", "recover_1", "recover_2"]),
                variables: Some(BTreeMap::from([("trusted".to_string(), hd_key("Trusted Party's HdKey"))])),
            },
        ),
    ]),
    scenarios: Some(BTreeMap::from([
        (
            "after_recovery_time".to_string(),
            WalletTemplateScenario {
                data: None,
                description: Some("An example of a time after the recovery delay has passed.".to_string()),
                extends: Some("before_recovery_time".to_string()),
                name: Some("After Recovery Time".to_string()),
                source_outputs: None,
                transaction: Some(transaction(CompilerDefaults::defaultScenarioCurrentBlockTime + secondsIn30Days as f64)),
            },
        ),
        (
            "before_recovery_time".to_string(),
            WalletTemplateScenario {
                data: Some(WalletTemplateScenarioData {
                    bytecode: Some(BTreeMap::from([("delay_seconds".to_string(), "2592000".to_string())])),
                    current_block_height: None,
                    current_block_time: None,
                    hd_keys: None,
                    keys: None,
                }),
                description: Some(
                    "An example of a time before a 30 day recovery delay (2592000 seconds) has passed.".to_string(),
                ),
                extends: None,
                name: Some("Before Recovery Time".to_string()),
                source_outputs: None,
                transaction: Some(transaction(CompilerDefaults::defaultScenarioCurrentBlockTime)),
            },
        ),
    ])),
    scripts: BTreeMap::from([
        (
            "lock".to_string(),
            WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                locking_type: WalletTemplateLockingType::P2sh20,
                name: Some("2-of-2 Recoverable Vault".to_string()),
                script: "OP_IF\n  <$(\n    <current_block_time> <delay_seconds>\n    OP_ADD\n  )>\n  OP_CHECKLOCKTIMEVERIFY OP_DROP\n  <trusted.public_key>\n  OP_CHECKSIGVERIFY\n  <1>\nOP_ELSE\n  <2>\nOP_ENDIF\n<first.public_key> <second.public_key> <2>\nOP_CHECKMULTISIG".to_string(),
            }),
        ),
        (
            "recover_1".to_string(),
            WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                age_lock: None,
                estimate: Some("after_recovery_time".to_string()),
                fails: strings(&["before_recovery_time"]),
                invalid: None,
                name: Some("Recover – Signer 1".to_string()),
                passes: strings(&["after_recovery_time"]),
                script: "<0>\n<first.ecdsa_signature.all_outputs>\n<trusted.ecdsa_signature.all_outputs>\n<1>".to_string(),
                time_lock_type: Some(WalletTemplateTimeLockType::Timestamp),
                unlocks: "lock".to_string(),
            }),
        ),
        (
            "recover_2".to_string(),
            WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                age_lock: None,
                estimate: Some("after_recovery_time".to_string()),
                fails: strings(&["before_recovery_time"]),
                invalid: None,
                name: Some("Recover – Signer 2".to_string()),
                passes: strings(&["after_recovery_time"]),
                script: "<0>\n<second.ecdsa_signature.all_outputs>\n<trusted.ecdsa_signature.all_outputs>\n<1>"
                    .to_string(),
                time_lock_type: Some(WalletTemplateTimeLockType::Timestamp),
                unlocks: "lock".to_string(),
            }),
        ),
        (
            "spend".to_string(),
            WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                age_lock: None,
                estimate: Some("before_recovery_time".to_string()),
                fails: None,
                invalid: None,
                name: Some("Standard Spend".to_string()),
                passes: strings(&["after_recovery_time", "before_recovery_time"]),
                script: "<0>\n<first.ecdsa_signature.all_outputs>\n<second.ecdsa_signature.all_outputs>\n<0>"
                    .to_string(),
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
