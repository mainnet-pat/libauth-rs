use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{
    AuthenticationVirtualMachineIdentifier, WalletTemplate, WalletTemplateEntity, WalletTemplateHdKey,
    WalletTemplateKey, WalletTemplateLockingType, WalletTemplateScriptDefinition,
    WalletTemplateScriptLocking, WalletTemplateScriptUnlocking, WalletTemplateVariable,
    WalletTemplateVariableType,
};

const SUPPORTED: [AuthenticationVirtualMachineIdentifier; 8] = [
    AuthenticationVirtualMachineIdentifier::Bch2020_05,
    AuthenticationVirtualMachineIdentifier::Bch2021_05,
    AuthenticationVirtualMachineIdentifier::Bch2022_05,
    AuthenticationVirtualMachineIdentifier::Bch2023_05,
    AuthenticationVirtualMachineIdentifier::Bch2024_05,
    AuthenticationVirtualMachineIdentifier::Bch2025_05,
    AuthenticationVirtualMachineIdentifier::Bch2026_05,
    AuthenticationVirtualMachineIdentifier::BchSpec,
];

fn p2pkh_template(description: &str, key: WalletTemplateVariable) -> WalletTemplate {
    WalletTemplate {
        schema: Some("https://libauth.org/schemas/wallet-template-v0.schema.json".to_string()),
        description: Some(description.to_string()),
        entities: BTreeMap::from([(
            "owner".to_string(),
            WalletTemplateEntity {
                description: Some("The individual who can spend from this wallet.".to_string()),
                name: Some("Owner".to_string()),
                scripts: Some(vec!["lock".to_string(), "unlock".to_string()]),
                variables: Some(BTreeMap::from([("key".to_string(), key)])),
            },
        )]),
        name: Some("Single Signature (P2PKH)".to_string()),
        scenarios: None,
        scripts: BTreeMap::from([
            (
                "lock".to_string(),
                WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                    locking_type: WalletTemplateLockingType::Standard,
                    name: Some("P2PKH Lock".to_string()),
                    script: "OP_DUP\nOP_HASH160 <$(<key.public_key> OP_HASH160\n)> OP_EQUALVERIFY\nOP_CHECKSIG"
                        .to_string(),
                }),
            ),
            (
                "unlock".to_string(),
                WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                    age_lock: None,
                    estimate: None,
                    fails: None,
                    invalid: None,
                    name: Some("Unlock".to_string()),
                    passes: None,
                    script: "<key.schnorr_signature.all_outputs>\n<key.public_key>".to_string(),
                    time_lock_type: None,
                    unlocks: "lock".to_string(),
                }),
            ),
        ]),
        supported: SUPPORTED.to_vec(),
        version: None,
    }
}

/// A standard single-factor wallet template that uses Pay-to-Public-Key-Hash
/// (P2PKH), the most common authentication scheme in use on the network.
///
/// This P2PKH template uses BCH Schnorr signatures, reducing the size of
/// transactions.
///
/// Note, this wallet template uses only a single `Key`. For HD key support, see
/// {@link walletTemplateP2pkh}.
pub static walletTemplateP2pkhNonHd: LazyLock<WalletTemplate> = LazyLock::new(|| {
    p2pkh_template(
        "A standard single-factor wallet template that uses Pay-to-Public-Key-Hash (P2PKH), the most common authentication scheme in use on the network.\n\nThis P2PKH template uses BCH Schnorr signatures, reducing the size of transactions.",
        WalletTemplateVariable::Key(WalletTemplateKey {
            description: Some("The private key that controls this wallet.".to_string()),
            name: Some("Key".to_string()),
            never_sign_twice: None,
            r#type: WalletTemplateVariableType::Key,
        }),
    )
});

/// A standard single-factor wallet template that uses
/// Pay-to-Public-Key-Hash (P2PKH), the most common authentication scheme in use
/// on the network.
///
/// This P2PKH template uses BCH Schnorr signatures, reducing the size of
/// transactions.
///
/// Because the template uses a Hierarchical Deterministic (HD) key, it also
/// supports watch-only clients.
pub static walletTemplateP2pkh: LazyLock<WalletTemplate> = LazyLock::new(|| {
    p2pkh_template(
        "A standard single-factor wallet template that uses Pay-to-Public-Key-Hash (P2PKH), the most common authentication scheme in use on the network.\n\nThis P2PKH template uses BCH Schnorr signatures, reducing the size of transactions. Because the template uses a Hierarchical Deterministic (HD) key, it also supports watch-only clients.",
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
    )
});

