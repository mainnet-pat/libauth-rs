//! P2PKH derivation utilities.
//!
//! Port of libauth's `compiler/p2pkh-utils.ts`.

use std::collections::BTreeMap;

use crate::address::locking_bytecode_to_cash_address;
use crate::address::CashAddressResult;
use crate::language::stringify_errors;

use super::standard::{walletTemplateP2pkh, walletTemplateP2pkhNonHd};
use crate::compiler::wallet_template_to_compiler_bch;
use crate::compiler::{BytecodeGenerationResult, CompilationData, CompilationDataHdKeys, CompilationDataKeys};
use crate::engine::{WalletTemplate, WalletTemplateVariable};

/// The errors which may be returned by the P2PKH utilities.
pub struct P2pkhUtilityError;

#[allow(non_upper_case_globals)]
impl P2pkhUtilityError {
    pub const hdPrivateKeyToP2pkhLockingBytecodeCompilation: &'static str =
        "P2PKH utility error: could not derive P2PKH locking bytecode from the provided HD private key.";
    pub const hdPublicKeyToP2pkhLockingBytecodeCompilation: &'static str =
        "P2PKH utility error: could not derive P2PKH locking bytecode from the provided HD public key.";
    pub const privateKeyToP2pkhLockingBytecodeCompilation: &'static str =
        "P2PKH utility error: could not derive P2PKH locking bytecode from the provided private key.";
    pub const publicKeyToP2pkhLockingBytecodeCompilation: &'static str =
        "P2PKH utility error: could not derive P2PKH locking bytecode from the provided public key.";
}

/// Compile the `lock` script of `template` with the provided compilation data,
/// formatting any compilation errors as a P2PKH utility error.
fn compile_p2pkh_lock(template: &WalletTemplate, data: &CompilationData, error: &str) -> Result<Vec<u8>, String> {
    let compiler = wallet_template_to_compiler_bch(template, None);
    match compiler.generate_bytecode(data, "lock") {
        BytecodeGenerationResult::Success { bytecode } => Ok(bytecode),
        BytecodeGenerationResult::Error(result) => Err(crate::format::format_error(
            error,
            Some(&stringify_errors(&result.errors, None)),
        )),
    }
}

fn template_hd_key(template: &mut WalletTemplate) -> &mut crate::engine::WalletTemplateHdKey {
    let Some(WalletTemplateVariable::HdKey(key)) = template
        .entities
        .get_mut("owner")
        .and_then(|owner| owner.variables.as_mut())
        .and_then(|variables| variables.get_mut("key"))
    else {
        unreachable!("walletTemplateP2pkh includes the owner's HdKey");
    };
    key
}

/// Set the private derivation path of the template's `key` variable.
fn with_private_derivation_path(template: &mut WalletTemplate, path: &str) {
    template_hd_key(template).private_derivation_path = Some(path.to_string());
}

/// Set the HD public key paths of the template's `key` variable.
fn with_hd_public_key_derivation_paths(
    template: &mut WalletTemplate,
    hd_public_key_derivation_path: &str,
    public_derivation_path: &str,
) {
    let key = template_hd_key(template);
    key.public_derivation_path = Some(public_derivation_path.to_string());
    key.hd_public_key_derivation_path = Some(hd_public_key_derivation_path.to_string());
    key.private_derivation_path = Some(if hd_public_key_derivation_path.is_empty() {
        public_derivation_path.to_string()
    } else {
        format!("{hd_public_key_derivation_path}/{public_derivation_path}")
    });
}

/// Derive the P2PKH locking bytecode of the provided private key.
pub fn private_key_to_p2pkh_locking_bytecode(private_key: &[u8]) -> Result<Vec<u8>, String> {
    let data = CompilationData {
        keys: Some(CompilationDataKeys {
            private_keys: Some(BTreeMap::from([(
                "key".to_string(),
                private_key.to_vec(),
            )])),
        }),
        ..Default::default()
    };
    compile_p2pkh_lock(
        &walletTemplateP2pkhNonHd,
        &data,
        P2pkhUtilityError::privateKeyToP2pkhLockingBytecodeCompilation,
    )
}

/// Derive the P2PKH locking bytecode of the provided public key.
pub fn public_key_to_p2pkh_locking_bytecode(public_key: &[u8]) -> Result<Vec<u8>, String> {
    let data = CompilationData {
        bytecode: Some(BTreeMap::from([(
            "key.public_key".to_string(),
            public_key.to_vec(),
        )])),
        ..Default::default()
    };
    compile_p2pkh_lock(
        &walletTemplateP2pkhNonHd,
        &data,
        P2pkhUtilityError::publicKeyToP2pkhLockingBytecodeCompilation,
    )
}

/// Derive the P2PKH locking bytecode at the provided path and address index of
/// the provided HD private key.
///
/// Errors are returned as strings (libauth's `throwErrors: false` behavior);
/// address indexes are limited to the `u32` range.
pub fn hd_private_key_to_p2pkh_locking_bytecode(
    address_index: f64,
    hd_private_key: &str,
    private_derivation_path: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut template = walletTemplateP2pkh.clone();
    with_private_derivation_path(&mut template, private_derivation_path.unwrap_or("i"));
    let data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            address_index: Some(address_index),
            hd_private_keys: Some(BTreeMap::from([(
                "owner".to_string(),
                hd_private_key.to_string(),
            )])),
            ..Default::default()
        }),
        ..Default::default()
    };
    compile_p2pkh_lock(
        &template,
        &data,
        P2pkhUtilityError::hdPrivateKeyToP2pkhLockingBytecodeCompilation,
    )
}

/// Derive the P2PKH locking bytecode at the provided index of the provided HD
/// public key.
///
/// Errors are returned as strings (libauth's `throwErrors: false` behavior);
/// non-hardened address indexes are limited to the `u32` range.
pub fn hd_public_key_to_p2pkh_locking_bytecode(
    address_index: f64,
    hd_public_key: &str,
    hd_public_key_derivation_path: Option<&str>,
    public_derivation_path: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut template = walletTemplateP2pkh.clone();
    with_hd_public_key_derivation_paths(
        &mut template,
        hd_public_key_derivation_path.unwrap_or(""),
        public_derivation_path.unwrap_or("i"),
    );
    let data = CompilationData {
        hd_keys: Some(CompilationDataHdKeys {
            address_index: Some(address_index),
            hd_public_keys: Some(BTreeMap::from([(
                "owner".to_string(),
                hd_public_key.to_string(),
            )])),
            ..Default::default()
        }),
        ..Default::default()
    };
    compile_p2pkh_lock(
        &template,
        &data,
        P2pkhUtilityError::hdPublicKeyToP2pkhLockingBytecodeCompilation,
    )
}

fn locking_bytecode_to_address(
    bytecode: Result<Vec<u8>, String>,
    prefix: &str,
    token_support: bool,
) -> Result<CashAddressResult, String> {
    let bytecode = bytecode?;
    locking_bytecode_to_cash_address(Some(prefix), &bytecode, Some(token_support))
}

/// Derive the P2PKH address of the provided private key.
pub fn private_key_to_p2pkh_cash_address(
    private_key: &[u8],
    prefix: Option<&str>,
    token_support: Option<bool>,
) -> Result<CashAddressResult, String> {
    let prefix = prefix.unwrap_or("bitcoincash");
    let token_support = token_support.unwrap_or(false);
    locking_bytecode_to_address(
        private_key_to_p2pkh_locking_bytecode(private_key),
        prefix,
        token_support,
    )
}

/// Derive the P2PKH address of the provided public key.
pub fn public_key_to_p2pkh_cash_address(
    public_key: &[u8],
    prefix: Option<&str>,
    token_support: Option<bool>,
) -> Result<CashAddressResult, String> {
    let prefix = prefix.unwrap_or("bitcoincash");
    let token_support = token_support.unwrap_or(false);
    locking_bytecode_to_address(
        public_key_to_p2pkh_locking_bytecode(public_key),
        prefix,
        token_support,
    )
}

/// Derive the P2PKH address at the provided index of the provided HD private
/// key.
pub fn hd_private_key_to_p2pkh_cash_address(
    address_index: f64,
    hd_private_key: &str,
    prefix: Option<&str>,
    private_derivation_path: Option<&str>,
    token_support: Option<bool>,
) -> Result<CashAddressResult, String> {
    let prefix = prefix.unwrap_or("bitcoincash");
    let token_support = token_support.unwrap_or(false);
    locking_bytecode_to_address(
        hd_private_key_to_p2pkh_locking_bytecode(
            address_index,
            hd_private_key,
            private_derivation_path,
        ),
        prefix,
        token_support,
    )
}

/// Derive the P2PKH address at the provided index of the provided HD public
/// key.
pub fn hd_public_key_to_p2pkh_cash_address(
    address_index: f64,
    hd_public_key: &str,
    hd_public_key_derivation_path: Option<&str>,
    prefix: Option<&str>,
    public_derivation_path: Option<&str>,
    token_support: Option<bool>,
) -> Result<CashAddressResult, String> {
    let prefix = prefix.unwrap_or("bitcoincash");
    let token_support = token_support.unwrap_or(false);
    locking_bytecode_to_address(
        hd_public_key_to_p2pkh_locking_bytecode(
            address_index,
            hd_public_key,
            hd_public_key_derivation_path,
            public_derivation_path,
        ),
        prefix,
        token_support,
    )
}
