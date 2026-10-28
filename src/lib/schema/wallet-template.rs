use super::ajv::ajv_utils::ajv_standalone_json_parse;
use super::ajv::validate_wallet_template;
use crate::engine::WalletTemplate;
use crate::runtime::json::Json;

/// Parse and validate a {@link WalletTemplate}, returning either an error
/// message as a string or a valid {@link WalletTemplate}. The template may be
/// provided either as an untyped object or as a JSON string.
///
/// This method validates both the structure and the contents of a template:
/// - All properties and sub-properties are verified to be of the expected
///   type.
/// - The template contains no unknown properties.
/// - The ID of each variable, script, and entity is unique and valid
///   CashAssembly identifiers.
pub fn import_wallet_template(untrusted_json_or_object: &Json) -> Result<WalletTemplate, String> {
    let error_prefix = "Wallet template import failed:";
    ajv_standalone_json_parse(untrusted_json_or_object, &validate_wallet_template::default())
        .map_err(|error| format!("{error_prefix}{error}"))
}
