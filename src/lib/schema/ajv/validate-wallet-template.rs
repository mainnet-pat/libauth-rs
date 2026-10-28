use std::sync::LazyLock;

use super::ajv_utils::SchemaValidator;

/// The validator for libauth's wallet template JSON schema
/// (`wallet-template.schema.json`).
static VALIDATOR: LazyLock<SchemaValidator> =
    LazyLock::new(|| SchemaValidator::new(include_str!("../wallet-template.schema.json")));

/// The default export of the standalone AJV validator module: the validator
/// for libauth's wallet template JSON schema. Like the module's single
/// validation function, it is process-wide: every returned handle shares its
/// `errors` property.
pub fn default() -> SchemaValidator {
    VALIDATOR.clone()
}
