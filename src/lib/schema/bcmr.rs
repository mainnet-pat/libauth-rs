use super::ajv::ajv_utils::ajv_standalone_json_parse;
use super::ajv::validate_bcmr;
use crate::engine::MetadataRegistry;
use crate::runtime::json::Json;

/// Safely parse and validate a Bitcoin Cash Metadata Registry (BCMR).
///
/// This method validates both JSON strings and already-parsed objects. The
/// result is either the validated registry or an error message.
///
/// Note: as in libauth, a registry which fails validation is described using
/// the errors of the most recent wallet template validation (see
/// [`ajv_standalone_json_parse`]).
pub fn import_metadata_registry(untrusted_json_or_object: &Json) -> Result<MetadataRegistry, String> {
    let error_prefix = "Metadata Registry import failed:";
    ajv_standalone_json_parse(untrusted_json_or_object, &validate_bcmr::default())
        .map_err(|error| format!("{error_prefix}{error}"))
}
