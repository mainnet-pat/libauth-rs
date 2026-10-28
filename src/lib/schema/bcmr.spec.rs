//! Port of `schema/bcmr.spec.ts`.

use libauth::runtime::json::{encode_json, parse_json, Json};
use libauth::{import_metadata_registry, sort_object_keys};

#[test]
fn import_metadata_registry_accepts_templates_as_either_json_strings_or_pre_parsed_objects() {
    // libauth's `MetadataRegistry` object literal, as JSON; imported
    // registries are compared as their JSON (ignoring key order, like AVA).
    let registry: Json = parse_json(
        r#"{"latestRevision":"","registryIdentity":{"name":""},"version":{"major":0,"minor":0,"patch":0}}"#,
    )
    .unwrap();
    let imported = |input: &Json| import_metadata_registry(input).map(|registry| sort_object_keys(&Json::from(&registry)));
    assert_eq!(Ok(sort_object_keys(&registry)), imported(&registry));
    assert_eq!(Ok(sort_object_keys(&registry)), imported(&Json::String(encode_json(&registry))));
}
