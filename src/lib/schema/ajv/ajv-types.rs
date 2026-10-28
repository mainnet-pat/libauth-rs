use std::collections::BTreeMap;

use crate::runtime::json::Json;

/// An Ajv validation error (`AjvError` in libauth's `schema/ajv`).
#[derive(Clone, Debug, PartialEq)]
pub struct AjvError {
    pub keyword: String,
    pub instance_path: String,
    pub schema_path: String,
    /// The error's parameters, e.g. `{ missingProperty: 'script' }` (values
    /// are JSON: `enum` errors list their `allowedValues`, `type` errors of
    /// union types list the `type`s).
    pub params: BTreeMap<String, Json>,
    pub message: String,
}

/// The Ajv errors produced by libauth's validators (`LibauthAjvError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LibauthAjvError {
    AdditionalProperties { additional_property: String },
    Required { missing_property: String },
    Type { r#type: String },
}

impl LibauthAjvError {
    /// The Ajv error message for this error.
    pub fn message(&self) -> String {
        match self {
            Self::AdditionalProperties { .. } => "must NOT have additional properties".to_string(),
            Self::Required { missing_property } => {
                format!("must have required property '{missing_property}'")
            }
            Self::Type { r#type } => format!("must be {type}"),
        }
    }
}

/// The value of a validator's `errors` property: `undefined` until the
/// validator is first called, `null` after a successful validation, and the
/// errors of the most recent validation otherwise.
#[derive(Clone, Debug, PartialEq)]
pub enum AjvValidatorErrors {
    Undefined,
    Null,
    Errors(Vec<AjvError>),
}

/// A JSON validator (libauth's `AjvValidator`: a type predicate whose
/// `errors` property describes the most recent failure).
pub trait AjvValidator {
    /// Validate `data` (the type predicate), setting the validator's `errors`.
    fn validate(&self, data: &Json) -> bool;

    /// The validator's `errors` property.
    fn errors(&self) -> AjvValidatorErrors;
}
