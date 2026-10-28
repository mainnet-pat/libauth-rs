use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use super::ajv_types::{AjvError, AjvValidator, AjvValidatorErrors};
use super::validate_wallet_template;
use crate::format::lossy_normalize;
use crate::runtime::json::{dispose_json, encode_json, parse_json, Json};
use crate::runtime::number::number_to_string;

// JavaScript semantics of parsed JSON.
//
// libauth validates the JavaScript value `JSON.parse` returns. A `Json` value
// keeps what the source text says, so these helpers give it the semantics of
// that JavaScript value.

/// The JavaScript number a JSON number denotes (`1e400` is `Infinity`).
fn js_number(text: &str) -> f64 {
    text.parse().unwrap_or(f64::NAN)
}

/// Whether `key` is an array index (`0` to `2 ** 32 - 2` in canonical form):
/// JavaScript objects list such keys first.
fn is_array_index(key: &str) -> bool {
    key == "0"
        || (!key.starts_with('0')
            && (1..=10).contains(&key.len())
            && key.bytes().all(|byte| byte.is_ascii_digit())
            && key.parse::<u64>().is_ok_and(|index| index < 4_294_967_295))
}

/// The properties of the JavaScript object created from a JSON object, in
/// property order (the order of `for...in` and `Object.keys`): array index
/// keys in ascending order, then other keys in creation order. A repeated key
/// keeps the position of its first occurrence and the value of its last.
fn js_properties(entries: &[(String, Json)]) -> Vec<(&str, &Json)> {
    let mut properties: Vec<(&str, &Json)> = Vec::with_capacity(entries.len());
    let mut positions: HashMap<&str, usize> = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        match positions.get(key.as_str()) {
            Some(&position) => properties[position].1 = value,
            None => {
                positions.insert(key, properties.len());
                properties.push((key, value));
            }
        }
    }
    let (mut indexed, named): (Vec<_>, Vec<_>) =
        properties.into_iter().partition(|(key, _)| is_array_index(key));
    indexed.sort_by_key(|(key, _)| key.parse::<u64>().unwrap_or(0));
    indexed.extend(named);
    indexed
}

/// `object[key]` for the JavaScript object created from a JSON object (only
/// own properties: schema property names may not name `Object.prototype`
/// members, see [`OBJECT_PROTOTYPE_PROPERTIES`]).
fn js_get<'a>(entries: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    entries
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// The JavaScript value `JSON.parse` returns for `value`, as JSON: object
/// properties in JavaScript property order (without repeated keys), numbers
/// in their JavaScript form (`1.0` is `1`).
fn js_value(value: &Json) -> Json {
    match value {
        Json::Number(text) => Json::Number(number_to_string(js_number(text))),
        Json::Array(items) => Json::Array(items.iter().map(js_value).collect()),
        Json::Object(entries) => Json::Object(
            js_properties(entries)
                .into_iter()
                .map(|(key, value)| (key.to_string(), js_value(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `JSON.stringify` of the JavaScript value `value` represents (object
/// properties in JavaScript property order, numbers in their JavaScript form,
/// non-finite numbers as `null`). Iterative, so any nesting depth works.
fn json_stringify(value: &Json) -> String {
    enum Part<'a> {
        Value(&'a Json),
        Key(&'a str),
        Text(&'static str),
    }
    let mut result = String::new();
    let mut pending = vec![Part::Value(value)];
    while let Some(part) = pending.pop() {
        match part {
            Part::Text(text) => result.push_str(text),
            Part::Key(key) => {
                result.push_str(&encode_json(&Json::String(key.to_string())));
                result.push(':');
            }
            Part::Value(Json::Number(text)) => {
                let number = js_number(text);
                result.push_str(&if number.is_finite() {
                    number_to_string(number)
                } else {
                    "null".to_string()
                });
            }
            Part::Value(Json::Array(items)) => {
                result.push('[');
                pending.push(Part::Text("]"));
                for (index, item) in items.iter().enumerate().rev() {
                    pending.push(Part::Value(item));
                    if index > 0 {
                        pending.push(Part::Text(","));
                    }
                }
            }
            Part::Value(Json::Object(entries)) => {
                result.push('{');
                pending.push(Part::Text("}"));
                for (index, (key, item)) in js_properties(entries).into_iter().enumerate().rev() {
                    pending.push(Part::Value(item));
                    pending.push(Part::Key(key));
                    if index > 0 {
                        pending.push(Part::Text(","));
                    }
                }
            }
            Part::Value(other) => result.push_str(&encode_json(other)),
        }
    }
    result
}

/// Strict equality (`===`) of JavaScript values, with the deep equality Ajv
/// uses (`fast-deep-equal`) for arrays and objects.
fn js_equal(left: &Json, right: &Json) -> bool {
    match (left, right) {
        (Json::Number(left), Json::Number(right)) => js_number(left) == js_number(right),
        (Json::Array(left), Json::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(left, right)| js_equal(left, right))
        }
        (Json::Object(left), Json::Object(right)) => {
            let (left, right) = (js_properties(left), js_properties(right));
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .iter()
                        .any(|(other_key, other_value)| key == other_key && js_equal(value, other_value))
                })
        }
        _ => left == right,
    }
}

/// JSON pointer escaping (`~` as `~0`, `/` as `~1`).
fn escape_json_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// `encodeURIComponent` of an escaped JSON pointer segment (Ajv's
/// `escapeFragment`, used in schema paths).
fn escape_fragment(segment: &str) -> String {
    let mut result = String::new();
    for byte in escape_json_pointer(segment).bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            result.push(char::from(byte));
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

/// Decode `%XX` escapes (in `$ref` fragments).
fn decode_uri_component(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = (bytes[index] == b'%')
            .then(|| text.get(index + 1..index + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
            }
            None => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

// The compiled schema.

/// The JSON types of the `type` keyword.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataType {
    Null,
    Boolean,
    Object,
    Array,
    Number,
    Integer,
    String,
}

impl DataType {
    fn parse(name: &str) -> Self {
        match name {
            "null" => Self::Null,
            "boolean" => Self::Boolean,
            "object" => Self::Object,
            "array" => Self::Array,
            "number" => Self::Number,
            "integer" => Self::Integer,
            "string" => Self::String,
            other => panic!("unknown JSON schema type: {other}"),
        }
    }

    /// Ajv's data type check (with its default `strictNumbers`, so numbers
    /// must be finite).
    fn matches(self, data: &Json) -> bool {
        match (self, data) {
            (Self::Null, Json::Null)
            | (Self::Boolean, Json::Bool(_))
            | (Self::Object, Json::Object(_))
            | (Self::Array, Json::Array(_))
            | (Self::String, Json::String(_)) => true,
            (Self::Number, Json::Number(text)) => js_number(text).is_finite(),
            (Self::Integer, Json::Number(text)) => {
                let number = js_number(text);
                number.is_finite() && number.fract() == 0.0
            }
            _ => false,
        }
    }

    /// The keyword group applying to data of this type (none for `integer`,
    /// `boolean`, and `null`).
    fn group(self) -> Option<Group> {
        match self {
            Self::Number => Some(Group::Number),
            Self::String => Some(Group::String),
            Self::Array => Some(Group::Array),
            Self::Object => Some(Group::Object),
            Self::Null | Self::Boolean | Self::Integer => None,
        }
    }
}

/// Ajv's keyword groups (`RULES.rules`), in evaluation order: keywords for any
/// type, then those for numbers, strings, arrays, and objects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Any,
    Number,
    String,
    Array,
    Object,
}

impl Group {
    const ALL: [Group; 5] = [Group::Any, Group::Number, Group::String, Group::Array, Group::Object];

    fn data_type(self) -> Option<DataType> {
        match self {
            Self::Any => None,
            Self::Number => Some(DataType::Number),
            Self::String => Some(DataType::String),
            Self::Array => Some(DataType::Array),
            Self::Object => Some(DataType::Object),
        }
    }
}

/// The supported keywords with validation code, by group, in Ajv's order.
#[derive(Clone, Copy)]
enum Keyword {
    Ref,
    Const,
    Enum,
    AnyOf,
    MaxItems,
    MinItems,
    Items,
    Required,
    AdditionalProperties,
    Properties,
}

impl Keyword {
    fn of_group(group: Group) -> &'static [Keyword] {
        match group {
            Group::Any => &[Keyword::Ref, Keyword::Const, Keyword::Enum, Keyword::AnyOf],
            Group::Array => &[Keyword::MaxItems, Keyword::MinItems, Keyword::Items],
            Group::Object => &[Keyword::Required, Keyword::AdditionalProperties, Keyword::Properties],
            Group::Number | Group::String => &[],
        }
    }
}

/// Keywords without validation code.
const ANNOTATION_KEYWORDS: [&str; 13] = [
    "$schema",
    "$comment",
    "$defs",
    "definitions",
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    "contentMediaType",
    "contentEncoding",
];

/// The properties of `Object.prototype` (which `object[key]` would find on any
/// object): unsupported as schema property names.
const OBJECT_PROTOTYPE_PROPERTIES: [&str; 12] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

enum Schema {
    Boolean(bool),
    Object(Box<SchemaObject>),
}

#[derive(Default)]
struct SchemaObject {
    reference: Option<Reference>,
    /// The `type` keyword's value and types.
    type_value: Option<Json>,
    types: Vec<DataType>,
    constant: Option<Json>,
    enumeration: Option<Json>,
    any_of: Option<Vec<Schema>>,
    max_items: Option<Json>,
    min_items: Option<Json>,
    items: Option<Schema>,
    required: Option<Vec<String>>,
    additional_properties: Option<Schema>,
    /// `properties`, in JavaScript property order.
    properties: Option<Vec<(String, Schema)>>,
}

impl SchemaObject {
    /// Whether the schema has any keyword with validation code other than
    /// `$ref` (Ajv's `schemaHasRulesButRef`; `type` counts).
    fn has_rules_but_ref(&self) -> bool {
        self.type_value.is_some()
            || self.constant.is_some()
            || self.enumeration.is_some()
            || self.any_of.is_some()
            || self.max_items.is_some()
            || self.min_items.is_some()
            || self.items.is_some()
            || self.required.is_some()
            || self.additional_properties.is_some()
            || self.properties.is_some()
    }

    /// Whether the schema has keywords of the group (Ajv's `shouldUseGroup`;
    /// `type` counts for the group of keywords for any type).
    fn uses_group(&self, group: Group) -> bool {
        match group {
            Group::Any => {
                self.reference.is_some()
                    || self.type_value.is_some()
                    || self.constant.is_some()
                    || self.enumeration.is_some()
                    || self.any_of.is_some()
            }
            Group::Array => self.max_items.is_some() || self.min_items.is_some() || self.items.is_some(),
            Group::Object => {
                self.required.is_some() || self.additional_properties.is_some() || self.properties.is_some()
            }
            Group::Number | Group::String => false,
        }
    }
}

impl Schema {
    /// Ajv's `alwaysValidSchema`.
    fn always_valid(&self) -> bool {
        match self {
            Schema::Boolean(value) => *value,
            Schema::Object(object) => object.reference.is_none() && !object.has_rules_but_ref(),
        }
    }
}

/// A `$ref` and the index of its target in [`SchemaDocument::targets`].
struct Reference {
    pointer: String,
    target: usize,
}

/// A `$ref` target: Ajv inlines a referenced schema which contains no `$ref`
/// itself, and compiles any other as a separate validation function.
struct Target {
    schema: Schema,
    inline: bool,
}

/// A JSON schema document, compiled for evaluation.
struct SchemaDocument {
    root: Schema,
    targets: Vec<Target>,
}

struct Compiler<'a> {
    document: &'a Json,
    pointers: HashMap<String, usize>,
    targets: Vec<Option<Target>>,
}

impl<'a> Compiler<'a> {
    fn compile(&mut self, schema: &'a Json) -> Schema {
        match schema {
            Json::Bool(value) => Schema::Boolean(*value),
            Json::Object(entries) => Schema::Object(Box::new(self.compile_object(entries))),
            other => panic!("invalid JSON schema: {other}"),
        }
    }

    fn compile_object(&mut self, entries: &'a [(String, Json)]) -> SchemaObject {
        let mut object = SchemaObject::default();
        let property_name = |name: &str| {
            assert!(
                !OBJECT_PROTOTYPE_PROPERTIES.contains(&name),
                "unsupported JSON schema property name: {name}"
            );
            name.to_string()
        };
        for (keyword, value) in js_properties(entries) {
            match keyword {
                "$ref" => {
                    object.reference = Some(self.reference(value.as_str().expect("a $ref string")));
                }
                "type" => {
                    object.types = match value {
                        Json::String(name) => vec![DataType::parse(name)],
                        Json::Array(names) => names
                            .iter()
                            .map(|name| DataType::parse(name.as_str().expect("a type name")))
                            .collect(),
                        other => panic!("invalid type: {other}"),
                    };
                    object.type_value = Some(value.clone());
                }
                "const" => object.constant = Some(value.clone()),
                "enum" => {
                    assert!(
                        value.as_array().is_some_and(|values| !values.is_empty()),
                        "enum must have non-empty array"
                    );
                    object.enumeration = Some(value.clone());
                }
                "anyOf" => {
                    let schemas = value.as_array().expect("an anyOf array");
                    object.any_of = Some(schemas.iter().map(|schema| self.compile(schema)).collect());
                }
                "maxItems" | "minItems" => {
                    assert!(matches!(value, Json::Number(_)), "{keyword} must be a number");
                    if keyword == "maxItems" {
                        object.max_items = Some(value.clone());
                    } else {
                        object.min_items = Some(value.clone());
                    }
                }
                "items" => {
                    assert!(!matches!(value, Json::Array(_)), "unsupported JSON schema: tuple items");
                    object.items = Some(self.compile(value));
                }
                "required" => {
                    let names = value.as_array().expect("an array of property names");
                    object.required = Some(
                        names
                            .iter()
                            .map(|name| property_name(name.as_str().expect("a property name")))
                            .collect(),
                    );
                }
                "additionalProperties" => object.additional_properties = Some(self.compile(value)),
                "properties" => {
                    let properties = value.as_object().expect("a properties object");
                    object.properties = Some(
                        js_properties(properties)
                            .into_iter()
                            .map(|(name, schema)| (property_name(name), self.compile(schema)))
                            .collect(),
                    );
                }
                annotation if ANNOTATION_KEYWORDS.contains(&annotation) => {}
                other => panic!("unsupported JSON schema keyword: {other}"),
            }
        }
        object
    }

    fn reference(&mut self, pointer: &str) -> Reference {
        let target = match self.pointers.get(pointer) {
            Some(&target) => target,
            None => {
                let target = self.targets.len();
                self.pointers.insert(pointer.to_string(), target);
                self.targets.push(None);
                let schema = self.resolve(pointer);
                let inline = !has_ref(schema);
                let schema = self.compile(schema);
                self.targets[target] = Some(Target { schema, inline });
                target
            }
        };
        Reference {
            pointer: pointer.to_string(),
            target,
        }
    }

    fn resolve(&self, pointer: &str) -> &'a Json {
        let path = pointer
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("unsupported $ref: {pointer}"));
        let mut schema = self.document;
        for segment in path.split('/').skip(1) {
            let segment = decode_uri_component(segment).replace("~1", "/").replace("~0", "~");
            schema = match schema {
                Json::Object(entries) => js_get(entries, &segment),
                Json::Array(items) => segment.parse::<usize>().ok().and_then(|index| items.get(index)),
                _ => None,
            }
            .unwrap_or_else(|| panic!("unresolvable $ref: {pointer}"));
        }
        schema
    }
}

/// Whether a schema contains a reference (Ajv's `hasRef`).
fn has_ref(schema: &Json) -> bool {
    match schema {
        Json::Object(entries) => entries.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "$ref" | "$recursiveRef" | "$recursiveAnchor" | "$dynamicRef" | "$dynamicAnchor"
            ) || has_ref(value)
        }),
        Json::Array(items) => items.iter().any(has_ref),
        _ => false,
    }
}

// Evaluation.
//
// Ajv (`allErrors: false`) compiles a schema into JavaScript validation
// functions: one for the root schema and one for each `$ref` target which is
// not inlined. This evaluator follows that generated code:
// - A function collects errors in its own list (`vErrors`). Outside of a
//   "composite rule" (an `anyOf` branch), the first error a keyword reports
//   returns from the function (with `[error]` as its errors); within a
//   composite rule, errors are collected and evaluation continues.
// - A schema first checks its `type`, unless it has a single type and uses
//   that type's keyword group (which then reports the type error itself).
//   Then it evaluates the keyword groups it uses, in order (see [`Group`]):
//   after each group, any error since the start of the schema skips the
//   remaining groups (so within a composite rule, the first group still runs
//   after a type error); within a group, the first keyword with an error skips
//   the remaining keywords.
// - `anyOf` collects the errors of each failing branch (until one passes),
//   then adds its own error; outside of a composite rule, the function then
//   returns all of its collected errors. If a branch passes, the errors of
//   earlier branches are discarded.
// - Calling another function adds that function's errors to the caller's.

/// A validation function's early return, with the function's `errors`.
struct Return(Vec<AjvError>);

/// Where a subschema is evaluated.
struct Context {
    /// The JSON pointer to the data.
    instance_path: String,
    /// The schema path (Ajv's `errSchemaPath`).
    schema_path: String,
    /// Whether the subschema is within a composite rule (`anyOf`).
    composite: bool,
}

impl Context {
    /// The context of a subschema at `schema_segment` (for the data at
    /// `data_segment`, if any).
    fn child(&self, data_segment: Option<&str>, schema_segment: &str) -> Context {
        Context {
            instance_path: match data_segment {
                Some(segment) => format!("{}/{}", self.instance_path, escape_json_pointer(segment)),
                None => self.instance_path.clone(),
            },
            schema_path: format!("{}/{schema_segment}", self.schema_path),
            composite: self.composite,
        }
    }

    fn error(&self, keyword: &str, params: Vec<(&str, Json)>, message: String) -> AjvError {
        AjvError {
            keyword: keyword.to_string(),
            instance_path: self.instance_path.clone(),
            schema_path: format!("{}/{keyword}", self.schema_path),
            params: params
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect::<BTreeMap<_, _>>(),
            message,
        }
    }

    /// Report an error: collect it within a composite rule, or else return it
    /// from the validation function.
    fn report(&self, errors: &mut Vec<AjvError>, error: AjvError) -> Result<(), Return> {
        if self.composite {
            errors.push(error);
            Ok(())
        } else {
            Err(Return(vec![error]))
        }
    }
}

impl SchemaDocument {
    /// Call the validation function compiled from `schema`, returning its
    /// errors on failure.
    fn call(&self, schema: &Schema, data: &Json, instance_path: &str) -> Result<(), Vec<AjvError>> {
        let context = Context {
            instance_path: instance_path.to_string(),
            schema_path: "#".to_string(),
            composite: false,
        };
        let mut errors = Vec::new();
        match self.evaluate(schema, data, &context, &mut errors) {
            Err(Return(errors)) => Err(errors),
            Ok(()) if errors.is_empty() => Ok(()),
            Ok(()) => Err(errors),
        }
    }

    fn evaluate(
        &self,
        schema: &Schema,
        data: &Json,
        context: &Context,
        errors: &mut Vec<AjvError>,
    ) -> Result<(), Return> {
        match schema {
            Schema::Boolean(true) => Ok(()),
            Schema::Boolean(false) => context.report(
                errors,
                context.error("false schema", Vec::new(), "boolean schema is false".to_string()),
            ),
            Schema::Object(object) => self.evaluate_object(object, data, context, errors),
        }
    }

    fn evaluate_object(
        &self,
        schema: &SchemaObject,
        data: &Json,
        context: &Context,
        errors: &mut Vec<AjvError>,
    ) -> Result<(), Return> {
        if let Some(reference) = &schema.reference {
            if !schema.has_rules_but_ref() {
                return self.evaluate_reference(reference, data, context, errors);
            }
        }
        let errors_before = errors.len();
        let types = &schema.types;
        // The type is checked up front unless a group of keywords applies to
        // the (single) type, which then reports type errors itself.
        let check_types = !types.is_empty()
            && !(types.len() == 1 && types[0].group().is_some_and(|group| schema.uses_group(group)));
        if check_types && !types.iter().any(|data_type| data_type.matches(data)) {
            context.report(errors, Self::type_error(schema, context))?;
        }
        let mut guarded = false;
        for group in Group::ALL {
            if !schema.uses_group(group) {
                continue;
            }
            if guarded && errors.len() != errors_before {
                break;
            }
            guarded = true;
            match group.data_type() {
                Some(data_type) if !data_type.matches(data) => {
                    if !check_types && types.as_slice() == [data_type] {
                        context.report(errors, Self::type_error(schema, context))?;
                    }
                }
                _ => {
                    for &keyword in Keyword::of_group(group) {
                        let before = errors.len();
                        self.evaluate_keyword(keyword, schema, data, context, errors)?;
                        if errors.len() != before {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn type_error(schema: &SchemaObject, context: &Context) -> AjvError {
        let value = schema.type_value.clone().expect("a type");
        let types = match &value {
            Json::Array(names) => names.iter().map(Json::as_string).collect::<Vec<_>>().join(","),
            other => other.as_string(),
        };
        context.error("type", vec![("type", value)], format!("must be {types}"))
    }

    fn evaluate_reference(
        &self,
        reference: &Reference,
        data: &Json,
        context: &Context,
        errors: &mut Vec<AjvError>,
    ) -> Result<(), Return> {
        let target = &self.targets[reference.target];
        if target.inline {
            let context = Context {
                instance_path: context.instance_path.clone(),
                schema_path: reference.pointer.clone(),
                composite: context.composite,
            };
            self.evaluate(&target.schema, data, &context, errors)
        } else {
            if let Err(function_errors) = self.call(&target.schema, data, &context.instance_path) {
                errors.extend(function_errors);
            }
            Ok(())
        }
    }

    fn evaluate_keyword(
        &self,
        keyword: Keyword,
        schema: &SchemaObject,
        data: &Json,
        context: &Context,
        errors: &mut Vec<AjvError>,
    ) -> Result<(), Return> {
        match keyword {
            Keyword::Ref => {
                if let Some(reference) = &schema.reference {
                    self.evaluate_reference(reference, data, context, errors)?;
                }
            }
            Keyword::Const => {
                if let Some(constant) = &schema.constant {
                    if !js_equal(constant, data) {
                        context.report(
                            errors,
                            context.error(
                                "const",
                                vec![("allowedValue", constant.clone())],
                                "must be equal to constant".to_string(),
                            ),
                        )?;
                    }
                }
            }
            Keyword::Enum => {
                if let Some(values @ Json::Array(options)) = &schema.enumeration {
                    if !options.iter().any(|option| js_equal(option, data)) {
                        context.report(
                            errors,
                            context.error(
                                "enum",
                                vec![("allowedValues", values.clone())],
                                "must be equal to one of the allowed values".to_string(),
                            ),
                        )?;
                    }
                }
            }
            Keyword::AnyOf => {
                if let Some(branches) = &schema.any_of {
                    self.evaluate_any_of(branches, data, context, errors)?;
                }
            }
            Keyword::MaxItems | Keyword::MinItems => {
                let (limit, more) = match keyword {
                    Keyword::MaxItems => (&schema.max_items, true),
                    _ => (&schema.min_items, false),
                };
                if let (Some(Json::Number(limit)), Json::Array(items)) = (limit, data) {
                    let limit = js_number(limit);
                    let length = items.len() as f64;
                    if if more { length > limit } else { length < limit } {
                        let name = if more { "maxItems" } else { "minItems" };
                        let comparison = if more { "more" } else { "fewer" };
                        context.report(
                            errors,
                            context.error(
                                name,
                                vec![("limit", Json::Number(number_to_string(limit)))],
                                format!("must NOT have {comparison} than {} items", number_to_string(limit)),
                            ),
                        )?;
                    }
                }
            }
            Keyword::Items => {
                if let (Some(item_schema), Json::Array(items)) = (&schema.items, data) {
                    if !item_schema.always_valid() {
                        for (index, item) in items.iter().enumerate() {
                            let before = errors.len();
                            let context = context.child(Some(&index.to_string()), "items");
                            self.evaluate(item_schema, item, &context, errors)?;
                            if errors.len() != before {
                                break;
                            }
                        }
                    }
                }
            }
            Keyword::Required => {
                if let (Some(required), Json::Object(entries)) = (&schema.required, data) {
                    if let Some(missing) = required.iter().find(|name| js_get(entries, name).is_none()) {
                        context.report(
                            errors,
                            context.error(
                                "required",
                                vec![("missingProperty", Json::String(missing.clone()))],
                                format!("must have required property '{missing}'"),
                            ),
                        )?;
                    }
                }
            }
            Keyword::AdditionalProperties => {
                if let (Some(additional), Json::Object(entries)) = (&schema.additional_properties, data) {
                    if !additional.always_valid() {
                        self.evaluate_additional_properties(schema, additional, entries, context, errors)?;
                    }
                }
            }
            Keyword::Properties => {
                if let (Some(properties), Json::Object(entries)) = (&schema.properties, data) {
                    for (name, property_schema) in properties {
                        if property_schema.always_valid() {
                            continue;
                        }
                        if let Some(value) = js_get(entries, name) {
                            let before = errors.len();
                            let context =
                                context.child(Some(name), &format!("properties/{}", escape_fragment(name)));
                            self.evaluate(property_schema, value, &context, errors)?;
                            if errors.len() != before {
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn evaluate_any_of(
        &self,
        branches: &[Schema],
        data: &Json,
        context: &Context,
        errors: &mut Vec<AjvError>,
    ) -> Result<(), Return> {
        if branches.iter().any(Schema::always_valid) {
            return Ok(());
        }
        let errors_before = errors.len();
        let mut valid = false;
        for (index, branch) in branches.iter().enumerate() {
            let before = errors.len();
            let context = Context {
                instance_path: context.instance_path.clone(),
                schema_path: format!("{}/anyOf/{index}", context.schema_path),
                composite: true,
            };
            self.evaluate(branch, data, &context, errors)?;
            valid = errors.len() == before;
            if valid {
                break;
            }
        }
        if valid {
            errors.truncate(errors_before);
            return Ok(());
        }
        errors.push(context.error("anyOf", Vec::new(), "must match a schema in anyOf".to_string()));
        if context.composite {
            Ok(())
        } else {
            Err(Return(std::mem::take(errors)))
        }
    }

    fn evaluate_additional_properties(
        &self,
        schema: &SchemaObject,
        additional: &Schema,
        entries: &[(String, Json)],
        context: &Context,
        errors: &mut Vec<AjvError>,
    ) -> Result<(), Return> {
        let defined = |key: &str| {
            schema
                .properties
                .as_ref()
                .is_some_and(|properties| properties.iter().any(|(name, _)| name == key))
        };
        for (key, value) in js_properties(entries) {
            if defined(key) {
                continue;
            }
            if let Schema::Boolean(false) = additional {
                context.report(
                    errors,
                    context.error(
                        "additionalProperties",
                        vec![("additionalProperty", Json::String(key.to_string()))],
                        "must NOT have additional properties".to_string(),
                    ),
                )?;
                break;
            }
            let before = errors.len();
            self.evaluate(additional, value, &context.child(Some(key), "additionalProperties"), errors)?;
            if errors.len() != before {
                break;
            }
        }
        Ok(())
    }
}

/// A validator for a JSON schema: the Rust counterpart of the standalone
/// validation functions libauth generates from its schemas with Ajv (with
/// Ajv's default options, `allErrors: false` and `strictNumbers: true`),
/// producing the same errors, in the same order.
///
/// The schema may use the keywords `$ref` (local JSON pointers), `type`,
/// `const`, `enum`, `anyOf`, `items` (a schema), `maxItems`, `minItems`,
/// `required`, `properties`, and `additionalProperties`, plus annotations.
///
/// Like the JavaScript validation function, a validator has an `errors`
/// property ([`AjvValidator::errors`]); clones share it.
#[derive(Clone)]
pub struct SchemaValidator {
    document: Arc<SchemaDocument>,
    errors: Arc<Mutex<AjvValidatorErrors>>,
}

impl SchemaValidator {
    /// Create a validator for the provided JSON schema document.
    ///
    /// Panics if the schema is not valid JSON or uses an unsupported keyword.
    pub fn new(schema: &str) -> Self {
        let schema = parse_json(schema).expect("a valid JSON schema");
        let mut compiler = Compiler {
            document: &schema,
            pointers: HashMap::new(),
            targets: Vec::new(),
        };
        let root = compiler.compile(&schema);
        let targets = compiler
            .targets
            .into_iter()
            .map(|target| target.expect("a compiled $ref target"))
            .collect();
        SchemaValidator {
            document: Arc::new(SchemaDocument { root, targets }),
            errors: Arc::new(Mutex::new(AjvValidatorErrors::Undefined)),
        }
    }
}

impl AjvValidator for SchemaValidator {
    fn validate(&self, data: &Json) -> bool {
        let result = self.document.call(&self.document.root, data, "");
        let valid = result.is_ok();
        *self.errors.lock().unwrap_or_else(PoisonError::into_inner) = match result {
            Ok(()) => AjvValidatorErrors::Null,
            Err(errors) => AjvValidatorErrors::Errors(errors),
        };
        valid
    }

    fn errors(&self) -> AjvValidatorErrors {
        self.errors.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

/// libauth's validators run on JavaScript's single thread, so validating and
/// then reading a validator's `errors` can't be interleaved with other
/// validations; this lock provides the same guarantee across threads.
static VALIDATION: Mutex<()> = Mutex::new(());

fn avj_errors_to_description(errors: &[AjvError]) -> String {
    // TODO: translate instancePath
    errors
        .iter()
        .map(|error| format!("{}: {}", error.instance_path, error.message))
        .collect::<Vec<_>>()
        .join(",")
}

/// Given an untrusted JSON string or object and an AJV validator, verify that
/// the untrusted value is of the expected shape, returning it as a `T` or an
/// error description. Note, this method first normalizes all characters in
/// the input using `Normalization Form KC` (Compatibility Decomposition,
/// followed by Canonical Composition).
///
/// As in libauth, validation failures are described using the `errors` of
/// the wallet template validator (`validate-wallet-template`), whichever
/// validator is provided: process-wide state, like the JavaScript module's.
/// With another validator, the description is that of the wallet template
/// validator's most recent failure; if its most recent validation passed (or
/// it was never called), reading its `errors` throws a `TypeError`, which
/// libauth reports as invalid JSON (e.g. `Invalid JSON. TypeError: Cannot read
/// properties of null (reading 'map')`).
///
/// Other errors match libauth's: invalid JSON produces `Invalid JSON.
/// SyntaxError: …` with V8's message (see
/// [`parse_json`](crate::runtime::json::parse_json)), and validation errors are
/// described as `` `${instancePath}: ${message}` ``, joined by commas.
pub fn ajv_standalone_json_parse<T>(
    untrusted_json_or_object: &Json,
    validator: &dyn AjvValidator,
) -> Result<T, String>
where
    T: for<'a> TryFrom<&'a Json, Error = String>,
{
    let stringified = match untrusted_json_or_object {
        Json::String(value) => value.clone(),
        other => json_stringify(other),
    };
    let normalized = lossy_normalize(&stringified);
    let parsed = parse_json(&normalized).map_err(|message| format!("Invalid JSON. SyntaxError: {message}"))?;
    let validation = VALIDATION.lock().unwrap_or_else(PoisonError::into_inner);
    let wallet_template_errors = (!validator.validate(&parsed)).then(|| validate_wallet_template::default().errors());
    drop(validation);
    let result = match wallet_template_errors {
        None => T::try_from(&js_value(&parsed)),
        Some(AjvValidatorErrors::Errors(errors)) => Err(avj_errors_to_description(&errors)),
        Some(AjvValidatorErrors::Null) => {
            Err("Invalid JSON. TypeError: Cannot read properties of null (reading 'map')".to_string())
        }
        Some(AjvValidatorErrors::Undefined) => {
            Err("Invalid JSON. TypeError: Cannot read properties of undefined (reading 'map')".to_string())
        }
    };
    dispose_json(parsed);
    result
}
