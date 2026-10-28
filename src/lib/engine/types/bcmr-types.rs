//! Bitcoin Cash Metadata Registry (BCMR) types.
//!
//! Port of libauth's `engine/types/bcmr-types.ts`. BCMRs are authenticated JSON
//! documents standardizing metadata for identities (tokens, registries,
//! organizations, etc.) and the chains they exist on.
//!
//! Field doc comments note the original (wire) property names, which are
//! camelCase in JSON and snake_case on the Rust structs.

use std::collections::BTreeMap;

/// A mapping of identifiers to URIs associated with an entity.
///
/// Values must be valid URIs, including a protocol prefix (e.g. `https://` or
/// `ipfs://`). Rust equivalent of the TypeScript `URIs` record.
pub type URIs = BTreeMap<String, String>;

/// A mapping of extension identifiers to extension definitions.
///
/// Extensions may be standardized or application-specific; each definition is
/// either a `string`, a key-value mapping of `string`s, or a two-dimensional,
/// key-value mapping of `string`s.
pub type Extensions = BTreeMap<String, Extension>;

/// An extension definition (a value of [`Extensions`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extension {
    /// A single `string` value (the TypeScript union's `string` member).
    String(String),
    /// A key-value mapping of `string`s.
    Map(BTreeMap<String, String>),
    /// A two-dimensional, key-value mapping of `string`s.
    Nested(BTreeMap<String, BTreeMap<String, String>>),
}

/// Tags allow registries to classify and group identities by a variety of
/// characteristics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    /// The name of this tag for use in interfaces. Wire name: `name`.
    pub name: String,
    /// A string describing this tag for use in user interfaces. Wire name:
    /// `description`.
    pub description: Option<String>,
    /// A mapping of identifiers to URIs associated with this tag. Wire name:
    /// `uris`.
    pub uris: Option<URIs>,
    /// A mapping of tag extension identifiers to extension definitions. Wire
    /// name: `extensions`.
    pub extensions: Option<Extensions>,
}

/// A definition for one type of NFT within a token category.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftType {
    /// The name of this NFT type for use in interfaces. Wire name: `name`.
    pub name: String,
    /// A string describing this NFT type for use in user interfaces. Wire
    /// name: `description`.
    pub description: Option<String>,
    /// The identifiers of the fields contained in NFTs of this type, ordered
    /// by recommended importance. Wire name: `fields`.
    pub fields: Option<Vec<String>>,
    /// A mapping of identifiers to URIs associated with this NFT type. Wire
    /// name: `uris`.
    pub uris: Option<URIs>,
    /// A mapping of NFT type extension identifiers to extension definitions.
    /// Wire name: `extensions`.
    pub extensions: Option<Extensions>,
}

/// A mapping of field identifiers to definitions of the fields that can be
/// encoded in NFTs of a token category.
pub type NftCategoryField = BTreeMap<String, NftCategoryFieldDefinition>;

/// The definition of a single NFT field within an [`NftCategoryField`] entry.
#[derive(Clone, Debug, PartialEq)]
pub struct NftCategoryFieldDefinition {
    /// The name of this field for use in interfaces. Wire name: `name`.
    pub name: Option<String>,
    /// A string describing how this identity uses NFTs. Wire name:
    /// `description`.
    pub description: Option<String>,
    /// The expected encoding of this field when read from the parsing
    /// altstack. Wire name: `encoding`.
    pub encoding: NftCategoryFieldEncoding,
    /// A mapping of identifiers to URIs associated with this NFT field. Wire
    /// name: `uris`.
    pub uris: Option<URIs>,
    /// A mapping of NFT field extension identifiers to extension definitions.
    /// Wire name: `extensions`.
    pub extensions: Option<Extensions>,
}

/// The expected encoding of an NFT field.
///
/// The TypeScript definition is a union of seven single-literal shapes and a
/// `number` shape carrying additional display hints; each literal becomes a
/// unit variant here, with [`NftCategoryFieldEncoding::Number`] carrying the
/// additional properties.
#[derive(Clone, Debug, PartialEq)]
pub enum NftCategoryFieldEncoding {
    /// Display as a binary literal (e.g. `0b0101`). Literal: `binary`.
    Binary,
    /// Display as `true` for exactly `0x01`, `false` for exactly `0x00`.
    /// Literal: `boolean`.
    Boolean,
    /// Display as a hex literal (e.g. `0xabcd`). Literal: `hex`.
    Hex,
    /// A percent-encoded HTTPS URL with the `https://` prefix omitted.
    /// Literal: `https-url`.
    HttpsUrl,
    /// A binary-encoded IPFS Content Identifier. Literal: `ipfs-cid`.
    IpfsCid,
    /// Display as a utf8 string. Literal: `utf8`.
    Utf8,
    /// A locktime value (`0` to `4294967295`). Literal: `locktime`.
    Locktime,
    /// A number displayed according to its `decimals` and `unit`. Literal:
    /// `number`.
    Number(NftCategoryFieldNumberEncoding),
}

impl NftCategoryFieldEncoding {
    /// The exact encoding identifier used in registry JSON.
    pub fn text(&self) -> &'static str {
        match self {
            NftCategoryFieldEncoding::Binary => "binary",
            NftCategoryFieldEncoding::Boolean => "boolean",
            NftCategoryFieldEncoding::Hex => "hex",
            NftCategoryFieldEncoding::HttpsUrl => "https-url",
            NftCategoryFieldEncoding::IpfsCid => "ipfs-cid",
            NftCategoryFieldEncoding::Utf8 => "utf8",
            NftCategoryFieldEncoding::Locktime => "locktime",
            NftCategoryFieldEncoding::Number(_) => "number",
        }
    }
}

/// The additional properties of a `number`-encoded NFT field.
#[derive(Clone, Debug, PartialEq)]
pub struct NftCategoryFieldNumberEncoding {
    /// The aggregation operation clients should use when displaying the field
    /// across multiple NFTs. Wire name: `aggregate`.
    pub aggregate: Option<NftCategoryFieldAggregate>,
    /// An integer between `0` and `18` (inclusive) indicating divisibility.
    /// Wire name: `decimals`.
    pub decimals: Option<f64>,
    /// The unit in which this field is denominated. Wire name: `unit`.
    pub unit: Option<String>,
}

/// The aggregating operation supported for `number`-encoded NFT fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NftCategoryFieldAggregate {
    /// Aggregate the field by addition. Literal: `add`.
    Add,
}

impl NftCategoryFieldAggregate {
    /// The exact aggregation identifier used in registry JSON.
    pub const fn text(self) -> &'static str {
        match self {
            NftCategoryFieldAggregate::Add => "add",
        }
    }
}

/// Interpretation information for a collection of sequential NFTs, in which
/// each NFT includes only a sequential identifier within its commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequentialNftCollection {
    /// A mapping of each NFT commitment (typically a positive VM number
    /// encoded as hex) to metadata for that NFT type. Wire name: `types`.
    pub types: BTreeMap<String, NftType>,
}

/// Interpretation information for a collection of parsable NFTs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsableNftCollection {
    /// A segment of hex-encoded Bitcoin Cash VM bytecode that parses UTXOs
    /// holding NFTs of this category. Wire name: `bytecode`.
    pub bytecode: String,
    /// A mapping of hex-encoded bottom-altstack values to NFT type
    /// definitions. Wire name: `types`.
    pub types: BTreeMap<String, NftType>,
}

/// The `parse` property of an [`NftCategory`]: either a parsable or a
/// sequential NFT collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NftCollection {
    /// A collection parsed with a bytecode program.
    Parsable(ParsableNftCollection),
    /// A collection whose NFT type is the full commitment.
    Sequential(SequentialNftCollection),
}

/// A definition specifying the non-fungible token information for a token
/// category.
#[derive(Clone, Debug, PartialEq)]
pub struct NftCategory {
    /// A string describing how this identity uses NFTs. Wire name:
    /// `description`.
    pub description: Option<String>,
    /// A mapping of field identifiers to definitions of the data fields that
    /// can appear in NFT commitments of this category. Wire name: `fields`.
    pub fields: Option<NftCategoryField>,
    /// Parsing and interpretation information for all NFTs of this category.
    /// Wire name: `parse`.
    pub parse: NftCollection,
}

/// A definition specifying information about an identity's token category.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenCategory {
    /// The current token category used by this identity. Wire name:
    /// `category`.
    pub category: String,
    /// An abbreviation used to uniquely identify this token category. Wire
    /// name: `symbol`.
    pub symbol: String,
    /// An integer between `0` and `18` (inclusive) indicating divisibility;
    /// defaults to `0`. Wire name: `decimals`.
    pub decimals: Option<f64>,
    /// Display information for non-fungible tokens of this identity. Wire
    /// name: `nfts`.
    pub nfts: Option<NftCategory>,
}

/// The status of an identity, as recorded in an [`IdentitySnapshot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityStatus {
    /// The identity should be actively tracked by clients. Literal: `active`.
    Active,
    /// The identity has been permanently terminated. Literal: `burned`.
    Burned,
    /// The identity may be considered for archival. Literal: `inactive`.
    Inactive,
}

impl IdentityStatus {
    /// The exact status identifier used in registry JSON.
    pub const fn text(self) -> &'static str {
        match self {
            IdentityStatus::Active => "active",
            IdentityStatus::Burned => "burned",
            IdentityStatus::Inactive => "inactive",
        }
    }
}

/// A snapshot of the metadata for a particular identity at a specific time.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentitySnapshot {
    /// The name of this identity for use in interfaces. Wire name: `name`.
    pub name: String,
    /// A string describing this identity for use in user interfaces. Wire
    /// name: `description`.
    pub description: Option<String>,
    /// The identifiers of the tags associated with this identity. Wire name:
    /// `tags`.
    pub tags: Option<Vec<String>>,
    /// The simplified extended ISO 8601 timestamp at which this snapshot is
    /// fully in effect. Wire name: `migrated`.
    pub migrated: Option<String>,
    /// Token display information, present for token identities. Wire name:
    /// `token`.
    pub token: Option<TokenCategory>,
    /// The status of this identity; defaults to `active`. Wire name:
    /// `status`.
    pub status: Option<IdentityStatus>,
    /// The split ID of this identity's chain of record. Wire name:
    /// `splitId`.
    pub split_id: Option<String>,
    /// A mapping of identifiers to URIs associated with this identity. Wire
    /// name: `uris`.
    pub uris: Option<URIs>,
    /// A mapping of snapshot extension identifiers to extension definitions.
    /// Wire name: `extensions`.
    pub extensions: Option<Extensions>,
}

/// The native currency display information of a [`ChainSnapshot`].
#[derive(Clone, Debug, PartialEq)]
pub struct ChainSnapshotToken {
    /// An abbreviation used to uniquely identify this native currency unit.
    /// Wire name: `symbol`.
    pub symbol: String,
    /// An integer between `0` and `18` (inclusive) indicating divisibility;
    /// defaults to `0`. Wire name: `decimals`.
    pub decimals: Option<f64>,
}

/// A snapshot of the metadata for a particular chain/network at a specific
/// time.
///
/// Equivalent to the TypeScript `Omit<IdentitySnapshot, 'migrated' | 'token'>`
/// intersected with a required native-currency `token` definition.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainSnapshot {
    /// The name of this chain for use in interfaces. Wire name: `name`.
    pub name: String,
    /// A string describing this chain for use in user interfaces. Wire name:
    /// `description`.
    pub description: Option<String>,
    /// The identifiers of the tags associated with this chain. Wire name:
    /// `tags`.
    pub tags: Option<Vec<String>>,
    /// The status of this chain identity. Wire name: `status`.
    pub status: Option<IdentityStatus>,
    /// The split ID of this chain's chain of record. Wire name: `splitId`.
    pub split_id: Option<String>,
    /// A mapping of identifiers to URIs associated with this chain. Wire
    /// name: `uris`.
    pub uris: Option<URIs>,
    /// A mapping of snapshot extension identifiers to extension definitions.
    /// Wire name: `extensions`.
    pub extensions: Option<Extensions>,
    /// A data structure indicating how the chain's native currency units
    /// should be displayed. Wire name: `token`.
    pub token: ChainSnapshotToken,
}

/// A field keyed by timestamps to document the evolution of the field.
///
/// Each timestamp is a simplified extended ISO 8601 string (`YYYY-MM-DDTHH:mm:ss.sssZ`).
pub type RegistryTimestampKeyedValues<T> = BTreeMap<String, T>;

/// A timestamp-keyed map of [`ChainSnapshot`]s documenting the evolution of a
/// particular chain/network's identity.
pub type ChainHistory = RegistryTimestampKeyedValues<ChainSnapshot>;

/// A timestamp-keyed map of [`IdentitySnapshot`]s documenting the evolution of
/// a particular identity.
pub type IdentityHistory = RegistryTimestampKeyedValues<IdentitySnapshot>;

/// An identity representing a metadata registry that is not published
/// on-chain and therefore has no authbase or trackable authchain.
///
/// Equivalent to the TypeScript
/// `Pick<IdentitySnapshot, 'description' | 'extensions' | 'name' | 'tags' | 'uris'>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffChainRegistryIdentity {
    /// A string describing this registry for use in user interfaces. Wire
    /// name: `description`.
    pub description: Option<String>,
    /// A mapping of extension identifiers to extension definitions. Wire
    /// name: `extensions`.
    pub extensions: Option<Extensions>,
    /// The name of this registry for use in interfaces. Wire name: `name`.
    pub name: String,
    /// The identifiers of the tags associated with this registry. Wire name:
    /// `tags`.
    pub tags: Option<Vec<String>>,
    /// A mapping of identifiers to URIs associated with this registry. Wire
    /// name: `uris`.
    pub uris: Option<URIs>,
}

/// The semantic version of a [`MetadataRegistry`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RegistryVersion {
    /// Incremented when an identity is removed. Wire name: `major`.
    pub major: f64,
    /// Incremented when an identity or identity snapshot is added. Wire name:
    /// `minor`.
    pub minor: f64,
    /// Incremented when an existing property is modified. Wire name:
    /// `patch`.
    pub patch: f64,
}

/// The `registryIdentity` property of a [`MetadataRegistry`]: either an
/// authbase (a 32-byte, hex-encoded transaction hash) or a directly-provided
/// off-chain identity snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryIdentity {
    /// An off-chain identity snapshot, authenticated only via DNS/HTTPS.
    OffChain(OffChainRegistryIdentity),
    /// The authbase of the registry's zeroth-descendant transaction chain.
    Authbase(String),
}

/// A Bitcoin Cash Metadata Registry: an authenticated JSON file containing
/// metadata about tokens, identities, contract applications, and other
/// on-chain artifacts.
#[derive(Clone, Debug, PartialEq)]
pub struct MetadataRegistry {
    /// The JSON Schema URI used by this registry. Wire name: `$schema`.
    pub schema: Option<String>,
    /// The version of this registry. Wire name: `version`.
    pub version: RegistryVersion,
    /// The simplified extended ISO 8601 timestamp of the latest revision to
    /// this registry version. Wire name: `latestRevision`.
    pub latest_revision: String,
    /// The identity information of this registry, provided as either an
    /// authbase or an identity snapshot. Wire name: `registryIdentity`.
    pub registry_identity: RegistryIdentity,
    /// A mapping of authbases to the identity history for that identity.
    /// Wire name: `identities`.
    pub identities: Option<BTreeMap<String, IdentityHistory>>,
    /// A map of registry-specific tags used to convey information about
    /// tracked identities. Wire name: `tags`.
    pub tags: Option<BTreeMap<String, Tag>>,
    /// The split ID of the chain/network considered the "default" chain for
    /// this registry. Wire name: `defaultChain`.
    pub default_chain: Option<String>,
    /// A map of split IDs tracked by this registry to the chain history for
    /// that chain/network. Wire name: `chains`.
    pub chains: Option<BTreeMap<String, ChainHistory>>,
    /// The license under which this registry is published. Wire name:
    /// `license`.
    pub license: Option<String>,
    /// A mapping of registry extension identifiers to extension definitions.
    /// Wire name: `extensions`.
    pub extensions: Option<Extensions>,
}


// Conversions between metadata registries and JSON. In libauth, a registry is a
// plain object (interchangeable with its JSON); in this port, `TryFrom<&Json>`
// types a JSON value (see `importMetadataRegistry`) and `From<&_> for Json`
// produces the equivalent JSON (with keys in sorted order).

use crate::runtime::json::typed::{
    from_f64, from_map, from_string, from_strings, map, number, object, optional, properties, required, string,
    strings,
};
use crate::runtime::json::Json;

fn string_map(json: &Json) -> Result<BTreeMap<String, String>, String> {
    map(json, string)
}

fn from_string_map(value: &BTreeMap<String, String>) -> Json {
    from_map(value, |value| from_string(value))
}

impl TryFrom<&Json> for Extension {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        if let Some(text) = json.as_str() {
            return Ok(Extension::String(text.to_string()));
        }
        let entries = json
            .as_object()
            .ok_or_else(|| format!("Expected an extension definition, received {json}."))?;
        if entries.iter().all(|(_, value)| value.as_str().is_some()) {
            return Ok(Extension::Map(string_map(json)?));
        }
        Ok(Extension::Nested(map(json, string_map)?))
    }
}

impl From<&Extension> for Json {
    fn from(extension: &Extension) -> Json {
        match extension {
            Extension::String(text) => from_string(text),
            Extension::Map(values) => from_string_map(values),
            Extension::Nested(values) => from_map(values, from_string_map),
        }
    }
}

fn extensions(json: &Json) -> Result<Extensions, String> {
    map(json, |value| Extension::try_from(value))
}

fn from_extensions(value: &Extensions) -> Json {
    from_map(value, |value| Json::from(value))
}

impl TryFrom<&Json> for Tag {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["description", "extensions", "name", "uris"], "Tag")?;
        Ok(Tag {
            name: string(required(&p, "name", "Tag")?)?,
            description: optional(&p, "description", string)?,
            uris: optional(&p, "uris", string_map)?,
            extensions: optional(&p, "extensions", extensions)?,
        })
    }
}

impl From<&Tag> for Json {
    fn from(tag: &Tag) -> Json {
        object(vec![
            ("description", tag.description.as_deref().map(from_string)),
            ("extensions", tag.extensions.as_ref().map(from_extensions)),
            ("name", Some(from_string(&tag.name))),
            ("uris", tag.uris.as_ref().map(from_string_map)),
        ])
    }
}

impl TryFrom<&Json> for NftType {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["description", "extensions", "fields", "name", "uris"], "NFT type")?;
        Ok(NftType {
            name: string(required(&p, "name", "NFT type")?)?,
            description: optional(&p, "description", string)?,
            fields: optional(&p, "fields", strings)?,
            uris: optional(&p, "uris", string_map)?,
            extensions: optional(&p, "extensions", extensions)?,
        })
    }
}

impl From<&NftType> for Json {
    fn from(nft_type: &NftType) -> Json {
        object(vec![
            ("description", nft_type.description.as_deref().map(from_string)),
            ("extensions", nft_type.extensions.as_ref().map(from_extensions)),
            ("fields", nft_type.fields.as_deref().map(from_strings)),
            ("name", Some(from_string(&nft_type.name))),
            ("uris", nft_type.uris.as_ref().map(from_string_map)),
        ])
    }
}

impl TryFrom<&Json> for NftCategoryFieldDefinition {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["description", "encoding", "extensions", "name", "uris"], "NFT field")?;
        let encoding = required(&p, "encoding", "NFT field")?;
        let e = properties(encoding, &["aggregate", "decimals", "type", "unit"], "NFT field encoding")?;
        let r#type = string(required(&e, "type", "NFT field encoding")?)?;
        let encoding = if r#type == "number" {
            NftCategoryFieldEncoding::Number(NftCategoryFieldNumberEncoding {
                aggregate: optional(&e, "aggregate", |value| match value.as_str() {
                    Some("add") => Ok(NftCategoryFieldAggregate::Add),
                    _ => Err(format!("Unknown aggregate: {value}.")),
                })?,
                decimals: optional(&e, "decimals", number)?,
                unit: optional(&e, "unit", string)?,
            })
        } else {
            if e.len() != 1 {
                return Err(format!("NFT field encoding: unexpected properties for type \"{type}\".", type = r#type));
            }
            use NftCategoryFieldEncoding as Encoding;
            [
                Encoding::Binary,
                Encoding::Boolean,
                Encoding::Hex,
                Encoding::HttpsUrl,
                Encoding::IpfsCid,
                Encoding::Utf8,
                Encoding::Locktime,
            ]
            .into_iter()
            .find(|candidate| candidate.text() == r#type)
            .ok_or_else(|| format!("Unknown NFT field encoding: {type}.", type = r#type))?
        };
        Ok(NftCategoryFieldDefinition {
            name: optional(&p, "name", string)?,
            description: optional(&p, "description", string)?,
            encoding,
            uris: optional(&p, "uris", string_map)?,
            extensions: optional(&p, "extensions", extensions)?,
        })
    }
}

impl From<&NftCategoryFieldDefinition> for Json {
    fn from(field: &NftCategoryFieldDefinition) -> Json {
        let encoding = match &field.encoding {
            NftCategoryFieldEncoding::Number(number) => object(vec![
                ("aggregate", number.aggregate.map(|aggregate| from_string(aggregate.text()))),
                ("decimals", number.decimals.map(from_f64)),
                ("type", Some(from_string("number"))),
                ("unit", number.unit.as_deref().map(from_string)),
            ]),
            other => object(vec![("type", Some(from_string(other.text())))]),
        };
        object(vec![
            ("description", field.description.as_deref().map(from_string)),
            ("encoding", Some(encoding)),
            ("extensions", field.extensions.as_ref().map(from_extensions)),
            ("name", field.name.as_deref().map(from_string)),
            ("uris", field.uris.as_ref().map(from_string_map)),
        ])
    }
}

impl TryFrom<&Json> for NftCategory {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["description", "fields", "parse"], "NFT category")?;
        let parse = required(&p, "parse", "NFT category")?;
        let types = |collection: &BTreeMap<&str, &Json>, context: &str| {
            map(required(collection, "types", context)?, |value| NftType::try_from(value))
        };
        let parse = if parse.get("bytecode").is_some() {
            let c = properties(parse, &["bytecode", "types"], "Parsable NFT collection")?;
            NftCollection::Parsable(ParsableNftCollection {
                bytecode: string(required(&c, "bytecode", "Parsable NFT collection")?)?,
                types: types(&c, "Parsable NFT collection")?,
            })
        } else {
            let c = properties(parse, &["types"], "Sequential NFT collection")?;
            NftCollection::Sequential(SequentialNftCollection {
                types: types(&c, "Sequential NFT collection")?,
            })
        };
        Ok(NftCategory {
            description: optional(&p, "description", string)?,
            fields: optional(&p, "fields", |value| map(value, |value| NftCategoryFieldDefinition::try_from(value)))?,
            parse,
        })
    }
}

impl From<&NftCategory> for Json {
    fn from(category: &NftCategory) -> Json {
        let parse = match &category.parse {
            NftCollection::Parsable(collection) => object(vec![
                ("bytecode", Some(from_string(&collection.bytecode))),
                ("types", Some(from_map(&collection.types, |value| Json::from(value)))),
            ]),
            NftCollection::Sequential(collection) => {
                object(vec![("types", Some(from_map(&collection.types, |value| Json::from(value))))])
            }
        };
        object(vec![
            ("description", category.description.as_deref().map(from_string)),
            ("fields", category.fields.as_ref().map(|fields| from_map(fields, |value| Json::from(value)))),
            ("parse", Some(parse)),
        ])
    }
}

impl TryFrom<&Json> for TokenCategory {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["category", "decimals", "nfts", "symbol"], "Token category")?;
        Ok(TokenCategory {
            category: string(required(&p, "category", "Token category")?)?,
            symbol: string(required(&p, "symbol", "Token category")?)?,
            decimals: optional(&p, "decimals", number)?,
            nfts: optional(&p, "nfts", |value| NftCategory::try_from(value))?,
        })
    }
}

impl From<&TokenCategory> for Json {
    fn from(token: &TokenCategory) -> Json {
        object(vec![
            ("category", Some(from_string(&token.category))),
            ("decimals", token.decimals.map(from_f64)),
            ("nfts", token.nfts.as_ref().map(Json::from)),
            ("symbol", Some(from_string(&token.symbol))),
        ])
    }
}

fn identity_status(json: &Json) -> Result<IdentityStatus, String> {
    [IdentityStatus::Active, IdentityStatus::Burned, IdentityStatus::Inactive]
        .into_iter()
        .find(|candidate| json.as_str() == Some(candidate.text()))
        .ok_or_else(|| format!("Unknown identity status: {json}."))
}

impl TryFrom<&Json> for IdentitySnapshot {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(
            json,
            &["description", "extensions", "migrated", "name", "splitId", "status", "tags", "token", "uris"],
            "Identity snapshot",
        )?;
        Ok(IdentitySnapshot {
            name: string(required(&p, "name", "Identity snapshot")?)?,
            description: optional(&p, "description", string)?,
            tags: optional(&p, "tags", strings)?,
            migrated: optional(&p, "migrated", string)?,
            token: optional(&p, "token", |value| TokenCategory::try_from(value))?,
            status: optional(&p, "status", identity_status)?,
            split_id: optional(&p, "splitId", string)?,
            uris: optional(&p, "uris", string_map)?,
            extensions: optional(&p, "extensions", extensions)?,
        })
    }
}

impl From<&IdentitySnapshot> for Json {
    fn from(snapshot: &IdentitySnapshot) -> Json {
        object(vec![
            ("description", snapshot.description.as_deref().map(from_string)),
            ("extensions", snapshot.extensions.as_ref().map(from_extensions)),
            ("migrated", snapshot.migrated.as_deref().map(from_string)),
            ("name", Some(from_string(&snapshot.name))),
            ("splitId", snapshot.split_id.as_deref().map(from_string)),
            ("status", snapshot.status.map(|status| from_string(status.text()))),
            ("tags", snapshot.tags.as_deref().map(from_strings)),
            ("token", snapshot.token.as_ref().map(Json::from)),
            ("uris", snapshot.uris.as_ref().map(from_string_map)),
        ])
    }
}

impl TryFrom<&Json> for ChainSnapshot {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(
            json,
            &["description", "extensions", "name", "splitId", "status", "tags", "token", "uris"],
            "Chain snapshot",
        )?;
        let token = required(&p, "token", "Chain snapshot")?;
        let t = properties(token, &["decimals", "symbol"], "Chain snapshot token")?;
        Ok(ChainSnapshot {
            name: string(required(&p, "name", "Chain snapshot")?)?,
            description: optional(&p, "description", string)?,
            tags: optional(&p, "tags", strings)?,
            status: optional(&p, "status", identity_status)?,
            split_id: optional(&p, "splitId", string)?,
            uris: optional(&p, "uris", string_map)?,
            extensions: optional(&p, "extensions", extensions)?,
            token: ChainSnapshotToken {
                symbol: string(required(&t, "symbol", "Chain snapshot token")?)?,
                decimals: optional(&t, "decimals", number)?,
            },
        })
    }
}

impl From<&ChainSnapshot> for Json {
    fn from(snapshot: &ChainSnapshot) -> Json {
        object(vec![
            ("description", snapshot.description.as_deref().map(from_string)),
            ("extensions", snapshot.extensions.as_ref().map(from_extensions)),
            ("name", Some(from_string(&snapshot.name))),
            ("splitId", snapshot.split_id.as_deref().map(from_string)),
            ("status", snapshot.status.map(|status| from_string(status.text()))),
            ("tags", snapshot.tags.as_deref().map(from_strings)),
            (
                "token",
                Some(object(vec![
                    ("decimals", snapshot.token.decimals.map(from_f64)),
                    ("symbol", Some(from_string(&snapshot.token.symbol))),
                ])),
            ),
            ("uris", snapshot.uris.as_ref().map(from_string_map)),
        ])
    }
}

impl TryFrom<&Json> for OffChainRegistryIdentity {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let p = properties(json, &["description", "extensions", "name", "tags", "uris"], "Registry identity")?;
        Ok(OffChainRegistryIdentity {
            description: optional(&p, "description", string)?,
            extensions: optional(&p, "extensions", extensions)?,
            name: string(required(&p, "name", "Registry identity")?)?,
            tags: optional(&p, "tags", strings)?,
            uris: optional(&p, "uris", string_map)?,
        })
    }
}

impl From<&OffChainRegistryIdentity> for Json {
    fn from(identity: &OffChainRegistryIdentity) -> Json {
        object(vec![
            ("description", identity.description.as_deref().map(from_string)),
            ("extensions", identity.extensions.as_ref().map(from_extensions)),
            ("name", Some(from_string(&identity.name))),
            ("tags", identity.tags.as_deref().map(from_strings)),
            ("uris", identity.uris.as_ref().map(from_string_map)),
        ])
    }
}

impl TryFrom<&Json> for MetadataRegistry {
    type Error = String;
    fn try_from(json: &Json) -> Result<Self, String> {
        let context = "Metadata registry";
        let p = properties(
            json,
            &[
                "$schema",
                "chains",
                "defaultChain",
                "extensions",
                "identities",
                "latestRevision",
                "license",
                "registryIdentity",
                "tags",
                "version",
            ],
            context,
        )?;
        let version = required(&p, "version", context)?;
        let v = properties(version, &["major", "minor", "patch"], "Registry version")?;
        let registry_identity = required(&p, "registryIdentity", context)?;
        Ok(MetadataRegistry {
            schema: optional(&p, "$schema", string)?,
            version: RegistryVersion {
                major: number(required(&v, "major", "Registry version")?)?,
                minor: number(required(&v, "minor", "Registry version")?)?,
                patch: number(required(&v, "patch", "Registry version")?)?,
            },
            latest_revision: string(required(&p, "latestRevision", context)?)?,
            registry_identity: match registry_identity.as_str() {
                Some(authbase) => RegistryIdentity::Authbase(authbase.to_string()),
                None => RegistryIdentity::OffChain(OffChainRegistryIdentity::try_from(registry_identity)?),
            },
            identities: optional(&p, "identities", |value| {
                map(value, |history| map(history, |value| IdentitySnapshot::try_from(value)))
            })?,
            tags: optional(&p, "tags", |value| map(value, |value| Tag::try_from(value)))?,
            default_chain: optional(&p, "defaultChain", string)?,
            chains: optional(&p, "chains", |value| {
                map(value, |history| map(history, |value| ChainSnapshot::try_from(value)))
            })?,
            license: optional(&p, "license", string)?,
            extensions: optional(&p, "extensions", extensions)?,
        })
    }
}

impl From<&MetadataRegistry> for Json {
    fn from(registry: &MetadataRegistry) -> Json {
        object(vec![
            ("$schema", registry.schema.as_deref().map(from_string)),
            (
                "chains",
                registry
                    .chains
                    .as_ref()
                    .map(|chains| from_map(chains, |history| from_map(history, |value| Json::from(value)))),
            ),
            ("defaultChain", registry.default_chain.as_deref().map(from_string)),
            ("extensions", registry.extensions.as_ref().map(from_extensions)),
            (
                "identities",
                registry
                    .identities
                    .as_ref()
                    .map(|identities| from_map(identities, |history| from_map(history, |value| Json::from(value)))),
            ),
            ("latestRevision", Some(from_string(&registry.latest_revision))),
            ("license", registry.license.as_deref().map(from_string)),
            (
                "registryIdentity",
                Some(match &registry.registry_identity {
                    RegistryIdentity::Authbase(authbase) => from_string(authbase),
                    RegistryIdentity::OffChain(identity) => Json::from(identity),
                }),
            ),
            ("tags", registry.tags.as_ref().map(|tags| from_map(tags, |value| Json::from(value)))),
            (
                "version",
                Some(object(vec![
                    ("major", Some(from_f64(registry.version.major))),
                    ("minor", Some(from_f64(registry.version.minor))),
                    ("patch", Some(from_f64(registry.version.patch))),
                ])),
            ),
        ])
    }
}
