//! JavaScript built-ins that libauth relies on, implemented in Rust.
//!
//! libauth runs on a JavaScript engine that provides these facilities; this
//! zero-dependency port must supply them itself. This directory is the only
//! part of the crate that has no counterpart in libauth's source tree, and it
//! contains nothing but substitutes for JavaScript globals:
//!
//! - [`bigint`] — `BigInt`
//! - [`crypto`] — `crypto.getRandomValues`
//! - [`intl`] — `Intl.Segmenter` (grapheme granularity)
//! - [`json`] — `JSON.parse` and `JSON.stringify`
//! - [`number`] — `Number.prototype.toString`
//! - [`regexp`] — `RegExp` (patterns with hand-written matchers)
//! - [`string`] — `String.prototype.normalize`, `localeCompare`, and `trim`
//! - [`webassembly`] — `WebAssembly` (an interpreter for libauth's embedded
//!   `.wasm` binaries)

pub mod bigint;
pub mod crypto;
pub mod intl;
pub mod json;
pub mod number;
pub mod regexp;
pub mod string;
pub mod webassembly;
