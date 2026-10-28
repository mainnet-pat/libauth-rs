//! A zero-dependency Rust port of `@bitauth/libauth` v3.1.0-next.8.
//!
//! The crate mirrors libauth's source tree: this file corresponds to
//! `src/index.ts`, and `src/lib/**` corresponds to `src/lib/**` (see the
//! README). The `runtime` module (`src/runtime/`) has no counterpart in
//! libauth: it provides the JavaScript built-ins libauth relies on.

// libauth exports many values with camelCase names (for example the error
// tables' `tooLong` and the BIP32 HMAC key); keep those names for parity.
#![allow(non_upper_case_globals)]
// libauth's `export *` barrels re-export several same-named modules (e.g. each
// hash module and its instance); as in TypeScript, the ambiguous names are
// available only by their full paths.
#![allow(ambiguous_glob_reexports)]

#[path = "lib/lib.rs"]
mod lib;
#[path = "runtime/runtime.rs"]
pub mod runtime;

pub use self::lib::*;
