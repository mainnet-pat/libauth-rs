//! `RegExp`, as used by libauth's CashAssembly parser.
//!
//! This port has no regular expression engine. A [`RegExp`] pairs a pattern's
//! source text and flags (which libauth's parser reports in error messages via
//! `String(regexp)`) with a hand-written matcher implementing that pattern.

use std::fmt;
use std::ops::Range;

/// A regular expression: its source, flags, and a matcher implementing it.
#[derive(Clone, Copy)]
pub struct RegExp {
    /// The pattern source, as written between the slashes of a literal.
    pub source: &'static str,
    /// The pattern flags (e.g. `u` or `iu`).
    pub flags: &'static str,
    /// Match the pattern anchored at the start of `input` (UTF-16 code units),
    /// returning the range of each capture group (index `0` is the whole
    /// match), or `None` if the pattern does not match.
    pub exec: fn(input: &[u16]) -> Option<Vec<Option<Range<usize>>>>,
}

/// `String(regexp)`: `/source/flags`.
impl fmt::Display for RegExp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "/{}/{}", self.source, self.flags)
    }
}

impl fmt::Debug for RegExp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Returns `true` if the UTF-16 code unit is matched by `\s` (a `WhiteSpace`
/// or `LineTerminator` code point).
pub fn is_white_space(unit: u16) -> bool {
    matches!(
        unit,
        0x0009..=0x000d | 0x0020 | 0x00a0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000 | 0xfeff
    )
}
