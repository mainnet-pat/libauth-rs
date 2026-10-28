/// Interpret a string as UTF-8 and encode it as a Uint8Array.
///
/// For the reverse, see {@link binToUtf8}.
pub fn utf8_to_bin(utf8: &str) -> Vec<u8> {
    utf8.as_bytes().to_vec()
}

/// Decode a Uint8Array as a UTF-8 string. Invalid byte sequences are replaced
/// with the Unicode replacement character (`U+FFFD`), as `TextDecoder` does.
///
/// For the reverse, see {@link utf8ToBin}.
pub fn bin_to_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Normalize a string using Unicode Normalization Form KC (NFKC):
/// compatibility decomposition, followed by canonical composition. Strings
/// normalized with this method are not equivalent to the unnormalized string,
/// but they are typically more easily compared and indexed (e.g. ligatures and
/// fullwidth characters are replaced by their compatibility equivalents).
pub fn lossy_normalize(utf8: &str) -> String {
    crate::runtime::string::normalize_nfkc(utf8)
}

/// Return the user-perceived character segments of the given string, e.g.:
///
/// ```js
/// const test = [..."👍🏼"];
/// // => ["👍", "🏼"]
/// const test2 = segment("👍🏼");
/// // => ["👍🏼"]
/// ```
///
/// Uses the same segmentation algorithm as `Intl.Segmenter` with
/// `granularity: 'grapheme'` (Unicode extended grapheme clusters).
pub fn segment(utf8: &str) -> Vec<&str> {
    crate::runtime::intl::segment_graphemes(utf8)
}

/// Return the user-perceived character length of the given string, e.g.:
///
/// ```js
/// const test = "👍🏼".length;
/// // => 4
/// const test2 = length("👍🏼");
/// // => 1
/// ```
///
/// Note, this method uses the same segmentation algorithm as {@link segment}.
pub fn length(utf8: &str) -> usize {
    segment(utf8).len()
}
