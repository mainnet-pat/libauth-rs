//! `Intl.Segmenter` with `granularity: 'grapheme'` (extended grapheme clusters
//! as segmented by ICU), used by libauth's `format/utf8.ts`.

mod grapheme_tables;
use grapheme_tables::{
    EXTENDED_PICTOGRAPHIC_RANGES, GCB_CONTROL, GCB_CR, GCB_EXTEND, GCB_L, GCB_LF, GCB_LV, GCB_LVT,
    GCB_OTHER, GCB_PREPEND, GCB_REGIONAL_INDICATOR, GCB_SPACING_MARK, GCB_T, GCB_V, GCB_ZWJ,
    GRAPHEME_BREAK_RANGES, INCB_CONSONANT, INCB_EXTEND, INCB_LINKER, INDIC_CONJUNCT_BREAK_RANGES,
};

fn grapheme_cluster_break(character: char) -> u8 {
    let code = character as u32;
    let mut low = 0_usize;
    let mut high = GRAPHEME_BREAK_RANGES.len();
    while low < high {
        let middle = (low + high) / 2;
        let (start, end, class) = GRAPHEME_BREAK_RANGES[middle];
        if code < start {
            high = middle;
        } else if code > end {
            low = middle + 1;
        } else {
            return class;
        }
    }
    GCB_OTHER
}

fn indic_conjunct_break(character: char) -> u8 {
    let code = character as u32;
    let mut low = 0_usize;
    let mut high = INDIC_CONJUNCT_BREAK_RANGES.len();
    while low < high {
        let middle = (low + high) / 2;
        let (start, end, class) = INDIC_CONJUNCT_BREAK_RANGES[middle];
        if code < start {
            high = middle;
        } else if code > end {
            low = middle + 1;
        } else {
            return class;
        }
    }
    0
}

fn is_extended_pictographic(character: char) -> bool {
    let code = character as u32;
    let mut low = 0_usize;
    let mut high = EXTENDED_PICTOGRAPHIC_RANGES.len();
    while low < high {
        let middle = (low + high) / 2;
        let (start, end) = EXTENDED_PICTOGRAPHIC_RANGES[middle];
        if code < start {
            high = middle;
        } else if code > end {
            low = middle + 1;
        } else {
            return true;
        }
    }
    false
}

/// Return the user-perceived character segments of a string.
///
/// This reproduces libauth's `segment`, which delegates to
/// `Intl.Segmenter(...).segment(utf8)` with grapheme granularity: the returned
/// slices are Unicode extended grapheme clusters (combining marks, emoji ZWJ
/// sequences, regional indicator pairs, and Hangul syllables are kept intact).
///
/// libauth throws a `TypeError` when `Intl.Segmenter` is unavailable; this port
/// always uses the crate's grapheme cluster break tables and therefore has no
/// such failure mode.
pub fn segment_graphemes(utf8: &str) -> Vec<&str> {
    let characters: Vec<(usize, char)> = utf8.char_indices().collect();
    if characters.is_empty() {
        return Vec::new();
    }
    let mut starts = Vec::new();
    starts.push(0_usize);
    let mut previous = grapheme_cluster_break(characters[0].1);
    let mut emoji_chain = u8::from(is_extended_pictographic(characters[0].1));
    let mut regional_indicator_run = usize::from(previous == GCB_REGIONAL_INDICATOR);
    let mut conjunct_state = u8::from(indic_conjunct_break(characters[0].1) == INCB_CONSONANT);
    let is_control = |class: u8| matches!(class, GCB_CONTROL | GCB_CR | GCB_LF);
    for index in 1..characters.len() {
        let character = characters[index].1;
        let current = grapheme_cluster_break(character);
        let current_is_pictographic = is_extended_pictographic(character);
        let current_conjunct = indic_conjunct_break(character);
        let joined = if previous == GCB_CR && current == GCB_LF {
            true
        } else if is_control(previous) {
            false
        } else if is_control(current) {
            false
        } else if previous == GCB_L && matches!(current, GCB_L | GCB_V | GCB_LV | GCB_LVT) {
            true
        } else if matches!(previous, GCB_LV | GCB_V) && matches!(current, GCB_V | GCB_T) {
            true
        } else if matches!(previous, GCB_LVT | GCB_T) && current == GCB_T {
            true
        } else if matches!(current, GCB_EXTEND | GCB_ZWJ) {
            true
        } else if current == GCB_SPACING_MARK {
            true
        } else if previous == GCB_PREPEND {
            true
        } else if conjunct_state == 2 && current_conjunct == INCB_CONSONANT {
            true
        } else if emoji_chain == 2 && current_is_pictographic {
            true
        } else if current == GCB_REGIONAL_INDICATOR
            && previous == GCB_REGIONAL_INDICATOR
            && regional_indicator_run % 2 == 1
        {
            true
        } else {
            false
        };
        if !joined {
            starts.push(index);
        }
        emoji_chain = if current_is_pictographic {
            1
        } else if current == GCB_EXTEND && emoji_chain == 1 {
            1
        } else if current == GCB_ZWJ && emoji_chain == 1 {
            2
        } else {
            0
        };
        regional_indicator_run = if current == GCB_REGIONAL_INDICATOR {
            regional_indicator_run + 1
        } else {
            0
        };
        conjunct_state = if current_conjunct == INCB_CONSONANT {
            1
        } else if current_conjunct == INCB_LINKER {
            if conjunct_state >= 1 {
                2
            } else {
                0
            }
        } else if current_conjunct == INCB_EXTEND {
            conjunct_state
        } else {
            0
        };
        previous = current;
    }
    let mut result = Vec::with_capacity(starts.len());
    for (position, &start) in starts.iter().enumerate() {
        let start = characters[start].0;
        let end = starts
            .get(position + 1)
            .map(|&next| characters[next].0)
            .unwrap_or(utf8.len());
        result.push(&utf8[start..end]);
    }
    result
}
