//! JavaScript `Number` behavior.

/// `Number.prototype.toString()` (radix 10): the shortest round-trip decimal
/// representation, using exponential notation for exponents of 21 or greater
/// and -7 or less, as specified by ECMAScript `Number::toString`.
pub fn number_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // Rust's `{:e}` formatting yields the shortest round-trip digits.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific notation");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exponent.parse::<i32>().expect("exponent") + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let exponent = n - 1;
        let exponent_sign = if exponent >= 0 { "+" } else { "-" };
        let fraction = if k == 1 {
            String::new()
        } else {
            format!(".{}", &digits[1..])
        };
        format!("{}{fraction}e{exponent_sign}{}", &digits[..1], exponent.abs())
    };
    format!("{sign}{body}")
}

/// ECMAScript `ToUint32`, as applied by `DataView#setUint32` and `>>>` (and so
/// by libauth's `numberToBinUint32LE`): non-finite values become `0`; other
/// values are truncated toward zero and reduced modulo 2^32.
pub fn to_uint32(value: f64) -> u32 {
    if !value.is_finite() {
        return 0;
    }
    let modulus = 4_294_967_296.0;
    // `%` is exact for doubles, and the sum is an integer below 2^32.
    let remainder = value.trunc() % modulus;
    (if remainder < 0.0 { remainder + modulus } else { remainder }) as u32
}
