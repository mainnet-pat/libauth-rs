/// A simple method used throughout Libauth to format error messages. By
/// formatting errors this way, downstream consumers can detect specific error
/// types by matching the `errorType`. For example, the error:
///
/// ```js
/// formatError(SomeTypeOfError.exceedsMaximum, `Provided value: ${value}`);
/// ```
///
/// Can be detected with `String.includes()`, even if the
/// `SomeTypeOfError.exceedsMaximum` error message changes:
/// ```js
/// error.includes(SomeTypeOfError.exceedsMaximum);
/// // => true
/// ```
///
/// Using this method ensures consistency across the library.
///
/// libauth's optional `throwError` parameter is expressed in Rust by panicking
/// with the formatted message at the call site.
pub fn format_error(error_type: &str, error_details: Option<&str>) -> String {
    match error_details {
        Some(details) => format!("{error_type} {details}"),
        None => error_type.to_string(),
    }
}

const UNKNOWN_VALUE_MESSAGE: &str =
    "Received an unknown value; this should have been caught by TypeScript - are your types correct?";

/// Panic with a message describing an unexpected value. In libauth, this
/// function's `value` parameter has type `never`, so calls are only reachable
/// when the type system has been circumvented; in Rust it marks code that
/// exhaustive matching should make unreachable.
pub fn unknown_value(value: impl core::fmt::Display, message: Option<&str>) -> ! {
    panic!(
        "{}",
        format_error(message.unwrap_or(UNKNOWN_VALUE_MESSAGE), Some(&value.to_string()))
    )
}

/// Panic if the provided result is an error (a `string` in libauth), otherwise
/// return the result.
///
/// This is useful in tests and other situations where errors are unexpected.
pub fn assert_success<T, E: core::fmt::Display>(result: Result<T, E>, expectation: Option<&str>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!(
            "{}{error}",
            expectation.unwrap_or("Expected a successful result, but encountered an error: ")
        ),
    }
}

/// Panic if the provided value is `None` (`null` or `undefined` in libauth),
/// otherwise return the value.
///
/// This is useful in tests and other situations where `None` is unexpected.
pub fn assert_non_null<T>(value: Option<T>, expectation: Option<&str>) -> T {
    match value {
        Some(value) => value,
        None => panic!(
            "{}None",
            expectation.unwrap_or("Expected a non-null value, but encountered: ")
        ),
    }
}
