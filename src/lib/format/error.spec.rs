//! Port of `format/error.spec.ts`.

use std::panic::{catch_unwind, UnwindSafe};

use libauth::{assert_success, bin_to_hex, decode_cash_address, format_error, unknown_value};

/// `t.throws(fn, { message })`: the message of the panic raised by `function`.
fn panic_message(function: impl FnOnce() + UnwindSafe) -> Option<String> {
    let error = catch_unwind(function).err()?;
    Some(match error.downcast::<String>() {
        Ok(message) => *message,
        Err(error) => error
            .downcast::<&str>()
            .map(|message| (*message).to_string())
            .unwrap_or_default(),
    })
}

/// `const enum TestConstEnum { one = 'TestConstEnum one.' }`
struct TestConstEnum;
impl TestConstEnum {
    const ONE: &'static str = "TestConstEnum one.";
}

/// `enum TestEnum { one = 'TestEnum one.' }`
struct TestEnum;
impl TestEnum {
    const ONE: &'static str = "TestEnum one.";
}

#[test]
fn format_error_() {
    assert_eq!(
        format_error(TestConstEnum::ONE, Some("More text.")),
        "TestConstEnum one. More text."
    );
    assert_eq!(format_error(TestEnum::ONE, Some("More.")), "TestEnum one. More.");
    assert_eq!(format_error("Anything.", None), "Anything.");
    assert_eq!(format_error("Anything.", Some("Details.")), "Anything. Details.");
}

#[test]
fn unknown_value_() {
    // const val = 'something' as never;
    let val = "something";
    assert_eq!(
        panic_message(|| {
            unknown_value(val, None);
        }),
        Some(
            "Received an unknown value; this should have been caught by TypeScript - are your types correct? something"
                .to_string()
        )
    );
}

#[test]
fn assert_success_() {
    // const resultError = 'error' as Uint8Array | string;
    let result_error: Result<Vec<u8>, String> = Err("error".to_string());
    // const resultSuccess = Uint8Array.of(0) as Uint8Array | string;
    let result_success: Result<Vec<u8>, String> = Ok(vec![0]);
    let error = result_error.clone();
    assert_eq!(
        panic_message(move || {
            assert_success(error, None);
        }),
        Some("Expected a successful result, but encountered an error: error".to_string())
    );
    let unwrapped: Vec<u8> = assert_success(result_success, None);
    assert_eq!(unwrapped, vec![0]);
    assert_eq!(
        panic_message(move || {
            assert_success(result_error, Some("Custom prefix: "));
        }),
        Some("Custom prefix: error".to_string())
    );
}

#[test]
fn assert_success_tsdoc_example() {
    let address = "bitcoincash:zq2azmyyv6dtgczexyalqar70q036yund5j2mspghf";
    let decoded = decode_cash_address(address);
    let token_address = assert_success(decoded, None);
    assert_eq!(
        bin_to_hex(&token_address.payload),
        "15d16c84669ab46059313bf0747e781f1d13936d"
    );
}
