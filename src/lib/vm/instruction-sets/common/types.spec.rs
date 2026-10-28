//! Port of `vm/instruction-sets/common/types.spec.ts`.

use libauth::runtime::bigint::BigInt;
use libauth::{
    big_int_to_vm_number, bin_to_hex, boolean_to_vm_number, hex_to_bin, stack_item_is_truthy,
    vm_number_to_big_int, VmNumberError,
};

// Derived from https://github.com/bitcoinjs/bitcoinjs-lib
const MINIMALLY_ENCODED_VM_NUMBERS: &[(&str, i64)] = &[
    ("", 0),
    ("01", 1),
    ("02", 2),
    ("03", 3),
    ("7e", 126),
    ("7f", 127),
    ("8000", 128),
    ("8100", 129),
    ("8200", 130),
    ("ff00", 255),
    ("fe7f", 32766),
    ("ff7f", 32767),
    ("008000", 32768),
    ("018000", 32769),
    ("028000", 32770),
    ("ffff00", 65535),
    ("ffffff00", 16777215),
    ("feff7f", 8388606),
    ("ffff7f", 8388607),
    ("00008000", 8388608),
    ("01008000", 8388609),
    ("02008000", 8388610),
    ("feffff7f", 2147483646),
    ("ffffff7f", 2147483647),
    ("ffffffff", -2147483647),
    ("feffffff", -2147483646),
    ("fdffffff", -2147483645),
    ("ffffff80", -16777215),
    ("01008080", -8388609),
    ("00008080", -8388608),
    ("ffffff", -8388607),
    ("feffff", -8388606),
    ("fdffff", -8388605),
    ("ffff80", -65535),
    ("018080", -32769),
    ("008080", -32768),
    ("ffff", -32767),
    ("feff", -32766),
    ("fdff", -32765),
    ("ff80", -255),
    ("8180", -129),
    ("8080", -128),
    ("ff", -127),
    ("fe", -126),
    ("fd", -125),
    ("82", -2),
    ("81", -1),
];

const NON_MINIMALLY_ENCODED_VM_NUMBERS: &[(&str, i64)] = &[
    ("00", 0),
    ("0000", 0),
    ("80", 0),
    ("0080", 0),
    ("0180", -1),
    ("010080", -1),
    ("01000080", -1),
    ("0100000080", -1),
    ("abcdef4280", -1123012011),
];

const EQUIVALENT_VM_NUMBERS: &[(&str, &str)] = &[
    ("01020380", "010283"),
    ("0102030480", "01020384"),
    ("abcdef4280", "abcdefc2"),
];

fn big(value: i64) -> BigInt {
    BigInt::from_i64(value)
}

#[test]
fn decode_vm_number() {
    for (hex, value) in MINIMALLY_ENCODED_VM_NUMBERS {
        assert_eq!(vm_number_to_big_int(&hex_to_bin(hex), None, None), Ok(big(*value)));
        assert_eq!(
            vm_number_to_big_int(&hex_to_bin(hex), None, Some(true)),
            Ok(big(*value))
        );
        assert_eq!(
            vm_number_to_big_int(&hex_to_bin(hex), Some(4), Some(true)),
            Ok(big(*value))
        );
    }
    for (hex, value) in MINIMALLY_ENCODED_VM_NUMBERS
        .iter()
        .chain(NON_MINIMALLY_ENCODED_VM_NUMBERS)
    {
        assert_eq!(
            vm_number_to_big_int(&hex_to_bin(hex), Some(5), Some(false)),
            Ok(big(*value))
        );
    }
    for (hex, _) in NON_MINIMALLY_ENCODED_VM_NUMBERS {
        assert_eq!(
            vm_number_to_big_int(&hex_to_bin(hex), Some(5), None),
            Err(VmNumberError::requiresMinimal.to_string())
        );
        assert_eq!(
            vm_number_to_big_int(&hex_to_bin(hex), Some(5), Some(true)),
            Err(VmNumberError::requiresMinimal.to_string())
        );
    }
    for (non_minimal, minimal) in EQUIVALENT_VM_NUMBERS {
        assert_eq!(
            vm_number_to_big_int(&hex_to_bin(non_minimal), Some(5), Some(false)),
            vm_number_to_big_int(&hex_to_bin(minimal), Some(5), Some(true))
        );
    }
    assert_eq!(
        vm_number_to_big_int(&hex_to_bin("abcdef1234"), Some(4), None),
        Err(VmNumberError::outOfRange.to_string())
    );
    assert_eq!(
        vm_number_to_big_int(&hex_to_bin("abcdef1234"), Some(5), None),
        Ok(big(223_656_005_035))
    );
}

#[test]
fn big_int_to_vm_number_() {
    for (hex, value) in MINIMALLY_ENCODED_VM_NUMBERS {
        assert_eq!(bin_to_hex(&big_int_to_vm_number(&big(*value))), *hex);
    }
}

// TODO: more test vectors
#[test]
fn stack_element_is_truthy() {
    assert_eq!(stack_item_is_truthy(&big_int_to_vm_number(&big(0))), false);
    assert_eq!(stack_item_is_truthy(&big_int_to_vm_number(&big(1))), true);
}

#[test]
fn boolean_to_vm_number_() {
    assert_eq!(boolean_to_vm_number(false), big_int_to_vm_number(&big(0)));
    assert_eq!(boolean_to_vm_number(true), big_int_to_vm_number(&big(1)));
}
