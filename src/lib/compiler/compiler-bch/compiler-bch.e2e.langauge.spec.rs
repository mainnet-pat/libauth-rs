//! Port of `compiler/compiler-bch/compiler-bch.e2e.langauge.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "compiler-bch.e2e.spec.helper.rs"]
mod compiler_bch_e2e_spec_helper;

use std::collections::BTreeMap;

use libauth::{
    hex_to_bin, BytecodeGenerationResult, CompilationError, CompilationErrorType, CompilationResultError,
    CompilerConfiguration, Range,
};

use compiler_bch_e2e_spec_helper::expect_compilation_result;

// [BCH compiler] language - empty script
#[test]
fn bch_compiler_language_empty_script() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin(""),
        },
        None,
        None,
    );
}

// [BCH compiler] language - compile BigIntLiterals to VM numbers
#[test]
fn bch_compiler_language_compile_big_int_literals_to_vm_numbers() {
    expect_compilation_result(
        "42 -42 2_147_483_647 -2_147_483_647",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("2aaaffffff7fffffffff"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - compile BinaryLiterals to VM numbers
#[test]
fn bch_compiler_language_compile_binary_literals_to_vm_numbers() {
    expect_compilation_result(
        "0b1 0b1111_1111 0b111 0b1111_1111__1111_1111__1111_1111__1111_1111____1111_1111__1111_1111__1111_1111__1111_1111_1",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("01ff07ffffffffffffffff01"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - compile UTF8Literal (')
#[test]
fn bch_compiler_language_compile_utf8_literal() {
    expect_compilation_result(
        "'abc\"`👍'",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("6162632260f09f918d"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - compile UTF8Literal (")
#[test]
fn bch_compiler_language_compile_utf8_literal_2() {
    expect_compilation_result(
        "\"abc'`👍\"",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("6162632760f09f918d"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - compile HexLiteral
#[test]
fn bch_compiler_language_compile_hex_literal() {
    expect_compilation_result(
        "0xdead__beef",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("deadbeef"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - compile opcodes
#[test]
fn bch_compiler_language_compile_opcodes() {
    expect_compilation_result(
        "OP_0 OP_1 OP_ADD",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("005193"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - comments
#[test]
fn bch_compiler_language_comments() {
    expect_compilation_result(
        "// a comment\n  0xab\n  // another comment\n  0xcd\n  /**\n   * A third, multi-line\n   * comment\n   */\n  0xef\n  ",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("abcdef"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - empty push (push an empty byte array, i.e. OP_0)
#[test]
fn bch_compiler_language_empty_push_push_an_empty_byte_array_i_e_op_0() {
    expect_compilation_result(
        "<>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("00"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - minimize BigIntLiteral pushes
#[test]
fn bch_compiler_language_minimize_big_int_literal_pushes() {
    expect_compilation_result(
        "< -1 > <0> <1> <2> <3> <4> <5> <6> <7> <8> <9> <10> <11> <12> <13> <14> <15> <16> <17>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("4f005152535455565758595a5b5c5d5e5f600111"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - minimize HexLiteral pushes
#[test]
fn bch_compiler_language_minimize_hex_literal_pushes() {
    expect_compilation_result(
        "<0x81> <> <0x01> <0x02> <0x03> <0x04> <0x05> <0x06> <0x07> <0x08> <0x09> <0x0a> <0x0b> <0x0c> <0x0d> <0x0e> <0x0f> <0x10> <0x11>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("4f005152535455565758595a5b5c5d5e5f600111"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - don't minimize <0x00>
#[test]
fn bch_compiler_language_don_t_minimize_0x00() {
    expect_compilation_result(
        "<0x00>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("0100"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - push UTF8Literal
#[test]
fn bch_compiler_language_push_utf8_literal() {
    expect_compilation_result(
        "<\"abc\">",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("03616263"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - push opcodes
#[test]
fn bch_compiler_language_push_opcodes() {
    expect_compilation_result(
        "<OP_0> <OP_1> <OP_2>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("010001510152"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - nested pushes (center minimized to OP_1)
#[test]
fn bch_compiler_language_nested_pushes_center_minimized_to_op_1() {
    expect_compilation_result(
        "<<<<1>>>>",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("03020151"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - complex script
#[test]
fn bch_compiler_language_complex_script() {
    expect_compilation_result(
        "\n// there are plenty of ways to push 0/call OP_0\n<0> OP_0 0x00 <''> <$(OP_0)> <$(< -1 > < 1 > OP_ADD)>\n/**\n * A multi-line comment 🚀\n * Followed by some UTF8Literals\n */\n'abc' \"'🧙'\"\n// a comment at the end\n",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("00000000000061626327f09fa79927"),
        },
        None,
        None,
    );
}

// [BCH compiler] language - compiles internal scripts
#[test]
fn bch_compiler_language_compiles_internal_scripts() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Success {
            bytecode: hex_to_bin("123456"),
        },
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            scripts: BTreeMap::from([
                ("a".to_string(), "b".to_string()),
                ("b".to_string(), "c".to_string()),
                ("c".to_string(), "0x123456".to_string()),
                ("test".to_string(), "a".to_string()),
            ]),
            ..configuration
        }),
    );
}

// [BCH compiler] language - error on cyclical compilations
#[test]
fn bch_compiler_language_error_on_cyclical_compilations() {
    expect_compilation_result(
        "",
        |data| data,
        BytecodeGenerationResult::Error(CompilationResultError {
            error_type: CompilationErrorType::Resolve,
            errors: vec![CompilationError {
                error: "Compilation error in resolved script \"a\": [2, 2] Compilation error in resolved script \"b\": [3, 3] Compilation error in resolved script \"c\": [2, 4] Compilation error in resolved script \"a\": [0, 0] A circular dependency was encountered: script \"a\" relies on itself to be generated. (Source scripts: test → a → b → c); [2, 4] Compilation error in resolved script \"c\": [2, 4] Compilation error in resolved script \"a\": [0, 0] A circular dependency was encountered: script \"a\" relies on itself to be generated. (Source scripts: test → a → c)".to_string(),
                missing_identifier: None,
                owning_entity: None,
                range: Range {
                    end_column: 2,
                    end_line_number: 2,
                    start_column: 1,
                    start_line_number: 2,
                },
            }],
            parse: None,
            reduce: None,
            resolve: None,
        }),
        Some(BTreeMap::new()),
        Some(|configuration| CompilerConfiguration {
            scripts: BTreeMap::from([
                ("a".to_string(), " \n b c".to_string()),
                ("b".to_string(), "  \n\n  c".to_string()),
                ("c".to_string(), "   \n   a".to_string()),
                ("test".to_string(), "\na".to_string()),
            ]),
            ..configuration
        }),
    );
}
