//! Port of `compiler/compiler-bch/compiler-bch.e2e.spec.helper.ts`.
#![allow(dead_code, non_upper_case_globals)]

use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::LazyLock;

use libauth::{
    compiler_configuration_to_compiler_bch, compiler_operations_bch, create_authentication_program_evaluation_common,
    create_compilation_context_common_testing, create_virtual_machine_bch, generate_bytecode_map, hex_to_bin,
    ripemd160, secp256k1, sha256, sha512, AuthenticationVirtualMachineBch, BytecodeGenerationResult, CompilationData,
    CompilerConfiguration, OpcodesBch, WalletTemplateVariable,
};

/// `m`
pub const hdPrivateKey: &str =
    "xprv9s21ZrQH143K2PfMvkNViFc1fgumGqBew45JD8SxA59Jc5M66n3diqb92JjvaR61zT9P89Grys12kdtV4EFVo6tMwER7U2hcUmZ9VfMYPLC";
/// `M`
pub const hdPublicKey: &str =
    "xpub661MyMwAqRbcEsjq2muW5PYkDikFgHuWJGzu1WrZiQgHUsgEeKMtGducsZe1iRsGAGNGDzmWYDM69ya24LMyR7mDhtzqQsc286XEQfM2kkV";

/// HD key at `m/0'`
pub const hdPrivateKeyM0H: &str =
    "xprv9uNAm3qC8EoibXd3mwgQ9rxF8XJdfA9V9sF25DpLtYcf1u51Rpf8tfV4n2PdChXM97miXGiJf6UL2SsathXbiVbF6tSgmAVGM3XNb6Yn2EZ";

/// The public key derived from {@link hdPrivateKeyM0H}.
pub const hdPublicKeyM0H: &str =
    "xpub68MXAZN5xcN1p1hWsyDQWztygZ984csLX6AcscDxSt9dthQ9yMyPSToYdJ24jCS5jaVMGSiLeGuP2cWvgKKYQsNXyg988XGGQYgk1FjDv4P";

/// `m/0`
pub static privateKeyM0: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex_to_bin("f85d4bd8a03ca106c9deb47b791803dac7f0333809e3f1dd04d182e0aba6e553"));

thread_local! {
    static vm: AuthenticationVirtualMachineBch = create_virtual_machine_bch(None);
}

/// The `expectCompilationResult` macro (`test.macro`) as a plain function.
///
/// The TS macro spreads `otherData` over `{ compilationContext:
/// createCompilationContextCommonTesting() }` and `configurationOverrides`
/// over the default configuration; here, each is a function receiving those
/// defaults and returning the spread result (e.g.
/// `|data| CompilationData { keys: ..., ..data }`). `None` for
/// `configuration_overrides` is the TS default (no overrides).
///
/// `BytecodeGenerationResult` does not implement `PartialEq`, so results are
/// compared via their (derived) `Debug` representations, which include every
/// field.
pub fn expect_compilation_result(
    test_script: &str,
    other_data: impl FnOnce(CompilationData) -> CompilationData,
    expected_result: BytecodeGenerationResult,
    variables: Option<BTreeMap<String, WalletTemplateVariable>>,
    configuration_overrides: Option<fn(CompilerConfiguration) -> CompilerConfiguration>,
) {
    let configuration = CompilerConfiguration {
        create_authentication_program: Some(Rc::new(create_authentication_program_evaluation_common)),
        entity_ownership: Some(BTreeMap::from([
            ("one".to_string(), "ownerEntityOne".to_string()),
            ("owner".to_string(), "ownerEntityId".to_string()),
            ("two".to_string(), "ownerEntityTwo".to_string()),
        ])),
        opcodes: Some(generate_bytecode_map(OpcodesBch::MEMBERS)),
        operations: Some(compiler_operations_bch()),
        ripemd160: Some(ripemd160.clone()),
        scripts: BTreeMap::from([
            ("another".to_string(), "0xabcdef".to_string()),
            ("broken".to_string(), "does_not_exist".to_string()),
            ("lock".to_string(), String::new()),
            ("test".to_string(), test_script.to_string()),
        ]),
        secp256k1: Some(secp256k1.clone()),
        sha256: Some(sha256.clone()),
        sha512: Some(sha512.clone()),
        unlocking_scripts: Some(BTreeMap::from([("test".to_string(), "lock".to_string())])),
        variables,
        vm: Some(vm.with(Clone::clone)),
        ..Default::default()
    };
    let compiler = compiler_configuration_to_compiler_bch(match configuration_overrides {
        Some(overrides) => overrides(configuration),
        None => configuration,
    });

    let result_unlock = compiler.generate_bytecode(
        &other_data(CompilationData {
            compilation_context: Some(create_compilation_context_common_testing(None, None, None, None, None)),
            ..Default::default()
        }),
        "test",
    );
    assert_eq!(
        format!("{result_unlock:#?}"),
        format!("{expected_result:#?}"),
        "- \nResult: {result_unlock:#?}\n\nExpected:\n {expected_result:#?}\n"
    );
}
