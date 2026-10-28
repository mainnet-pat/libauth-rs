//! Port of `docs.spec.ts`.
//!
//! This file tests all examples included in the repo's `docs` directory.
//!
//! `console.log` calls are kept as `println!`. Where libauth's examples rely on
//! the default `throwErrors: true` behavior (the function throws on error),
//! the Rust result is unwrapped.

use std::collections::BTreeMap;
use std::rc::Rc;

use libauth::runtime::json::Json;
use libauth::{
    assert_success, attempt_cash_address_format_error_correction, bin_to_hex, bins_are_equal,
    cash_address_to_locking_bytecode,
    crack_hd_private_node_from_hd_public_node_and_child_private_node, create_instruction_set_bch,
    create_virtual_machine, create_virtual_machine_bch, decode_cash_address,
    decode_cash_address_format, decode_hd_private_key, decode_hd_public_key,
    decode_private_key_wif, decode_transaction, decode_transaction_outputs, derive_hd_path,
    derive_hd_path_relative, derive_hd_private_node_from_bip39_mnemonic, derive_hd_public_key,
    derive_hd_public_node, encode_bip39_mnemonic, encode_cash_address, encode_cash_address_format,
    encode_hd_private_key, encode_hd_public_key, encode_private_key_wif, generate_bip39_mnemonic,
    generate_deterministic_entropy, generate_private_key, hd_private_key_to_p2pkh_cash_address,
    hd_public_key_to_p2pkh_cash_address, hex_to_bin, locking_bytecode_to_cash_address,
    private_key_to_p2pkh_cash_address, public_key_to_p2pkh_cash_address, push_to_stack, range,
    ripemd160, secp256k1, sha256, split_every, stringify, stringify_debug_trace_summary,
    summarize_debug_trace, use_three_stack_items, utf8_to_bin, wallet_template_to_compiler_bch,
    AuthenticationProgramStateStack, AuthenticationVirtualMachineIdentifier,
    CashAddressDecodingError, CashAddressResult, CashAddressType, DecodedCashAddress,
    DecodedCashAddressLockingBytecode, DecodedHdKey, DecodedPrivateKeyWif, HdKeyNetwork,
    HdNodeValid, HdPrivateNode, HdPrivateNodeValid, InstructionSet, OpcodesBch,
    ResolvedTransactionCommon, WalletImportFormatType, WalletTemplate, WalletTemplateLockingType,
    WalletTemplateScriptDefinition, WalletTemplateScriptLocking, WalletTemplateScriptUnlocking,
};

/// libauth's `deriveHdPrivateNodeFromBip39Mnemonic` returns an
/// `HdPrivateNodeValid` (throwing in the astronomically unlikely case of an
/// invalid node); the Rust function returns an `HdPrivateNode`.
fn valid_private_node(node: HdPrivateNode) -> HdPrivateNodeValid {
    match node {
        HdPrivateNode::Valid(node) => node,
        HdPrivateNode::Invalid(node) => panic!("invalid HD private node: {node:?}"),
    }
}

/// The private node of a derived [`HdNodeValid`] (libauth's derivation
/// functions return an `HdPrivateNodeValid` for a private input node).
fn private(node: HdNodeValid) -> HdPrivateNodeValid {
    match node {
        HdNodeValid::Private(node) => node,
        HdNodeValid::Public(node) => panic!("expected a private node: {node:?}"),
    }
}

/// libauth's `stringify` renders a `Uint8Array` as `<Uint8Array: 0x…>`. The
/// Rust `stringify` accepts a `Json` document, so the decoded address is first
/// converted to one (with libauth's property names, in libauth's order).
fn decoded_cash_address_to_json(decoded: &DecodedCashAddress) -> Json {
    Json::Object(vec![
        (
            "payload".to_string(),
            Json::String(format!("<Uint8Array: 0x{}>", bin_to_hex(&decoded.payload))),
        ),
        ("prefix".to_string(), Json::String(decoded.prefix.clone())),
        (
            "type".to_string(),
            Json::String(decoded.address_type.as_str().to_string()),
        ),
    ])
}

/// JavaScript's `parseInt(string, radix)` for the one-character strings of
/// these examples, as called by `.map(parseInt)` (which passes each element's
/// index as the `radix`): `None` represents `NaN`.
fn parse_int(string: &str, radix: usize) -> Option<u32> {
    let radix = if radix == 0 { 10 } else { radix };
    if !(2..=36).contains(&radix) {
        return None;
    }
    u32::from_str_radix(string, radix as u32).ok()
}

#[test]
fn addresses_md_encode_cash_addresses() {
    let public_key_hash = hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d");
    let CashAddressResult { address } = encode_cash_address(
        &public_key_hash,
        None,
        CashAddressType::P2pkh,
        /* throwErrors: false // (for type-safe handling of untrusted `payload`s) */
    )
    .unwrap();
    println!("{address}");
    // => bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6
    assert_eq!(address, "bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6");

    let testnet = encode_cash_address(&public_key_hash, Some("bchtest"), CashAddressType::P2pkh)
        .unwrap()
        .address;
    println!("{testnet}");
    // => bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x
    assert_eq!(testnet, "bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x");

    let accepts_tokens = encode_cash_address(
        &public_key_hash,
        Some("bitcoincash"),
        CashAddressType::P2pkhWithTokens,
    )
    .unwrap()
    .address;
    println!("{accepts_tokens}");
    // => bitcoincash:zq2azmyyv6dtgczexyalqar70q036yund5j2mspghf
    assert_eq!(
        accepts_tokens,
        "bitcoincash:zq2azmyyv6dtgczexyalqar70q036yund5j2mspghf"
    );
}

#[test]
fn addresses_md_decode_cash_addresses() {
    let address = "bitcoincash:zq2azmyyv6dtgczexyalqar70q036yund5j2mspghf";
    /*
     * If encoding is always expected to succeed, i.e. no user input is
     * involved, we can `assertSuccess` to remove the error `string` possibility
     * from the return type and use the address immediately (if an encoding
     * error occurs at runtime, `assertSuccess` will simply throw it in a new
     * `Error` object).
     */
    let token_address = assert_success(decode_cash_address(address), None);
    println!("{}", stringify(&decoded_cash_address_to_json(&token_address), None));
    /*
     * => {
     *  "payload": "<Uint8Array: 0x15d16c84669ab46059313bf0747e781f1d13936d>",
     *  "prefix": "bitcoincash",
     *  "type": "p2pkhWithTokens"
     * }
     */
    assert_eq!(
        stringify(&decoded_cash_address_to_json(&token_address), None),
        r#"{
  "payload": "<Uint8Array: 0x15d16c84669ab46059313bf0747e781f1d13936d>",
  "prefix": "bitcoincash",
  "type": "p2pkhWithTokens"
}"#
    );

    // Handling a possibly-invalid CashAddress:
    let decoded = decode_cash_address("bitcoincash:not_a_valid_address");
    // Handle any decoding errors:
    let DecodedCashAddress {
        payload,
        prefix,
        address_type,
    } = match decoded {
        Err(decoded) => {
            let handle_error = |error: &str| {
                assert_eq!(
                    error,
                    "CashAddress decoding error: the payload contains unexpected characters. Invalid characters: o, _, i."
                );
            };
            handle_error(&decoded); // => 'CashAddress decoding error: the payload contains unexpected characters. Invalid characters: o, _, i.'
            return;
        }
        Ok(decoded) => decoded,
    };
    panic!(
        "Should be unreachable. ({}; {prefix}; {address_type})",
        bin_to_hex(&payload)
    );
}

#[test]
fn addresses_md_cash_address_to_locking_bytecode() {
    let address = "bitcoincash:zq2azmyyv6dtgczexyalqar70q036yund5j2mspghf";
    // With `assertSuccess`, any errors are simply thrown
    let DecodedCashAddressLockingBytecode {
        bytecode,
        prefix,
        token_support,
    } = assert_success(cash_address_to_locking_bytecode(address), None);

    println!(
        "
Network: {prefix}
Supports tokens: {token_support}
Locking bytecode: {}
",
        bin_to_hex(&bytecode)
    );
    /*
     * =>
     * Network: bitcoincash
     * Supports tokens: true
     * Locking bytecode: 76a91415d16c84669ab46059313bf0747e781f1d13936d88ac
     */
    assert_eq!(
        format!(
            "
Network: {prefix}
Supports tokens: {token_support}
Locking bytecode: {}
",
            bin_to_hex(&bytecode)
        ),
        "
Network: bitcoincash
Supports tokens: true
Locking bytecode: 76a91415d16c84669ab46059313bf0747e781f1d13936d88ac
"
    );
}

#[test]
fn addresses_md_locking_bytecode_to_cash_address() {
    let p2pkh_bytecode = hex_to_bin("76a914fc916f213a3d7f1369313d5fa30f6168f9446a2d88ac");
    let p2pkh = locking_bytecode_to_cash_address(Some("bitcoincash"), &p2pkh_bytecode, None);
    // With `assertSuccess`, any errors are simply thrown
    println!("{}", assert_success(p2pkh.clone(), None).address);
    // => "bitcoincash:qr7fzmep8g7h7ymfxy74lgc0v950j3r2959lhtxxsl"
    assert_eq!(
        assert_success(p2pkh, None).address,
        "bitcoincash:qr7fzmep8g7h7ymfxy74lgc0v950j3r2959lhtxxsl"
    );

    let p2pk = hex_to_bin("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac");
    let genesis_coinbase = locking_bytecode_to_cash_address(Some("bitcoincash"), &p2pk, None);
    println!("{genesis_coinbase:?}");
    // => "CashAddress encoding error: no CashAddress type bit has been standardized for P2PK locking bytecode."
    assert_eq!(
        genesis_coinbase,
        Err("CashAddress encoding error: no CashAddress type bit has been standardized for P2PK locking bytecode.".to_string())
    );

    let p2sh32 = hex_to_bin("aa20000000000000000000000000000012345678900000000000000000000000000087");
    let p2sh32_with_tokens = locking_bytecode_to_cash_address(Some("bchtest"), &p2sh32, Some(true));
    println!("{}", assert_success(p2sh32_with_tokens.clone(), None).address);
    // => "bchtest:rvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqszvpgjlk"
    assert_eq!(
        assert_success(p2sh32_with_tokens, None).address,
        "bchtest:rvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqszvpgjlk"
    );

    let non_standard = hex_to_bin("52935387");
    let non_standard_address =
        locking_bytecode_to_cash_address(Some("bitcoincash"), &non_standard, None);
    println!("{non_standard_address:?}");
    // => "CashAddress encoding error: unknown locking bytecode type."
    assert_eq!(
        non_standard_address,
        Err("CashAddress encoding error: unknown locking bytecode type.".to_string())
    );
}

#[test]
fn addresses_md_cash_address_format() {
    let tx_id = "978306aa4e02fd06e251b38d2e961f78f4af2ea6524a3e4531126776276a6af1";
    // With `assertSuccess`, any errors are simply thrown
    let CashAddressResult { address } = assert_success(
        encode_cash_address_format(&hex_to_bin(tx_id), "bitauth", 3),
        None,
    );
    println!("Encoded authbase: {address}");
    assert_eq!(
        format!("Encoded authbase: {address}"),
        "Encoded authbase: bitauth:qwtcxp42fcp06phz2xec6t5krau0ftew5efy50j9xyfxwa38df40zp58z6t5w"
    );

    let payload = assert_success(decode_cash_address_format(&address), None).payload;
    println!("Encoded TXID: {}", bin_to_hex(&payload));

    assert_eq!(
        format!("Encoded TXID: {}", bin_to_hex(&payload)),
        "Encoded TXID: 978306aa4e02fd06e251b38d2e961f78f4af2ea6524a3e4531126776276a6af1"
    );
}

#[test]
fn addresses_md_cash_address_error_correction() {
    let ask_user_to_try_again = |message: &str| {
        assert_eq!(
            message,
            "You entered:  bch-est:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0z
Errors:       ---^---------------------------------------------^

Please review the address for errors and try again."
        );
    };
    let maybe_address = "bch-est:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0z";
    /* result.address is 'bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x' */

    let result = match attempt_cash_address_format_error_correction(maybe_address) {
        Err(result) => {
            ask_user_to_try_again(&result);
            return;
        }
        Ok(result) => result,
    };

    if result.corrections.is_empty() {
        // `return maybeAddress;`: AVA fails a test which finishes without
        // running any assertions.
        panic!("Test finished without running any assertions");
    }

    let point_to_corrections = |c: &[usize]| -> String {
        (0..c[c.len() - 1] + 1)
            .map(|i| if c.contains(&i) { '^' } else { '-' })
            .collect()
    };
    let message = format!(
        "You entered:  {maybe_address}
Errors:       {}

Please review the address for errors and try again.",
        point_to_corrections(&result.corrections)
    );
    ask_user_to_try_again(&message);
}

#[test]
fn addresses_md_libauth_secret_key_error_correction() {
    let prompt_user_to_backup = |message: &str| {
        assert_eq!(message, "secret-key:qqqq-zqsr-qszs-vpcg-py9q-krqd-pc8s-5c6s-605f");
    };
    let ask_user_to_try_again = |error: &str| {
        panic!("{error}");
    };

    let payload: Vec<u8> = range(16, None).into_iter().map(|value| value as u8).collect();
    let prefix = "secretkey";
    let raw = encode_cash_address_format(&payload, prefix, 0).unwrap().address;
    let hyphenated = format!("secret-key:{}", split_every(&raw[10..], 4).join("-"));
    prompt_user_to_backup(&hyphenated);
    // => 'secret-key:qqqq-zqsr-qszs-vpcg-py9q-krqd-pc8s-5c6s-605f'

    /* Later, to restore from the backup: */

    let user_enters = "secret-key:qqqq-zasr-qszs-vpcg-py9q-krqd-pc8s-sc6s-605f";
    /* `q` mistakenly transcribed as `a` ^,    `5` transcribed as `s` ^  */

    let compressed = user_enters.replace('-', "");
    let result = match attempt_cash_address_format_error_correction(&compressed) {
        Err(result) => {
            ask_user_to_try_again(&result);
            return;
        }
        Ok(result) => result,
    };

    let corrected = assert_success(decode_cash_address_format(&result.address), None);
    println!("{}", bins_are_equal(&payload, &corrected.payload));
    // => true
}

#[test]
fn crypto_md_utf8_to_bin_sha256() {
    let message = utf8_to_bin("Hello world!");
    let hash = sha256.hash(&message);
    let hex = bin_to_hex(&hash);
    println!("{hex}");
    // => 'c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a'
    assert_eq!(
        hex,
        "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
    );
}

#[test]
fn crypto_md_hex_to_bin_ripemd160() {
    let message = hex_to_bin("01020304");
    let hash = ripemd160.hash(&message);
    let hex = bin_to_hex(&hash);
    println!("{hex}");
    // => '179bb366e5e224b8bf4ce302cefc5744961839c5'
    assert_eq!(hex, "179bb366e5e224b8bf4ce302cefc5744961839c5");
}

#[test]
fn crypto_md_incremental_ripemd160() {
    let mut step1 = ripemd160.update(&mut ripemd160.init(), &[0x01]);
    let mut step2 = ripemd160.update(&mut step1, &[0x02]);
    let mut step3 = ripemd160.update(&mut step2, &[0x03]);
    let mut step4 = ripemd160.update(&mut step3, &[0x04]);
    let hash = ripemd160.r#final(&mut step4);
    let hex = bin_to_hex(&hash);
    println!("{hex}");
    // => '179bb366e5e224b8bf4ce302cefc5744961839c5'
    assert_eq!(hex, "179bb366e5e224b8bf4ce302cefc5744961839c5");
}

#[test]
fn crypto_md_secp256k1_verify_signature_der_low_s() {
    let sig = hex_to_bin("");
    let pubkey = hex_to_bin("");
    let msg_hash = hex_to_bin("");
    if secp256k1.verify_signature_der_low_s(&sig, &pubkey, &msg_hash) {
        println!("🚀 Signature valid");
    } else {
        println!("❌ Signature invalid");
    }
    // t.pass();
}

#[test]
fn errors_md_check_for_errors() {
    let ask_user_to_try_again = |_: &str| {
        // t.pass();
    };
    let get_utxos_by_locking_bytecode = |_: &[u8]| {
        panic!("t.fail()");
    };
    // ---
    let address = "bitcoincash:not_a_valid_address";
    let result = cash_address_to_locking_bytecode(address);

    // `decoded` is either a `string` or the result type:
    let result = match result {
        Err(result) => {
            ask_user_to_try_again(&result);
            return;
        }
        Ok(result) => result,
    };
    // `result.bytecode` can now be safely accessed:
    get_utxos_by_locking_bytecode(&result.bytecode);
}

#[test]
fn errors_md_assert_success() {
    // libauth's example is `async` (the address book lookup returns a
    // `Promise`); this port's lookup is synchronous.
    let ask_user_to_select_from_address_book =
        || "bchtest:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x".to_string();
    let get_utxos_by_locking_bytecode = |_: &[u8]| {
        // t.pass();
    };
    // ---
    let address = ask_user_to_select_from_address_book();
    // assertSuccess: all address book entries are valid addresses
    let result = assert_success(cash_address_to_locking_bytecode(&address), None);

    // `result.bytecode` can now be safely accessed:
    get_utxos_by_locking_bytecode(&result.bytecode);
}

#[test]
fn errors_md_detect_specific_error() {
    // AVA fails a test which finishes without running any assertions; the
    // only assertion of this example is the `t.pass()` of the matched branch.
    let mut assertions = 0;
    let decoded = cash_address_to_locking_bytecode("bitcoincash:not_a_valid_address");
    match decoded {
        Err(decoded) => {
            if decoded.contains(CashAddressDecodingError::InvalidCharacters.as_str()) {
                // handle matched error
                assertions += 1; // t.pass();
            }
            // handle other errors
        }
        Ok(_) => panic!("t.fail()"),
    }
    assert!(assertions > 0, "Test finished without running any assertions");
}

#[test]
fn errors_md_configure_throw_errors_1() {
    let handle_error = |error: &str| panic!("{error}");
    let public_key_hash = hex_to_bin("15d16c84669ab46059313bf0747e781f1d13936d");
    // `throwErrors: false` (the Rust function always returns a `Result`)
    let result = match encode_cash_address(&public_key_hash, None, CashAddressType::P2pkh) {
        Err(result) => {
            handle_error(&result);
            return;
        }
        Ok(result) => result,
    };
    println!("{}", result.address);
    // => bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6
    assert_eq!(
        result.address,
        "bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund54qgw0wg6"
    );
}

#[test]
fn errors_md_configure_throw_errors_2() {
    let handle_error = |error: &str| {
        assert_eq!(
            error,
            "CashAddress encoding error: no CashAddress type bit has been standardized for P2PK locking bytecode."
        );
    };

    let genesis_coinbase = hex_to_bin("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac");
    let result = match locking_bytecode_to_cash_address(Some("bitcoincash"), &genesis_coinbase, None) {
        Err(result) => {
            handle_error(&result);
            return;
        }
        Ok(result) => result,
    };
    println!("{}", result.address);
    // (unreachable)
    panic!("{}", result.address);
}

#[test]
fn keys_md_wif_encode() {
    let private_key = generate_private_key(None).unwrap();
    let wif = encode_private_key_wif(&private_key, WalletImportFormatType::Mainnet, None);
    println!("{wif}");
    // => "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi"

    assert_eq!(
        decode_private_key_wif(&wif, None),
        Ok(DecodedPrivateKeyWif {
            private_key,
            key_type: WalletImportFormatType::Mainnet,
        })
    );
}

#[test]
fn keys_md_wif_decode() {
    let wif = "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi";
    // (`assertSuccess` simply throws any decoding errors)
    let DecodedPrivateKeyWif { private_key, .. } =
        assert_success(decode_private_key_wif(wif, None), None);

    let CashAddressResult { address } =
        private_key_to_p2pkh_cash_address(&private_key, None, None).unwrap();
    println!("{address}");
    // => "bitcoincash:qrfdnw009wga3yg5ann9v930s8upw2h33s9ahmklw6"

    assert_eq!(
        address,
        "bitcoincash:qrfdnw009wga3yg5ann9v930s8upw2h33s9ahmklw6"
    );
}

#[test]
fn keys_md_generate_a_random_bip39_mnemonic_phrase() {
    let phrase = generate_bip39_mnemonic().unwrap();
    println!("{phrase}");
    // => "legal winner thank year wave sausage worth useful legal winner thank yellow"

    assert_eq!(phrase.split(' ').count(), 12);
}

#[test]
fn keys_md_bip39_mnemonic_phrase_from_coin_flips() {
    /* 128 simulate coin flips (`binToBinString(generateRandomBytes(16))`) */
    let flip128 = "11101000100010110101110111110111000110000001011110001110111011001001111011010011000111000110000010100110101101110100110000001111";

    let faces = 2;
    // `splitEvery(flip128, 1).map(parseInt)`: `map` passes each index as the
    // radix, so most events are `NaN` (e.g. `parseInt('1', 1)` and every
    // radix above 36); `generateDeterministicEntropy` hashes
    // `events.join('')`, so each `NaN` contributes the characters "NaN" (as
    // zero bytes), and the expected phrase below depends on that behavior.
    let events: Vec<f64> = split_every(flip128, 1)
        .iter()
        .enumerate()
        .map(|(index, digit)| parse_int(digit, index).map_or(f64::NAN, f64::from))
        .collect();
    /* `assertSuccess` simply throws any errors */
    let entropy = assert_success(generate_deterministic_entropy(faces, &events, None, None), None);
    /* Slice produced entropy at 16 bytes (128 bits) for 12 words: */
    let phrase = assert_success(encode_bip39_mnemonic(&entropy[..16]), None).phrase;
    println!("{phrase}");
    // => "crawl actual tool rally crazy lab work paper fragile favorite draft income"
    assert_eq!(
        phrase,
        "crawl actual tool rally crazy lab work paper fragile favorite draft income"
    );
}

#[test]
fn keys_md_bip39_mnemonic_phrase_from_coin_flips_error() {
    let flip10 = "1110100010";
    let faces = 2;
    // `splitEvery(flip10, 1).map(parseInt)` yields `[1, NaN, 1, 0, 1, 0, 0, 0,
    // 1, 0]`.
    let events: Vec<f64> = split_every(flip10, 1)
        .iter()
        .enumerate()
        .map(|(index, digit)| parse_int(digit, index).map_or(f64::NAN, f64::from))
        .collect();
    let result = generate_deterministic_entropy(faces, &events, None, None);
    println!("{result:?}");
    // => "Entropy generation error: the provided list of events contains insufficient entropy. With 2 possible results per event, a minimum of 128 events are required to obtain sufficient entropy. Events provided: 10."
    assert_eq!(
        result,
        Err("Entropy generation error: the provided list of events contains insufficient entropy. With 2 possible results per event, a minimum of 128 events are required to obtain sufficient entropy. Events provided: 10.".to_string())
    );
}

#[test]
fn keys_md_bip39_mnemonic_phrase_from_dice_rolls() {
    /* Fifty, 6-sided dice rolls */
    let events: [f64; 50] = [
        1.0, 5.0, 5.0, 2.0, 2.0, 3.0, 6.0, 4.0, 4.0, 3.0, 2.0, 4.0, 4.0, 6.0, 3.0, 3.0, 6.0, 3.0, 6.0, 5.0, 3.0, 5.0, 1.0, 4.0, 2.0, 5.0, 1.0, 1.0, 3.0, 1.0,
        3.0, 2.0, 3.0, 5.0, 5.0, 6.0, 5.0, 6.0, 2.0, 2.0, 5.0, 2.0, 5.0, 5.0, 4.0, 3.0, 5.0, 3.0, 6.0, 3.0,
    ];
    let faces = 6;
    /*
     * `generateDeterministicEntropy` is designed to be easily verified, e.g.:
     * $ echo -n 15522364432446336365351425113132355656225255435363 | sha256sum
     * 8d270d32340c28d8708023a5becf5dd8d55da45808c2ba97cfb7c2b0dcfefad1
     */
    let entropy = assert_success(generate_deterministic_entropy(faces, &events, None, None), None);
    println!("{}", bin_to_hex(&entropy));
    // => "8d270d32340c28d8708023a5becf5dd8d55da45808c2ba97cfb7c2b0dcfefad1"
    assert_eq!(
        bin_to_hex(&entropy),
        "8d270d32340c28d8708023a5becf5dd8d55da45808c2ba97cfb7c2b0dcfefad1"
    );
    /* Slice produced entropy at 16 bytes (128 bits) for 12 words: */
    let phrase = assert_success(encode_bip39_mnemonic(&entropy[..16]), None).phrase;
    println!("{phrase}");
    // => "minor debris erode gym secret history search afford pizza wait student ranch"
    assert_eq!(
        phrase,
        "minor debris erode gym secret history search afford pizza wait student ranch"
    );
}

#[test]
fn keys_md_bip39_mnemonic_phrase_to_bch_wallet() {
    let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let node = valid_private_node(derive_hd_private_node_from_bip39_mnemonic(
        mnemonic, None, None, None,
    ));
    /*
     * SLIP44 standardizes `m/44'/145'` as the derivation path for BCH accounts,
     * followed by a hardened index for te account number (here, account `0`).
     */
    let bch_account0 = derive_hd_path(&HdNodeValid::Private(node), "m/44'/145'/0'", None).unwrap();
    /*
     * From account 0, derive the private key for external address 0 (as
     * standardized by BIP44):
     */
    let HdPrivateNodeValid { private_key, .. } =
        private(derive_hd_path_relative(&bch_account0, "0/0", None).unwrap());
    let CashAddressResult { address } =
        assert_success(private_key_to_p2pkh_cash_address(&private_key, None, None), None);
    println!("{address}");
    // => "bitcoincash:qpdtccrxx78kcuc65mceurfwg60gmmqu9cwpjdt25n"
    assert_eq!(
        address,
        "bitcoincash:qpdtccrxx78kcuc65mceurfwg60gmmqu9cwpjdt25n"
    );
}

#[test]
fn keys_md_derive_a_watch_only_wallet_1() {
    let node = private(
        derive_hd_path(
            &HdNodeValid::Private(valid_private_node(derive_hd_private_node_from_bip39_mnemonic(
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                None,
                None,
                None,
            ))),
            "m/44'/145'/0'",
            None,
        )
        .unwrap(),
    );
    let hd_private_key = encode_hd_private_key(
        &DecodedHdKey {
            network: HdKeyNetwork::Mainnet,
            node,
        },
        None,
    )
    .unwrap()
    .hd_private_key;
    // hdPrivateKey: "xprv9yG4X8zfB77WS2vwx49tbDtHE1Cyq5wQe2iFcGy5jhizqSEgh22ZXzBaFpMYbLJN4EK459UgFWAxb5rSwzqzx6gw7xxH8z5vvcvUi4oFQqj"
    assert_eq!(
        hd_private_key,
        "xprv9yG4X8zfB77WS2vwx49tbDtHE1Cyq5wQe2iFcGy5jhizqSEgh22ZXzBaFpMYbLJN4EK459UgFWAxb5rSwzqzx6gw7xxH8z5vvcvUi4oFQqj"
    );
    let hd_public_key = derive_hd_public_key(&hd_private_key, None).unwrap().hd_public_key;
    println!("{hd_public_key}");
    // => "xpub6CFQveXZ1UfoeX1R45gtxMq1n33UEYfG1FdrQfNhJ3FyiEZqEZLp5nW474QiDWfVQ6NGk5iPv1h14Vhz2CtzNkGNhimgUucyUtWGdMdofhe"
    assert_eq!(
        hd_public_key,
        "xpub6CFQveXZ1UfoeX1R45gtxMq1n33UEYfG1FdrQfNhJ3FyiEZqEZLp5nW474QiDWfVQ6NGk5iPv1h14Vhz2CtzNkGNhimgUucyUtWGdMdofhe"
    );
}

#[test]
fn keys_md_derive_a_watch_only_wallet_2() {
    let hd_public_key = "xpub6CFQveXZ1UfoeX1R45gtxMq1n33UEYfG1FdrQfNhJ3FyiEZqEZLp5nW474QiDWfVQ6NGk5iPv1h14Vhz2CtzNkGNhimgUucyUtWGdMdofhe";

    let node = assert_success(decode_hd_public_key(hd_public_key, None), None).node;
    let public_key = match derive_hd_path_relative(&HdNodeValid::Public(node), "0/0", None).unwrap() {
        HdNodeValid::Public(node) => node.public_key,
        HdNodeValid::Private(node) => panic!("expected a public node: {node:?}"),
    };
    let CashAddressResult { address } =
        public_key_to_p2pkh_cash_address(&public_key, None, None).unwrap();
    println!("{address}");
    // => "bitcoincash:qpdtccrxx78kcuc65mceurfwg60gmmqu9cwpjdt25n"
    assert_eq!(
        address,
        "bitcoincash:qpdtccrxx78kcuc65mceurfwg60gmmqu9cwpjdt25n"
    );
}

#[test]
fn keys_md_crack_hd_private_node_from_hd_public_node_and_child_private_node() {
    let hd_private_key = "xprv9yG4X8zfB77WS2vwx49tbDtHE1Cyq5wQe2iFcGy5jhizqSEgh22ZXzBaFpMYbLJN4EK459UgFWAxb5rSwzqzx6gw7xxH8z5vvcvUi4oFQqj";
    let hd_public_key = derive_hd_public_key(hd_private_key, None).unwrap().hd_public_key;
    let hd_private_node = assert_success(decode_hd_private_key(hd_private_key, None), None).node;
    let hd_public_node = assert_success(decode_hd_public_key(&hd_public_key, None), None).node;

    /*
     * The HD public key is shared with an observer, and somehow, the observer
     * gains access to a non-hardened child private key (in this case, the key
     * at index `1234`.)
     */
    let some_child_node = private(
        derive_hd_path_relative(&HdNodeValid::Private(hd_private_node), "1234", None).unwrap(),
    );

    /*
     * The observer can now trivially derive the parent HD private key using
     * the HD public key:
     */
    let parent_key = encode_hd_private_key(
        &DecodedHdKey {
            network: HdKeyNetwork::Mainnet,
            node: assert_success(
                crack_hd_private_node_from_hd_public_node_and_child_private_node(
                    &hd_public_node,
                    &some_child_node,
                    None,
                ),
                None,
            ),
        },
        None,
    )
    .unwrap()
    .hd_private_key;
    println!("{parent_key}");
    // => "xprv9yG4X8zfB77WS2vwx49tbDtHE1Cyq5wQe2iFcGy5jhizqSEgh22ZXzBaFpMYbLJN4EK459UgFWAxb5rSwzqzx6gw7xxH8z5vvcvUi4oFQqj"
    assert_eq!(
        parent_key,
        "xprv9yG4X8zfB77WS2vwx49tbDtHE1Cyq5wQe2iFcGy5jhizqSEgh22ZXzBaFpMYbLJN4EK459UgFWAxb5rSwzqzx6gw7xxH8z5vvcvUi4oFQqj"
    );
}

#[test]
fn verify_transactions_md_simple_verification() {
    let vm = create_virtual_machine_bch(Some(true));
    /* Example transaction from Virtual Machine Bytecode (VMB) test ID: "dv5k4" */
    struct VmbTestExample {
        #[allow(dead_code)]
        description: &'static str,
        #[allow(dead_code)]
        id: &'static str,
        tx: Vec<u8>,
        utxos: Vec<u8>,
    }
    let vmb_test = VmbTestExample {
        description: "Basic push operations: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (P2SH20)",
        id: "dv5k4",
        tx: hex_to_bin("020000000201000000000000000000000000000000000000000000000000000000000000000000000064417dfb529d352908ee0a88a0074c216b09793d6aa8c94c7640bb4ced51eaefc75d0aef61f7685d0307491e2628da3d4f91e86329265a4a58ca27a41ec0b8910779c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7850000000001000000000000000000000000000000000000000000000000000000000000000100000006000482008777000000000100000000000000000a6a08766d625f7465737400000000"),
        utxos: hex_to_bin("0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000017a91498e86c508e780cfb822bba3d5ab9b3e30450196b87"),
    };

    /* Decode the transaction, throwing any errors */
    let transaction = assert_success(decode_transaction(&vmb_test.tx), None);
    /* Decode the serialized outputs, throwing any errors */
    let source_outputs = assert_success(decode_transaction_outputs(&vmb_test.utxos), None);

    // Result is either `true` or an error message (`string`)
    let result = vm.verify(&ResolvedTransactionCommon {
        source_outputs,
        transaction,
    });

    match result {
        Err(result) => {
            eprintln!("{result}");
            panic!("t.fail()");
        }
        Ok(()) => {
            println!("Transaction verified 🚀");
            // t.pass();
        }
    }
}

#[test]
fn verify_transactions_md_add_op_unrot() {
    let instruction_set = create_instruction_set_bch(Some(true), None, None, None, None, None);
    /*
     * A hypothetical "OP_UNROT" which rotates the top stack items in the
     * direction opposite that of OP_ROT. (The generic `<State extends ...>`
     * is only necessary for TypeScript usage.)
     */
    let op_un_rot = |state: &mut AuthenticationProgramStateStack| {
        use_three_stack_items(state, |next_state, [a, b, c]| {
            push_to_stack(next_state, vec![c, a, b], None);
        });
    };

    /* We assign "OP_UNROT" at the index held by "OP_RESERVED1" */
    let opcode = OpcodesBch::OP_RESERVED1;
    /* All other features of the BCH instruction set are unmodified: */
    let mut operations = instruction_set.operations.clone();
    operations.insert(opcode, Rc::new(op_un_rot));
    let vm = create_virtual_machine(InstructionSet {
        operations,
        ..instruction_set
    });

    let op_unrot = format!("0x{}", bin_to_hex(&[opcode]));
    /* A compiler for a simple wallet template to test the new opcode: */
    let compiler = wallet_template_to_compiler_bch(
        &WalletTemplate {
            schema: None,
            description: None,
            entities: BTreeMap::new(),
            name: None,
            scenarios: None,
            scripts: BTreeMap::from([
                (
                    "lock".to_string(),
                    WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                        name: None,
                        locking_type: WalletTemplateLockingType::P2sh20,
                        script: format!("{op_unrot} OP_CAT OP_CAT <0x030102> OP_EQUAL"),
                    }),
                ),
                (
                    "unlock".to_string(),
                    WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                        name: None,
                        script: "<1> <2> <3>".to_string(),
                        age_lock: None,
                        estimate: None,
                        fails: None,
                        invalid: None,
                        passes: None,
                        time_lock_type: None,
                        unlocks: "lock".to_string(),
                    }),
                ),
            ]),
            supported: vec![AuthenticationVirtualMachineIdentifier::BchSpec],
            version: None,
        },
        None,
    );

    /* Generate a testing scenario, throwing any errors */
    let program = assert_success(compiler.generate_scenario(None, None, Some("unlock")), None).program;

    /* Debug the `program`: an inputIndex, sourceOutputs, and transaction */
    let trace = vm.debug(&program, None);
    let summary = summarize_debug_trace(&trace);
    // `{ ...OpcodesBch, [opcode]: 'OP_UNROT' }` (later entries take precedence)
    let mut opcodes = OpcodesBch::MEMBERS.to_vec();
    opcodes.push(("OP_UNROT", opcode));
    let formatted = stringify_debug_trace_summary(&summary, Some(&opcodes), None, None);
    println!("{formatted}");

    assert_eq!(
        formatted,
        "0. OP_1:                0x01(1)
1. OP_2:                0x01(1) 0x02(2)
2. OP_3:                0x01(1) 0x02(2) 0x03(3)
3. OP_PUSHBYTES_8:      0x01(1) 0x02(2) 0x03(3) 0x897e7e0303010287(-504967220674068105)
=>                      0x01(1) 0x02(2) 0x03(3) 0x897e7e0303010287(-504967220674068105)
0. OP_HASH160:          0x01(1) 0x02(2) 0x03(3) 0x1e2083f589fd7943289cfaba1dcdc50e395f3019
1. OP_PUSHBYTES_20:     0x01(1) 0x02(2) 0x03(3) 0x1e2083f589fd7943289cfaba1dcdc50e395f3019 0x1e2083f589fd7943289cfaba1dcdc50e395f3019
2. OP_EQUAL:            0x01(1) 0x02(2) 0x03(3) 0x01(1)
=>                      0x01(1) 0x02(2) 0x03(3)
0. OP_UNROT:            0x03(3) 0x01(1) 0x02(2)
1. OP_CAT:              0x03(3) 0x0102(513)
2. OP_CAT:              0x030102(131331)
3. OP_PUSHBYTES_3:      0x030102(131331) 0x030102(131331)
4. OP_EQUAL:            0x01(1)
=>                      0x01(1)"
    );
}

#[test]
fn wallets_md_hd_private_key_to_p2pkh_cash_address() {
    let save_somewhere = |_: &str| {
        // t.pass();
    };

    // let mnemonic = generate_bip39_mnemonic();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    save_somewhere(mnemonic);
    let hd_private_key = encode_hd_private_key(
        &DecodedHdKey {
            network: HdKeyNetwork::Mainnet,
            node: valid_private_node(derive_hd_private_node_from_bip39_mnemonic(
                mnemonic, None, None, None,
            )),
        },
        None,
    )
    .unwrap()
    .hd_private_key;

    /* BCH account standardized by SLIP44 */
    let private_derivation_path = "m/44'/145'/0'/0/i";
    let address_index = 0.0;
    let CashAddressResult { address } = hd_private_key_to_p2pkh_cash_address(
        address_index,
        &hd_private_key,
        None,
        Some(private_derivation_path),
        None,
    )
    .unwrap();
    println!(
        "The address at external BCH account ({private_derivation_path}) index {address_index} is: {address}."
    );
    assert_eq!(
        format!(
            "The address at external BCH account ({private_derivation_path}) index {address_index} is: {address}."
        ),
        "The address at external BCH account (m/44'/145'/0'/0/i) index 0 is: bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6."
    );
}

#[test]
fn wallets_md_hd_public_key_to_p2pkh_cash_address() {
    /* On the signing device: */
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let master_node = valid_private_node(derive_hd_private_node_from_bip39_mnemonic(
        mnemonic, None, None, None,
    ));

    /* BCH account 0 as standardized by SLIP44 */
    let bch_account0 = "m/44'/145'/0'";
    let node = derive_hd_public_node(
        &private(derive_hd_path(&HdNodeValid::Private(master_node), bch_account0, None).unwrap()),
        None,
    )
    .unwrap();
    let hd_public_key = encode_hd_public_key(
        &DecodedHdKey {
            network: HdKeyNetwork::Mainnet,
            node,
        },
        None,
    )
    .unwrap()
    .hd_public_key;

    /* A watch-only observer can derive addresses given only the HD public key: */
    let address_index = 0.0;
    let external_addresses = "0/i"; /* Change addresses use '1/i' */
    let CashAddressResult { address } = hd_public_key_to_p2pkh_cash_address(
        address_index,
        &hd_public_key,
        Some(bch_account0),
        None,
        Some(external_addresses),
        None,
    )
    .unwrap();
    println!(
        "The address at external BCH account 0 ({bch_account0}) index {address_index} is: {address}."
    );
    assert_eq!(
        format!("The address at BCH account 0, external index {address_index} is: {address}."),
        "The address at BCH account 0, external index 0 is: bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6."
    );
}

#[test]
fn wallets_md_private_key_to_p2pkh_cash_address_and_public_key_to_p2pkh_cash_address() {
    let wif = "KxbEv3FeYig2afQp7QEA9R3gwqdTBFwAJJ6Ma7j1SkmZoxC9bAXZ";

    // `assertSuccess` simply throws any decoding errors
    let DecodedPrivateKeyWif { private_key, .. } =
        assert_success(decode_private_key_wif(wif, None), None);
    let CashAddressResult { address } =
        private_key_to_p2pkh_cash_address(&private_key, None, None).unwrap();
    println!("The address is: {address}.");
    assert_eq!(
        format!("The address is: {address}."),
        "The address is: bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6."
    );

    /* Using only the public key: */
    let public_key = assert_success(secp256k1.derive_public_key_compressed(&private_key), None);

    let result = public_key_to_p2pkh_cash_address(&public_key, None, None).unwrap();
    println!("Address derived from the public key: {}.", result.address);
    assert_eq!(
        format!("Address derived from the public key: {}.", result.address),
        "Address derived from the public key: bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6."
    );
}
