//! Port of `transaction/fixtures/template.cash-channels-v1.spec.helper.ts`.
#![allow(dead_code, non_upper_case_globals)]

use std::collections::BTreeMap;
use std::sync::LazyLock;

use libauth::{
    AuthenticationVirtualMachineIdentifier, WalletTemplate, WalletTemplateAddressData, WalletTemplateEntity,
    WalletTemplateKey, WalletTemplateLockingType, WalletTemplateScenario, WalletTemplateScenarioBytecode,
    WalletTemplateScenarioBytecodeDefinition, WalletTemplateScenarioData, WalletTemplateScenarioDataHdKeys,
    WalletTemplateScenarioOutput, WalletTemplateScenarioOutputLockingBytecode, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioValueSatoshis, WalletTemplateScriptDefinition, WalletTemplateScriptLocking,
    WalletTemplateScriptTest, WalletTemplateScriptTested, WalletTemplateScriptUnlocking, WalletTemplateVariable,
    WalletTemplateVariableType,
};

pub static cashChannels: LazyLock<WalletTemplate> = LazyLock::new(|| {
    WalletTemplate {
    schema: Some("https://libauth.org/schemas/wallet-template-v0.schema.json".to_string()),
    description: Some("**Noncustodial, Privacy-Preserving, Flexibly-Denominated, Recurring Payments for Bitcoin Cash**\n\nA single-key channel that allows the owner to preauthorize any number of future payments to a receiver.\n\nEach authorization specifies a payment value, payment time, channel and payment identification information, and maximum satoshi value. When the payment time for an authorization is reached, the receiver can create a single transaction to withdraw the authorized amount to their own wallet, sending the change back to the channel. Beyond initially signing authorizations, the owner does not need to participate in executing authorized payments.\n\nThe channel does not need to hold a balance to preauthorize transactions – much like a debit account, the owner only needs to ensure that the wallet contains adequate funds to satisfy upcoming payments.\n\nChannel payments can be denominated in any asset. If the channel is denominated in an asset other than BCH, the precise payment amount is determined by a Rate Oracle, an entity partially-trusted with determining the current value of the denominating asset. (If the value of the denominating asset rises dramatically in terms of BCH, the Owner must sign a new authorization with a larger maximum authorized satoshi value.)\n \nThis wallet is entirely noncustodial: at any time, the owner can withdraw their funds to end the arrangement.\n\nIn normal use, the owner should create a unique channel for each Receiver. This provides better privacy (receivers can not determine the payment amounts or frequency of payments to other receivers) and better security (misbehaving receivers can not disrupt upcoming payments to other receivers).\n\nImplementation note: a single authorization can be used to withdraw from any channel UTXO. In most cases, authorizations are meant to be used only once, so wallets should never hold more than one unspent UTXO per channel. To “top up” the wallet, the existing UTXO should be spent back to itself, adding funds as necessary.".to_string()),
    entities: BTreeMap::from([
        (
            "owner_entity".to_string(),
            WalletTemplateEntity {
                description: Some("The owner of this channel. The owner can pre-sign authorizations or withdraw from the channel at any time.".to_string()),
                name: Some("Owner".to_string()),
                scripts: None,
                variables: Some(BTreeMap::from([
                    (
                        "authorized_amount".to_string(),
                        WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                            description: Some("The value of the authorized payment in terms of the denominating asset encoded as a VM Number, e.g. `10000`.\n\nIf the denominating asset is BCH, this number is represented in satoshis. If the denominating asset is another currency, it should be represented in the smallest common decimal unit of that currency, e.g. for $100.00 \"USD\", this value should be `10000`. All fiat currencies must be represented with 2 decimal places, even for currencies where fractional units are not commonly used, e.g. IRR, VND, IDR.\n\nBecause this value is not operated upon by the locking script, if desired, the value may be encrypted (using a key shared by all entities) so the terms of authorizations are not publicly auditable.".to_string()),
                            name: Some("Authorized Amount".to_string()),
                            r#type: WalletTemplateVariableType::AddressData,
                        }),
                    ),
                    (
                        "denominating_asset".to_string(),
                        WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                            description: Some("The asset in which the Authorized Amount is specified. This should be an identifier (like a currency code or ticker symbol) that is understood by each party, encoded as a UTF8Literal, e.g. `\"BCH\"`, `\"XAU\"`, or `\"USD\"`. \n\nIf desired, the value can be encrypted (using a key shared by all entities) so the exact terms of the transaction are not publicly auditable.".to_string()),
                            name: Some("Denominating Asset".to_string()),
                            r#type: WalletTemplateVariableType::AddressData,
                        }),
                    ),
                    (
                        "maximum_authorized_satoshis".to_string(),
                        WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                            description: Some("The maximum allowed satoshi value of a payment authorization, encoded as a VM Number, e.g. `10000`.\n\nIf the Denominating Asset is BCH, this is the exact value of the payment.\n\nIf the Denominating Asset is not BCH, the exact payment amount is chosen by the Rate Oracle (Payment Satoshis). If the rate has changed dramatically enough that the payment will exceed the Maximum Authorized Satoshis, the authorization is no longer valid, and the Owner must sign another authorization with a higher Maximum Authorized Satoshis value. The Owner should calculate this based on the percentage market price increase they're willing to continue allowing this authorization. E.g.: maximum_authorized_satoshis = current_estimated_satoshis *  (1 + price_flexibility_percentage)".to_string()),
                            name: Some("Maximum Authorized Satoshis".to_string()),
                            r#type: WalletTemplateVariableType::AddressData,
                        }),
                    ),
                    (
                        "owner".to_string(),
                        WalletTemplateVariable::Key(WalletTemplateKey {
                            description: Some("".to_string()),
                            name: Some("Owner's Key".to_string()),
                            never_sign_twice: None,
                            r#type: WalletTemplateVariableType::Key,
                        }),
                    ),
                    (
                        "payment_number".to_string(),
                        WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                            description: Some("The sequence number of this payment, used as an identifier for an authorization. Authorizations must be used in order, and this number should be incremented by one for each authorization signed.\n\nEncoded as a VM Number between 0 and 32767, e.g. `42`.".to_string()),
                            name: Some("Payment Number".to_string()),
                            r#type: WalletTemplateVariableType::AddressData,
                        }),
                    ),
                    (
                        "payment_time".to_string(),
                        WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                            description: Some("The planned Block Time at which an Authorization should become valid for spending. This is also the time at which the Rate Oracle (if present) should determine the Payment Satoshis.\n\nMust be encoded as a VM Number (of up to 5 bytes as is consumed by OP_CHECKLOCKTIMEVERIFY).".to_string()),
                            name: Some("Payment Time".to_string()),
                            r#type: WalletTemplateVariableType::AddressData,
                        }),
                    ),
                ])),
            },
        ),
        (
            "rate_oracle_entity".to_string(),
            WalletTemplateEntity {
                description: Some("The Rate Oracle is an entity trusted with determining the current exchange rate of the denominating asset at each authorization’s payment time. If the denominating asset is BCH, no rate oracle is required.\n\nDepending on the relationship between Owner and Receiver, the Receiver (or a party contracted by the receiver) may also serve as the Rate Oracle. (If the Receiver abuses the role, the Owner can end the arrangement.) In a merchant scenario, the payment processor is a good candidate for Rate Oracle.\n\nThe Rate Oracle’s claims are used by the channel to determine the exact BCH amount of the payment, so long as the rate remains below the maximum satoshi value specified by the authorization.".to_string()),
                name: Some("Rate Oracle".to_string()),
                scripts: None,
                variables: Some(BTreeMap::from([
                    (
                        "payment_satoshis".to_string(),
                        WalletTemplateVariable::AddressData(WalletTemplateAddressData {
                            description: Some("The exact number of satoshis to be paid when executing an authorization. The Rate Oracle decides this value based on the Authorized Amount and the Denominating Asset.\n\nThe Channel restricts this value to never exceed the Maximum Authorized Satoshis specified in the Owner's authorization.".to_string()),
                            name: Some("Payment Satoshis".to_string()),
                            r#type: WalletTemplateVariableType::AddressData,
                        }),
                    ),
                    (
                        "rate_oracle".to_string(),
                        WalletTemplateVariable::Key(WalletTemplateKey {
                            description: Some("".to_string()),
                            name: Some("Rate Oracle's Key".to_string()),
                            never_sign_twice: None,
                            r#type: WalletTemplateVariableType::Key,
                        }),
                    ),
                ])),
            },
        ),
        (
            "receiver_entity".to_string(),
            WalletTemplateEntity {
                description: Some("The entity designated as the recipient of all channel payments. \n\nThe receiver holds authorizations signed by the Owner. When the payment time of an authorization is reached, the Receiver can create a transaction for the value specified by the authorization, spending the change back to the channel.".to_string()),
                name: Some("Receiver".to_string()),
                scripts: None,
                variables: Some(BTreeMap::from([(
                    "receiver".to_string(),
                    WalletTemplateVariable::Key(WalletTemplateKey {
                        description: Some("".to_string()),
                        name: Some("Receiver's Key".to_string()),
                        never_sign_twice: None,
                        r#type: WalletTemplateVariableType::Key,
                    }),
                )])),
            },
        ),
    ]),
    name: Some("CashChannels".to_string()),
    scenarios: Some(BTreeMap::from([
        (
            "after_payment_time".to_string(),
            WalletTemplateScenario {
                data: None,
                description: Some("An example of successful payment authorization execution.".to_string()),
                extends: Some("before_payment_time".to_string()),
                name: Some("$10.00 USD – After Payment Time".to_string()),
                source_outputs: None,
                transaction: Some(WalletTemplateScenarioTransaction {
                    inputs: None,
                    locktime: Some(1580515200.0),
                    outputs: None,
                    version: None,
                }),
            },
        ),
        (
            "before_payment_time".to_string(),
            WalletTemplateScenario {
                data: Some(WalletTemplateScenarioData {
                    bytecode: Some(BTreeMap::from([
                        ("authorized_amount".to_string(), "1000".to_string()),
                        ("denominating_asset".to_string(), "'USD'".to_string()),
                        ("maximum_authorized_satoshis".to_string(), "10500".to_string()),
                        ("payment_number".to_string(), "2".to_string()),
                        ("payment_satoshis".to_string(), "10000".to_string()),
                        ("payment_time".to_string(), "1580515200".to_string()),
                    ])),
                    current_block_height: None,
                    current_block_time: None,
                    hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                        address_index: Some(0.0),
                        hd_private_keys: None,
                        hd_public_keys: None,
                    }),
                    keys: None,
                }),
                description: Some("An example attempting to execute a payment authorization before the payment time authorized by the owner. The authorization is for \"1000\" in asset \"USD\" (described in cents, so $10.00 USD), and it authorizes a payment of a maximum of 10500 satoshis. The hypothetical UTXO being spent has a value of 20000 satoshis.".to_string()),
                extends: None,
                name: Some("$10.00 USD – Before Payment Time".to_string()),
                source_outputs: Some(vec![WalletTemplateScenarioOutput {
                    locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Slot),
                    token: None,
                    value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(20000.0)),
                }]),
                transaction: Some(WalletTemplateScenarioTransaction {
                    inputs: None,
                    locktime: Some(1577836800.0),
                    outputs: Some(vec![WalletTemplateScenarioOutput {
                        locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
                            overrides: Some(WalletTemplateScenarioData {
                                bytecode: Some(BTreeMap::from([("payment_number".to_string(), "3".to_string())])),
                                current_block_height: None,
                                current_block_time: None,
                                hd_keys: Some(WalletTemplateScenarioDataHdKeys {
                                    address_index: Some(0.0),
                                    hd_private_keys: None,
                                    hd_public_keys: None,
                                }),
                                keys: None,
                            }),
                            script: None,
                        }))),
                        token: None,
                        value_satoshis: Some(WalletTemplateScenarioValueSatoshis::Number(10000.0)),
                    }]),
                    version: None,
                }),
            },
        ),
        (
            "exceeds_maximum_payment_number".to_string(),
            WalletTemplateScenario {
                data: Some(WalletTemplateScenarioData {
                    bytecode: Some(BTreeMap::from([("payment_number".to_string(), "32768".to_string())])),
                    current_block_height: None,
                    current_block_time: None,
                    hd_keys: None,
                    keys: None,
                }),
                description: Some("An example scenario where the payment number exceeds the maximum uint16 value.".to_string()),
                extends: None,
                name: Some("Payment Number Exceeds Maximum".to_string()),
                source_outputs: None,
                transaction: None,
            },
        ),
        (
            "test_bytecode_values".to_string(),
            WalletTemplateScenario {
                data: None,
                description: Some("A scenario for testing all bytecode values. Because this scenario doesn't require compiling the script under test for its outputs, errors are a little easier to debug.".to_string()),
                extends: Some("after_payment_time".to_string()),
                name: Some("Test Bytecode Values".to_string()),
                source_outputs: None,
                transaction: Some(WalletTemplateScenarioTransaction {
                    inputs: None,
                    locktime: None,
                    outputs: Some(vec![WalletTemplateScenarioOutput {
                        locking_bytecode: Some(WalletTemplateScenarioOutputLockingBytecode::Bytecode(WalletTemplateScenarioBytecode::Hex("".to_string()))),
                        token: None,
                        value_satoshis: None,
                    }]),
                    version: None,
                }),
            },
        ),
    ])),
    scripts: BTreeMap::from([
        (
            "channel".to_string(),
            WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
                locking_type: WalletTemplateLockingType::P2sh20,
                name: Some("Channel".to_string()),
                script: "<owner.public_key>\nOP_SWAP\nOP_IF\n    /**\n     * Execute Authorization\n     */\n    OP_DUP OP_TOALTSTACK // save owner.public_key\n\n    /**\n     * Reconstruct payment authorization message\n     */\n    <6> OP_PICK // channel_identifier\n    <15> OP_PICK // payment_number_padded\n    <7> OP_PICK // maximum_authorized_satoshis\n    OP_DUP\n    <12> OP_PICK // payment_satoshis\n    OP_GREATERTHANOREQUAL OP_VERIFY // maximum_authorized_satoshis >= payment_satoshis\n    <8> OP_NUM2BIN\n    <7> OP_PICK <8> OP_NUM2BIN // authorized_amount\n    <7> OP_PICK <8> OP_NUM2BIN // denominating_asset\n    <7> OP_PICK <8> OP_NUM2BIN // payment_time\n    OP_CAT OP_CAT\n    OP_DUP OP_TOALTSTACK // save (authorized_amount + denominating_asset + payment_time)\n    OP_CAT OP_CAT OP_CAT\n    OP_SWAP \n\n   OP_CHECKDATASIGVERIFY // check payment authorization signature\n\n    OP_CHECKLOCKTIMEVERIFY // fail if not past payment_time\n    OP_2DROP OP_2DROP\n\n    <8> OP_PICK // payment_number_padded\n    <payment_number_padded>\n    OP_EQUALVERIFY // check against payment_number in authorization\n\n    // reconstruct rate_claim\n    OP_FROMALTSTACK\n    <3> OP_PICK // payment_satoshis\n    <8> OP_NUM2BIN\n    OP_CAT\n\n\n    OP_SWAP\n    OP_FROMALTSTACK // load owner.public_key\n    <receiver.public_key>\n    OP_DUP\n    OP_TOALTSTACK // save receiver.public_key\n    OP_CAT\n    OP_HASH160\n\n    OP_EQUALVERIFY // verify channel_identifier\n\n    <rate_oracle.public_key>\n    OP_CHECKDATASIGVERIFY // verify rate_claim\n\n    <7> OP_PICK // covered_bytecode_before_payment_number\n    <7> OP_PICK // payment_number_padded\n    OP_BIN2NUM\n    <1> OP_ADD <2> OP_NUM2BIN // next payment_number\n    <7> OP_PICK // covered_bytecode_after_payment_number\n    OP_CAT OP_CAT \n    OP_HASH160 // P2SH redeem bytecode hash\n    \n    /**\n     * prefix locking bytecode with its length (required in serialization)\n     */\n    <23>\n    <OP_HASH160 OP_PUSHBYTES_20>\n    OP_ROT\n    <OP_EQUAL>\n    OP_CAT OP_CAT // expected locking bytecode\n    OP_CAT // length + locking bytecode\n\n    // calculate expected output value\n    <5> OP_PICK // outpoint_value\n    OP_BIN2NUM\n    OP_ROT\n    OP_SUB <8> OP_NUM2BIN // remaining balance\n    OP_SWAP OP_CAT // expected output serialization\n    OP_SWAP OP_CAT\n\n    /**\n     * Verify signing serialization transaction outputs (uncomment for testing)\n     */\n    // OP_DUP OP_TOALTSTACK\n    // <8> OP_PICK // signing_serialization.transaction_outputs\n    // OP_EQUALVERIFY\n    // OP_FROMALTSTACK\n    /**\n     * End signing serialization transaction outputs verification (uncomment for testing)\n     */\n\n    OP_HASH256 // expected transaction_outputs_hash\n    OP_SWAP\n    OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT\n\n    /**\n     * Verify full signing serialization (uncomment for testing)\n     */\n    // OP_DUP OP_TOALTSTACK\n    // OP_EQUALVERIFY\n    // OP_FROMALTSTACK\n    /**\n     * End full signing serialization verification (uncomment for testing)\n     */\n    \n    OP_SHA256\n\n    OP_FROMALTSTACK\n    OP_DUP\n    <3> OP_PICK // receiver.schnorr_signature.all_outputs\n    OP_ROT\n    OP_CHECKSIGVERIFY // signature covers transaction\n    OP_ROT \n    <64> OP_SPLIT OP_DROP // remove signature serialization type bit\n    OP_ROT OP_ROT\n    OP_CHECKDATASIG // signature covers expected transaction\nOP_ELSE\n    // Owner Spend\n    OP_CHECKSIG\nOP_ENDIF \n\n\n".to_string(),
            }),
        ),
        (
            "channel_components".to_string(),
            WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: Some("Channel Components".to_string()),
                pushed: None,
                script: "/**\n * This is just a convenience script to split the locking bytecode\n * at the location of \"payment_number_padded\". Since this is used in\n * several places, using a single script makes updates easier.\n **/\n<channel> // The raw locking bytecode of the current channel\n<78> OP_SPLIT // the location of payment_number_padded in channel\n<2> OP_SPLIT // the length of payment_number_padded".to_string(),
                tests: BTreeMap::from([(
                    "contains_padded_payment_number".to_string(),
                    WalletTemplateScriptTest {
                        check: "/**\n * Here we confirm that we split the bytecode at the\n * correct indexes:\n * - item 1 should be the bytecode before payment_number_padded\n * - item 2 should be payment_number_padded\n * - item 3 should be the bytecode after payment_number_padded\n */\n\n<1> OP_PICK OP_TOALTSTACK\n\nOP_CAT OP_CAT <channel> OP_EQUALVERIFY\n\nOP_FROMALTSTACK <payment_number_padded> OP_EQUAL".to_string(),
                        fails: None,
                        invalid: None,
                        name: Some("Contains Padded Payment Number".to_string()),
                        passes: Some(vec!["after_payment_time".to_string(), "before_payment_time".to_string()]),
                        setup: None,
                    },
                )]),
            }),
        ),
        (
            "channel_identifier".to_string(),
            WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: Some("Channel Identifier".to_string()),
                pushed: Some(true),
                script: "$(<owner.public_key>\n<receiver.public_key>\nOP_CAT\nOP_HASH160)".to_string(),
                tests: BTreeMap::from([(
                    "expected_id".to_string(),
                    WalletTemplateScriptTest {
                        check: "<0x564752b9f1c9f0246c8444a7f0a0ee8348f2e339>\nOP_EQUAL".to_string(),
                        fails: None,
                        invalid: None,
                        name: Some("Expected ID".to_string()),
                        passes: None,
                        setup: None,
                    },
                )]),
            }),
        ),
        (
            "covered_bytecode_after_payment_number".to_string(),
            WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: Some("Covered Bytecode After Payment Number".to_string()),
                pushed: Some(true),
                script: "$(\n    channel_components <0> OP_PICK\n    OP_NIP OP_NIP OP_NIP\n)".to_string(),
                tests: BTreeMap::from([(
                    "check_bytecode".to_string(),
                    WalletTemplateScriptTest {
                        check: "<0x886c537958807e7c6c2102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13766b7ea9882102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9bb57795779815193528057797e7ea9011702a9147b01877e7e7e5579817b9458807c7e7c7eaa7c7e7e7e7e7e7e7ea86c7653797bad7b01407f757b7bba67ac68>\nOP_EQUAL".to_string(),
                        fails: None,
                        invalid: None,
                        name: Some("Check Bytecode".to_string()),
                        passes: Some(vec!["test_bytecode_values".to_string()]),
                        setup: None,
                    },
                )]),
            }),
        ),
        (
            "covered_bytecode_before_payment_number".to_string(),
            WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: Some("Covered Bytecode Before Payment Number".to_string()),
                pushed: Some(true),
                script: "$(\n    channel_components <2> OP_PICK\n    OP_NIP OP_NIP OP_NIP\n)".to_string(),
                tests: BTreeMap::from([(
                    "check_bytecode".to_string(),
                    WalletTemplateScriptTest {
                        check: "<0x210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817987c63766b56795f795779765c79a26958805779588057795880577958807e7e766b7e7e7e7cbbb16d6d587902>\nOP_EQUAL".to_string(),
                        fails: None,
                        invalid: None,
                        name: Some("Check Bytecode".to_string()),
                        passes: Some(vec!["test_bytecode_values".to_string()]),
                        setup: None,
                    },
                )]),
            }),
        ),
        (
            "execute_authorization".to_string(),
            WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                age_lock: None,
                estimate: None,
                fails: Some(vec!["before_payment_time".to_string()]),
                invalid: None,
                name: Some("Execute Authorization".to_string()),
                passes: Some(vec!["after_payment_time".to_string()]),
                script: "/**\n * Once the payment time for an authorization has passed,\n * this script can be used to execute it.\n */\n<receiver.schnorr_signature.all_outputs>\n\n/**\n * Verify signing serialization transaction outputs (uncomment for testing)\n */\n// <signing_serialization.transaction_outputs>\n/**\n * Verify full signing serialization (uncomment for testing)\n */\n// <signing_serialization.full_all_outputs>\n\n<$(  \n    <signing_serialization.version>\n    <signing_serialization.transaction_outpoints_hash>\n    <signing_serialization.transaction_sequence_numbers_hash>\n    <signing_serialization.outpoint_transaction_hash>\n    <signing_serialization.outpoint_index>\n    <signing_serialization.covered_bytecode_length>\n    OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT\n)> // signing serialization before the covered bytecode\n<covered_bytecode_before_payment_number>\n<payment_number_padded>\n<covered_bytecode_after_payment_number>\n<signing_serialization.output_value> // initial balance of channel\n<signing_serialization.sequence_number>\n<$(\n    <signing_serialization.locktime>\n    <0x41000000> // signing serialization type\n    OP_CAT\n)>\n<$(\n/**\n * signing_serialization.transaction_outputs with the\n * first output (the next channel UTXO) removed\n */\n<signing_serialization.transaction_outputs>\n    <32> // length of channel output (P2SH output)\n    OP_SPLIT\n    OP_NIP\n)>\n<payment_satoshis>\n<rate_oracle.ecdsa_data_signature.rate_claim>\n<channel_identifier>\n<maximum_authorized_satoshis>\n<authorized_amount>\n<denominating_asset>\n<payment_time>\n<owner.ecdsa_data_signature.payment_authorization>\n<1>".to_string(),
                time_lock_type: None,
                unlocks: "channel".to_string(),
            }),
        ),
        (
            "owner_spend".to_string(),
            WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
                age_lock: None,
                estimate: None,
                fails: None,
                invalid: None,
                name: Some("Owner Spend".to_string()),
                passes: Some(vec!["after_payment_time".to_string(), "before_payment_time".to_string()]),
                script: "/**\n * This script lets the Owner spend the current channel UTXO\n * to either \"top up\" the channel or close it.\n */\n<owner.schnorr_signature.all_outputs>\n<0>".to_string(),
                time_lock_type: None,
                unlocks: "channel".to_string(),
            }),
        ),
        (
            "payment_authorization".to_string(),
            WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: Some("Payment Authorization".to_string()),
                pushed: Some(true),
                script: "$(\n    <channel_identifier>\n    <payment_number>\n    <2> OP_NUM2BIN\n    <maximum_authorized_satoshis>\n    <8> OP_NUM2BIN\n    <authorized_amount>\n    <8> OP_NUM2BIN\n    <denominating_asset>\n    <8> OP_NUM2BIN\n    <payment_time>\n    <8> OP_NUM2BIN\n    OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT\n)".to_string(),
                tests: BTreeMap::from([(
                    "check_format".to_string(),
                    WalletTemplateScriptTest {
                        check: "<0x564752b9f1c9f0246c8444a7f0a0ee8348f2e33902000429000000000000e803000000000000555344000000000080bf345e00000000>\nOP_EQUAL".to_string(),
                        fails: None,
                        invalid: None,
                        name: Some("Check Format".to_string()),
                        passes: Some(vec!["before_payment_time".to_string()]),
                        setup: None,
                    },
                )]),
            }),
        ),
        (
            "payment_number_padded".to_string(),
            WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: Some("Payment Number Padded".to_string()),
                pushed: Some(true),
                script: "$(\n    <payment_number>\n    OP_DUP <0> OP_GREATERTHAN OP_VERIFY OP_DUP <0xff7f> OP_LESSTHANOREQUAL OP_VERIFY\n    <2> OP_NUM2BIN\n)".to_string(),
                tests: BTreeMap::from([(
                    "is_2_bytes".to_string(),
                    WalletTemplateScriptTest {
                        check: "OP_SIZE <2> OP_EQUALVERIFY\nOP_BIN2NUM <payment_number>\nOP_EQUAL".to_string(),
                        fails: None,
                        invalid: Some(vec!["exceeds_maximum_payment_number".to_string()]),
                        name: Some("Is 2 Bytes".to_string()),
                        passes: Some(vec!["before_payment_time".to_string()]),
                        setup: None,
                    },
                )]),
            }),
        ),
        (
            "rate_claim".to_string(),
            WalletTemplateScriptDefinition::Tested(WalletTemplateScriptTested {
                name: Some("Rate Claim".to_string()),
                pushed: Some(true),
                script: "$(\n    <authorized_amount>\n    <8> OP_NUM2BIN\n    <denominating_asset>\n    <8> OP_NUM2BIN\n    <payment_time>\n    <8> OP_NUM2BIN\n    <payment_satoshis>\n    <8> OP_NUM2BIN\n    OP_CAT\n    OP_CAT\n    OP_CAT\n)".to_string(),
                tests: BTreeMap::from([(
                    "check_format".to_string(),
                    WalletTemplateScriptTest {
                        check: "<\n    0xe803000000000000\n    0x5553440000000000\n    0x80bf345e00000000\n    0x1027000000000000\n>\nOP_EQUAL".to_string(),
                        fails: None,
                        invalid: None,
                        name: Some("Check Format".to_string()),
                        passes: Some(vec!["after_payment_time".to_string()]),
                        setup: None,
                    },
                )]),
            }),
        ),
    ]),
    supported: vec![AuthenticationVirtualMachineIdentifier::Bch2022_05],
    version: None,
}
});
