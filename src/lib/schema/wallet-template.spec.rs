//! Port of `schema/wallet-template.spec.ts`.
//!
//! libauth's `test.failing(...)` tests (expected to fail: AVA reports an error
//! if one passes) are ported as `#[should_panic]` tests which expect the
//! `assert_eq!` of `test_validation` to fail (so that a panic elsewhere, e.g.
//! in the library, is not mistaken for the expected failure). Test inputs are the
//! object literals of the TypeScript spec as JSON documents (libauth
//! `JSON.stringify`s object inputs before validation, so sparse array holes
//! are `null`).

use libauth::runtime::json::{encode_json, parse_json, Json};
use libauth::{import_wallet_template, sort_object_keys, stringify, WalletTemplate};

fn json(text: &str) -> Json {
    parse_json(text).expect("valid JSON")
}

/// `t.deepEqual` ignores the order of object keys (imported templates are
/// compared as their JSON).
fn deep_equal_form(result: Result<WalletTemplate, String>) -> Result<Json, String> {
    result.map(|template| sort_object_keys(&Json::from(&template)))
}

#[test]
fn import_wallet_template_accepts_templates_as_either_json_strings_or_pre_parsed_objects() {
    // libauth's `WalletTemplate` object literal, as JSON.
    let template = json(r#"{"entities":{},"scripts":{"a":{"script":""}},"supported":["BCH_2022_05"],"version":0}"#);
    assert_eq!(Ok(sort_object_keys(&template)), deep_equal_form(import_wallet_template(&template)));
    assert_eq!(
        Ok(sort_object_keys(&template)),
        deep_equal_form(import_wallet_template(&Json::String(encode_json(&template))))
    );
}

/// libauth's `testValidation` macro (title: `importWalletTemplate: ${title}`):
/// `expected` is either the expected template (as JSON) or the expected error.
fn test_validation(input: Json, expected: Result<&str, &str>) {
    let result = import_wallet_template(&input);
    let message = stringify(
        &match &result {
            Ok(template) => Json::from(template),
            Err(error) => Json::String(error.clone()),
        },
        None,
    );
    assert_eq!(
        deep_equal_form(result),
        expected.map(|expected| sort_object_keys(&json(expected))).map_err(str::to_string),
        "{message}"
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_must_be_an_object() {
    test_validation(
        Json::String("a string".to_string()),
        Err("A valid wallet template must be an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_must_be_version_0() {
    test_validation(
        json(r#"{"version":1}"#),
        Err("Only version 0 wallet templates are currently supported."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_must_provide_a_supported_property() {
    test_validation(
        json(r#"{"supported":42,"version":0}"#),
        Err("Version 0 wallet templates must include a \"supported\" list of authentication virtual machine versions. Available identifiers are: BCH_SPEC, BCH_2022_11, BCH_2022_05_SPEC, BCH_2022_05, BCH_2021_11_SPEC, BCH_2021_11, BCH_2021_05_SPEC, BCH_2021_05, BCH_2020_11_SPEC, BCH_2020_11, BCH_2020_05, BCH_2019_11, BCH_2019_05, BSV_2018_11, BTC_2017_08."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_must_use_only_known_virtual_machine_identifiers_in_supported() {
    test_validation(
        json(r#"{"supported":["not supported"],"version":0}"#),
        Err("Version 0 wallet templates must include a \"supported\" list of authentication virtual machine versions. Available identifiers are: BCH_SPEC, BCH_2022_11, BCH_2022_05_SPEC, BCH_2022_05, BCH_2021_11_SPEC, BCH_2021_11, BCH_2021_05_SPEC, BCH_2021_05, BCH_2020_11_SPEC, BCH_2020_11, BCH_2020_05, BCH_2019_11, BCH_2019_05, BSV_2018_11, BTC_2017_08."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_may_not_have_empty_items_in_supported() {
    test_validation(
        json(r#"{"supported":["BCH_2020_05",null,"BCH_2020_11_SPEC"],"version":0}"#),
        Err("Version 0 wallet templates must include a \"supported\" list of authentication virtual machine versions. Available identifiers are: BCH_SPEC, BCH_2022_11, BCH_2022_05_SPEC, BCH_2022_05, BCH_2021_11_SPEC, BCH_2021_11, BCH_2021_05_SPEC, BCH_2021_05, BCH_2020_11_SPEC, BCH_2020_11, BCH_2020_05, BCH_2019_11, BCH_2019_05, BSV_2018_11, BTC_2017_08."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_schema_must_be_a_string_if_present() {
    test_validation(
        json(r#"{"$schema":42,"supported":["BCH_SPEC"],"version":0}"#),
        Err("The \"$schema\" property of a wallet template must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_name_must_be_a_string_if_present() {
    test_validation(
        json(r#"{"name":42,"supported":["BCH_SPEC"],"version":0}"#),
        Err("The \"name\" property of a wallet template must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_description_must_be_a_string_if_present() {
    test_validation(
        json(r#"{"description":42,"supported":["BCH_SPEC"],"version":0}"#),
        Err("The \"description\" property of a wallet template must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_entities_must_be_a_an_object() {
    test_validation(
        json(r#"{"entities":42,"scripts":{},"supported":["BCH_SPEC"],"version":0}"#),
        Err("The \"entities\" property of a wallet template must be an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scripts_must_be_a_an_object() {
    test_validation(
        json(r#"{"entities":{},"scripts":42,"supported":["BCH_SPEC"],"version":0}"#),
        Err("The \"scripts\" property of a wallet template must be an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenarios_must_be_a_an_object_if_present() {
    test_validation(
        json(r#"{"entities":{},"scenarios":42,"scripts":{},"supported":["BCH_SPEC"],"version":0}"#),
        Err("If defined, the \"scenarios\" property of a wallet template must be an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_script_shapes_are_checked() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": 42
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("All wallet template scripts must be objects, but the following scripts are not objects: \"a\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_empty_script_object() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {}
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"script\" property of script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_no_content() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "unlocks": "b"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"script\" property of unlocking script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_unlocks() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "unlocks": 42
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"unlocks\" property of unlocking script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unknown_locking_script() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "unlocks": "b"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The following locking scripts (referenced in \"unlocks\" properties) were not provided: \"b\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_time_lock_type() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "timeLockType": "democracy",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"timeLockType\" property of unlocking script \"a\" must be either \"timestamp\" or \"height\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_name() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "name": 42,
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" property of unlocking script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_age_lock() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "ageLock": 42,
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"ageLock\" property of unlocking script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_estimate() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "estimate": 42,
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"estimate\" property of unlocking script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_passes() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "passes": 42,
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"passes\" property of unlocking script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_fails() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "fails": 42,
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"fails\" property of unlocking script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_invalid_invalid() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "invalid": 42,
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"invalid\" property of unlocking script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_empty_passes_item() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "passes": [
                "s1",
                null,
                "s2"
              ],
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"passes\" property of unlocking script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_non_string_fails_item() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "fails": [
                0
              ],
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"fails\" property of unlocking script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_unlocking_script_non_string_invalid_item() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "invalid": [
                0
              ],
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"invalid\" property of unlocking script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
fn import_wallet_template_unlocking_script_valid_age_lock() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "ageLock": "0xffffff",
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20",
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "ageLock": "0xffffff",
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20",
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_locking_script_no_type() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "unlocks": "b"
            },
            "b": {}
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"lockingType\" property of locking script \"b\" must be either \"standard\" or \"p2sh20\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_locking_script_no_contents() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20"
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"script\" property of locking script \"b\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_locking_script_invalid_name() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20",
              "name": 42,
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" property of locking script \"b\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_no_contents() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "tests": []
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"script\" property of tested script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_name() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "name": 42,
              "script": "",
              "tests": []
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" property of tested script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_tests() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": 42
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"tests\" property of tested script \"a\" must be an array."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_test_with_no_check() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": [
                {
                  "name": ""
                }
              ]
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"check\" properties of all tests in tested script \"a\" must be a strings."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_test_name() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": [
                {
                  "check": "",
                  "name": 42
                }
              ]
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" properties of all tests in tested script \"a\" must be strings."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_test_setup() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": [
                {
                  "check": "",
                  "setup": 42
                }
              ]
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"setup\" properties of all tests in tested script \"a\" must be strings."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_passes() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": [
                {
                  "check": "",
                  "passes": [
                    0
                  ]
                }
              ]
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"passes\" property of each test in tested script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_fails() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": [
                {
                  "check": "",
                  "fails": [
                    0
                  ]
                }
              ]
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"fails\" property of each test in tested script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_invalid() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": [
                {
                  "check": "",
                  "invalid": [
                    0
                  ]
                }
              ]
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"invalid\" property of each test in tested script \"a\" must be an array containing only scenario identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_invalid_pushed() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "pushed": 0,
              "script": "",
              "tests": [
                {
                  "check": ""
                }
              ]
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"pushed\" property of tested script \"a\" must be a boolean value."),
    );
}

#[test]
fn import_wallet_template_tested_script_valid_test() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "s1": {},
            "s2": {},
            "s3": {}
          },
          "scripts": {
            "a": {
              "pushed": true,
              "script": "",
              "tests": {
                "a": {
                  "check": ""
                },
                "b": {
                  "check": "",
                  "name": "",
                  "setup": ""
                }
              }
            },
            "b": {
              "name": "",
              "pushed": false,
              "script": "",
              "tests": {
                "a": {
                  "check": "",
                  "fails": [
                    "s1"
                  ]
                },
                "b": {
                  "check": "",
                  "passes": [
                    "s2"
                  ]
                },
                "c": {
                  "check": "",
                  "invalid": [
                    "s3"
                  ]
                }
              }
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "s1": {},
            "s2": {},
            "s3": {}
          },
          "scripts": {
            "a": {
              "pushed": true,
              "script": "",
              "tests": {
                "a": {
                  "check": ""
                },
                "b": {
                  "check": "",
                  "name": "",
                  "setup": ""
                }
              }
            },
            "b": {
              "name": "",
              "pushed": false,
              "script": "",
              "tests": {
                "a": {
                  "check": "",
                  "fails": [
                    "s1"
                  ]
                },
                "b": {
                  "check": "",
                  "passes": [
                    "s2"
                  ]
                },
                "c": {
                  "check": "",
                  "invalid": [
                    "s3"
                  ]
                }
              }
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_tested_script_can_t_test_a_locking_script() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "script": "",
              "tests": [],
              "unlocks": "b"
            },
            "b": {
              "lockingType": "p2sh20",
              "script": "",
              "tests": []
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("Locking and unlocking scripts may not have tests, but the following scripts include a \"tests\" property: \"a\", \"b\""),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_other_script_invalid_name() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "name": 42,
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" property of script \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_invalid_entity() {
    test_validation(
        json(r#"{
          "entities": {
            "e": 42
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("All wallet template entities must be objects, but the following entities are not objects: \"e\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_invalid_entity_description() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "description": 42
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"description\" property of entity \"e\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_invalid_entity_name() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "name": 42
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" property of entity \"e\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_invalid_entity_scripts() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "scripts": ""
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"scripts\" property of entity \"e\" must be an array containing only script identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_invalid_entity_scripts_items() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "scripts": [
                "",
                null,
                0,
                ""
              ]
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"scripts\" property of entity \"e\" must be an array containing only script identifiers (strings)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_invalid_entity_variables() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": 42
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"variables\" property of entity \"e\" must be an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_variable_wrong_type() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": 42
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("All wallet template variables must be objects, but the following variables owned by entity \"e\" are not objects: \"v\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_variable_no_type() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {}
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"type\" property of variable \"v\" must be a valid wallet template variable type. Available types are: \"AddressData\", \"HdKey\", \"Key\", \"WalletData\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_variable_invalid_description() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "description": 42,
                  "type": "AddressData"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"description\" property of variable \"v\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_variable_invalid_name() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "name": 42,
                  "type": "AddressData"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" property of variable \"v\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_address_offset() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "addressOffset": "0",
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"addressOffset\" property of HdKey \"v\" must be a number."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_hd_public_key_derivation_path() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "hdPublicKeyDerivationPath": 42,
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"hdPublicKeyDerivationPath\" property of HdKey \"v\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_private_derivation_path() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "privateDerivationPath": 42,
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"privateDerivationPath\" property of HdKey \"v\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_public_derivation_path() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "publicDerivationPath": 42,
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"publicDerivationPath\" property of HdKey \"v\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_private_derivation_path_content() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "privateDerivationPath": "bad",
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"privateDerivationPath\" property of HdKey \"v\" must be a valid private derivation path, but the provided value is \"m\". A valid path must begin with \"m\" and include only \"/\", \"'\", a single \"i\" address index character, and numbers."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_hd_public_key_derivation_path_content() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "hdPublicKeyDerivationPath": "M/0",
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"hdPublicKeyDerivationPath\" property of an HdKey must be a valid private derivation path for the HdKey's HD public node, but the provided value for HdKey \"v\" is \"M/0\". A valid path must begin with \"m\" and include only \"/\", \"'\", and numbers (the \"i\" character cannot be used in \"hdPublicKeyDerivationPath\")."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_public_derivation_path_content() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "publicDerivationPath": "m/0",
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"publicDerivationPath\" property of HdKey \"v\" must be a valid public derivation path, but the current value is \"m/0\". Public derivation paths must begin with \"M\" and include only \"/\", a single \"i\" address index character, and numbers. If the \"privateDerivationPath\" uses hardened derivation, the \"publicDerivationPath\" should be set to enable public derivation from the \"hdPublicKeyDerivationPath\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_hd_key_variable_invalid_implied_private_derivation_path() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "addressOffset": 0,
                  "hdPublicKeyDerivationPath": "m/1'",
                  "privateDerivationPath": "m/2'/i",
                  "publicDerivationPath": "M/i",
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The \"privateDerivationPath\" property of HdKey \"v\" is \"m/2'/i\", but the implied private derivation path of \"hdPublicKeyDerivationPath\" and \"publicDerivationPath\" is \"m/1'/i\". The \"publicDerivationPath\" property must be set to allow for public derivation of the same HD node derived by \"privateDerivationPath\" beginning from the HD public key derived at \"hdPublicKeyDerivationPath\"."),
    );
}

#[test]
fn import_wallet_template_address_data_variable_valid() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "type": "AddressData"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "type": "AddressData"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
fn import_wallet_template_hd_key_variable_valid() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "addressOffset": 0,
                  "hdPublicKeyDerivationPath": "m/0'",
                  "privateDerivationPath": "m/0'/i",
                  "publicDerivationPath": "M/i",
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {
            "e": {
              "variables": {
                "v": {
                  "addressOffset": 0,
                  "hdPublicKeyDerivationPath": "m/0'",
                  "privateDerivationPath": "m/0'/i",
                  "publicDerivationPath": "M/i",
                  "type": "HdKey"
                }
              }
            }
          },
          "scenarios": {},
          "scripts": {
            "a": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_type() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": ""
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("All wallet template scenarios must be objects, but the following scenarios are not objects: \"a\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_name() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "name": 1
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"name\" property of scenario \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_description() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "description": 1
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"description\" property of scenario \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_extends() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "extends": 1
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"extends\" property of scenario \"a\" must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_unknown_extends() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "extends": "c"
            },
            "b": {
              "extends": "d"
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, each scenario ID referenced by another scenario's \"extends\" property must exist. Unknown scenario IDs: \"c\", \"d\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_value_negative() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "value": -1
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"value\" property of scenario \"a\" must be either a number or a little-endian, unsigned 64-bit integer as a hexadecimal-encoded string (16 characters)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_value_greater_than_number_max_safe_integer() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "value": 9007199254740992
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"value\" property of scenario \"a\" must be either a number or a little-endian, unsigned 64-bit integer as a hexadecimal-encoded string (16 characters)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_value_insufficient_hex() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "value": ""
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"value\" property of scenario \"a\" must be either a number or a little-endian, unsigned 64-bit integer as a hexadecimal-encoded string (16 characters)."),
    );
}

#[test]
fn import_wallet_template_scenario_value_hex() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "sourceOutputs": [
                {
                  "valueSatoshis": "ffffffffffffffff"
                }
              ]
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "sourceOutputs": [
                {
                  "valueSatoshis": "ffffffffffffffff"
                }
              ]
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": ""
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data\" property of scenario \"a\" must be an object."),
    );
}

#[test]
fn import_wallet_template_scenario_empty_data() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {}
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {}
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_bytecode() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "bytecode": 1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.bytecode\" property of scenario \"a\" must be an object, and each value must be a string."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_bytecode() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "bytecode": {
                  "a": ""
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "bytecode": {
                  "a": ""
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_current_block_height_string() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockHeight": "42"
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"currentBlockHeight\" property of scenario \"a\" must be a positive integer from 0 to 499,999,999 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_current_block_height_negative() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockHeight": -1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"currentBlockHeight\" property of scenario \"a\" must be a positive integer from 0 to 499,999,999 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_current_block_height_decimal() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockHeight": 1.1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"currentBlockHeight\" property of scenario \"a\" must be a positive integer from 0 to 499,999,999 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_current_block_height_exceeds_maximum() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockHeight": 500000000
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"currentBlockHeight\" property of scenario \"a\" must be a positive integer from 0 to 499,999,999 (inclusive)."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_current_block_height() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockHeight": 0
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockHeight": 0
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_current_block_time_below_minimum() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockTime": 1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"currentBlockTime\" property of scenario \"a\" must be a positive integer from 500,000,000 to 4,294,967,295 (inclusive)."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_current_block_time() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockTime": 500000000
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "currentBlockTime": 500000000
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": ""
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys\" property of scenario \"a\" must be an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_address_index_string() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "addressIndex": "1"
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.addressIndex\" property of scenario \"a\" must be a positive integer between 0 and 2,147,483,648 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_address_index_negative() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "addressIndex": -1
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.addressIndex\" property of scenario \"a\" must be a positive integer between 0 and 2,147,483,648 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_address_index_decimal() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "addressIndex": 1.3
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.addressIndex\" property of scenario \"a\" must be a positive integer between 0 and 2,147,483,648 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_address_index_exceeds_maximum() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "addressIndex": 2147483649
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.addressIndex\" property of scenario \"a\" must be a positive integer between 0 and 2,147,483,648 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_hd_public_keys() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "hdPublicKeys": 1
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.hdPublicKeys\" property of scenario \"a\" must be an object, and each value must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_hd_public_keys_non_string_value() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "hdPublicKeys": {
                    "e": 1
                  }
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.hdPublicKeys\" property of scenario \"a\" must be an object, and each value must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_hd_private_keys() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "hdPrivateKeys": 1
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.hdPrivateKeys\" property of scenario \"a\" must be an object, and each value must be a string."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_hd_keys_hd_private_keys_non_string_value() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "hdPrivateKeys": {
                    "e": 1
                  }
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.hdKeys.hdPrivateKeys\" property of scenario \"a\" must be an object, and each value must be a string."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_data_hd_keys() {
    test_validation(
        json(r#"{
          "entities": {
            "e": {},
            "f": {}
          },
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "addressIndex": 1,
                  "hdPrivateKeys": {
                    "f": ""
                  },
                  "hdPublicKeys": {
                    "e": ""
                  }
                }
              }
            },
            "b": {
              "data": {
                "hdKeys": {}
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {
            "e": {},
            "f": {}
          },
          "scenarios": {
            "a": {
              "data": {
                "hdKeys": {
                  "addressIndex": 1,
                  "hdPrivateKeys": {
                    "f": ""
                  },
                  "hdPublicKeys": {
                    "e": ""
                  }
                }
              }
            },
            "b": {
              "data": {
                "hdKeys": {}
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_keys() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "keys": ""
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.keys\" property of scenario \"a\" must be an object."),
    );
}

#[test]
fn import_wallet_template_scenario_empty_data_keys() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "keys": {}
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "keys": {}
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_keys_private_keys() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "keys": {
                  "privateKeys": 1
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.keys.privateKeys\" property of scenario \"a\" must be an object, and each value must be a 32-byte, hexadecimal-encoded private key."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_data_keys_private_keys_non_string_value() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "keys": {
                  "privateKeys": {
                    "b": 1
                  }
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"data.keys.privateKeys\" property of scenario \"a\" must be an object, and each value must be a 32-byte, hexadecimal-encoded private key."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_data_keys() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "keys": {
                  "privateKeys": {
                    "b": "0000000000000000000000000000000000000000000000000000000000000001"
                  }
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "data": {
                "keys": {
                  "privateKeys": {
                    "b": "0000000000000000000000000000000000000000000000000000000000000001"
                  }
                }
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": ""
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"transaction\" property of scenario \"a\" must be an object."),
    );
}

#[test]
fn import_wallet_template_scenario_empty_transaction() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {}
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {}
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_locktime() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "locktime": ""
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"locktime\" property of scenario \"a\" must be an integer between 0 and 4,294,967,295 (inclusive)."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_transaction_locktime() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "locktime": 1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "locktime": 1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_version() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "version": ""
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"version\" property of scenario \"a\" must be an integer between 0 and 4,294,967,295 (inclusive)."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_transaction_version() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "version": 1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "version": 1
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_inputs_no_inputs() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": []
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"transaction.inputs\" array of scenario \"a\" must have exactly one input under test (an \"unlockingBytecode\" set to \"null\")."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_inputs_sparse_array() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  null,
                  {
                    "unlockingBytecode": true
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"transaction.inputs\" property of scenario \"a\" must be an array of scenario input objects."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_input_outpoint_index_negative() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  {
                    "outpointIndex": -1,
                    "unlockingBytecode": true
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"outpointIndex\" property of input 0 in scenario \"a\" must be a positive integer."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_input_outpoint_transaction_hash_non_string() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  {
                    "outpointTransactionHash": 1,
                    "unlockingBytecode": true
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"outpointTransactionHash\" property of input 0 in scenario \"a\" must be a 32-byte, hexadecimal-encoded hash (string)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_input_outpoint_transaction_hash_incorrect_length() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  {
                    "outpointTransactionHash": "beef",
                    "unlockingBytecode": true
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"outpointTransactionHash\" property of input 0 in scenario \"a\" must be a 32-byte, hexadecimal-encoded hash (string)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_input_sequence_number() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  {
                    "sequenceNumber": -1,
                    "unlockingBytecode": true
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"sequenceNumber\" property of input 0 in scenario \"a\" must be a number between 0 and 4294967295 (inclusive)."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_input_unlocking_bytecode() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  {
                    "unlockingBytecode": 1
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"unlockingBytecode\" property of input 0 in scenario \"a\" must be either a null value or a hexadecimal-encoded string."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_transaction_inputs() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  {
                    "outpointIndex": 0,
                    "outpointTransactionHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "sequenceNumber": 0,
                    "unlockingBytecode": "beef"
                  },
                  {}
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "inputs": [
                  {
                    "outpointIndex": 0,
                    "outpointTransactionHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "sequenceNumber": 0,
                    "unlockingBytecode": "beef"
                  },
                  {}
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_empty_transaction_outputs() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": []
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"transaction.outputs\" property of scenario \"a\" must be have at least one output."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_outputs_sparse_array() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  null,
                  {
                    "lockingBytecode": "beef"
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"transaction.outputs\" property of scenario \"a\" must be an array of scenario output objects."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_output_locking_bytecode_type() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  {
                    "lockingBytecode": 1
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"lockingBytecode\" property of output 0 in scenario \"a\" must be a string or an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_output_locking_bytecode_non_hex() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  {
                    "lockingBytecode": "g"
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If the \"lockingBytecode\" property of output 0 in scenario \"a\" is a string, it must be a valid, hexadecimal-encoded locking bytecode."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_output_locking_bytecode_script() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  {
                    "lockingBytecode": {
                      "script": false
                    }
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"script\" property of output 0 in scenario \"a\" must be a hexadecimal-encoded string or \"null\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_output_locking_bytecode_override() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  {
                    "lockingBytecode": {
                      "overrides": false
                    }
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"overrides\" property of output 0 in scenario \"a\" must be an object."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_scenario_invalid_transaction_output_satoshis() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  {
                    "valueSatoshis": false
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("If defined, the \"valueSatoshis\" property of output 0 in scenario \"a\" must be either a number or a little-endian, unsigned 64-bit integer as a hexadecimal-encoded string (16 characters)."),
    );
}

#[test]
fn import_wallet_template_scenario_valid_transaction_output() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  {
                    "lockingBytecode": {
                      "overrides": {
                        "bytecode": {
                          "a": "beef"
                        }
                      },
                      "script": "beef"
                    },
                    "valueSatoshis": "ffffffffffffffff"
                  },
                  {
                    "lockingBytecode": {}
                  },
                  {
                    "lockingBytecode": "beef"
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Ok(r#"{
          "entities": {},
          "scenarios": {
            "a": {
              "transaction": {
                "outputs": [
                  {
                    "lockingBytecode": {
                      "overrides": {
                        "bytecode": {
                          "a": "beef"
                        }
                      },
                      "script": "beef"
                    },
                    "valueSatoshis": "ffffffffffffffff"
                  },
                  {
                    "lockingBytecode": {}
                  },
                  {
                    "lockingBytecode": "beef"
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_built_in_identifiers_may_not_be_re_used() {
    test_validation(
        json(r#"{
          "entities": {
            "current_block_height": {}
          },
          "scripts": {
            "signing_serialization": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("Built-in identifiers may not be re-used by any entity, variable, script, or scenario. The following built-in identifiers are re-used: \"current_block_height\", \"signing_serialization\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_all_i_ds_must_be_unique() {
    test_validation(
        json(r#"{
          "entities": {
            "a": {},
            "b": {},
            "d": {}
          },
          "scenarios": {
            "b": {}
          },
          "scripts": {
            "c": {
              "script": ""
            },
            "d": {
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("The ID of each entity, variable, script, and scenario in a wallet template must be unique. The following IDs are re-used: \"b\", \"d\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_all_entity_script_i_ds_must_exist() {
    test_validation(
        json(r#"{
          "entities": {
            "a": {
              "scripts": [
                "b",
                "c"
              ]
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("Only known scripts may be assigned to entities. The following script IDs are not provided in this template: \"b\", \"c\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_all_scenarios_reference_by_scripts_must_exist() {
    test_validation(
        json(r#"{
          "entities": {},
          "scenarios": {},
          "scripts": {
            "a": {
              "estimate": "s3",
              "fails": [
                "s1",
                "s4"
              ],
              "invalid": [
                "s6"
              ],
              "passes": [
                "s3",
                "s5"
              ],
              "script": "",
              "unlocks": "c"
            },
            "b": {
              "script": "",
              "tests": [
                {
                  "check": "",
                  "fails": [
                    "s1"
                  ]
                },
                {
                  "check": "",
                  "passes": [
                    "s2"
                  ]
                },
                {
                  "check": "",
                  "invalid": [
                    "s7"
                  ]
                }
              ]
            },
            "c": {
              "lockingType": "p2sh20",
              "script": ""
            }
          },
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("Only known scenarios may be referenced by scripts. The following scenario IDs are not provided in this template: \"s1\", \"s2\", \"s3\", \"s4\", \"s5\", \"s6\", \"s7\"."),
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")] // test.failing
fn import_wallet_template_all_entities_referenced_by_data_hd_keys_must_exist() {
    test_validation(
        json(r#"{
          "entities": {
            "a": {},
            "b": {}
          },
          "scenarios": {
            "s": {
              "data": {
                "hdKeys": {
                  "hdPrivateKeys": {
                    "b": "",
                    "c": ""
                  },
                  "hdPublicKeys": {
                    "a": "",
                    "d": ""
                  }
                }
              },
              "transaction": {
                "outputs": [
                  {
                    "lockingBytecode": {
                      "overrides": {
                        "hdKeys": {
                          "hdPrivateKeys": {
                            "b": "",
                            "c": "",
                            "f": ""
                          },
                          "hdPublicKeys": {
                            "a": "",
                            "e": ""
                          }
                        }
                      }
                    }
                  },
                  {
                    "lockingBytecode": {}
                  }
                ]
              }
            }
          },
          "scripts": {},
          "supported": [
            "BCH_SPEC"
          ],
          "version": 0
        }"#),
        Err("Only known entities may be referenced by hdKeys properties within scenarios. The following entity IDs are not provided in this template: \"c\", \"d\", \"e\", \"f\"."),
    );
}
