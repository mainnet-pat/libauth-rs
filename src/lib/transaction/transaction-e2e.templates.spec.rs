//! Port of `transaction/transaction-e2e.templates.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "fixtures/template.2-of-2-recoverable.spec.helper.rs"]
mod template_2_of_2_recoverable_spec_helper;
#[path = "fixtures/template.2-of-3.spec.helper.rs"]
mod template_2_of_3_spec_helper;
#[path = "fixtures/template.cash-channels-v1.spec.helper.rs"]
mod template_cash_channels_v1_spec_helper;
#[path = "fixtures/template.sig-of-sig.spec.helper.rs"]
mod template_sig_of_sig_spec_helper;
#[path = "transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use libauth::{walletTemplateP2pkh, WalletTemplate};

use template_2_of_2_recoverable_spec_helper::twoOfTwoRecoverable;
use template_2_of_3_spec_helper::twoOfThree;
use template_cash_channels_v1_spec_helper::cashChannels;
use template_sig_of_sig_spec_helper::sigOfSig;
use transaction_e2e_spec_helper::{
    cashChannelsJson, p2pkhJson, sigOfSigJson, twoOfThreeJson, twoOfTwoRecoverableJson,
};

// libauth compares `ignoreDefault(template)` with `ignoreDefault(json)`, adding
// `default: true` to both to neutralize the `default` property of JSON module
// imports. The Rust fixtures are parsed `Json` values, compared here as typed
// `WalletTemplate`s (the analog of libauth's `as WalletTemplate` imports).
#[test]
fn example_wallet_templates_are_updated() {
    let solution = "Run \"yarn gen:templates\" to correct this issue. (Note: watch tasks don't always update cached JSON imports when the source file changes. You may need to restart tsc.)";
    assert_eq!(
        *twoOfTwoRecoverable,
        WalletTemplate::try_from(&*twoOfTwoRecoverableJson).expect("a valid template"),
        "Inconsistency in twoOfTwoRecoverableJson. {solution}"
    );
    assert_eq!(
        *twoOfThree,
        WalletTemplate::try_from(&*twoOfThreeJson).expect("a valid template"),
        "Inconsistency in twoOfThreeJson. {solution}"
    );
    assert_eq!(
        *cashChannels,
        WalletTemplate::try_from(&*cashChannelsJson).expect("a valid template"),
        "Inconsistency in cashChannelsJson. {solution}"
    );
    assert_eq!(
        *walletTemplateP2pkh,
        WalletTemplate::try_from(&*p2pkhJson).expect("a valid template"),
        "Inconsistency in p2pkhJson. {solution}"
    );
    assert_eq!(
        *sigOfSig,
        WalletTemplate::try_from(&*sigOfSigJson).expect("a valid template"),
        "Inconsistency in sigOfSigJson. {solution}"
    );
}
