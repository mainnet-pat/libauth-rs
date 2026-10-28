//! Port of `compiler/standard/p2pkh.spec.ts`.
#![allow(non_upper_case_globals)]

#[path = "../../transaction/transaction-e2e.spec.helper.rs"]
mod transaction_e2e_spec_helper;

use libauth::runtime::json::Json;
use libauth::{import_wallet_template, walletTemplateP2pkh, walletTemplateP2pkhNonHd};


#[test]
fn wallet_template_p2pkh_is_valid() {
    // libauth passes the template object; `Json::from` is its JSON.
    let template = import_wallet_template(&Json::from(&*walletTemplateP2pkhNonHd));
    assert!(template.is_ok(), "{template:?}");
}

#[test]
fn wallet_template_p2pkh_is_mostly_equivalent_to_wallet_template_p2pkh_hd() {
    assert_eq!(walletTemplateP2pkhNonHd.schema, walletTemplateP2pkh.schema);
    assert_eq!(walletTemplateP2pkhNonHd.scripts, walletTemplateP2pkh.scripts);
    assert_eq!(walletTemplateP2pkhNonHd.supported, walletTemplateP2pkh.supported);
    assert_eq!(walletTemplateP2pkhNonHd.version, walletTemplateP2pkh.version);
}

#[test]
fn wallet_template_p2pkh_hd_is_valid() {
    let template = import_wallet_template(&Json::from(&*walletTemplateP2pkh));
    assert!(template.is_ok(), "{template:?}");
}
