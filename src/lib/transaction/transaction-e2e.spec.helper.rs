//! Port of `transaction/transaction-e2e.spec.helper.ts`.
#![allow(dead_code, non_upper_case_globals)]

use std::sync::LazyLock;

use libauth::runtime::json::{parse_json, Json};

fn import_json(text: &str) -> Json {
    parse_json(text).expect("the fixture is valid JSON")
}

// `import x from './fixtures/templates/x.json' with { type: 'json' };`
pub static twoOfTwoRecoverableJson: LazyLock<Json> =
    LazyLock::new(|| import_json(include_str!("fixtures/templates/2-of-2-recoverable.json")));
pub static twoOfThreeJson: LazyLock<Json> =
    LazyLock::new(|| import_json(include_str!("fixtures/templates/2-of-3.json")));
pub static cashChannelsJson: LazyLock<Json> =
    LazyLock::new(|| import_json(include_str!("fixtures/templates/cash-channels-v1.json")));
pub static p2pkhJson: LazyLock<Json> = LazyLock::new(|| import_json(include_str!("fixtures/templates/p2pkh.json")));
pub static sigOfSigJson: LazyLock<Json> =
    LazyLock::new(|| import_json(include_str!("fixtures/templates/sig-of-sig.json")));

/// `m` from `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong`
pub const hdPrivateKey: &str =
    "xprv9s21ZrQH143K2PfMvkNViFc1fgumGqBew45JD8SxA59Jc5M66n3diqb92JjvaR61zT9P89Grys12kdtV4EFVo6tMwER7U2hcUmZ9VfMYPLC";

/// `M`
pub const hdPublicKey: &str =
    "xpub661MyMwAqRbcEsjq2muW5PYkDikFgHuWJGzu1WrZiQgHUsgEeKMtGducsZe1iRsGAGNGDzmWYDM69ya24LMyR7mDhtzqQsc286XEQfM2kkV";

/// `m/0'`
pub const hdPrivateKey0H: &str =
    "xprv9uNAm3qC8EoibXd3mwgQ9rxF8XJdfA9V9sF25DpLtYcf1u51Rpf8tfV4n2PdChXM97miXGiJf6UL2SsathXbiVbF6tSgmAVGM3XNb6Yn2EZ";

/// HD public key for `m/0'`
pub const hdPublicKey0H: &str =
    "xpub68MXAZN5xcN1p1hWsyDQWztygZ984csLX6AcscDxSt9dthQ9yMyPSToYdJ24jCS5jaVMGSiLeGuP2cWvgKKYQsNXyg988XGGQYgk1FjDv4P";

/// `m/1'`
pub const hdPrivateKey1H: &str =
    "xprv9uNAm3qC8EoicAhBeTEJyZE9DCPtmoQ2noPeFCiDxSqgTGV8ZwM89SAyw8Hhygg3Lkgqy53XM2nHtyMmhyVuDwxJupg9F3bemDN6XcdYNJd";

/// HD public key for `m/1'`
pub const hdPublicKey1H: &str =
    "xpub68MXAZN5xcN1pemekUmKLhAsmEEPBG7tA2KF3b7qWnNfL4pH7UfNhEVTnQGeMZycFEGbS7w2gsyG7w77YWkoupkn6QZvRq7zeFS98Fic25b";

/// `m/2'`
pub const hdPrivateKey2H: &str =
    "xprv9uNAm3qC8EoieXyZAVbnB5LeeCMKUKe8HcE9mi38ghdBrjgay1ixgt9Ve2EjvB4udeZdp7XeyvU4PyezsjVP6xmjBDcsidobgAYCBLVYyrj";

/// HD public key for `m/2'`
pub const hdPublicKey2H: &str =
    "xpub68MXAZN5xcN1s242GX8nYDHPCEBosnMyeq9ka6SkF3AAjY1jWZ3DEgTyVKFwPNXcKsY1snLZV7rNcVdYUpL3eFWTrr8xnHhRW4XGmcgHdr7";
