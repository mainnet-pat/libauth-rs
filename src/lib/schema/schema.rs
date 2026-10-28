pub mod ajv {
    #[path = "ajv-types.rs"]
    pub mod ajv_types;
    #[path = "ajv-utils.rs"]
    pub mod ajv_utils;
    #[path = "validate-bcmr.rs"]
    pub mod validate_bcmr;
    #[path = "validate-wallet-template.rs"]
    pub mod validate_wallet_template;
}
pub mod bcmr;
#[path = "wallet-template.rs"]
pub mod wallet_template;

pub use bcmr::*;
pub use wallet_template::*;
