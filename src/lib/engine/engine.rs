pub mod types {
    #[path = "bcmr-types.rs"]
    pub mod bcmr_types;
    #[path = "template-types.rs"]
    pub mod template_types;
}

pub use types::bcmr_types::*;
pub use types::template_types::*;
