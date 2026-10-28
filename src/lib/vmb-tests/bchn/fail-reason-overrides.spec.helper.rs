//! Port of `vmb-tests/bchn/fail-reason-overrides.spec.helper.ts`.

// import { libauthErrorPrefixToBchnError } from './bchn-error-map.spec.helper.js';

/// Test IDs for which BCHN's expected error message differs from the one
/// mapped by `libauthErrorPrefixToBchnError*` (`{ [shortId]: bchnError }`).
pub const vmbTestBchnErrorMessageIdOverrides: &[(&str, &str)] = &[
    // aktdrv: libauthErrorPrefixToBchnError.excessiveOperationCost,
];
