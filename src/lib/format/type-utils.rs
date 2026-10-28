/// A mapped type in which every property may be either omitted or explicitly
/// `undefined`. In Rust, an optional property is an `Option<T>`; this marker
/// trait is implemented by `Option<T>` for every `T`.
pub trait PartialExactOptional<T> {}

impl<T> PartialExactOptional<T> for Option<T> {}

/// Assert that two types are equal. In libauth this is a type-level assertion
/// (`AssertTypesEqual<T1, T2>` is `true` only when `T1` and `T2` are
/// identical); in Rust the trait is only implemented when both parameters are
/// the same type, so `fn check<T: AssertTypesEqual<A, B>>()` compiles only when
/// `A` and `B` are equal.
pub trait AssertTypesEqual<T1, T2 = T1> {}

impl<T> AssertTypesEqual<T, T> for T {}
