use super::error::format_error;
use super::number::read_compact_uint_minimal;

/// A position within a byte array: the `Uint8Array` being read and the index
/// at which the next byte should be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPosition<'a> {
    /// The `Uint8Array` from which bytes are being read.
    pub bin: &'a [u8],
    /// The index at which the next byte should be read.
    pub index: usize,
}

/// The successful result of reading a value: the value and the position
/// following it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResult<'a, Type> {
    /// The next {@link ReadPosition}.
    pub position: ReadPosition<'a>,
    /// The result of the read.
    pub result: Type,
}

/// Either a {@link ReadResult} or an error message.
pub type MaybeReadResult<'a, Type> = Result<ReadResult<'a, Type>, String>;

/// A function that reads a value from a {@link ReadPosition}.
pub trait ReadFunction<Type>: for<'a> Fn(ReadPosition<'a>) -> MaybeReadResult<'a, Type> {}

impl<Type, F> ReadFunction<Type> for F where
    F: for<'a> Fn(ReadPosition<'a>) -> MaybeReadResult<'a, Type>
{
}

/// A list (tuple) of {@link ReadFunction}s producing `Results`, as accepted by
/// {@link readMultiple}.
pub trait ReadFunctionList<Results> {
    /// Read each value in order.
    fn read_all<'a>(&self, position: ReadPosition<'a>) -> MaybeReadResult<'a, Results>;
}

macro_rules! read_function_list {
    ($(($function:ident, $result:ident, $value:ident)),+) => {
        impl<$($function, $result),+> ReadFunctionList<($($result,)+)> for ($($function,)+)
        where
            $($function: ReadFunction<$result>),+
        {
            #[allow(non_snake_case)]
            fn read_all<'a>(&self, position: ReadPosition<'a>) -> MaybeReadResult<'a, ($($result,)+)> {
                let ($($function,)+) = self;
                let next_position = position;
                $(
                    let ReadResult { position: next_position, result: $value } =
                        $function(next_position)?;
                )+
                Ok(ReadResult {
                    position: next_position,
                    result: ($($value,)+),
                })
            }
        }
    };
}

read_function_list!((A, RA, a));
read_function_list!((A, RA, a), (B, RB, b));
read_function_list!((A, RA, a), (B, RB, b), (C, RC, c));
read_function_list!((A, RA, a), (B, RB, b), (C, RC, c), (D, RD, d));
read_function_list!((A, RA, a), (B, RB, b), (C, RC, c), (D, RD, d), (E, RE, e));
read_function_list!((A, RA, a), (B, RB, b), (C, RC, c), (D, RD, d), (E, RE, e), (F, RF, f));

/// Read a series of values from the provided {@link ReadPosition}, returning
/// either an error message (as a string) or an object containing the array of
/// results and the next {@link ReadPosition}.
pub fn read_multiple<'a, Results>(
    position: ReadPosition<'a>,
    read_functions: impl ReadFunctionList<Results>,
) -> MaybeReadResult<'a, Results> {
    read_functions.read_all(position)
}

/// Errors produced by {@link readItemCount}.
pub struct ReadItemCountError;

impl ReadItemCountError {
    pub const itemCount: &'static str = "Error reading item count.";
    pub const item: &'static str = "Error reading item.";
}

/// Read a count of items (as a minimally-encoded `CompactUint`) from the
/// provided {@link ReadPosition}, then read that number of items using the
/// provided {@link ReadFunction}, returning either an error message (as a
/// string) or an object containing the array of items and the next
/// {@link ReadPosition}.
pub fn read_item_count<'a, Type>(
    position: ReadPosition<'a>,
    read_function: impl ReadFunction<Type>,
) -> MaybeReadResult<'a, Vec<Type>> {
    let count_read = read_compact_uint_minimal(position)
        .map_err(|error| format_error(ReadItemCountError::itemCount, Some(&error)))?;
    let mut next_position = count_read.position;
    let mut result = Vec::new();
    let mut remaining = count_read.result;
    while remaining > 0 {
        let read = read_function(next_position)
            .map_err(|error| format_error(ReadItemCountError::item, Some(&error)))?;
        result.push(read.result);
        next_position = read.position;
        remaining -= 1;
    }
    Ok(ReadResult {
        position: next_position,
        result,
    })
}
