//! libauth's `HashFunction` type.
//!
//! libauth instantiates its hash functions from Rust-compiled WebAssembly
//! (`instantiateRustWasm`). This port implements them natively (see
//! `crypto/sha256.rs` and the other hash modules), so this module provides only
//! the `HashFunction` type and the incremental hashing state they share.

/// An object of hash functions (libauth's `HashFunction`). To incrementally
/// construct a hash (e.g. for streaming), use `init`, `update`, and `final`.
///
/// The members are function pointers, so custom implementations (e.g. mocks)
/// can be provided.
#[derive(Clone, Copy)]
pub struct HashFunction {
    /// Finish an incremental hash computation, returning the final hash.
    pub r#final: fn(raw_state: &[u8]) -> Vec<u8>,
    /// Returns the hash of the provided input.
    pub hash: fn(input: &[u8]) -> Vec<u8>,
    /// Begin an incremental hash computation, returning the raw state.
    pub init: fn() -> Vec<u8>,
    /// Add input to an incremental hash computation, returning the new raw
    /// state.
    pub update: fn(raw_state: &[u8], input: &[u8]) -> Vec<u8>,
}

impl HashFunction {
    /// Finish an incremental hash computation, returning the final hash.
    pub fn r#final(&self, raw_state: &[u8]) -> Vec<u8> {
        (self.r#final)(raw_state)
    }

    /// Returns the hash of the provided input. To incrementally construct a
    /// hash (e.g. for streaming), use `init`, `update`, and `final`.
    pub fn hash(&self, input: &[u8]) -> Vec<u8> {
        (self.hash)(input)
    }

    /// Begin an incremental hash computation, returning the raw state.
    pub fn init(&self) -> Vec<u8> {
        (self.init)()
    }

    /// Add input to an incremental hash computation, returning the new raw
    /// state.
    pub fn update(&self, raw_state: &[u8], input: &[u8]) -> Vec<u8> {
        (self.update)(raw_state, input)
    }
}

impl core::fmt::Debug for HashFunction {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HashFunction")
    }
}

/// A Merkle–Damgård hash function, providing the incremental `init`, `update`,
/// and `final` functions of a {@link HashFunction}.
///
/// The raw state is this port's own encoding (libauth's is the in-memory
/// layout of the hasher in its WebAssembly modules): the chaining value in
/// digest byte order, the number of bytes hashed (8 bytes, little-endian), and
/// the pending partial block (zero-filled).
pub(crate) trait MerkleDamgard {
    /// The block length in bytes.
    const BLOCK_LENGTH: usize;
    /// The length in bytes of the message length field of the final padding.
    const LENGTH_FIELD_LENGTH: usize;
    /// Whether the message length field is big-endian (little-endian if not).
    const BIG_ENDIAN_LENGTH: bool;
    /// The initial chaining value, in digest byte order.
    fn initial_chaining_value() -> Vec<u8>;
    /// Compress `blocks` (a multiple of `BLOCK_LENGTH` bytes) into
    /// `chaining_value`.
    fn compress(chaining_value: &mut [u8], blocks: &[u8]);
}

fn state_length<H: MerkleDamgard>() -> usize {
    H::initial_chaining_value().len() + 8 + H::BLOCK_LENGTH
}

/// Begin an incremental hash computation.
pub(crate) fn init<H: MerkleDamgard>() -> Vec<u8> {
    let mut state = H::initial_chaining_value();
    state.resize(state_length::<H>(), 0);
    state
}

/// Copy a raw state. Like libauth's modules, which read a fixed-length prefix
/// of the raw state, a shorter raw state throws (here, panics).
fn load_state<H: MerkleDamgard>(raw_state: &[u8]) -> Vec<u8> {
    let length = state_length::<H>();
    if raw_state.len() < length {
        panic!("RuntimeError: unreachable");
    }
    raw_state[..length].to_vec()
}

/// Add input to an incremental hash computation.
pub(crate) fn update<H: MerkleDamgard>(raw_state: &[u8], input: &[u8]) -> Vec<u8> {
    let mut state = load_state::<H>(raw_state);
    let chaining_value_length = state.len() - 8 - H::BLOCK_LENGTH;
    let (chaining_value, rest) = state.split_at_mut(chaining_value_length);
    let (count_bytes, buffer) = rest.split_at_mut(8);
    let count = u64::from_le_bytes(count_bytes.try_into().expect("8 bytes"));
    let mut buffered = (count % H::BLOCK_LENGTH as u64) as usize;
    let mut remaining = input;
    if buffered > 0 {
        let taken = remaining.len().min(H::BLOCK_LENGTH - buffered);
        buffer[buffered..buffered + taken].copy_from_slice(&remaining[..taken]);
        buffered += taken;
        remaining = &remaining[taken..];
        if buffered == H::BLOCK_LENGTH {
            H::compress(chaining_value, buffer);
            buffered = 0;
        }
    }
    if buffered == 0 {
        let full_blocks = remaining.len() - remaining.len() % H::BLOCK_LENGTH;
        H::compress(chaining_value, &remaining[..full_blocks]);
        let tail = &remaining[full_blocks..];
        buffer.fill(0);
        buffer[..tail.len()].copy_from_slice(tail);
    }
    count_bytes.copy_from_slice(&count.wrapping_add(input.len() as u64).to_le_bytes());
    state
}

/// Finish an incremental hash computation, returning the hash.
pub(crate) fn r#final<H: MerkleDamgard>(raw_state: &[u8]) -> Vec<u8> {
    let state = load_state::<H>(raw_state);
    let chaining_value_length = state.len() - 8 - H::BLOCK_LENGTH;
    let mut chaining_value = state[..chaining_value_length].to_vec();
    let count = u64::from_le_bytes(state[chaining_value_length..chaining_value_length + 8].try_into().expect("8 bytes"));
    let buffered = (count % H::BLOCK_LENGTH as u64) as usize;
    let mut padding = state[chaining_value_length + 8..chaining_value_length + 8 + buffered].to_vec();
    padding.push(0x80);
    while padding.len() % H::BLOCK_LENGTH != H::BLOCK_LENGTH - H::LENGTH_FIELD_LENGTH {
        padding.push(0);
    }
    let bit_length = u128::from(count) * 8;
    let length_field = if H::BIG_ENDIAN_LENGTH { bit_length.to_be_bytes() } else { bit_length.to_le_bytes() };
    if H::BIG_ENDIAN_LENGTH {
        padding.extend_from_slice(&length_field[16 - H::LENGTH_FIELD_LENGTH..]);
    } else {
        padding.extend_from_slice(&length_field[..H::LENGTH_FIELD_LENGTH]);
    }
    H::compress(&mut chaining_value, &padding);
    chaining_value
}
