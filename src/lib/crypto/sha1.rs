use sha1::digest::generic_array::GenericArray;
use sha1::Digest;

use super::dependencies::HashFunction;
use crate::bin::hashes::{self, MerkleDamgard};

/// An instantiated sha1 hash function: `hash`, `init`, `update`, and
/// `final`. To incrementally construct a hash (e.g. for streaming), use
/// `init`, `update`, and `final`.
pub type Sha1 = HashFunction;

/// The sha1 compression function and padding.
struct Sha1Blocks;

impl MerkleDamgard for Sha1Blocks {
    const BLOCK_LENGTH: usize = 64;
    const LENGTH_FIELD_LENGTH: usize = 8;
    const BIG_ENDIAN_LENGTH: bool = true;

    fn initial_chaining_value() -> Vec<u8> {
        [0x6745_2301_u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0].iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn compress(chaining_value: &mut [u8], blocks: &[u8]) {
        let mut state = [0_u32; 5];
        for (word, bytes) in state.iter_mut().zip(chaining_value.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("a whole word"));
        }
        for block in blocks.chunks_exact(64) {
            sha1::compress(&mut state, core::slice::from_ref(GenericArray::from_slice(block)));
        }
        for (bytes, word) in chaining_value.chunks_exact_mut(4).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
    }
}

fn hash(input: &[u8]) -> Vec<u8> {
    sha1::Sha1::digest(input).to_vec()
}

/// Instantiate sha1 functionality. (libauth instantiates its embedded
/// WebAssembly binary; this port implements sha1 natively.)
pub const fn instantiate_sha1() -> Sha1 {
    HashFunction {
        r#final: hashes::r#final::<Sha1Blocks>,
        hash,
        init: hashes::init::<Sha1Blocks>,
        update: hashes::update::<Sha1Blocks>,
    }
}
