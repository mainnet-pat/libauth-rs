use sha2::digest::generic_array::GenericArray;
use sha2::Digest;

use super::dependencies::HashFunction;
use crate::bin::hashes::{self, MerkleDamgard};

/// An instantiated sha256 hash function: `hash`, `init`, `update`, and
/// `final`. To incrementally construct a hash (e.g. for streaming), use
/// `init`, `update`, and `final`.
pub type Sha256 = HashFunction;

/// The sha256 compression function and padding.
struct Sha256Blocks;

impl MerkleDamgard for Sha256Blocks {
    const BLOCK_LENGTH: usize = 64;
    const LENGTH_FIELD_LENGTH: usize = 8;
    const BIG_ENDIAN_LENGTH: bool = true;

    fn initial_chaining_value() -> Vec<u8> {
        [0x6a09_e667_u32, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19].iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn compress(chaining_value: &mut [u8], blocks: &[u8]) {
        let mut state = [0_u32; 8];
        for (word, bytes) in state.iter_mut().zip(chaining_value.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("a whole word"));
        }
        for block in blocks.chunks_exact(64) {
            sha2::compress256(&mut state, core::slice::from_ref(GenericArray::from_slice(block)));
        }
        for (bytes, word) in chaining_value.chunks_exact_mut(4).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
    }
}

fn hash(input: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(input).to_vec()
}

/// Instantiate sha256 functionality. (libauth instantiates its embedded
/// WebAssembly binary; this port implements sha256 natively.)
pub const fn instantiate_sha256() -> Sha256 {
    HashFunction {
        r#final: hashes::r#final::<Sha256Blocks>,
        hash,
        init: hashes::init::<Sha256Blocks>,
        update: hashes::update::<Sha256Blocks>,
    }
}
