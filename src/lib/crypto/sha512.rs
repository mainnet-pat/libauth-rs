use sha2::digest::generic_array::GenericArray;
use sha2::Digest;

use super::dependencies::HashFunction;
use crate::bin::hashes::{self, MerkleDamgard};

/// An instantiated sha512 hash function: `hash`, `init`, `update`, and
/// `final`. To incrementally construct a hash (e.g. for streaming), use
/// `init`, `update`, and `final`.
pub type Sha512 = HashFunction;

/// The sha512 compression function and padding.
struct Sha512Blocks;

impl MerkleDamgard for Sha512Blocks {
    const BLOCK_LENGTH: usize = 128;
    const LENGTH_FIELD_LENGTH: usize = 16;
    const BIG_ENDIAN_LENGTH: bool = true;

    fn initial_chaining_value() -> Vec<u8> {
        [0x6a09_e667_f3bc_c908_u64, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1, 0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179].iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn compress(chaining_value: &mut [u8], blocks: &[u8]) {
        let mut state = [0_u64; 8];
        for (word, bytes) in state.iter_mut().zip(chaining_value.chunks_exact(8)) {
            *word = u64::from_be_bytes(bytes.try_into().expect("a whole word"));
        }
        for block in blocks.chunks_exact(128) {
            sha2::compress512(&mut state, core::slice::from_ref(GenericArray::from_slice(block)));
        }
        for (bytes, word) in chaining_value.chunks_exact_mut(8).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
    }
}

fn hash(input: &[u8]) -> Vec<u8> {
    sha2::Sha512::digest(input).to_vec()
}

/// Instantiate sha512 functionality. (libauth instantiates its embedded
/// WebAssembly binary; this port implements sha512 natively.)
pub const fn instantiate_sha512() -> Sha512 {
    HashFunction {
        r#final: hashes::r#final::<Sha512Blocks>,
        hash,
        init: hashes::init::<Sha512Blocks>,
        update: hashes::update::<Sha512Blocks>,
    }
}
