//! Natively compiled functions for the WebAssembly modules libauth embeds.
//!
//! A JavaScript engine compiles WebAssembly to machine code before running it;
//! this crate's interpreter is roughly two orders of magnitude slower. For
//! libauth's hash function modules (recognized by the SHA-256 digest of their
//! bytes), the runtime therefore executes the hashing exports with equivalent
//! native code, the way a JIT would. Everything else about the module is
//! unchanged: it is instantiated and initialized normally, its linear memory and
//! own allocator (`__wbindgen_malloc`/`__wbindgen_free`) are used, and the
//! natively executed exports follow the module's `wasm-bindgen` calling
//! convention. Only the opaque "raw state" passed between `*_init`, `*_update`,
//! and `*_final` uses a native layout.

mod ripemd160;
mod sha1;
mod sha256;
mod sha512;

use std::collections::HashMap;

use super::{Instance, Module, Trap};

/// A natively executed function: `(instance, arguments) -> results`.
pub(super) type NativeFunction = fn(&mut Instance, &[u64]) -> Result<Vec<u64>, Trap>;

macro_rules! md_hasher {
    ($name:ident, $module:ident, $word:ty, $words:expr, $block:expr, $length_bytes:expr, $big_endian:expr, $initial:expr) => {
        #[derive(Clone)]
        struct $name {
            state: [$word; $words],
            buffer: Vec<u8>,
            length: u128,
        }

        impl $name {
            const WORD_BYTES: usize = core::mem::size_of::<$word>();
            const RAW_STATE_LENGTH: usize = $words * Self::WORD_BYTES + 16 + 1 + $block;

            fn new() -> Self {
                $name {
                    state: $initial,
                    buffer: Vec::with_capacity($block),
                    length: 0,
                }
            }

            fn update(&mut self, mut data: &[u8]) {
                self.length = self.length.wrapping_add(data.len() as u128);
                if !self.buffer.is_empty() {
                    let take = ($block - self.buffer.len()).min(data.len());
                    self.buffer.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if self.buffer.len() == $block {
                        $module::compress(&mut self.state, &self.buffer);
                        self.buffer.clear();
                    }
                }
                let mut blocks = data.chunks_exact($block);
                for block in &mut blocks {
                    $module::compress(&mut self.state, block);
                }
                self.buffer.extend_from_slice(blocks.remainder());
            }

            fn finalize(mut self) -> Vec<u8> {
                let bit_length = self.length.wrapping_mul(8);
                let mut tail = core::mem::take(&mut self.buffer);
                tail.push(0x80);
                while tail.len() % $block != $block - $length_bytes {
                    tail.push(0);
                }
                if $big_endian {
                    tail.extend_from_slice(&bit_length.to_be_bytes()[16 - $length_bytes..]);
                } else {
                    tail.extend_from_slice(&bit_length.to_le_bytes()[..$length_bytes]);
                }
                for block in tail.chunks_exact($block) {
                    $module::compress(&mut self.state, block);
                }
                let mut digest = Vec::with_capacity($words * Self::WORD_BYTES);
                for word in self.state {
                    if $big_endian {
                        digest.extend_from_slice(&word.to_be_bytes());
                    } else {
                        digest.extend_from_slice(&word.to_le_bytes());
                    }
                }
                digest
            }

            /// Serialize: chaining words (little-endian), the message length
            /// (u128, little-endian), the buffer length, and the zero-padded buffer.
            fn to_raw_state(&self) -> Vec<u8> {
                let mut raw = Vec::with_capacity(Self::RAW_STATE_LENGTH);
                for word in self.state {
                    raw.extend_from_slice(&word.to_le_bytes());
                }
                raw.extend_from_slice(&self.length.to_le_bytes());
                raw.push(self.buffer.len() as u8);
                raw.extend_from_slice(&self.buffer);
                raw.resize(Self::RAW_STATE_LENGTH, 0);
                raw
            }

            fn from_raw_state(raw: &[u8]) -> Option<Self> {
                if raw.len() != Self::RAW_STATE_LENGTH {
                    return None;
                }
                let mut hasher = Self::new();
                for (index, word) in raw[..$words * Self::WORD_BYTES]
                    .chunks_exact(Self::WORD_BYTES)
                    .enumerate()
                {
                    hasher.state[index] = <$word>::from_le_bytes(word.try_into().ok()?);
                }
                let offset = $words * Self::WORD_BYTES;
                hasher.length = u128::from_le_bytes(raw[offset..offset + 16].try_into().ok()?);
                let buffer_length = raw[offset + 16] as usize;
                if buffer_length >= $block {
                    return None;
                }
                hasher.buffer = raw[offset + 17..offset + 17 + buffer_length].to_vec();
                Some(hasher)
            }
        }
    };
}

md_hasher!(Sha1Hasher, sha1, u32, 5, 64, 8, true, [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0]);
md_hasher!(
    Sha256Hasher,
    sha256,
    u32,
    8,
    64,
    8,
    true,
    [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19]
);
md_hasher!(
    Sha512Hasher,
    sha512,
    u64,
    8,
    128,
    16,
    true,
    [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ]
);
md_hasher!(Ripemd160Hasher, ripemd160, u32, 5, 64, 8, false, [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0]);

/// The SHA-256 digest of a module's bytes.
pub(super) fn module_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize().try_into().expect("a SHA-256 digest is 32 bytes")
}

fn read(instance: &Instance, pointer: u64, length: u64) -> Result<Vec<u8>, Trap> {
    Ok(instance.memory_slice(pointer as u32, length as u32)?.to_vec())
}

/// Return `value` as wasm-bindgen does: allocate it with the module's own
/// allocator and write its pointer and length to `return_pointer`.
fn write_return(instance: &mut Instance, return_pointer: u64, value: &[u8]) -> Result<Vec<u64>, Trap> {
    let pointer = instance.call_export("__wbindgen_malloc", &[value.len() as u64])?[0] as u32;
    instance
        .memory_slice_mut(pointer, value.len() as u32)?
        .copy_from_slice(value);
    let mut header = [0_u8; 8];
    header[..4].copy_from_slice(&pointer.to_le_bytes());
    header[4..].copy_from_slice(&(value.len() as u32).to_le_bytes());
    instance
        .memory_slice_mut(return_pointer as u32, 8)?
        .copy_from_slice(&header);
    Ok(Vec::new())
}

macro_rules! native_exports {
    ($hasher:ident, $hash:ident, $init:ident, $update:ident, $final:ident) => {
        fn $hash(instance: &mut Instance, args: &[u64]) -> Result<Vec<u64>, Trap> {
            let input = read(instance, args[1], args[2])?;
            let mut hasher = $hasher::new();
            hasher.update(&input);
            write_return(instance, args[0], &hasher.finalize())
        }

        fn $init(instance: &mut Instance, args: &[u64]) -> Result<Vec<u64>, Trap> {
            write_return(instance, args[0], &$hasher::new().to_raw_state())
        }

        fn $update(instance: &mut Instance, args: &[u64]) -> Result<Vec<u64>, Trap> {
            let raw_state = read(instance, args[1], args[2])?;
            let input = read(instance, args[3], args[4])?;
            let mut hasher = $hasher::from_raw_state(&raw_state)
                .ok_or_else(|| Trap("Invalid hash function raw state.".to_string()))?;
            hasher.update(&input);
            write_return(instance, args[0], &hasher.to_raw_state())
        }

        fn $final(instance: &mut Instance, args: &[u64]) -> Result<Vec<u64>, Trap> {
            let raw_state = read(instance, args[1], args[2])?;
            let hasher = $hasher::from_raw_state(&raw_state)
                .ok_or_else(|| Trap("Invalid hash function raw state.".to_string()))?;
            write_return(instance, args[0], &hasher.finalize())
        }
    };
}

native_exports!(Sha1Hasher, sha1_hash, sha1_init, sha1_update, sha1_final);
native_exports!(Sha256Hasher, sha256_hash, sha256_init, sha256_update, sha256_final);
native_exports!(Sha512Hasher, sha512_hash, sha512_init, sha512_update, sha512_final);
native_exports!(Ripemd160Hasher, ripemd160_hash, ripemd160_init, ripemd160_update, ripemd160_final);

fn hex_digest(hex: &str) -> [u8; 32] {
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("a valid digest");
    }
    digest
}

/// Natively executed exports for a module, by function index (empty for
/// modules without a native implementation).
pub(super) fn native_functions(module: &Module) -> HashMap<u32, NativeFunction> {
    let known: [(&str, &str, [NativeFunction; 4]); 4] = [
        (
            "92931b6be545eb33e217cfeed95aa006c1f8dd82fcfe9fd3691e0da82dda2ccb",
            "sha1",
            [sha1_hash, sha1_init, sha1_update, sha1_final],
        ),
        (
            "de488afc3d34bec3ea7e03ea06397f4f2cc40ab9a7a95fefd453cea1b98c09be",
            "sha256",
            [sha256_hash, sha256_init, sha256_update, sha256_final],
        ),
        (
            "2120129945daf2d76d9963ab90674c49f40637dd2ef8da71f325d2d02c66bf71",
            "sha512",
            [sha512_hash, sha512_init, sha512_update, sha512_final],
        ),
        (
            "f16c1a5930448b80f40b77264afdcaaf853bd8d2592655e3e6119c63a50332b5",
            "ripemd160",
            [ripemd160_hash, ripemd160_init, ripemd160_update, ripemd160_final],
        ),
    ];
    let mut natives = HashMap::new();
    for (digest, name, functions) in known {
        if module.digest != hex_digest(digest) {
            continue;
        }
        let names = [
            name.to_string(),
            format!("{name}_init"),
            format!("{name}_update"),
            format!("{name}_final"),
        ];
        for (export_name, function) in names.iter().zip(functions) {
            if let Some(export) = module
                .exports
                .iter()
                .find(|export| &export.name == export_name && export.kind == 0)
            {
                natives.insert(export.index, function);
            }
        }
    }
    natives
}
