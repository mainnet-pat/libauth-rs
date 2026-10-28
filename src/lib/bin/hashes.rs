use crate::runtime::webassembly::{parse_module, HostImports, Instance, PerThread, Trap};

/// Initial memory for the hash module; the module's own allocator grows it.
const HASH_MODULE_MEMORY_BYTES: usize = 0;

/// The interface of a hash function instantiated by {@link instantiateRustWasm}
/// (libauth's `HashFunction` object: `final`, `hash`, `init`, and `update`).
///
/// Each thread that uses a `HashFunction` runs its own instance of the
/// WebAssembly module (see `PerThread`), as each JavaScript agent would.
#[derive(Clone)]
pub struct HashFunction {
    engine: PerThread<HashEngine>,
}

struct HashEngine {
    instance: Instance,
    hash_export: u32,
    init_export: u32,
    update_export: u32,
    final_export: u32,
    global_argument_ptr: u32,
}

/// Reports a `__wbindgen_throw` from the module, as libauth does.
struct WbindgenHost;

impl HostImports for WbindgenHost {
    fn call(
        &mut self,
        instance: &mut Instance,
        name: &str,
        args: &[u64],
    ) -> Result<Option<u64>, Trap> {
        match name {
            "__wbindgen_throw" => {
                let pointer = args.first().copied().unwrap_or(0) as u32;
                let length = args.get(1).copied().unwrap_or(0) as u32;
                let message = instance
                    .memory_slice(pointer, length)
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .unwrap_or_else(|_| "wasm-bindgen throw".to_string());
                Err(Trap(message))
            }
            other => Err(Trap(format!("Unsupported host import: {other}"))),
        }
    }
}

impl HashFunction {
    /// Finish an incremental hash computation, returning the final hash.
    ///
    /// As in libauth, `raw_state` is updated in place with the module's copy of
    /// the state.
    pub fn r#final(&self, raw_state: &mut [u8]) -> Vec<u8> {
        self.engine.with(|engine| engine.finalize(raw_state))
    }

    /// Returns the hash of the provided input. To incrementally construct a
    /// hash (e.g. for streaming), use `init`, `update`, and `final`.
    pub fn hash(&self, input: &[u8]) -> Vec<u8> {
        self.engine.with(|engine| engine.hash(input))
    }

    /// Begin an incremental hash computation, returning the raw state.
    pub fn init(&self) -> Vec<u8> {
        self.engine.with(HashEngine::init)
    }

    /// Add input to an incremental hash computation, returning the new raw
    /// state. As in libauth, `raw_state` is also updated in place.
    pub fn update(&self, raw_state: &mut [u8], input: &[u8]) -> Vec<u8> {
        self.engine.with(|engine| engine.update(raw_state, input))
    }
}

impl core::fmt::Debug for HashFunction {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HashFunction")
    }
}

/// Instantiate a WebAssembly hash function module built with `wasm-bindgen`
/// (as libauth's hash function modules are), returning a {@link HashFunction}.
///
/// `expected_import_module_name` must match the module named by every
/// function import (libauth's payloads import from `./sha256`, etc.), and each
/// of the four export names must be exported by the module. Failures are
/// reported with the wording used by `WebAssembly.instantiate` (`module is not
/// an object or function`) and by missing exports (`Missing export`).
pub fn instantiate_rust_wasm(
    webassembly_bytes: &[u8],
    expected_import_module_name: &str,
    hash_export_name: &str,
    init_export_name: &str,
    update_export_name: &str,
    final_export_name: &str,
) -> Result<HashFunction, String> {
    let bytes = std::sync::Arc::new(webassembly_bytes.to_vec());
    let names = [
        expected_import_module_name.to_string(),
        hash_export_name.to_string(),
        init_export_name.to_string(),
        update_export_name.to_string(),
        final_export_name.to_string(),
    ];
    // Instantiate once on the calling thread to report any errors.
    HashEngine::instantiate(&bytes, &names)?;
    Ok(HashFunction {
        engine: PerThread::new(move || {
            HashEngine::instantiate(&bytes, &names)
                .expect("the module instantiated successfully on another thread")
        }),
    })
}

fn export_index(instance: &Instance, name: &str) -> Result<u32, String> {
    instance
        .function_index(name)
        .ok_or_else(|| format!("Missing export: {name}"))
}

impl HashEngine {
    fn instantiate(webassembly_bytes: &[u8], names: &[String; 5]) -> Result<Self, String> {
        let [expected_import_module_name, hash_export_name, init_export_name, update_export_name, final_export_name] =
            names;
        let module = parse_module(webassembly_bytes)?;
        for (index, import) in module.imports.iter().enumerate() {
            if &import.module != expected_import_module_name {
                return Err(format!(
                    "Import #{index} module=\"{}\" error: module is not an object or function",
                    import.module
                ));
            }
        }
        let instance = Instance::new(
            module,
            HASH_MODULE_MEMORY_BYTES,
            Vec::new(),
            Box::new(WbindgenHost),
        );
        Ok(HashEngine {
            hash_export: export_index(&instance, hash_export_name)?,
            init_export: export_index(&instance, init_export_name)?,
            update_export: export_index(&instance, update_export_name)?,
            final_export: export_index(&instance, final_export_name)?,
            global_argument_ptr: export_index(&instance, "__wbindgen_global_argument_ptr")?,
            instance,
        })
    }

    fn call(&mut self, index: u32, args: &[u64]) -> Vec<u64> {
        self.instance
            .call_function(index, args)
            .expect("hash module call succeeds")
    }

    fn global_argument_ptr(&mut self) -> u32 {
        let index = self.global_argument_ptr;
        self.call(index, &[])[0] as u32
    }

    fn malloc(&mut self, length: usize) -> u32 {
        self.instance
            .call_export("__wbindgen_malloc", &[length as u64])
            .expect("hash module allocation succeeds")[0] as u32
    }

    fn free(&mut self, pointer: u32, length: usize) {
        let _ = self
            .instance
            .call_export("__wbindgen_free", &[u64::from(pointer), length as u64]);
    }

    fn pass_array(&mut self, array: &[u8]) -> (u32, usize) {
        let pointer = self.malloc(array.len());
        self.instance
            .memory_slice_mut(pointer, array.len() as u32)
            .expect("hash module allocation is in bounds")
            .copy_from_slice(array);
        (pointer, array.len())
    }

    fn read_return(&mut self, ret_ptr: u32) -> Vec<u8> {
        let header = self
            .instance
            .memory_slice(ret_ptr, 8)
            .expect("return pointer is in bounds")
            .to_vec();
        let pointer = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let value = self
            .instance
            .memory_slice(pointer, length)
            .expect("returned value is in bounds")
            .to_vec();
        self.free(pointer, length as usize);
        value
    }

    fn hash(&mut self, input: &[u8]) -> Vec<u8> {
        let (input_ptr, input_len) = self.pass_array(input);
        let ret_ptr = self.global_argument_ptr();
        let export = self.hash_export;
        self.call(
            export,
            &[u64::from(ret_ptr), u64::from(input_ptr), input_len as u64],
        );
        let value = self.read_return(ret_ptr);
        self.free(input_ptr, input_len);
        value
    }

    fn init(&mut self) -> Vec<u8> {
        let ret_ptr = self.global_argument_ptr();
        let export = self.init_export;
        self.call(export, &[u64::from(ret_ptr)]);
        self.read_return(ret_ptr)
    }

    fn update(&mut self, raw_state: &mut [u8], input: &[u8]) -> Vec<u8> {
        let (state_ptr, state_len) = self.pass_array(raw_state);
        let (input_ptr, input_len) = self.pass_array(input);
        let ret_ptr = self.global_argument_ptr();
        let export = self.update_export;
        self.call(
            export,
            &[
                u64::from(ret_ptr),
                u64::from(state_ptr),
                state_len as u64,
                u64::from(input_ptr),
                input_len as u64,
            ],
        );
        let value = self.read_return(ret_ptr);
        // libauth copies the module's (possibly advanced) raw state back.
        let updated = self
            .instance
            .memory_slice(state_ptr, state_len as u32)
            .expect("raw state is in bounds")
            .to_vec();
        raw_state.copy_from_slice(&updated);
        self.free(state_ptr, state_len);
        self.free(input_ptr, input_len);
        value
    }

    fn finalize(&mut self, raw_state: &mut [u8]) -> Vec<u8> {
        let (state_ptr, state_len) = self.pass_array(raw_state);
        let ret_ptr = self.global_argument_ptr();
        let export = self.final_export;
        self.call(
            export,
            &[u64::from(ret_ptr), u64::from(state_ptr), state_len as u64],
        );
        let value = self.read_return(ret_ptr);
        let updated = self
            .instance
            .memory_slice(state_ptr, state_len as u32)
            .expect("raw state is in bounds")
            .to_vec();
        raw_state.copy_from_slice(&updated);
        self.free(state_ptr, state_len);
        value
    }
}
