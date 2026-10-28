//! A minimal WebAssembly interpreter sufficient to execute libauth's embedded
//! `secp256k1.wasm` (an Emscripten-built module using the MVP instruction set
//! plus sign-extension and bulk-memory helpers).
//!
//! The implementation parses the binary module format directly and interprets
//! function bodies. Floating-point operations are parsed but not used by the
//! target module.

use std::sync::Arc;
use std::sync::OnceLock;

pub mod exec;
mod precompiled;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
}

impl ValType {
    fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0x7f => Ok(ValType::I32),
            0x7e => Ok(ValType::I64),
            0x7d => Ok(ValType::F32),
            0x7c => Ok(ValType::F64),
            other => Err(format!("Unsupported value type: 0x{other:02x}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

#[derive(Clone, Debug)]
pub enum ImportDesc {
    Function(u32),
    Table { initial: u32, maximum: Option<u32> },
    Memory { initial: u32, maximum: Option<u32> },
    Global(ValType, bool),
}

#[derive(Clone, Debug)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub desc: ImportDesc,
}

#[derive(Clone, Debug)]
pub struct Export {
    pub name: String,
    pub kind: u8,
    pub index: u32,
}

#[derive(Clone, Debug)]
pub struct DefinedFunction {
    pub type_index: u32,
    pub parameter_count: usize,
    pub result_count: usize,
    pub locals: Vec<ValType>,
    /// The pre-decoded function body with resolved branch targets.
    pub code: std::sync::Arc<Vec<exec::Op>>,
}

#[derive(Clone, Debug)]
pub struct Module {
    pub types: Vec<Arc<FuncType>>,
    pub imports: Vec<Import>,
    pub functions: Vec<Arc<DefinedFunction>>,
    pub imported_function_count: usize,
    pub table_initial: u32,
    pub memory_pages: u32,
    pub memory_max_pages: Option<u32>,
    pub global_types: Vec<(ValType, bool)>,
    pub global_inits: Vec<Vec<u8>>,
    pub exports: Vec<Export>,
    pub table_elements: Vec<u32>,
    pub data_segments: Vec<(u32, Vec<u8>)>,
    /// The SHA-256 digest of the module's bytes.
    pub digest: [u8; 32],
}

fn read_uleb(bytes: &[u8], position: &mut usize) -> Result<u64, String> {
    let mut result = 0_u64;
    let mut shift = 0;
    loop {
        let byte = *bytes
            .get(*position)
            .ok_or_else(|| "Unexpected end of LEB128".to_string())?;
        *position += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err("LEB128 too long".to_string());
        }
    }
}

fn read_sleb(bytes: &[u8], position: &mut usize) -> Result<i64, String> {
    let mut result = 0_i64;
    let mut shift = 0;
    let mut byte;
    loop {
        byte = *bytes
            .get(*position)
            .ok_or_else(|| "Unexpected end of SLEB128".to_string())?;
        *position += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err("SLEB128 too long".to_string());
        }
    }
    if shift < 64 && byte & 0x40 != 0 {
        result |= -1_i64 << shift;
    }
    Ok(result)
}

fn read_name(bytes: &[u8], position: &mut usize) -> Result<String, String> {
    let length = read_uleb(bytes, position)? as usize;
    if *position + length > bytes.len() {
        return Err("Unexpected end of name".to_string());
    }
    let name = String::from_utf8_lossy(&bytes[*position..*position + length]).into_owned();
    *position += length;
    Ok(name)
}

fn read_limits(bytes: &[u8], position: &mut usize) -> Result<(u32, Option<u32>), String> {
    let flags = *bytes
        .get(*position)
        .ok_or_else(|| "Unexpected end of limits".to_string())?;
    *position += 1;
    let initial = read_uleb(bytes, position)? as u32;
    let maximum = if flags & 1 != 0 {
        Some(read_uleb(bytes, position)? as u32)
    } else {
        None
    };
    Ok((initial, maximum))
}


/// Read a constant offset expression (`i32.const N end` or `global.get N end`).
fn read_offset_expression(bytes: &[u8], cursor: &mut usize) -> Result<Option<u32>, String> {
    let opcode = *bytes
        .get(*cursor)
        .ok_or_else(|| "Truncated offset expression".to_string())?;
    *cursor += 1;
    let value = match opcode {
        0x41 => read_sleb(bytes, cursor)? as u32,
        // Imported globals used as offsets (e.g. Emscripten's `tableBase`) are zero here.
        0x23 => {
            let _index = read_uleb(bytes, cursor)?;
            0
        }
        _ => return Ok(None),
    };
    if bytes.get(*cursor) != Some(&0x0b) {
        return Err("Offset expression must end with 0x0b".to_string());
    }
    *cursor += 1;
    Ok(Some(value))
}

/// Parse a WebAssembly binary module.
pub fn parse_module(bytes: &[u8]) -> Result<Module, String> {
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return Err("Not a WebAssembly module".to_string());
    }
    let mut types = Vec::new();
    let mut imports = Vec::new();
    let mut function_type_indices = Vec::new();
    let mut table_initial = 0;
    let mut memory_pages = 0;
    let mut memory_max_pages = None;
    let mut global_types = Vec::new();
    let mut global_inits: Vec<Vec<u8>> = Vec::new();
    let mut exports = Vec::new();
    let mut table_elements = Vec::new();
    let mut data_segments = Vec::new();
    let mut code_bodies: Vec<(Vec<ValType>, Vec<u8>)> = Vec::new();

    let mut position = 8_usize;
    while position < bytes.len() {
        let section_id = bytes[position];
        position += 1;
        let section_size = read_uleb(bytes, &mut position)? as usize;
        let section_end = position + section_size;
        if section_end > bytes.len() {
            return Err("Section extends past end of module".to_string());
        }
        let mut cursor = position;
        match section_id {
            0 => {}
            1 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let form = bytes[cursor];
                    cursor += 1;
                    if form != 0x60 {
                        return Err("Unsupported function type form".to_string());
                    }
                    let param_count = read_uleb(bytes, &mut cursor)?;
                    let mut params = Vec::with_capacity(param_count as usize);
                    for _ in 0..param_count {
                        params.push(ValType::from_byte(bytes[cursor])?);
                        cursor += 1;
                    }
                    let result_count = read_uleb(bytes, &mut cursor)?;
                    let mut results = Vec::with_capacity(result_count as usize);
                    for _ in 0..result_count {
                        results.push(ValType::from_byte(bytes[cursor])?);
                        cursor += 1;
                    }
                    types.push(Arc::new(FuncType { params, results }));
                }
            }
            2 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let module = read_name(bytes, &mut cursor)?;
                    let name = read_name(bytes, &mut cursor)?;
                    let kind = bytes[cursor];
                    cursor += 1;
                    let desc = match kind {
                        0 => ImportDesc::Function(read_uleb(bytes, &mut cursor)? as u32),
                        1 => {
                            let element_type = bytes[cursor];
                            cursor += 1;
                            if element_type != 0x70 && element_type != 0x6f {
                                return Err("Unsupported table element type".to_string());
                            }
                            let (initial, maximum) = read_limits(bytes, &mut cursor)?;
                            ImportDesc::Table { initial, maximum }
                        }
                        2 => {
                            let (initial, maximum) = read_limits(bytes, &mut cursor)?;
                            ImportDesc::Memory { initial, maximum }
                        }
                        3 => {
                            let value_type = ValType::from_byte(bytes[cursor])?;
                            cursor += 1;
                            let mutable = bytes[cursor] != 0;
                            cursor += 1;
                            ImportDesc::Global(value_type, mutable)
                        }
                        other => return Err(format!("Unsupported import kind: {other}")),
                    };
                    imports.push(Import {
                        module,
                        name,
                        desc,
                    });
                }
            }
            3 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    function_type_indices.push(read_uleb(bytes, &mut cursor)? as u32);
                }
            }
            4 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let element_type = bytes[cursor];
                    cursor += 1;
                    if element_type != 0x70 {
                        return Err("Unsupported table element type".to_string());
                    }
                    let (initial, _maximum) = read_limits(bytes, &mut cursor)?;
                    table_initial = initial;
                }
            }
            5 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let (_initial, maximum) = read_limits(bytes, &mut cursor)?;
                    memory_pages = _initial;
                    memory_max_pages = maximum;
                }
            }
            6 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let value_type = ValType::from_byte(bytes[cursor])?;
                    cursor += 1;
                    let mutable = bytes[cursor] != 0;
                    cursor += 1;
                    global_types.push((value_type, mutable));
                    let init_start = cursor;
                    // Skip the const init expression (opcode + immediate).
                    cursor += 1;
                    match bytes[init_start] {
                        0x41 | 0x42 => {
                            read_sleb(bytes, &mut cursor)?;
                        }
                        0x43 => cursor += 4,
                        0x44 => cursor += 8,
                        0xd0 | 0xd2 => {
                            read_uleb(bytes, &mut cursor)?;
                        }
                        0x23 => {
                            read_uleb(bytes, &mut cursor)?;
                        }
                        0x6a | 0x6b | 0x7c | 0x7d => {}
                        other => return Err(format!("Unsupported global init opcode: 0x{other:02x}")),
                    }
                    if bytes.get(cursor) != Some(&0x0b) {
                        return Err("Global init expression must end with 0x0b".to_string());
                    }
                    cursor += 1;
                    global_inits.push(bytes[init_start..cursor].to_vec());
                }
            }
            7 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let name = read_name(bytes, &mut cursor)?;
                    let kind = bytes[cursor];
                    cursor += 1;
                    let index = read_uleb(bytes, &mut cursor)? as u32;
                    exports.push(Export { name, kind, index });
                }
            }
            8 => {
                // Start section: record as a synthetic export-free function call.
                let function_index = read_uleb(bytes, &mut cursor)? as u32;
                exports.push(Export {
                    name: "__start".to_string(),
                    kind: 0xff,
                    index: function_index,
                });
            }
            9 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let flags = read_uleb(bytes, &mut cursor)?;
                    if flags == 0 {
                        if read_offset_expression(bytes, &mut cursor)?.is_none() {
                            return Err("Unsupported element offset expression".to_string());
                        }
                        let item_count = read_uleb(bytes, &mut cursor)?;
                        for _ in 0..item_count {
                            table_elements.push(read_uleb(bytes, &mut cursor)? as u32);
                        }
                    } else if flags == 1 || flags == 2 || flags == 3 {
                        return Err("Unsupported element segment flags".to_string());
                    } else {
                        return Err("Unsupported element segment flags".to_string());
                    }
                }
            }
            10 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let body_size = read_uleb(bytes, &mut cursor)? as usize;
                    let body_end = cursor + body_size;
                    let local_group_count = read_uleb(bytes, &mut cursor)?;
                    let mut locals = Vec::new();
                    for _ in 0..local_group_count {
                        let local_count = read_uleb(bytes, &mut cursor)? as usize;
                        let value_type = ValType::from_byte(bytes[cursor])?;
                        cursor += 1;
                        locals.extend(std::iter::repeat(value_type).take(local_count));
                    }
                    let code = bytes[cursor..body_end].to_vec();
                    code_bodies.push((locals, code));
                    cursor = body_end;
                }
            }
            11 => {
                let count = read_uleb(bytes, &mut cursor)?;
                for _ in 0..count {
                    let flags = read_uleb(bytes, &mut cursor)?;
                    if flags == 2 {
                        let memory_index = read_uleb(bytes, &mut cursor)?;
                        if memory_index != 0 {
                            return Err("Unsupported data segment memory index".to_string());
                        }
                    } else if flags != 0 {
                        return Err("Unsupported data segment flags".to_string());
                    }
                    let offset = read_offset_expression(bytes, &mut cursor)?
                        .ok_or_else(|| "Unsupported data segment offset expression".to_string())?;
                    let length = read_uleb(bytes, &mut cursor)? as usize;
                    if cursor + length > bytes.len() {
                        return Err("Data segment extends past end of module".to_string());
                    }
                    data_segments.push((offset, bytes[cursor..cursor + length].to_vec()));
                    cursor += length;
                }
            }
            12 => {}
            other => return Err(format!("Unsupported section: {other}")),
        }
        position = section_end;
    }

    if code_bodies.len() != function_type_indices.len() {
        return Err("Function and code section lengths differ".to_string());
    }
    let imported_function_count = imports
        .iter()
        .filter(|import| matches!(import.desc, ImportDesc::Function(_)))
        .count();
    let mut functions = Vec::with_capacity(code_bodies.len());
    for (index, (locals, code)) in code_bodies.into_iter().enumerate() {
        let type_index = function_type_indices[index];
        let function_type = types
            .get(type_index as usize)
            .ok_or_else(|| "Function type index out of range".to_string())?;
        let decoded = exec::decode_function(&code)?;
        functions.push(Arc::new(DefinedFunction {
            type_index,
            parameter_count: function_type.params.len(),
            result_count: function_type.results.len(),
            locals,
            code: Arc::new(decoded),
        }));
    }

    Ok(Module {
        types,
        imports,
        functions,
        imported_function_count,
        table_initial,
        memory_pages,
        memory_max_pages,
        global_types,
        global_inits,
        exports,
        table_elements,
        data_segments,
        digest: precompiled::module_digest(bytes),
    })
}

/// True when interpreter tracing is enabled (`LIBAUTH_WASM_TRACE`).
fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("LIBAUTH_WASM_TRACE").is_some())
}

/// Trap raised during WebAssembly execution.
#[derive(Debug, Clone)]
pub struct Trap(pub String);

impl std::fmt::Display for Trap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Imported host functions required by the embedded module.
pub trait HostImports: Send {
    fn call(&mut self, instance: &mut Instance, name: &str, args: &[u64]) -> Result<Option<u64>, Trap>;
}

/// A parsed and instantiated WebAssembly module.
pub struct Instance {
    pub module: Module,
    pub memory: Vec<u8>,
    pub globals: Vec<u64>,
    pub table: Vec<Option<u32>>,
    pub host: Option<Box<dyn HostImports>>,
    pub memory_base: u32,
    /// Exports executed natively (see `precompiled`), by function index.
    native: std::collections::HashMap<u32, precompiled::NativeFunction>,
}

impl Instance {
    pub fn new(
        module: Module,
        memory_bytes: usize,
        imported_globals: Vec<u64>,
        host: Box<dyn HostImports>,
    ) -> Self {
        let memory_pages = core::cmp::max(module.memory_pages, (memory_bytes / 65536) as u32);
        let mut globals = imported_globals;
        for init in &module.global_inits {
            let mut position = 1;
            let value = match init[0] {
                0x41 => read_sleb(init, &mut position).unwrap_or(0) as u32 as u64,
                0x42 => read_sleb(init, &mut position).unwrap_or(0) as u64,
                0x23 => {
                    let index = read_uleb(init, &mut position).unwrap_or(0) as usize;
                    globals.get(index).copied().unwrap_or(0)
                }
                _ => 0,
            };
            globals.push(value);
        }
        let imported_table_initial = module
            .imports
            .iter()
            .find_map(|import| match import.desc {
                ImportDesc::Table { initial, .. } => Some(initial),
                _ => None,
            })
            .unwrap_or(0);
        let table_size = core::cmp::max(core::cmp::max(module.table_initial, imported_table_initial), 1);
        let mut table = vec![None; table_size as usize];
        for (index, function_index) in module.table_elements.iter().enumerate() {
            if index < table.len() {
                table[index] = Some(*function_index);
            }
        }
        let mut instance = Instance {
            memory: vec![0_u8; memory_pages as usize * 65536],
            globals,
            table,
            host: Some(host),
            memory_base: 0,
            native: precompiled::native_functions(&module),
            module,
        };
        for (offset, data) in instance.module.data_segments.clone() {
            let start = offset as usize;
            if start + data.len() <= instance.memory.len() {
                instance.memory[start..start + data.len()].copy_from_slice(&data);
            }
        }
        instance
    }

    pub fn memory_slice(&self, offset: u32, length: u32) -> Result<&[u8], Trap> {
        let start = offset as usize;
        let end = start + length as usize;
        if end > self.memory.len() {
            return Err(Trap(format!(
                "Out of bounds memory read: {start}..{end} (memory length {})",
                self.memory.len()
            )));
        }
        Ok(&self.memory[start..end])
    }

    pub fn memory_slice_mut(&mut self, offset: u32, length: u32) -> Result<&mut [u8], Trap> {
        let start = offset as usize;
        let end = start + length as usize;
        if end > self.memory.len() {
            return Err(Trap(format!(
                "Out of bounds memory write: {start}..{end} (memory length {})",
                self.memory.len()
            )));
        }
        Ok(&mut self.memory[start..end])
    }

    pub fn function_index(&self, name: &str) -> Option<u32> {
        self.module
            .exports
            .iter()
            .find(|export| export.name == name && export.kind == 0)
            .map(|export| export.index)
    }

    /// Call an exported function with raw `u64`-encoded arguments.
    pub fn call_export(&mut self, name: &str, args: &[u64]) -> Result<Vec<u64>, Trap> {
        let index = self
            .function_index(name)
            .ok_or_else(|| Trap(format!("Missing export: {name}")))?;
        self.call_function(index, args)
    }

    pub fn call_function(&mut self, index: u32, args: &[u64]) -> Result<Vec<u64>, Trap> {
        if let Some(native) = self.native.get(&index).copied() {
            return native(self, args);
        }
        let parameter_count = exec::function_type_for(self, index)?.params.len();
        if args.len() > parameter_count {
            return Err(Trap(format!(
                "Function {index} expects {parameter_count} arguments, got {}",
                args.len()
            )));
        }
        let mut stack: Vec<u64> = Vec::with_capacity(64);
        stack.extend_from_slice(args);
        while stack.len() < parameter_count {
            stack.push(0);
        }
        let base = stack.len() - parameter_count;
        if base != 0 {
            stack.truncate(0);
            // Re-push in the correct order (arguments are the only values).
            stack.extend_from_slice(args);
            while stack.len() < parameter_count {
                stack.push(0);
            }
        }
        let mut locals: Vec<u64> = Vec::with_capacity(64);
        let mut control: Vec<exec::Frame> = Vec::new();
        match exec::invoke(self, index, &mut stack, &mut locals, &mut control) {
            Ok(()) => Ok(stack),
            Err(error) => {
                if trace_enabled() {
                    eprintln!("trap: {error}");
                }
                Err(error)
            }
        }
    }
}

/// A value created independently on each thread that uses it.
///
/// Each JavaScript agent (the main thread or a worker) instantiates its own
/// copies of WebAssembly modules, so libauth's objects that wrap a WebAssembly
/// instance (`HashFunction`, `Secp256k1`, ...) are never shared between
/// threads of execution. `PerThread` gives their Rust counterparts the same
/// behavior: a shareable handle (`Send + Sync`) whose underlying instance is
/// created lazily, once per thread, by the same constructor.
pub struct PerThread<T: 'static> {
    id: u64,
    create: Arc<dyn Fn() -> T + Send + Sync>,
}

impl<T: 'static> Clone for PerThread<T> {
    fn clone(&self) -> Self {
        PerThread {
            id: self.id,
            create: Arc::clone(&self.create),
        }
    }
}

impl<T: 'static> std::fmt::Debug for PerThread<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PerThread").field("id", &self.id).finish()
    }
}

thread_local! {
    static PER_THREAD_SLOTS: std::cell::RefCell<std::collections::HashMap<u64, Box<dyn std::any::Any>>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

impl<T: 'static> PerThread<T> {
    /// Create a handle whose per-thread instances are produced by `create`.
    pub fn new(create: impl Fn() -> T + Send + Sync + 'static) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        PerThread {
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            create: Arc::new(create),
        }
    }

    /// Run `operation` with this thread's instance, creating it on first use.
    pub fn with<Output>(&self, operation: impl FnOnce(&mut T) -> Output) -> Output {
        // The instance is taken out of the slot while `operation` runs, so a
        // re-entrant call (which would need a second, simultaneous borrow)
        // simply creates another instance.
        let existing = PER_THREAD_SLOTS.with(|slots| slots.borrow_mut().remove(&self.id));
        let mut instance = existing.unwrap_or_else(|| Box::new((self.create)()));
        let output = operation(
            instance
                .downcast_mut::<T>()
                .expect("a per-thread slot always holds its handle's type"),
        );
        PER_THREAD_SLOTS.with(|slots| slots.borrow_mut().insert(self.id, instance));
        output
    }
}
