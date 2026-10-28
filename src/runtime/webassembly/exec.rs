//! Pre-decoded WebAssembly execution.
//!
//! Function bodies are decoded once into a flat instruction array with resolved
//! branch targets. The interpreter then runs a tight dispatch loop with no
//! binary decoding, no control-target hash lookups, and no per-call operand or
//! local stack allocations.

use std::sync::Arc;

use super::{ImportDesc, Instance, Trap};

#[derive(Clone, Debug)]
pub enum Op {
    Unreachable,
    Nop,
    Block { end: u32, arity: u8 },
    Loop { end: u32, body: u32 },
    If { else_target: u32, end: u32, arity: u8 },
    Else { end: u32 },
    End,
    Br(u32),
    BrIf(u32),
    BrTable(Box<[u32]>, u32),
    Return,
    Call(u32),
    CallIndirect(u32),
    Drop,
    Select,
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    I32Load(u32),
    I64Load(u32),
    I32Load8S(u32),
    I32Load8U(u32),
    I32Load16S(u32),
    I32Load16U(u32),
    I64Load8S(u32),
    I64Load8U(u32),
    I64Load16S(u32),
    I64Load16U(u32),
    I64Load32S(u32),
    I64Load32U(u32),
    I32Store(u32),
    I64Store(u32),
    I32Store8(u32),
    I32Store16(u32),
    I64Store8(u32),
    I64Store16(u32),
    I64Store32(u32),
    MemorySize,
    MemoryGrow,
    I32Const(u32),
    I64Const(u64),
    F32Const,
    F64Const,
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    I64Eqz,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
    I32Clz,
    I32Ctz,
    I32Popcnt,
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    I64Clz,
    I64Ctz,
    I64Popcnt,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,
    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    RefNull,
    RefIsNull,
    RefFunc(u32),
    MemoryCopy,
    MemoryFill,
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

fn block_arity(code: &[u8], position: &mut usize) -> Result<u8, String> {
    let byte = *code
        .get(*position)
        .ok_or_else(|| "Truncated block type".to_string())?;
    if byte == 0x40 {
        *position += 1;
        Ok(0)
    } else if (0x7c..=0x7f).contains(&byte) {
        *position += 1;
        Ok(1)
    } else {
        Err("Multi-value block types are unsupported".to_string())
    }
}

struct OpenBlock {
    op_index: usize,
    else_index: Option<usize>,
}

/// Decode a function body into a flat instruction array with resolved targets.
pub fn decode_function(code: &[u8]) -> Result<Vec<Op>, String> {
    let mut ops: Vec<Op> = Vec::with_capacity(code.len());
    let mut open: Vec<OpenBlock> = Vec::new();
    let mut position = 0_usize;
    while position < code.len() {
        let opcode = code[position];
        position += 1;
        let op = match opcode {
            0x00 => Op::Unreachable,
            0x01 => Op::Nop,
            0x02 | 0x03 => {
                let arity = block_arity(code, &mut position)?;
                let index = ops.len();
                open.push(OpenBlock {
                    op_index: index,
                    else_index: None,
                });
                if opcode == 0x03 {
                    ops.push(Op::Loop { end: 0, body: (index + 1) as u32 });
                } else {
                    ops.push(Op::Block { end: 0, arity });
                }
                continue;
            }
            0x04 => {
                let arity = block_arity(code, &mut position)?;
                let index = ops.len();
                open.push(OpenBlock {
                    op_index: index,
                    else_index: None,
                });
                ops.push(Op::If {
                    else_target: 0,
                    end: 0,
                    arity,
                });
                continue;
            }
            0x05 => {
                let index = ops.len();
                ops.push(Op::Else { end: 0 });
                if let Some(entry) = open.last_mut() {
                    entry.else_index = Some(index);
                }
                continue;
            }
            0x0b => {
                let end_index = ops.len();
                ops.push(Op::End);
                if let Some(entry) = open.pop() {
                    match &mut ops[entry.op_index] {
                        Op::Block { end, .. } => *end = end_index as u32,
                        Op::Loop { end, .. } => *end = end_index as u32,
                        Op::If { else_target, end, .. } => {
                            *end = end_index as u32;
                            *else_target = entry
                                .else_index
                                .map(|index| (index + 1) as u32)
                                .unwrap_or(end_index as u32);
                        }
                        _ => {}
                    }
                    if let Some(else_index) = entry.else_index {
                        if let Op::Else { end } = &mut ops[else_index] {
                            *end = end_index as u32;
                        }
                    }
                }
                continue;
            }
            0x0c => Op::Br(read_uleb(code, &mut position)? as u32),
            0x0d => Op::BrIf(read_uleb(code, &mut position)? as u32),
            0x0e => {
                let count = read_uleb(code, &mut position)? as usize;
                let mut labels = Vec::with_capacity(count);
                for _ in 0..count {
                    labels.push(read_uleb(code, &mut position)? as u32);
                }
                let default = read_uleb(code, &mut position)? as u32;
                Op::BrTable(labels.into_boxed_slice(), default)
            }
            0x0f => Op::Return,
            0x10 => Op::Call(read_uleb(code, &mut position)? as u32),
            0x11 => {
                let type_index = read_uleb(code, &mut position)? as u32;
                let _table_index = read_uleb(code, &mut position)?;
                Op::CallIndirect(type_index)
            }
            0x1a => Op::Drop,
            0x1b => Op::Select,
            0x20 => Op::LocalGet(read_uleb(code, &mut position)? as u32),
            0x21 => Op::LocalSet(read_uleb(code, &mut position)? as u32),
            0x22 => Op::LocalTee(read_uleb(code, &mut position)? as u32),
            0x23 => Op::GlobalGet(read_uleb(code, &mut position)? as u32),
            0x24 => Op::GlobalSet(read_uleb(code, &mut position)? as u32),
            0x28..=0x3e => {
                let _align = read_uleb(code, &mut position)?;
                let offset = read_uleb(code, &mut position)? as u32;
                match opcode {
                    0x28 => Op::I32Load(offset),
                    0x29 => Op::I64Load(offset),
                    0x2c => Op::I32Load8S(offset),
                    0x2d => Op::I32Load8U(offset),
                    0x2e => Op::I32Load16S(offset),
                    0x2f => Op::I32Load16U(offset),
                    0x30 => Op::I64Load8S(offset),
                    0x31 => Op::I64Load8U(offset),
                    0x32 => Op::I64Load16S(offset),
                    0x33 => Op::I64Load16U(offset),
                    0x34 => Op::I64Load32S(offset),
                    0x35 => Op::I64Load32U(offset),
                    0x36 => Op::I32Store(offset),
                    0x37 => Op::I64Store(offset),
                    0x3a => Op::I32Store8(offset),
                    0x3b => Op::I32Store16(offset),
                    0x3c => Op::I64Store8(offset),
                    0x3d => Op::I64Store16(offset),
                    0x3e => Op::I64Store32(offset),
                    other => {
                        return Err(format!("Unsupported memory opcode: 0x{other:02x}"))
                    }
                }
            }
            0x3f => {
                let _memory = read_uleb(code, &mut position)?;
                Op::MemorySize
            }
            0x40 => {
                let _memory = read_uleb(code, &mut position)?;
                Op::MemoryGrow
            }
            0x41 => Op::I32Const(read_sleb(code, &mut position)? as i32 as u32),
            0x42 => Op::I64Const(read_sleb(code, &mut position)? as u64),
            0x43 => {
                position += 4;
                Op::F32Const
            }
            0x44 => {
                position += 8;
                Op::F64Const
            }
            0x45 => Op::I32Eqz,
            0x46 => Op::I32Eq,
            0x47 => Op::I32Ne,
            0x48 => Op::I32LtS,
            0x49 => Op::I32LtU,
            0x4a => Op::I32GtS,
            0x4b => Op::I32GtU,
            0x4c => Op::I32LeS,
            0x4d => Op::I32LeU,
            0x4e => Op::I32GeS,
            0x4f => Op::I32GeU,
            0x50 => Op::I64Eqz,
            0x51 => Op::I64Eq,
            0x52 => Op::I64Ne,
            0x53 => Op::I64LtS,
            0x54 => Op::I64LtU,
            0x55 => Op::I64GtS,
            0x56 => Op::I64GtU,
            0x57 => Op::I64LeS,
            0x58 => Op::I64LeU,
            0x59 => Op::I64GeS,
            0x5a => Op::I64GeU,
            0x67 => Op::I32Clz,
            0x68 => Op::I32Ctz,
            0x69 => Op::I32Popcnt,
            0x6a => Op::I32Add,
            0x6b => Op::I32Sub,
            0x6c => Op::I32Mul,
            0x6d => Op::I32DivS,
            0x6e => Op::I32DivU,
            0x6f => Op::I32RemS,
            0x70 => Op::I32RemU,
            0x71 => Op::I32And,
            0x72 => Op::I32Or,
            0x73 => Op::I32Xor,
            0x74 => Op::I32Shl,
            0x75 => Op::I32ShrS,
            0x76 => Op::I32ShrU,
            0x77 => Op::I32Rotl,
            0x78 => Op::I32Rotr,
            0x79 => Op::I64Clz,
            0x7a => Op::I64Ctz,
            0x7b => Op::I64Popcnt,
            0x7c => Op::I64Add,
            0x7d => Op::I64Sub,
            0x7e => Op::I64Mul,
            0x7f => Op::I64DivS,
            0x80 => Op::I64DivU,
            0x81 => Op::I64RemS,
            0x82 => Op::I64RemU,
            0x83 => Op::I64And,
            0x84 => Op::I64Or,
            0x85 => Op::I64Xor,
            0x86 => Op::I64Shl,
            0x87 => Op::I64ShrS,
            0x88 => Op::I64ShrU,
            0x89 => Op::I64Rotl,
            0x8a => Op::I64Rotr,
            0xa7 => Op::I32WrapI64,
            0xac => Op::I64ExtendI32S,
            0xad => Op::I64ExtendI32U,
            0xc0 => Op::I32Extend8S,
            0xc1 => Op::I32Extend16S,
            0xc2 => Op::I64Extend8S,
            0xc3 => Op::I64Extend16S,
            0xc4 => Op::I64Extend32S,
            0xd0 => {
                let _type = read_uleb(code, &mut position)?;
                Op::RefNull
            }
            0xd1 => Op::RefIsNull,
            0xd2 => Op::RefFunc(read_uleb(code, &mut position)? as u32),
            0xfc => {
                let sub = read_uleb(code, &mut position)?;
                match sub {
                    10 => {
                        let _dst = read_uleb(code, &mut position)?;
                        let _src = read_uleb(code, &mut position)?;
                        Op::MemoryCopy
                    }
                    11 => {
                        let _memory = read_uleb(code, &mut position)?;
                        Op::MemoryFill
                    }
                    other => {
                        return Err(format!("Unsupported 0xfc subopcode: {other}"));
                    }
                }
            }
            other => return Err(format!("Unsupported opcode: 0x{other:02x}")),
        };
        ops.push(op);
    }
    if !open.is_empty() {
        return Err(format!(
            "Unbalanced control structure: {} open block(s)",
            open.len()
        ));
    }
    if !matches!(ops.last(), Some(Op::End)) {
        return Err("Function body does not end with `end`".to_string());
    }
    for (index, op) in ops.iter().enumerate() {
        let target = match op {
            Op::Block { end, .. } | Op::Loop { end, .. } | Op::If { end, .. } | Op::Else { end } => {
                Some(*end)
            }
            _ => None,
        };
        if let Some(target) = target {
            if target as usize >= ops.len() || !matches!(ops[target as usize], Op::End) {
                return Err(format!(
                    "Invalid control target at instruction {index}: {target}"
                ));
            }
        }
        if let Op::If { else_target, .. } = op {
            if *else_target as usize > ops.len() {
                return Err(format!(
                    "Invalid else target at instruction {index}: {else_target}"
                ));
            }
        }
    }
    Ok(ops)
}


#[derive(Clone, Copy)]
pub struct Frame {
    pub end: u32,
    pub body: u32,
    pub height: usize,
    pub arity: u8,
    pub is_loop: bool,
}

pub fn function_type_for(instance: &Instance, index: u32) -> Result<Arc<super::FuncType>, Trap> {
    let imported = instance.module.imported_function_count as u32;
    let type_index = if index < imported {
        instance
            .module
            .imports
            .iter()
            .filter_map(|import| match import.desc {
                ImportDesc::Function(type_index) => Some(type_index),
                _ => None,
            })
            .nth(index as usize)
            .ok_or_else(|| Trap("Missing imported function".to_string()))?
    } else {
        instance
            .module
            .functions
            .get((index - imported) as usize)
            .ok_or_else(|| Trap(format!("Function index out of range: {index}")))?
            .type_index
    };
    instance
        .module
        .types
        .get(type_index as usize)
        .cloned()
        .ok_or_else(|| Trap("Type index out of range".to_string()))
}

/// The largest memory this interpreter will grow to (4 GiB, the wasm32 limit).
const MAXIMUM_MEMORY_PAGES: u32 = 65_536;

/// Invoke a function; arguments are on `stack`, and results replace them.
pub fn invoke(
    instance: &mut Instance,
    index: u32,
    stack: &mut Vec<u64>,
    locals: &mut Vec<u64>,
    control: &mut Vec<Frame>,
) -> Result<(), Trap> {
    let imported = instance.module.imported_function_count as u32;
    if index < imported {
        let name = instance
            .module
            .imports
            .iter()
            .filter(|import| matches!(import.desc, ImportDesc::Function(_)))
            .nth(index as usize)
            .map(|import| import.name.clone())
            .ok_or_else(|| Trap("Missing imported function".to_string()))?;
        let parameter_count = function_type_for(instance, index)?.params.len();
        if stack.len() < parameter_count {
            return Err(Trap("Stack underflow in call".to_string()));
        }
        let base = stack.len() - parameter_count;
        let arguments: Vec<u64> = stack[base..].to_vec();
        stack.truncate(base);
        let mut host = instance
            .host
            .take()
            .ok_or_else(|| Trap("Host imports unavailable".to_string()))?;
        let result = host.call(instance, &name, &arguments);
        instance.host = Some(host);
        if let Some(value) = result? {
            stack.push(value);
        }
        return Ok(());
    }
    let defined_index = (index - imported) as usize;
    if defined_index >= instance.module.functions.len() {
        return Err(Trap("Function index out of range".to_string()));
    }
    // Function bodies are immutable and owned by the module, which outlives this
    // call, so the reference is valid for the duration of the invocation.
    let function: &super::DefinedFunction =
        unsafe { &*std::sync::Arc::as_ptr(&instance.module.functions[defined_index]) };
    let parameter_count = function.parameter_count;
    if stack.len() < parameter_count {
        return Err(Trap("Stack underflow in call".to_string()));
    }
    let stack_base = stack.len() - parameter_count;
    let locals_base = locals.len();
    locals.extend_from_slice(&stack[stack_base..]);
    locals.extend(std::iter::repeat(0).take(function.locals.len()));
    let result = execute(
        instance,
        &function,
        locals,
        locals_base,
        stack,
        stack_base,
        control,
    );
    locals.truncate(locals_base);
    result
}

fn finish(
    func: &super::DefinedFunction,
    stack: &mut Vec<u64>,
    stack_base: usize,
    control: &mut Vec<Frame>,
    control_base: usize,
) -> Result<(), Trap> {
    control.truncate(control_base);
    if func.result_count == 0 {
        stack.truncate(stack_base);
        return Ok(());
    }
    let mut results = [0_u64; 8];
    let count = func.result_count.min(8);
    for slot in results.iter_mut().take(count) {
        *slot = stack
            .pop()
            .ok_or_else(|| Trap("Stack underflow at function return".to_string()))?;
    }
    stack.truncate(stack_base);
    for index in (0..count).rev() {
        stack.push(results[index]);
    }
    Ok(())
}

fn execute(
    instance: &mut Instance,
    func: &super::DefinedFunction,
    locals: &mut Vec<u64>,
    locals_base: usize,
    stack: &mut Vec<u64>,
    stack_base: usize,
    control: &mut Vec<Frame>,
) -> Result<(), Trap> {
    let control_base = control.len();
    let code = &func.code;
    let mut pc = 0_usize;

    macro_rules! pop {
        () => {
            stack
                .pop()
                .ok_or_else(|| Trap("Value stack underflow".to_string()))?
        };
    }
    macro_rules! local {
        ($index:expr) => {{
            let position = locals_base + $index as usize;
            *locals
                .get(position)
                .ok_or_else(|| Trap("Local index out of range".to_string()))?
        }};
    }
    macro_rules! local_mut {
        ($index:expr) => {{
            let position = locals_base + $index as usize;
            locals
                .get_mut(position)
                .ok_or_else(|| Trap("Local index out of range".to_string()))?
        }};
    }
    macro_rules! i32_unary {
        ($operation:expr) => {{
            let value = pop!() as u32;
            stack.push($operation(value) as u64);
        }};
    }
    macro_rules! i64_unary {
        ($operation:expr) => {{
            let value = pop!();
            stack.push($operation(value));
        }};
    }
    macro_rules! i32_binary {
        ($operation:expr) => {{
            let right = pop!() as u32;
            let left = pop!() as u32;
            stack.push($operation(left, right) as u64);
        }};
    }
    macro_rules! i64_binary {
        ($operation:expr) => {{
            let right = pop!();
            let left = pop!();
            stack.push($operation(left, right));
        }};
    }
    macro_rules! i32_compare {
        ($operation:expr) => {{
            let right = pop!() as u32;
            let left = pop!() as u32;
            stack.push($operation(left, right) as u64);
        }};
    }
    macro_rules! i64_compare {
        ($operation:expr) => {{
            let right = pop!();
            let left = pop!();
            stack.push($operation(left, right) as u64);
        }};
    }

    loop {
        let Some(op) = code.get(pc) else {
            let frames: Vec<String> = control[control_base..]
                .iter()
                .map(|frame| {
                    format!(
                        "{{end {}, body {}, height {}, arity {}, loop {}}}",
                        frame.end, frame.body, frame.height, frame.arity, frame.is_loop
                    )
                })
                .collect();
            return Err(Trap(format!(
                "Program counter out of range: pc {pc}, code length {}, control depth {}, arity {}, frames {:?}",
                code.len(),
                control.len() - control_base,
                func.result_count,
                frames
            )));
        };
        pc += 1;
        match op {
            Op::Unreachable => return Err(Trap("unreachable".to_string())),
            Op::Nop => {}
            Op::Block { end: block_end, arity } => {
                control.push(Frame {
                    end: *block_end,
                    body: 0,
                    height: stack.len(),
                    arity: *arity,
                    is_loop: false,
                });
            }
            Op::Loop { end: loop_end, body } => {
                control.push(Frame {
                    end: *loop_end,
                    body: *body,
                    height: stack.len(),
                    arity: 0,
                    is_loop: true,
                });
            }
            Op::If {
                else_target,
                end: block_end,
                arity,
            } => {
                let condition = pop!() as u32;
                control.push(Frame {
                    end: *block_end,
                    body: 0,
                    height: stack.len(),
                    arity: *arity,
                    is_loop: false,
                });
                if condition == 0 {
                    pc = *else_target as usize;
                }
            }
            Op::Else { end: block_end } => {
                pc = *block_end as usize;
            }
            Op::End => {
                if control.len() == control_base {
                    return finish(func, stack, stack_base, control, control_base);
                }
                let frame = control.pop().unwrap();
                if frame.arity == 1 {
                    let value = pop!();
                    stack.truncate(frame.height);
                    stack.push(value);
                } else {
                    stack.truncate(frame.height);
                }
            }
            Op::Br(depth) => {
                let depth = *depth as usize;
                if control.len() - control_base <= depth {
                    return finish(func, stack, stack_base, control, control_base);
                }
                let target_index = control.len() - 1 - depth;
                let frame = control[target_index];
                let arity = if frame.is_loop { 0 } else { frame.arity as usize };
                let mut value = 0_u64;
                if arity == 1 {
                    value = pop!();
                }
                stack.truncate(frame.height);
                if arity == 1 {
                    stack.push(value);
                }
                control.truncate(target_index + 1);
                pc = if frame.is_loop {
                    frame.body as usize
                } else {
                    frame.end as usize
                };
            }
            Op::BrIf(depth) => {
                if pop!() as u32 != 0 {
                    let depth = *depth as usize;
                    if control.len() - control_base <= depth {
                        return finish(func, stack, stack_base, control, control_base);
                    }
                    let target_index = control.len() - 1 - depth;
                    let frame = control[target_index];
                    let arity = if frame.is_loop { 0 } else { frame.arity as usize };
                    let mut values = Vec::with_capacity(arity);
                    for _ in 0..arity {
                        values.push(pop!());
                    }
                    values.reverse();
                    stack.truncate(frame.height);
                    stack.extend_from_slice(&values);
                    control.truncate(target_index + 1);
                    pc = if frame.is_loop {
                        frame.body as usize
                    } else {
                        frame.end as usize
                    };
                }
            }
            Op::BrTable(labels, default) => {
                let selector = pop!() as usize;
                let depth = *labels.get(selector).unwrap_or(default) as usize;
                if control.len() - control_base <= depth {
                    return finish(func, stack, stack_base, control, control_base);
                }
                let target_index = control.len() - 1 - depth;
                let frame = control[target_index];
                let arity = if frame.is_loop { 0 } else { frame.arity as usize };
                let mut value = 0_u64;
                if arity == 1 {
                    value = pop!();
                }
                stack.truncate(frame.height);
                if arity == 1 {
                    stack.push(value);
                }
                control.truncate(target_index + 1);
                pc = if frame.is_loop {
                    frame.body as usize
                } else {
                    frame.end as usize
                };
            }
            Op::Return => return finish(func, stack, stack_base, control, control_base),
            Op::Call(target) => {
                invoke(instance, *target, stack, locals, control)?;
            }
            Op::CallIndirect(type_index) => {
                let element_index = pop!() as usize;
                let function_index = instance
                    .table
                    .get(element_index)
                    .and_then(|entry| *entry)
                    .ok_or_else(|| Trap("Undefined table element".to_string()))?;
                let expected = instance
                    .module
                    .types
                    .get(*type_index as usize)
                    .cloned()
                    .ok_or_else(|| Trap("Type index out of range".to_string()))?;
                let actual = function_type_for(instance, function_index)?;
                if expected.params != actual.params || expected.results != actual.results {
                    return Err(Trap("Indirect call type mismatch".to_string()));
                }
                invoke(instance, function_index, stack, locals, control)?;
            }
            Op::Drop => {
                pop!();
            }
            Op::Select => {
                let condition = pop!() as u32;
                let if_false = pop!();
                let if_true = pop!();
                stack.push(if condition != 0 { if_true } else { if_false });
            }
            Op::LocalGet(index) => stack.push(local!(*index)),
            Op::LocalSet(index) => {
                let value = pop!();
                *local_mut!(*index) = value;
            }
            Op::LocalTee(index) => {
                let value = *stack
                    .last()
                    .ok_or_else(|| Trap("Stack underflow".to_string()))?;
                *local_mut!(*index) = value;
            }
            Op::GlobalGet(index) => {
                stack.push(
                    *instance
                        .globals
                        .get(*index as usize)
                        .ok_or_else(|| Trap("Global index out of range".to_string()))?,
                );
            }
            Op::GlobalSet(index) => {
                let value = pop!();
                *instance
                    .globals
                    .get_mut(*index as usize)
                    .ok_or_else(|| Trap("Global index out of range".to_string()))? = value;
            }
            Op::I32Load(offset) => {
                let address = (pop!() as u32).wrapping_add(*offset) as usize;
                if address + 4 > instance.memory.len() {
                    return Err(Trap("Out of bounds memory read".to_string()));
                }
                let value = unsafe {
                    u32::from_le((instance.memory.as_ptr().add(address) as *const u32).read_unaligned())
                };
                stack.push(value as u64);
            }
            Op::I64Load(offset) => {
                let address = (pop!() as u32).wrapping_add(*offset) as usize;
                if address + 8 > instance.memory.len() {
                    return Err(Trap("Out of bounds memory read".to_string()));
                }
                let value = unsafe {
                    u64::from_le((instance.memory.as_ptr().add(address) as *const u64).read_unaligned())
                };
                stack.push(value);
            }
            Op::I32Load8S(offset) => {
                let address = pop!() as u32;
                let byte = instance.memory_slice(address.wrapping_add(*offset), 1)?[0];
                stack.push((byte as i8 as i32 as u32) as u64);
            }
            Op::I32Load8U(offset) => {
                let address = pop!() as u32;
                let byte = instance.memory_slice(address.wrapping_add(*offset), 1)?[0];
                stack.push(byte as u64);
            }
            Op::I32Load16S(offset) => {
                let address = pop!() as u32;
                let bytes = instance.memory_slice(address.wrapping_add(*offset), 2)?;
                let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                stack.push((value as i16 as i32 as u32) as u64);
            }
            Op::I32Load16U(offset) => {
                let address = pop!() as u32;
                let bytes = instance.memory_slice(address.wrapping_add(*offset), 2)?;
                stack.push(u16::from_le_bytes([bytes[0], bytes[1]]) as u64);
            }
            Op::I64Load8S(offset) => {
                let address = pop!() as u32;
                let byte = instance.memory_slice(address.wrapping_add(*offset), 1)?[0];
                stack.push((byte as i8 as i64) as u64);
            }
            Op::I64Load8U(offset) => {
                let address = pop!() as u32;
                let byte = instance.memory_slice(address.wrapping_add(*offset), 1)?[0];
                stack.push(byte as u64);
            }
            Op::I64Load16S(offset) => {
                let address = pop!() as u32;
                let bytes = instance.memory_slice(address.wrapping_add(*offset), 2)?;
                let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                stack.push((value as i16 as i64) as u64);
            }
            Op::I64Load16U(offset) => {
                let address = pop!() as u32;
                let bytes = instance.memory_slice(address.wrapping_add(*offset), 2)?;
                stack.push(u16::from_le_bytes([bytes[0], bytes[1]]) as u64);
            }
            Op::I64Load32S(offset) => {
                let address = pop!() as u32;
                let bytes = instance.memory_slice(address.wrapping_add(*offset), 4)?;
                let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                stack.push((value as i32 as i64) as u64);
            }
            Op::I64Load32U(offset) => {
                let address = pop!() as u32;
                let bytes = instance.memory_slice(address.wrapping_add(*offset), 4)?;
                stack.push(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64);
            }
            Op::I32Store(offset) => {
                let value = pop!() as u32;
                let address = (pop!() as u32).wrapping_add(*offset) as usize;
                if address + 4 > instance.memory.len() {
                    return Err(Trap("Out of bounds memory write".to_string()));
                }
                unsafe {
                    (instance.memory.as_mut_ptr().add(address) as *mut u32)
                        .write_unaligned(value.to_le());
                }
            }
            Op::I64Store(offset) => {
                let value = pop!();
                let address = (pop!() as u32).wrapping_add(*offset) as usize;
                if address + 8 > instance.memory.len() {
                    return Err(Trap("Out of bounds memory write".to_string()));
                }
                unsafe {
                    (instance.memory.as_mut_ptr().add(address) as *mut u64)
                        .write_unaligned(value.to_le());
                }
            }
            Op::I32Store8(offset) => {
                let value = pop!() as u8;
                let address = pop!() as u32;
                instance.memory_slice_mut(address.wrapping_add(*offset), 1)?[0] = value;
            }
            Op::I32Store16(offset) => {
                let value = pop!() as u16;
                let address = pop!() as u32;
                instance
                    .memory_slice_mut(address.wrapping_add(*offset), 2)?
                    .copy_from_slice(&value.to_le_bytes());
            }
            Op::I64Store8(offset) => {
                let value = pop!() as u8;
                let address = pop!() as u32;
                instance.memory_slice_mut(address.wrapping_add(*offset), 1)?[0] = value;
            }
            Op::I64Store16(offset) => {
                let value = pop!() as u16;
                let address = pop!() as u32;
                instance
                    .memory_slice_mut(address.wrapping_add(*offset), 2)?
                    .copy_from_slice(&value.to_le_bytes());
            }
            Op::I64Store32(offset) => {
                let value = pop!() as u32;
                let address = pop!() as u32;
                instance
                    .memory_slice_mut(address.wrapping_add(*offset), 4)?
                    .copy_from_slice(&value.to_le_bytes());
            }
            Op::MemorySize => stack.push((instance.memory.len() / 65536) as u64),
            Op::MemoryGrow => {
                let delta = pop!() as u32;
                let previous_pages = (instance.memory.len() / 65536) as u32;
                let maximum_pages = instance.module.memory_max_pages.unwrap_or(u32::MAX);
                let requested = previous_pages.saturating_add(delta);
                if requested < previous_pages
                    || requested > maximum_pages
                    || requested > MAXIMUM_MEMORY_PAGES
                {
                    stack.push(u32::MAX as u64);
                } else {
                    instance.memory.resize(requested as usize * 65536, 0);
                    stack.push(u64::from(previous_pages));
                }
            }
            Op::I32Const(value) => stack.push(*value as u64),
            Op::I64Const(value) => stack.push(*value),
            Op::F32Const | Op::F64Const => stack.push(0),
            Op::I32Eqz => {
                let value = pop!() as u32;
                stack.push((value == 0) as u64);
            }
            Op::I32Eq => i32_compare!(|a: u32, b: u32| a == b),
            Op::I32Ne => i32_compare!(|a: u32, b: u32| a != b),
            Op::I32LtS => i32_compare!(|a: u32, b: u32| (a as i32) < (b as i32)),
            Op::I32LtU => i32_compare!(|a: u32, b: u32| a < b),
            Op::I32GtS => i32_compare!(|a: u32, b: u32| (a as i32) > (b as i32)),
            Op::I32GtU => i32_compare!(|a: u32, b: u32| a > b),
            Op::I32LeS => i32_compare!(|a: u32, b: u32| (a as i32) <= (b as i32)),
            Op::I32LeU => i32_compare!(|a: u32, b: u32| a <= b),
            Op::I32GeS => i32_compare!(|a: u32, b: u32| (a as i32) >= (b as i32)),
            Op::I32GeU => i32_compare!(|a: u32, b: u32| a >= b),
            Op::I64Eqz => {
                let value = pop!();
                stack.push((value == 0) as u64);
            }
            Op::I64Eq => i64_compare!(|a: u64, b: u64| a == b),
            Op::I64Ne => i64_compare!(|a: u64, b: u64| a != b),
            Op::I64LtS => i64_compare!(|a: u64, b: u64| (a as i64) < (b as i64)),
            Op::I64LtU => i64_compare!(|a: u64, b: u64| a < b),
            Op::I64GtS => i64_compare!(|a: u64, b: u64| (a as i64) > (b as i64)),
            Op::I64GtU => i64_compare!(|a: u64, b: u64| a > b),
            Op::I64LeS => i64_compare!(|a: u64, b: u64| (a as i64) <= (b as i64)),
            Op::I64LeU => i64_compare!(|a: u64, b: u64| a <= b),
            Op::I64GeS => i64_compare!(|a: u64, b: u64| (a as i64) >= (b as i64)),
            Op::I64GeU => i64_compare!(|a: u64, b: u64| a >= b),
            Op::I32Clz => i32_unary!(|value: u32| value.leading_zeros()),
            Op::I32Ctz => i32_unary!(|value: u32| value.trailing_zeros()),
            Op::I32Popcnt => i32_unary!(|value: u32| value.count_ones()),
            Op::I32Add => i32_binary!(|a: u32, b: u32| a.wrapping_add(b)),
            Op::I32Sub => i32_binary!(|a: u32, b: u32| a.wrapping_sub(b)),
            Op::I32Mul => i32_binary!(|a: u32, b: u32| a.wrapping_mul(b)),
            Op::I32DivS => {
                let right = pop!() as u32;
                let left = pop!() as u32;
                if right == 0 {
                    return Err(Trap("i32 division by zero".to_string()));
                }
                if left == 0x8000_0000 && right == 0xffff_ffff {
                    return Err(Trap("i32 division overflow".to_string()));
                }
                stack.push(((left as i32) / (right as i32)) as u32 as u64);
            }
            Op::I32DivU => {
                let right = pop!() as u32;
                let left = pop!() as u32;
                if right == 0 {
                    return Err(Trap("i32 division by zero".to_string()));
                }
                stack.push((left / right) as u64);
            }
            Op::I32RemS => {
                let right = pop!() as u32;
                let left = pop!() as u32;
                if right == 0 {
                    return Err(Trap("i32 remainder by zero".to_string()));
                }
                let result = if left == 0x8000_0000 && right == 0xffff_ffff {
                    0
                } else {
                    ((left as i32) % (right as i32)) as u32
                };
                stack.push(result as u64);
            }
            Op::I32RemU => {
                let right = pop!() as u32;
                let left = pop!() as u32;
                if right == 0 {
                    return Err(Trap("i32 remainder by zero".to_string()));
                }
                stack.push((left % right) as u64);
            }
            Op::I32And => i32_binary!(|a: u32, b: u32| a & b),
            Op::I32Or => i32_binary!(|a: u32, b: u32| a | b),
            Op::I32Xor => i32_binary!(|a: u32, b: u32| a ^ b),
            Op::I32Shl => i32_binary!(|a: u32, b: u32| a.wrapping_shl(b & 31)),
            Op::I32ShrS => i32_binary!(|a: u32, b: u32| ((a as i32) >> (b & 31)) as u32),
            Op::I32ShrU => i32_binary!(|a: u32, b: u32| a >> (b & 31)),
            Op::I32Rotl => i32_binary!(|a: u32, b: u32| a.rotate_left(b & 31)),
            Op::I32Rotr => i32_binary!(|a: u32, b: u32| a.rotate_right(b & 31)),
            Op::I64Clz => i64_unary!(|value: u64| value.leading_zeros() as u64),
            Op::I64Ctz => i64_unary!(|value: u64| value.trailing_zeros() as u64),
            Op::I64Popcnt => i64_unary!(|value: u64| value.count_ones() as u64),
            Op::I64Add => i64_binary!(|a: u64, b: u64| a.wrapping_add(b)),
            Op::I64Sub => i64_binary!(|a: u64, b: u64| a.wrapping_sub(b)),
            Op::I64Mul => i64_binary!(|a: u64, b: u64| a.wrapping_mul(b)),
            Op::I64DivS => {
                let right = pop!();
                let left = pop!();
                if right == 0 {
                    return Err(Trap("i64 division by zero".to_string()));
                }
                if left == 0x8000_0000_0000_0000 && right == 0xffff_ffff_ffff_ffff {
                    return Err(Trap("i64 division overflow".to_string()));
                }
                stack.push(((left as i64) / (right as i64)) as u64);
            }
            Op::I64DivU => {
                let right = pop!();
                let left = pop!();
                if right == 0 {
                    return Err(Trap("i64 division by zero".to_string()));
                }
                stack.push(left / right);
            }
            Op::I64RemS => {
                let right = pop!();
                let left = pop!();
                if right == 0 {
                    return Err(Trap("i64 remainder by zero".to_string()));
                }
                let result = if left == 0x8000_0000_0000_0000 && right == 0xffff_ffff_ffff_ffff {
                    0
                } else {
                    ((left as i64) % (right as i64)) as u64
                };
                stack.push(result);
            }
            Op::I64RemU => {
                let right = pop!();
                let left = pop!();
                if right == 0 {
                    return Err(Trap("i64 remainder by zero".to_string()));
                }
                stack.push(left % right);
            }
            Op::I64And => i64_binary!(|a: u64, b: u64| a & b),
            Op::I64Or => i64_binary!(|a: u64, b: u64| a | b),
            Op::I64Xor => i64_binary!(|a: u64, b: u64| a ^ b),
            Op::I64Shl => i64_binary!(|a: u64, b: u64| a.wrapping_shl((b & 63) as u32)),
            Op::I64ShrS => i64_binary!(|a: u64, b: u64| ((a as i64) >> (b & 63)) as u64),
            Op::I64ShrU => i64_binary!(|a: u64, b: u64| a >> (b & 63)),
            Op::I64Rotl => i64_binary!(|a: u64, b: u64| a.rotate_left((b & 63) as u32)),
            Op::I64Rotr => i64_binary!(|a: u64, b: u64| a.rotate_right((b & 63) as u32)),
            Op::I32WrapI64 => {
                let value = pop!();
                stack.push((value as u32) as u64);
            }
            Op::I64ExtendI32S => {
                let value = pop!() as u32;
                stack.push((value as i32 as i64) as u64);
            }
            Op::I64ExtendI32U => {
                let value = pop!() as u32;
                stack.push(value as u64);
            }
            Op::I32Extend8S => {
                let value = pop!() as u32;
                stack.push((value as u8 as i8 as i32 as u32) as u64);
            }
            Op::I32Extend16S => {
                let value = pop!() as u32;
                stack.push((value as u16 as i16 as i32 as u32) as u64);
            }
            Op::I64Extend8S => {
                let value = pop!();
                stack.push((value as u8 as i8 as i64) as u64);
            }
            Op::I64Extend16S => {
                let value = pop!();
                stack.push((value as u16 as i16 as i64) as u64);
            }
            Op::I64Extend32S => {
                let value = pop!();
                stack.push((value as u32 as i32 as i64) as u64);
            }
            Op::RefNull => stack.push(0),
            Op::RefIsNull => {
                let value = pop!();
                stack.push((value == 0) as u64);
            }
            Op::RefFunc(function) => stack.push(*function as u64),
            Op::MemoryCopy => {
                let length = pop!() as u32;
                let source = pop!() as u32;
                let destination = pop!() as u32;
                let data = instance.memory_slice(source, length)?.to_vec();
                instance
                    .memory_slice_mut(destination, length)?
                    .copy_from_slice(&data);
            }
            Op::MemoryFill => {
                let length = pop!() as u32;
                let value = pop!() as u8;
                let destination = pop!() as u32;
                instance
                    .memory_slice_mut(destination, length)?
                    .fill(value);
            }
        }
    }
}
