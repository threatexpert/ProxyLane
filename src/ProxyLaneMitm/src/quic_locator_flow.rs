//! Bounded proof of the unknown-root call's guards and result, not a byte signature.
//! Unsupported instructions/ambiguous provenance fail closed. This is intentionally
//! a small interpreter for this decision, not a general x64 emulator.
use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic as M, OpAccess, OpKind,
    Register as R,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Job,
    Address(i64),
    Certificate(i64),
    Root(i64, i64),
    Status,
    Allow,
    Constant(u64),
}
type Registers = [Value; 16];
fn reg(r: R) -> Option<usize> {
    let r = r.full_register();
    if (R::RAX..=R::R15).contains(&r) {
        Some((r as usize) - R::RAX as usize)
    } else {
        None
    }
}
fn get(s: &Registers, r: R) -> Value {
    reg(r).map_or(Value::Unknown, |n| s[n])
}
fn put(s: &mut Registers, r: R, v: Value) {
    if let Some(n) = reg(r) {
        s[n] = v;
    }
}
fn address(s: &Registers, i: &Instruction) -> Value {
    if i.memory_index() != R::None || i.segment_prefix() != R::None {
        return Value::Unknown;
    }
    let d = i.memory_displacement64() as i64;
    match get(s, i.memory_base()) {
        Value::Job => Value::Address(d),
        Value::Address(a) => a.checked_add(d).map_or(Value::Unknown, Value::Address),
        _ => Value::Unknown,
    }
}
fn operand(s: &Registers, i: &Instruction, n: u32) -> Value {
    match i.op_kind(n) {
        OpKind::Register => {
            let r = i.op_register(n);
            let v = get(s, r);
            // Never treat a truncated pointer or a stale high part as provenance.
            match v {
                Value::Job | Value::Address(_) | Value::Certificate(_) if r.size() != 8 => {
                    Value::Unknown
                }
                Value::Status if r.size() != 4 => Value::Unknown,
                Value::Allow if r != R::AL => Value::Unknown,
                Value::Root(..) if matches!(r, R::AH | R::BH | R::CH | R::DH) => Value::Unknown,
                Value::Constant(c) if r.size() < 8 => {
                    let c = if matches!(r, R::AH | R::BH | R::CH | R::DH) {
                        c >> 8
                    } else {
                        c
                    };
                    Value::Constant(c & ((1u64 << (r.size() * 8)) - 1))
                }
                _ => v,
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Value::Constant(i.immediate(n)),
        OpKind::Memory => {
            if i.memory_index() != R::None || i.segment_prefix() != R::None {
                return Value::Unknown;
            }
            let d = i.memory_displacement64() as i64;
            match (get(s, i.memory_base()), i.memory_size().size()) {
                (Value::Job, 8) => Value::Certificate(d),
                (Value::Address(a), 8) => {
                    a.checked_add(d).map_or(Value::Unknown, Value::Certificate)
                }
                (Value::Certificate(a), 1) => Value::Root(a, d),
                _ => Value::Unknown,
            }
        }
        _ => Value::Unknown,
    }
}
fn assignment(s: &Registers, i: &Instruction) -> Option<Value> {
    if i.op0_kind() != OpKind::Register {
        return None;
    }
    let value = match i.mnemonic() {
        M::Mov | M::Movzx => operand(s, i, 1),
        M::Lea => address(s, i),
        M::Xor if i.op1_kind() == OpKind::Register && i.op0_register() == i.op1_register() => {
            Value::Constant(0)
        }
        _ => return None,
    };
    // Partial writes cannot establish the value of the full register.
    if i.op0_register().size() < 4 {
        return None;
    }
    if matches!(
        value,
        Value::Job | Value::Address(_) | Value::Certificate(_)
    ) && i.op0_register().size() != 8
    {
        return Some(Value::Unknown);
    }
    Some(value)
}
fn clobber_call(s: &mut Registers) {
    for r in [R::RAX, R::RCX, R::RDX, R::R8, R::R9, R::R10, R::R11] {
        put(s, r, Value::Unknown);
    }
    for v in s {
        if matches!(v, Value::Certificate(_) | Value::Root(..)) {
            *v = Value::Unknown;
        }
    }
}
fn transfer(s: &mut Registers, i: &Instruction, factory: &mut InstructionInfoFactory) {
    let value = assignment(s, i);
    for u in factory.info(i).used_registers() {
        if matches!(
            u.access(),
            OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
        ) {
            put(s, u.register(), Value::Unknown);
        }
    }
    if let Some(v) = value {
        put(s, i.op0_register(), v);
    }
    if matches!(
        i.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) {
        clobber_call(s);
    }
}

struct Graph<'a> {
    ins: &'a [Instruction],
    positions: BTreeMap<u64, usize>,
    next: Vec<Vec<usize>>,
}
impl<'a> Graph<'a> {
    fn new(ins: &'a [Instruction]) -> Self {
        let positions: BTreeMap<_, _> = ins.iter().enumerate().map(|(n, i)| (i.ip(), n)).collect();
        let next = ins
            .iter()
            .enumerate()
            .map(|(n, i)| {
                let mut out = Vec::new();
                if matches!(
                    i.flow_control(),
                    FlowControl::Next
                        | FlowControl::Call
                        | FlowControl::IndirectCall
                        | FlowControl::ConditionalBranch
                ) && n + 1 < ins.len()
                {
                    out.push(n + 1);
                }
                if i.is_jcc_short_or_near() || i.is_jmp_short_or_near() {
                    if let Some(&to) = positions.get(&i.near_branch_target()) {
                        out.push(to);
                    }
                }
                out
            })
            .collect();
        Self {
            ins,
            positions,
            next,
        }
    }
    fn target(&self, i: &Instruction) -> Option<usize> {
        self.positions.get(&i.near_branch_target()).copied()
    }
    // Must-provenance at every instruction. Merges retain only facts true on all
    // reachable paths, and calls kill volatile registers. No linear backtracking
    // across unrelated blocks to guess where RCX/RDX came from.
    fn facts(&self) -> Result<Vec<Option<Registers>>, String> {
        let mut facts = vec![None; self.ins.len()];
        let mut entry = [Value::Unknown; 16];
        put(&mut entry, R::RCX, Value::Job);
        put(&mut entry, R::EDX, Value::Status);
        facts[0] = Some(entry);
        let mut work = VecDeque::from([0]);
        let mut queued = vec![false; self.ins.len()];
        queued[0] = true;
        let mut factory = InstructionInfoFactory::new();
        let mut steps = 0;
        while let Some(n) = work.pop_front() {
            queued[n] = false;
            steps += 1;
            if steps > self.ins.len() * 64 {
                return Err("locator dataflow budget exceeded".into());
            }
            let mut output = facts[n].unwrap();
            transfer(&mut output, &self.ins[n], &mut factory);
            for &to in &self.next[n] {
                let merged = if let Some(old) = facts[to] {
                    std::array::from_fn(|k| {
                        if old[k] == output[k] {
                            old[k]
                        } else {
                            Value::Unknown
                        }
                    })
                } else {
                    output
                };
                if facts[to] != Some(merged) {
                    facts[to] = Some(merged);
                    if !queued[to] {
                        work.push_back(to);
                        queued[to] = true;
                    }
                }
            }
        }
        Ok(facts)
    }
}

fn zero_test(s: &Registers, i: &Instruction) -> Option<Value> {
    match i.mnemonic() {
        M::Test
            if i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Register
                && i.op0_register() == i.op1_register() =>
        {
            Some(operand(s, i, 0))
        }
        M::Cmp if operand(s, i, 1) == Value::Constant(0) => Some(operand(s, i, 0)),
        _ => None,
    }
}
#[derive(Default)]
struct Evidence {
    visited: BTreeSet<usize>,
    roots: BTreeSet<(i64, i64)>,
    calls: BTreeSet<usize>,
}
struct Case {
    error: bool,
    known_root: bool,
    allow: bool,
}
fn numeric(v: Value, c: &Case, e: &mut Evidence) -> Option<u64> {
    match v {
        Value::Constant(v) => Some(v),
        Value::Status => Some(if c.error { 0xfffffff1 } else { 0 }),
        Value::Root(a, b) => {
            e.roots.insert((a, b));
            Some(c.known_root as u64)
        }
        Value::Allow => Some(c.allow as u64),
        _ => None,
    }
}

// Interpret only the small guarded decision. Flags survive MOV/LEA, registers
// can be renamed, and JE/JNE, direct JMP and CMOV can rearrange its basic blocks.
fn step(
    g: &Graph<'_>,
    at: usize,
    s: &mut Registers,
    zf: &mut Option<bool>,
    c: &Case,
    e: &mut Evidence,
) -> Option<usize> {
    let i = &g.ins[at];
    e.visited.insert(at);
    let next = at.checked_add(1).filter(|n| *n < g.ins.len());
    if matches!(i.mnemonic(), M::Je | M::Jne) {
        let take = (*zf)? == (i.mnemonic() == M::Je);
        return if take { g.target(i) } else { next };
    }
    if i.is_jmp_short_or_near() {
        return g.target(i);
    }
    if i.is_call_near() {
        if c.error
            || c.known_root
            || !e.calls.is_empty()
            || get(s, R::RCX) != Value::Job
            || !matches!(get(s,R::RDX),Value::Address(d) if d>=0)
        {
            return None;
        }
        e.calls.insert(at);
        clobber_call(s);
        put(s, R::AL, Value::Allow);
        *zf = None;
        return next;
    }
    if matches!(i.mnemonic(), M::Cmove | M::Cmovne) {
        if i.op0_kind() != OpKind::Register || i.op0_register().size() != 4 {
            return None;
        }
        if (*zf)? == (i.mnemonic() == M::Cmove) {
            let value = operand(s, i, 1);
            numeric(value, c, e)?;
            put(s, i.op0_register(), value);
        }
        return next;
    }
    if let Some(v) = zero_test(s, i) {
        *zf = Some(numeric(v, c, e)? == 0);
        return next;
    }
    if let Some(v) = assignment(s, i) {
        if v == Value::Unknown {
            return None;
        }
        put(s, i.op0_register(), v);
        if i.mnemonic() == M::Xor {
            *zf = Some(true);
        } else if i.rflags_modified() != 0 {
            return None;
        }
        return next;
    }
    if matches!(i.mnemonic(), M::Nop | M::Endbr64) {
        return next;
    }
    None
}

fn prove(g: &Graph<'_>, start: usize, input: Registers, result: R) -> Option<usize> {
    let mut initial = input;
    put(&mut initial, result, Value::Status);
    // Find the bypass edge for a prior verification error. It is the common
    // continuation; stop there rather than interpreting unrelated networking code.
    let c = Case {
        error: true,
        known_root: false,
        allow: false,
    };
    let mut s = initial;
    let mut zf = None;
    let mut e = Evidence::default();
    let mut at = start;
    let mut join = None;
    for _ in 0..12 {
        let i = &g.ins[at];
        let next = step(g, at, &mut s, &mut zf, &c, &mut e)?;
        if matches!(i.mnemonic(), M::Je | M::Jne) {
            join = Some(next);
            break;
        }
        at = next;
    }
    let mut join = join?;
    // A compiler may place a JMP/NOP on the bypass edge.
    for _ in 0..8 {
        let i = &g.ins[join];
        if i.is_jmp_short_or_near() {
            join = g.target(i)?;
        } else if i.mnemonic() == M::Nop {
            join += 1;
            if join >= g.ins.len() {
                return None;
            }
        } else {
            break;
        }
    }
    let mut visited = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut calls = BTreeSet::new();
    for error in [false, true] {
        for known_root in [false, true] {
            for allow in [false, true] {
                let c = Case {
                    error,
                    known_root,
                    allow,
                };
                let mut s = initial;
                let mut zf = None;
                let mut at = start;
                let mut evidence = Evidence::default();
                let mut reached = false;
                for _ in 0..96 {
                    if at == join {
                        reached = true;
                        break;
                    }
                    // No loops or re-execution of instructions in the decision region.
                    if evidence.visited.contains(&at) {
                        return None;
                    }
                    at = step(g, at, &mut s, &mut zf, &c, &mut evidence)?;
                }
                if !reached {
                    return None;
                }
                let expected = if error {
                    0xfffffff1
                } else if !known_root && !allow {
                    (-380i32 as u32) as u64
                } else {
                    0
                };
                if (error && get(&s, result) != Value::Status)
                    || numeric(get(&s, result), &c, &mut evidence) != Some(expected)
                    || evidence.calls.len() != usize::from(!error && !known_root)
                {
                    return None;
                }
                visited.extend(evidence.visited);
                roots.extend(evidence.roots);
                calls.extend(evidence.calls);
            }
        }
    }
    if roots.len() != 1 || calls.len() != 1 {
        return None;
    }
    // A side entrance could reach the CALL without satisfying the proven guards.
    // Check fallthrough as well as explicit branches, including unreachable code.
    for (from, edges) in g.next.iter().enumerate() {
        if !visited.contains(&from) && edges.iter().any(|to| *to != start && visited.contains(to)) {
            return None;
        }
    }
    calls.into_iter().next()
}

pub(super) fn guarded_calls(ins: &[Instruction]) -> Result<Vec<&Instruction>, String> {
    if ins.is_empty() || ins.len() > 8192 {
        return Err("locator function budget exceeded".into());
    }
    if ins
        .iter()
        .any(|i| i.flow_control() == FlowControl::IndirectBranch)
    {
        return Err("unsupported indirect branch in completion function".into());
    }
    let g = Graph::new(ins);
    let facts = g.facts()?;
    // Identify the saved verification-result register from the entry block, with
    // copy propagation rather than a fixed prologue length or register number.
    let mut results = BTreeSet::new();
    for (n, i) in ins.iter().enumerate() {
        if let Some(s) = facts[n] {
            for r in [
                R::EAX,
                R::ECX,
                R::EDX,
                R::EBX,
                R::ESP,
                R::EBP,
                R::ESI,
                R::EDI,
                R::R8D,
                R::R9D,
                R::R10D,
                R::R11D,
                R::R12D,
                R::R13D,
                R::R14D,
                R::R15D,
            ] {
                if get(&s, r) == Value::Status {
                    results.insert(r);
                }
            }
        }
        if i.flow_control() != FlowControl::Next {
            break;
        }
    }
    let mut calls = BTreeSet::new();
    for (n, i) in ins.iter().enumerate() {
        if i.op0_kind() != OpKind::Register || !results.contains(&i.op0_register()) {
            continue;
        }
        let Some(input) = facts[n] else {
            continue;
        };
        let mut s = input;
        put(&mut s, i.op0_register(), Value::Status);
        if zero_test(&s, i) != Some(Value::Status) {
            continue;
        }
        if let Some(call) = prove(&g, n, input, i.op0_register()) {
            calls.insert(call);
        }
    }
    Ok(calls.into_iter().map(|n| &ins[n]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};
    #[derive(Default)]
    struct Code {
        bytes: Vec<u8>,
        labels: BTreeMap<&'static str, usize>,
        patches: Vec<(usize, &'static str)>,
    }
    impl Code {
        fn emit(&mut self, b: &[u8]) {
            self.bytes.extend(b);
        }
        fn label(&mut self, s: &'static str) {
            self.labels.insert(s, self.bytes.len());
        }
        fn branch(&mut self, op: &[u8], label: &'static str) {
            self.emit(op);
            self.patches.push((self.bytes.len(), label));
            self.emit(&[0; 4]);
        }
        fn finish(mut self) -> Vec<u8> {
            for (at, label) in self.patches {
                let d = self.labels[label] as i32 - at as i32 - 4;
                self.bytes[at..at + 4].copy_from_slice(&d.to_le_bytes());
            }
            self.bytes
        }
    }
    // Equivalent decisions with inline/split blocks, CMOV/branch return handling,
    // reordered arguments, and flag-preserving instructions between TEST/Jcc.
    fn fixture(split: bool, branch_result: bool, noise: bool, wrong_host: bool) -> Vec<u8> {
        let mut c = Code::default();
        c.emit(&[0x89, 0xd6, 0x48, 0x89, 0xcf, 0x4c, 0x8d, 0x77, 0x30]); // esi=edx; rdi=rcx; r14=&job.host
        c.label("start");
        c.emit(&[0x85, 0xf6]); // test esi,esi
        if noise {
            c.emit(&[0x90, 0x4c, 0x8d, 0x77, 0x30]);
        }
        c.branch(&[0x0f, 0x85], "done");
        c.emit(&[0x48, 0x8b, 0x07, 0x31, 0xf6, 0x80, 0x78, 0x30, 0x00]);
        c.branch(
            &[0x0f, if split { 0x84 } else { 0x85 }],
            if split { "call" } else { "done" },
        );
        if split {
            c.label("done");
            c.emit(&[0xc3]);
        }
        c.label("call");
        // RDX is prepared first; wrong-host must never be accepted.
        c.emit(if wrong_host {
            &[0x48, 0x89, 0xda]
        } else {
            &[0x4c, 0x89, 0xf2]
        });
        c.emit(&[0x48, 0x89, 0xf9]);
        c.branch(&[0xe8], "callee");
        if branch_result {
            c.emit(&[0x84, 0xc0]);
            c.branch(&[0x0f, 0x85], "allowed");
            c.emit(&[0xbe, 0x84, 0xfe, 0xff, 0xff]);
            c.branch(&[0xe9], "done");
            c.label("allowed");
            c.emit(&[0x31, 0xf6]);
            c.branch(&[0xe9], "done");
        } else {
            c.emit(&[
                0x31, 0xc9, 0x84, 0xc0, 0xbe, 0x84, 0xfe, 0xff, 0xff, 0x0f, 0x45, 0xf1,
            ]);
            c.branch(&[0xe9], "done");
        }
        if !split {
            c.label("done");
            c.emit(&[0xc3]);
        }
        c.label("callee");
        c.emit(&[0xc3]);
        c.finish()
    }
    fn calls(b: &[u8]) -> Vec<u64> {
        let ins: Vec<_> = Decoder::with_ip(64, b, 0x1000, DecoderOptions::NONE)
            .into_iter()
            .collect();
        guarded_calls(&ins)
            .unwrap()
            .iter()
            .map(|i| i.ip())
            .collect()
    }
    #[test]
    fn accepts_equivalent_control_flow_layouts() {
        for split in [false, true] {
            for branch_result in [false, true] {
                for noise in [false, true] {
                    assert_eq!(
                        calls(&fixture(split, branch_result, noise, false)).len(),
                        1,
                        "split={split} branch={branch_result} noise={noise}"
                    );
                }
            }
        }
    }
    #[test]
    fn rejects_unproven_host_argument() {
        assert!(calls(&fixture(true, false, true, true)).is_empty());
    }
    #[test]
    fn reports_all_candidates_for_the_outer_uniqueness_check() {
        let mut b = fixture(false, false, false, false);
        let len = b.len();
        b[len - 2] = 0x90;
        b[len - 1] = 0x90;
        // Continue into another guarded decision, retaining the same saved job.
        b.extend_from_slice(&fixture(false, false, false, false)[9..]);
        assert_eq!(calls(&b).len(), 2);
    }
    #[test]
    fn rejects_wrong_error_and_inverted_allow_result() {
        let b = fixture(false, false, false, false);
        let mut wrong = b.clone();
        let at = wrong
            .windows(4)
            .position(|w| w == [0x84, 0xfe, 0xff, 0xff])
            .unwrap();
        wrong[at] = 0x83;
        assert!(calls(&wrong).is_empty());
        let mut inverted = b.clone();
        let at = inverted
            .windows(3)
            .position(|w| w == [0x0f, 0x45, 0xf1])
            .unwrap();
        inverted[at + 1] = 0x44;
        assert!(calls(&inverted).is_empty());
    }
    #[test]
    fn rejects_reversed_root_guard_and_clobbered_flags() {
        let b = fixture(false, false, false, false);
        let mut reverse = b.clone();
        let at = reverse
            .windows(4)
            .position(|w| w == [0x80, 0x78, 0x30, 0])
            .unwrap();
        reverse[at + 5] = 0x84;
        assert!(calls(&reverse).is_empty());
        let mut flags = fixture(false, false, true, false);
        let at = flags
            .windows(5)
            .position(|w| w == [0x90, 0x4c, 0x8d, 0x77, 0x30])
            .unwrap();
        flags[at..at + 5].copy_from_slice(&[0x31, 0xc0, 0x90, 0x90, 0x90]);
        assert!(calls(&flags).is_empty());
    }
    #[test]
    fn rejects_side_entrance_and_loop() {
        let mut b = fixture(true, false, true, false);
        let call = calls(&b)[0];
        // Even an unreachable outside jump into the call region is rejected.
        let d = (call - 0x1000) as i32 - b.len() as i32 - 5;
        b.push(0xe9);
        b.extend(d.to_le_bytes());
        assert!(calls(&b).is_empty());
        let mut b = fixture(true, false, true, false);
        let at = b.iter().position(|v| *v == 0xe8).unwrap();
        b[at] = 0xe9;
        b[at + 1..at + 5].copy_from_slice(&(-5i32).to_le_bytes());
        assert!(calls(&b).is_empty());
    }
}
