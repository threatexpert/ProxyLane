//! Conservative offline x64 locator. No version list, fixed RVAs or object layouts.
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic as M};
use ring::digest::{digest as sha256, SHA256};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
#[path = "quic_locator_flow.rs"]
mod flow;
type Result<T> = std::result::Result<T, String>;
fn u32at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4).ok_or("truncated PE")?.try_into().unwrap(),
    ))
}
fn u16at(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2).ok_or("truncated PE")?.try_into().unwrap(),
    ))
}
fn digest(b: &[u8]) -> String {
    sha256(&SHA256, b)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn decode(b: &[u8], rva: u32) -> Result<Vec<Instruction>> {
    let mut d = Decoder::with_ip(64, b, rva as u64, DecoderOptions::NONE);
    let mut out = Vec::new();
    while d.can_decode() {
        let i = d.decode();
        require(!i.is_invalid(), "invalid function instruction")?;
        out.push(i);
    }
    Ok(out)
}
pub fn locate(path: &str) -> Result<Value> {
    locate_bytes(&std::fs::read(path).map_err(|e| e.to_string())?)
}
pub fn locate_bytes(raw: &[u8]) -> Result<Value> {
    locate_image(raw, false)
}
// A bounded snapshot of the loaded image, with sections at their virtual RVAs.
pub fn locate_image(raw: &[u8], mapped: bool) -> Result<Value> {
    require(raw.starts_with(b"MZ"), "not PE")?;
    let nt = u32at(raw, 60)? as usize;
    require(
        raw.get(nt..nt + 4) == Some(b"PE\0\0") && u16at(raw, nt + 4)? == 0x8664,
        "only x64 PE supported",
    )?;
    let optional = nt + 24;
    require(u16at(raw, optional)? == 0x20b, "not PE32+")?;
    let image_size = u32at(raw, optional + 56)?;
    require(image_size < 1024 * 1024 * 1024, "image too large")?;
    let section_at = optional + u16at(raw, nt + 20)? as usize;
    let mut sections = Vec::new();
    for n in 0..u16at(raw, nt + 6)? as usize {
        let at = section_at + n * 40;
        sections.push((
            u32at(raw, at + 12)?,
            if mapped {
                u32at(raw, at + 8)?
            } else {
                u32at(raw, at + 16)?
            },
            if mapped {
                u32at(raw, at + 12)?
            } else {
                u32at(raw, at + 20)?
            },
            u32at(raw, at + 36)?,
        ));
    }
    let bytes = |rva: u32, len: u32| -> Result<&[u8]> {
        let end = rva.checked_add(len).ok_or("RVA overflow")?;
        for &(start, size, file, _) in &sections {
            if rva >= start && end as u64 <= start as u64 + size as u64 {
                let at = file as usize + (rva - start) as usize;
                return raw
                    .get(at..at + len as usize)
                    .ok_or("PE range outside file".into());
            }
        }
        Err("unmapped PE range".into())
    };
    let exception = u32at(raw, optional + 112 + 3 * 8)?;
    let size = u32at(raw, optional + 116 + 3 * 8)?;
    require(size % 12 == 0, "invalid unwind directory")?;
    let mut ranges = BTreeMap::new();
    for e in bytes(exception, size)?.chunks_exact(12) {
        let begin = u32at(e, 0)?;
        let end = u32at(e, 4)?;
        // Modern linker tables may contain non-code/sentinel records. Only
        // bounded positive code ranges can be candidates; the selected entries
        // are checked again against RtlLookupFunctionEntry before patching.
        if begin < end && end <= image_size {
            ranges.insert(begin, end);
        }
    }
    let anchors: [&[u8]; 2] = [
        b"Net.QuicSession.CertVerificationResult",
        b"Failed to verify certificate chain: %s",
    ];
    let mut targets = BTreeMap::new();
    for (id, literal) in anchors.iter().enumerate() {
        for &(start, size, file, _) in &sections {
            let data = raw
                .get(file as usize..file as usize + size as usize)
                .ok_or("invalid section")?;
            for at in memchr::memmem::find_iter(data, literal) {
                targets.insert(start + at as u32, id);
            }
        }
    }
    let mut refs: BTreeMap<u32, Vec<(u32, usize)>> = BTreeMap::new();
    for &(start, size, _, flags) in &sections {
        if flags & 0x20000000 == 0 {
            continue;
        }
        let code = bytes(start, size)?;
        for op in memchr::memchr_iter(0x8d, code) {
            if op == 0 || op + 6 > code.len() {
                continue;
            }
            let at = op - 1;
            let w = &code[at..at + 7];
            if !matches!(w[0], 0x48 | 0x4c) || w[1] != 0x8d || w[2] & 0xc7 != 5 {
                continue;
            }
            let rva = start + at as u32;
            let target = rva as i64 + 7 + i32::from_le_bytes(w[3..7].try_into().unwrap()) as i64;
            if let Some(&id) = targets.get(&(target as u32)) {
                if let Some((&begin, &end)) = ranges.range(..=rva).next_back() {
                    if rva < end {
                        refs.entry(begin).or_default().push((rva, id));
                    }
                }
            }
        }
    }
    let candidates: Vec<_> = refs
        .iter()
        .filter(|(_, r)| r.iter().any(|x| x.1 == 0) && r.iter().any(|x| x.1 == 1))
        .collect();
    require(
        candidates.len() == 1,
        "completion anchors missing or ambiguous",
    )?;
    let (&begin, refs) = candidates[0];
    let end = ranges[&begin];
    require(
        (64..=16384).contains(&(end - begin)),
        "unexpected completion size",
    )?;
    let ins = decode(bytes(begin, end - begin)?, begin)?;
    let boundaries: BTreeSet<u64> = ins.iter().map(Instruction::ip).collect();
    require(
        refs.iter().all(|(r, _)| boundaries.contains(&(*r as u64))),
        "anchor not at instruction boundary",
    )?;
    let mut found = Vec::new();
    for call in flow::guarded_calls(&ins)? {
        let target = call.near_branch_target() as u32;
        let Some(&stop) = ranges.get(&target) else {
            continue;
        };
        let size = stop - target;
        if !(16..=8192).contains(&size) {
            continue;
        }
        let code = bytes(target, size)?;
        let callee = decode(code, target)?;
        if callee.is_empty()
            || matches!(callee[0].mnemonic(), M::Jmp | M::Call | M::Int3)
            || !callee.iter().any(|i| i.mnemonic() == M::Ret)
        {
            continue;
        }
        found.push(json!({"complete_rva":begin,"complete_size":end-begin,"allow_rva":target,"allow_size":size,
            "caller_return_rva":call.next_ip(),"complete_hash":digest(bytes(begin,end-begin)?),"allow_hash":digest(code)}));
    }
    require(
        found.len() == 1,
        "guarded unknown-root call missing or ambiguous",
    )?;
    let mut result = found.remove(0);
    if !mapped {
        result["module_hash"] = digest(raw).into();
    }
    result["image_size"] = image_size.into();
    Ok(result)
}
