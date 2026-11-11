//! Structural preflight for httlib-hpack 0.1.3. Its integer/string readers can
//! index past truncated input. Keep all Huffman/table decoding in the library,
//! but never pass it an incomplete representation. This is deliberately not a
//! catch_unwind wrapper: malformed input must produce an ordinary error.
use crate::model::Result;

fn integer(input: &[u8], position: &mut usize, prefix: u8) -> Result<usize> {
    let first = *input.get(*position).ok_or("incomplete HPACK integer")?;
    *position += 1;
    let mask = (1u8 << prefix) - 1;
    let mut value = (first & mask) as usize;
    if value < mask as usize {
        return Ok(value);
    }
    // Match the library's five-octet bound; this is safe on both 32/64 bit.
    for shift in [0, 7, 14, 21] {
        let next = *input.get(*position).ok_or("incomplete HPACK integer")?;
        *position += 1;
        value += ((next & 127) as usize) << shift;
        if next & 128 == 0 {
            return Ok(value);
        }
    }
    Err("HPACK integer limit".into())
}
fn string(input: &[u8], position: &mut usize) -> Result<()> {
    let length = integer(input, position, 7)?;
    if length > input.len() - *position {
        return Err("incomplete HPACK string".into());
    }
    *position += length;
    Ok(())
}
pub(crate) fn validate(input: &[u8]) -> Result<()> {
    let mut position = 0;
    let mut seen_header = false;
    while let Some(&first) = input.get(position) {
        if first & 128 != 0 {
            integer(input, &mut position, 7)?;
            seen_header = true;
        } else if first & 0xe0 == 0x20 {
            if seen_header {
                return Err("late HPACK table size update".into());
            }
            integer(input, &mut position, 5)?;
        } else {
            let prefix = if first & 64 != 0 { 6 } else { 4 };
            if integer(input, &mut position, prefix)? == 0 {
                string(input, &mut position)?;
            }
            string(input, &mut position)?;
            seen_header = true;
        }
    }
    Ok(())
}
