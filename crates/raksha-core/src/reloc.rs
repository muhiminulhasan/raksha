//! Delta-encoded per-page relocation-offset codec.
//!
//! Within a page, every relocation fixup offset is < 8192 (max page size), so it
//! fits in `u16`. We store consecutive *deltas* as little-endian `u16`. The page
//! count is held in [`crate::types::PageEntry::reloc_count`], so the byte stream
//! is exactly `reloc_count * 2` bytes — compact and constant-time to decode.

/// Encode sorted within-page offsets as u16 LE deltas. Returns bytes written.
/// `out` must be at least `sorted_offsets.len() * 2` bytes.
pub fn encode_relocs_into(sorted_offsets: &[u16], out: &mut [u8]) -> usize {
    let mut prev: u16 = 0;
    let need = sorted_offsets.len() * 2;
    assert!(out.len() >= need, "encode_relocs_into: out too small");
    for (i, &cur) in sorted_offsets.iter().enumerate() {
        let delta = cur.wrapping_sub(prev);
        out[i * 2..i * 2 + 2].copy_from_slice(&delta.to_le_bytes());
        prev = cur;
    }
    need
}

/// Decode `count` deltas back into absolute within-page offsets. Returns count decoded.
pub fn decode_relocs(bytes: &[u8], count: usize, out: &mut [u16]) -> usize {
    assert!(out.len() >= count, "decode_relocs: out too small");
    assert!(bytes.len() >= count * 2, "decode_relocs: bytes too small");
    let mut prev: u16 = 0;
    for i in 0..count {
        let delta = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
        prev = prev.wrapping_add(delta);
        out[i] = prev;
    }
    count
}
