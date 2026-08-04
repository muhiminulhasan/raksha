//! Encrypt `.text` page-by-page and assemble the page table + reloc table.
//!
//! The master key is drawn by the caller (from the OS CSPRNG) and passed in;
//! from it, each page key is derived via a two-input ChaCha20 PRF and the page
//! body is XORed with a ChaCha20 keystream ([`raksha_core::crypto::xor_page_v2`]).
//! The relocation offsets bucketed per page by [`crate::paginate`] are
//! delta-encoded and concatenated into a single reloc table the stub walks in
//! page order.

use raksha_core::crypto::xor_page_v2;
use raksha_core::reloc::encode_relocs_into;
use raksha_core::types::PageEntry;
use crate::paginate::PagePlan;

/// Output of [`encrypt_text`]: the master key, the now fully-populated page
/// table (with `raw_offset` set), and the concatenated per-page reloc delta
/// stream the stub consumes after decryption.
pub struct PackedPayload {
    pub master_key: [u8; 32],
    pub page_entries: Vec<PageEntry>,
    pub reloc_table: Vec<u8>,
}

/// Encrypt every page of `.text` in place and build the page + reloc tables.
///
/// - `pe_bytes`:  the full PE image; `.text` lives at file offset `text_raw`.
/// - `plan`:      the variable-size page plan from [`crate::paginate::paginate`].
/// - `text_raw`:  file offset of `.text`; the first page's `raw_offset`.
/// - `text_vsize`: virtual (unpadded) size of `.text`; encryption is capped at
///   this so a tail page rounded up for page-alignment never touches bytes
///   beyond `.text` (which belong to the next section on disk).
/// - `master_key`: 32-byte key from the OS CSPRNG (drawn by the caller so it
///   can also seed per-build page boundaries).
///
/// Each page's `raw_offset` is set to `text_raw` plus the cumulative size of
/// all preceding pages. The reloc table is the concatenation, in page order,
/// of each page's `reloc_count` delta-encoded offsets (2 bytes each).
pub fn encrypt_text(
    pe_bytes: &mut Vec<u8>,
    plan: &mut PagePlan,
    text_raw: u32,
    text_vsize: u32,
    master_key: [u8; 32],
) -> PackedPayload {

    // Assign each page its raw file offset: text_raw + cumulative preceding size.
    let mut off = text_raw;
    for entry in &mut plan.entries {
        entry.raw_offset = off;
        off += entry.size;
    }

    // Encrypt each page in place and append its delta-encoded reloc stream.
    // The tail page's size is rounded up to a 0x1000 boundary for alignment,
    // so cap each page's XOR at the remaining `.text` code bytes.
    let mut reloc_table = Vec::new();
    let mut code_off = 0u32;
    for (i, entry) in plan.entries.iter().enumerate() {
        let start = entry.raw_offset as usize;
        let size = entry.size as usize;
        let enc_len = size.min((text_vsize - code_off) as usize);
        xor_page_v2(&master_key, i as u32, &mut pe_bytes[start..start + enc_len]);
        code_off += entry.size;

        let relocs = &plan.per_page_relocs[i];
        // encode_relocs_into writes relocs.len() * 2 bytes; the stub reads back
        // exactly entry.reloc_count * 2 bytes per page.
        let mut buf = vec![0u8; relocs.len() * 2];
        let n = encode_relocs_into(relocs, &mut buf);
        reloc_table.extend_from_slice(&buf[..n]);
    }

    PackedPayload {
        master_key,
        page_entries: plan.entries.clone(),
        reloc_table,
    }
}
