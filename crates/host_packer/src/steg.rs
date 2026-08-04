//! Build the encrypted metadata blob (`master_key` + ChaCha20-encrypted
//! `PayloadInfo` fields + page table + reloc table + integrity tag), place it
//! inside the last (injected-stub) section, and point a small `Locator` at it
//! from the DOS stub.
//!
//! # Layout (all little-endian)
//!
//! ```text
//! [blob + 0        .. +32)   master_key (plaintext bootstrap)
//! [blob + 32       .. +72)   E(meta_key, PayloadInfo fields, 40 bytes)
//! [blob + 72       .. +72+N*10)   E(meta_key, PageEntry table, 10 B each)
//! [blob + 72+N*10  .. end-32)     E(meta_key, reloc table)
//! [blob + end-32   .. end)   E(meta_key, 32-byte integrity tag)
//! ```
//!
//! The master key is plaintext because the stub must read it before it can
//! derive the metadata key (unavoidable — a process that can decrypt must hold
//! the key). Everything else is encrypted, so the page layout, relocations and
//! the original entry point are not recoverable by static inspection. The tag
//! is encrypted together with the metadata: any modification to the ciphertext
//! breaks it after decryption.
//!
//! The blob is always placed inside the **last section** (`.raksha`), which the
//! loader maps READWRITE — the stub decrypts it in place. A blob in the
//! read-only header region could not be decrypted in place.
//!
//! The `Locator` at the fixed `LOCATOR_OFFSET` is a plain u32 RVA (no magic
//! marker — a fixed magic is a fingerprint; the stub validates structurally).

use anyhow::{bail, Context, Result};
use raksha_core::crypto::{keyed_mac, metadata_key, xor_metadata, xor_metadata_at};
use raksha_core::types::{
    Locator, PageEntry, PayloadInfo, BLOB_FIELDS_OFFSET, BLOB_KEY_OFFSET, BLOB_PAGE_TABLE_OFFSET,
    BLOB_TAG_SIZE, LOCATOR_OFFSET,
};

const PAGE_ENTRY_SIZE: usize = 10;

const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;

/// Append `size` bytes to the last section's raw data, growing the section's
/// virtual size / raw size and the image's SizeOfImage so the new bytes are
/// mapped at runtime. Returns `(file_offset, rva)` of the appended region.
///
/// The packer always appends the stub section last and pads it to
/// FILE_ALIGNMENT, so the last section's raw data ends exactly at EOF.
fn append_into_last_section(pe: &mut Vec<u8>, size: usize) -> Result<(usize, usize)> {
    let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let nt = e_lfanew + 4;
    if pe.len() < nt + 24 {
        bail!("PE too small to contain a section table");
    }
    let num_sections = u16::from_le_bytes(pe[nt + 2..nt + 4].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(pe[nt + 16..nt + 18].try_into().unwrap()) as usize;
    if num_sections == 0 {
        bail!("cannot place metadata blob: PE has no sections");
    }
    let opt = nt + 20;
    let last_off = opt + opt_size + (num_sections - 1) * 40;
    if last_off + 40 > pe.len() {
        bail!("section table runs past end of file");
    }
    let vs = u32::from_le_bytes(pe[last_off + 8..last_off + 12].try_into().unwrap());
    let va = u32::from_le_bytes(pe[last_off + 12..last_off + 16].try_into().unwrap());
    let rs = u32::from_le_bytes(pe[last_off + 16..last_off + 20].try_into().unwrap());
    let ro = u32::from_le_bytes(pe[last_off + 20..last_off + 24].try_into().unwrap());

    let file_off = (ro as usize) + (rs as usize);
    let rva = (va as usize) + (rs as usize);
    let content_end = (rs as usize) + size;
    let new_vs = (vs as usize).max(content_end) as u32;
    let new_rs = align_u32(content_end as u32, FILE_ALIGNMENT);

    pe[last_off + 8..last_off + 12].copy_from_slice(&new_vs.to_le_bytes());
    pe[last_off + 16..last_off + 20].copy_from_slice(&new_rs.to_le_bytes());

    // The loader validates that each section's SizeOfRawData lies within the
    // file, so grow the buffer to cover the full new raw extent (not just the
    // appended content).
    let raw_end = (ro as usize) + (new_rs as usize);
    if pe.len() < raw_end {
        pe.resize(raw_end, 0);
    }

    // Grow SizeOfImage (optional header +56) to cover the grown last section.
    let sa = u32::from_le_bytes(pe[opt + 32..opt + 36].try_into().unwrap()).max(SECTION_ALIGNMENT);
    let aligned_end = align_u32(new_vs, sa).wrapping_add(va);
    let cur = u32::from_le_bytes(pe[opt + 56..opt + 60].try_into().unwrap());
    let new_soi = cur.max(aligned_end);
    pe[opt + 56..opt + 60].copy_from_slice(&new_soi.to_le_bytes());

    Ok((file_off, rva))
}

/// Round `v` up to the next multiple of `a` (a power of two).
fn align_u32(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}

/// Translate a runtime RVA to a file offset using the section table. RVAs
/// inside a section resolve through its raw data; RVAs before the first
/// section live in the header region, where file offset == RVA.
fn rva_to_file_offset(pe: &[u8], rva: u32) -> Option<usize> {
    let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > pe.len() || &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let num_sections = u16::from_le_bytes(pe[e_lfanew + 6..e_lfanew + 8].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(pe[e_lfanew + 20..e_lfanew + 22].try_into().ok()?) as usize;
    let sect_table = e_lfanew + 24 + opt_size;
    let mut first_va = u32::MAX;
    for i in 0..num_sections {
        let off = sect_table + i * 40;
        if off + 40 > pe.len() {
            break;
        }
        let va = u32::from_le_bytes(pe[off + 12..off + 16].try_into().ok()?);
        if va != 0 {
            first_va = first_va.min(va);
        }
        let vs = u32::from_le_bytes(pe[off + 8..off + 12].try_into().ok()?);
        let rs = u32::from_le_bytes(pe[off + 16..off + 20].try_into().ok()?);
        let ro = u32::from_le_bytes(pe[off + 20..off + 24].try_into().ok()?);
        let extent = vs.max(rs);
        if rva >= va && rva < va.wrapping_add(extent) {
            return Some(ro as usize + (rva - va) as usize);
        }
    }
    if rva < first_va {
        // Header region (no section maps it): file offset == RVA.
        return Some(rva as usize);
    }
    None
}

/// Size in bytes of the plaintext metadata body (everything except the master
/// key): fields + page table + reloc table + tag.
fn plaintext_size(page_count: usize, reloc_table_len: usize) -> usize {
    40 + page_count * PAGE_ENTRY_SIZE + reloc_table_len + BLOB_TAG_SIZE
}

pub fn fragment_into(
    pe: &mut Vec<u8>,
    info: &PayloadInfo,
    reloc_table: &[u8],
    page_entries: &[PageEntry],
) -> Result<()> {
    let plain_len = plaintext_size(page_entries.len(), reloc_table.len());
    let blob_size = BLOB_KEY_OFFSET + 32 + plain_len;

    // Always append into the last (stub) section: it is mapped READWRITE, so
    // the stub can decrypt the metadata in place at runtime.
    let (file_off, blob_rva) = append_into_last_section(pe, blob_size)?;
    if pe.len() < file_off + blob_size {
        pe.resize(file_off + blob_size, 0);
    }

    // 1. Assemble plaintext: fields || page table || reloc table, then a
    //    two-stage keyed MAC over that content appended last. The tag's key is
    //    derived from the fields (so tampering with oep/text_rva/... breaks it)
    //    and the tag itself covers the page table + reloc table.
    let mk = info.master_key;
    let meta_key = metadata_key(&mk);
    let fields = info.to_fields();
    let mut plain = Vec::with_capacity(plain_len - BLOB_TAG_SIZE);
    plain.extend_from_slice(&fields);
    for e in page_entries {
        let mut b = [0u8; PAGE_ENTRY_SIZE];
        b[0..4].copy_from_slice(&e.size.to_le_bytes());
        b[4..6].copy_from_slice(&e.reloc_count.to_le_bytes());
        b[6..10].copy_from_slice(&e.raw_offset.to_le_bytes());
        plain.extend_from_slice(&b);
    }
    plain.extend_from_slice(reloc_table);
    let tag_key = keyed_mac(&meta_key, &fields);
    let tag = keyed_mac(&tag_key, &plain[40..]);
    plain.extend_from_slice(&tag);

    // 2. Encrypt the metadata in place (stream cipher — self-inverse).
    xor_metadata(&mk, &mut plain);

    // 3. Write blob: master_key (plaintext) || encrypted metadata.
    pe[file_off..file_off + BLOB_KEY_OFFSET + 32]
        .copy_from_slice(&mk[..32]);
    pe[file_off + BLOB_KEY_OFFSET + 32..file_off + blob_size].copy_from_slice(&plain);

    // 4. Locator at the fixed DOS-stub offset: the blob's RVA. No magic marker.
    let loc = Locator {
        metadata_offset: blob_rva as u32,
    };
    pe[LOCATOR_OFFSET..LOCATOR_OFFSET + 4].copy_from_slice(&loc.metadata_offset.to_le_bytes());

    Ok(())
}

pub fn defragment_from(pe: &[u8]) -> Result<(PayloadInfo, Vec<u8>, Vec<PageEntry>)> {
    if pe.len() < LOCATOR_OFFSET + 4 {
        bail!("PE too small to contain a Locator");
    }
    let blob_rva = u32::from_le_bytes(pe[LOCATOR_OFFSET..LOCATOR_OFFSET + 4].try_into().unwrap());
    if blob_rva == 0 {
        bail!("locator offset is zero — not a Raksha-packed image");
    }
    let blob_off = rva_to_file_offset(pe, blob_rva)
        .with_context(|| format!("metadata blob RVA {blob_rva:#x} not mappable to a file offset"))?;

    // Master key (plaintext) at the blob start.
    if pe.len() < blob_off + 32 + 40 {
        bail!("PE truncated: metadata blob missing master key / fields");
    }
    let mk: [u8; 32] = pe[blob_off + BLOB_KEY_OFFSET..blob_off + BLOB_KEY_OFFSET + 32]
        .try_into()
        .unwrap();

    // Decrypt the 40-byte PayloadInfo fields (plaintext position 0).
    let mut fields = [0u8; 40];
    fields.copy_from_slice(&pe[blob_off + BLOB_FIELDS_OFFSET..blob_off + BLOB_FIELDS_OFFSET + 40]);
    xor_metadata_at(&mk, 0, &mut fields);
    let info = PayloadInfo::from_fields(mk, &fields);

    let page_table_size = (info.page_count as usize) * PAGE_ENTRY_SIZE;
    let rest_len = page_table_size + info.reloc_table_size as usize + BLOB_TAG_SIZE;
    if pe.len() < blob_off + BLOB_PAGE_TABLE_OFFSET + rest_len {
        bail!("PE truncated mid-metadata");
    }

    // Decrypt the page table + reloc table + tag (plaintext position 40).
    let mut rest = pe[blob_off + BLOB_PAGE_TABLE_OFFSET..blob_off + BLOB_PAGE_TABLE_OFFSET + rest_len]
        .to_vec();
    xor_metadata_at(&mk, 40, &mut rest);

    // Verify the two-stage integrity tag over the decrypted metadata content.
    let tag_off = page_table_size + info.reloc_table_size as usize;
    let meta_key = metadata_key(&mk);
    let tag_key = keyed_mac(&meta_key, &fields);
    let expected = keyed_mac(&tag_key, &rest[..tag_off]);
    if rest[tag_off..tag_off + BLOB_TAG_SIZE] != expected {
        bail!("metadata integrity check failed — blob was modified");
    }

    // Parse the page table.
    let mut entries = Vec::with_capacity(info.page_count as usize);
    for i in 0..info.page_count as usize {
        let o = i * PAGE_ENTRY_SIZE;
        let size = u32::from_le_bytes(rest[o..o + 4].try_into().unwrap());
        let reloc_count = u16::from_le_bytes(rest[o + 4..o + 6].try_into().unwrap());
        let raw_offset = u32::from_le_bytes(rest[o + 6..o + 10].try_into().unwrap());
        entries.push(PageEntry {
            size,
            reloc_count,
            raw_offset,
        });
    }

    let reloc_table = rest[page_table_size..tag_off].to_vec();
    Ok((info, reloc_table, entries))
}
