//! Append the injected-stub section and repoint the entry point.
//!
//! This is the final structural transformation: a new PE section (section name
//! randomized per build) is appended to the image carrying the injected stub
//! bytes, `NumberOfSections` is bumped, `SizeOfImage` is grown, and
//! `AddressOfEntryPoint` is repointed at the stub's entry offset within the new
//! section. The host can then write the buffer out as a runnable packed PE.

use anyhow::{bail, Result};

const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;

/// Section characteristics for `.raksha`: CODE | EXECUTE | READ | WRITE.
///
/// WRITE is required: the packer copies the stub's *whole* loadable image
/// (`.text` + `.rdata` + `.data` + `.pdata` + `.tls`) into `.raksha`, and the
/// stub's `.data` globals (context, ready flag, fault-table pointer) are
/// written at runtime by `raksha_entry` and the VEH handler.
const RAKSHA_CHARS: u32 = 0xE000_0020;

/// Append a section carrying `stub_bytes` to `pe`, bump
/// `NumberOfSections`, grow `SizeOfImage`, and repoint
/// `AddressOfEntryPoint` to `new_section_rva + stub_entry_rva_offset`.
///
/// Returns the new `AddressOfEntryPoint` value.
///
/// `stub_entry_rva_offset` is the offset of the stub's entry point *within*
/// the stub bytes (i.e. relative to the start of the new section's content).
/// `section_name` is the full 8-byte section-name field; it is randomized per
/// build by the caller (a constant `.raksha` name is a fingerprint).
pub fn append_raksha(
    pe: &mut Vec<u8>,
    stub_bytes: &[u8],
    stub_entry_rva_offset: u32,
    section_name: &[u8; 8],
) -> Result<u32> {
    if pe.len() < 0x40 {
        bail!("buffer too small to contain a DOS header");
    }
    let lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    if lfanew + 4 > pe.len() || &pe[lfanew..lfanew + 4] != b"PE\0\0" {
        bail!("bad PE signature");
    }
    let nt = lfanew + 4;
    // SizeOfOptionalHeader is at COFF-header offset 16.
    let opt_size = u16::from_le_bytes(pe[nt + 16..nt + 18].try_into().unwrap()) as usize;
    // `nt` points at the COFF header (past the 4-byte PE signature). The COFF
    // header is 20 bytes, so the optional header starts at `nt + 20`.
    let opt = nt + 20;
    let sect_table = opt + opt_size;

    if num_sections(pe) == 0 {
        bail!("cannot append .raksha to an image with no existing sections");
    }
    if sect_table + num_sections(pe) as usize * 40 > pe.len() {
        bail!("section table runs past end of file; corrupt optional-header size");
    }

    // Room for one more 40-byte section header? Bail rather than overwrite the
    // first section's raw data — header expansion is out of scope here. A zero
    // raw pointer indicates a synthetic image with no real section data, in
    // which case there is nothing to overlap; a real PE always has
    // PointerToRawData > 0 (raw data lives after the headers).
    let first_section_raw = u32::from_le_bytes(
        pe[sect_table + 20..sect_table + 24].try_into().unwrap(),
    ) as usize;
    let new_hdr_end = sect_table + (num_sections(pe) as usize + 1) * 40;
    if first_section_raw != 0 && new_hdr_end > first_section_raw {
        bail!("no room in headers for a new section; would need header expansion");
    }

    // Compute the new section's RVA (after the last existing section) and its
    // file offset (the current end of file).
    let last = sect_table + (num_sections(pe) as usize - 1) * 40;
    let last_rva = u32::from_le_bytes(pe[last + 12..last + 16].try_into().unwrap());
    let last_vsize = u32::from_le_bytes(pe[last + 8..last + 12].try_into().unwrap());
    let mut new_rva = align(last_rva + last_vsize, SECTION_ALIGNMENT);
    // A real PE always has sections at RVA >= 0x1000; if the prior layout is
    // degenerate (e.g. a synthetic test image with zeroed section fields), fall
    // back to the conventional first section RVA so the new section does not
    // collide with the image headers at address 0.
    if new_rva == 0 {
        new_rva = SECTION_ALIGNMENT;
    }

    // PointerToRawData MUST be FILE_ALIGNMENT-aligned (0x200). The OS loader
    // maps a section's raw data starting at PointerToRawData rounded DOWN to
    // FILE_ALIGNMENT; if new_raw is unaligned, the loader maps bytes from
    // before the stub, shifting every RVA-to-file mapping and executing the
    // wrong code. Pad `pe` up to FILE_ALIGNMENT first, then the stub lands at
    // an aligned offset.
    let unaligned = pe.len();
    let pad_to_align = align(unaligned as u32, FILE_ALIGNMENT) as usize - unaligned;
    pe.extend(std::iter::repeat(0u8).take(pad_to_align));
    let new_raw = pe.len() as u32;
    let new_vsize = stub_bytes.len() as u32;
    let new_rawsize = align(new_vsize, FILE_ALIGNMENT);

    // Write the 40-byte section header at index = num_sections.
    let h = sect_table + num_sections(pe) as usize * 40;
    if h + 40 > pe.len() {
        bail!("section header write would run past the end of the file");
    }
    let mut hdr = [0u8; 40];
    // Name field is 8 bytes, randomized per build (see caller).
    hdr[..8].copy_from_slice(section_name);
    hdr[8..12].copy_from_slice(&new_vsize.to_le_bytes()); // VirtualSize
    hdr[12..16].copy_from_slice(&new_rva.to_le_bytes()); // VirtualAddress
    hdr[16..20].copy_from_slice(&new_rawsize.to_le_bytes()); // SizeOfRawData
    hdr[20..24].copy_from_slice(&new_raw.to_le_bytes()); // PointerToRawData
    hdr[36..40].copy_from_slice(&RAKSHA_CHARS.to_le_bytes()); // Characteristics
    pe[h..h + 40].copy_from_slice(&hdr);

    // Bump NumberOfSections (COFF header, offset +2 from the PE signature).
    let new_num = num_sections(pe) + 1;
    pe[nt + 2..nt + 4].copy_from_slice(&new_num.to_le_bytes());

    // Grow SizeOfImage (optional header, offset +56). Take the max with the
    // existing value so a larger image is never shrunk.
    let cur_size_of_image = u32::from_le_bytes(pe[opt + 56..opt + 60].try_into().unwrap());
    let grown = align(new_rva + new_vsize, SECTION_ALIGNMENT);
    let new_size_of_image = cur_size_of_image.max(grown);
    pe[opt + 56..opt + 60].copy_from_slice(&new_size_of_image.to_le_bytes());

    // Append the raw section data, padded up to FILE_ALIGNMENT.
    pe.extend_from_slice(stub_bytes);
    let pad = new_rawsize as usize - stub_bytes.len();
    pe.extend(std::iter::repeat(0u8).take(pad));

    // Repoint AddressOfEntryPoint (optional header, offset +16) into the stub.
    let new_ep = new_rva.checked_add(stub_entry_rva_offset).ok_or_else(|| {
        anyhow::anyhow!("entry point RVA overflow: {new_rva:#x} + {stub_entry_rva_offset:#x}")
    })?;
    pe[opt + 16..opt + 20].copy_from_slice(&new_ep.to_le_bytes());

    // ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, 0x40) is already set in the
    // target PE's DllCharacteristics (PE32+ optional header +70): the mingw
    // fixture builds with it on. That is load-bearing here — the stub is injected
    // shellcode with absolute self-references compiled against the stub DLL's
    // preferred base; with ASLR on (delta != 0) the loader applies the merged
    // base-relocations (see `merge_stub_relocs`) and fixes those references to
    // wherever `.raksha` lands. The original `.text` ciphertext is concurrently
    // patched by the loader for the same delta, but the stub re-applies per-page
    // relocations after decrypting each page (the core protect-in-place design),
    // reconstructing the original code correctly.

    Ok(new_ep)
}

/// Read `NumberOfSections` from the COFF header.
fn num_sections(pe: &[u8]) -> u16 {
    let lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let nt = lfanew + 4;
    u16::from_le_bytes(pe[nt + 2..nt + 4].try_into().unwrap())
}

/// Round `v` up to the next multiple of `a` (which must be a power of two).
fn align(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}

/// Offset of the NT headers (PE signature) within `pe`, i.e. `e_lfanew`.
fn lfanew_stub(pe: &[u8]) -> usize {
    u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize
}

/// Zero the packed image's TLS directory (DataDirectory[9]).
///
/// The target PE may carry a TLS directory (e.g. mingw CRT's
/// `_pei386_runtime_relocator` callback). That callback's code lives in
/// `.text`, which the packer encrypts — so at load time the TLS callback
/// pointer leads the OS loader into ciphertext, causing a wild jump / access
/// violation BEFORE the stub entry ever runs (TLS callbacks run during
/// `LdrpCallTlsInitializers`, before AddressOfEntryPoint).
///
/// Clearing the TLS directory tells the loader there are no TLS callbacks to
/// invoke, so execution proceeds straight to our stub entry. The mingw CRT
/// runtime-relocator is not needed once the stub controls execution.
pub fn clear_tls_directory(pe: &mut Vec<u8>) -> Result<()> {
    if pe.len() < 0x40 {
        bail!("buffer too small to contain a DOS header");
    }
    let lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    if lfanew + 4 > pe.len() || &pe[lfanew..lfanew + 4] != b"PE\0\0" {
        bail!("bad PE signature");
    }
    let nt = lfanew + 4;
    let opt = nt + 20;
    // DataDirectory[9] (TLS) is at optional-header offset 112 + 9*8 = 184.
    let tls_off = opt + 112 + 9 * 8;
    if tls_off + 8 <= pe.len() {
        pe[tls_off..tls_off + 8].copy_from_slice(&[0u8; 8]);
    }
    Ok(())
}

/// Remove base-relocation entries that target the encrypted `.text` range.
///
/// With ASLR on, the loader applies `delta` to every reloc slot. `.text` is
/// ciphertext, so the loader's patches corrupt it before the stub can decrypt
/// it cleanly. The stub re-applies `.text` relocations itself (per-page, after
/// decrypting), so the loader must NOT touch `.text`. We rebuild the reloc
/// directory keeping only entries whose target RVA falls OUTSIDE
/// `[text_rva, text_rva+text_vsize)`. Stub relocations (in `.raksha`) and any
/// other sections are preserved.
pub fn strip_text_relocs(pe: &mut Vec<u8>, text_rva: u32, text_vsize: u32) -> Result<()> {
    let lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let nt = lfanew + 4;
    let opt = nt + 20;
    let reloc_rva = u32::from_le_bytes(pe[opt + 152..opt + 156].try_into().unwrap());
    let reloc_size = u32::from_le_bytes(pe[opt + 156..opt + 160].try_into().unwrap());
    if reloc_rva == 0 || reloc_size == 0 {
        return Ok(()); // no relocs to strip
    }
    let reloc_file = match rva_to_file_offset(pe, reloc_rva) {
        Some(o) => o,
        None => bail!("reloc RVA not in any section"),
    };

    // Walk the existing blocks, collecting DIR64 entries that are OUTSIDE .text.
    let text_end = text_rva.checked_add(text_vsize).ok_or_else(|| {
        anyhow::anyhow!("text range overflow: {:#x}+{:#x}", text_rva, text_vsize)
    })?;
    let mut kept: Vec<u32> = Vec::new(); // target RVAs outside .text
    let mut pos = reloc_file;
    let end = reloc_file + reloc_size as usize;
    while pos + 8 <= end {
        let page_rva = u32::from_le_bytes(pe[pos..pos + 4].try_into().unwrap());
        let block_size = u32::from_le_bytes(pe[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if block_size < 8 || pos + block_size > end {
            break;
        }
        let n = (block_size - 8) / 2;
        for i in 0..n {
            let entry = u16::from_le_bytes(
                pe[pos + 8 + i * 2..pos + 8 + i * 2 + 2].try_into().unwrap(),
            );
            let typ = (entry >> 12) & 0xF;
            let offset = (entry & 0x0FFF) as u32;
            if typ == 0 {
                continue; // ABSOLUTE padding
            }
            let target_rva = page_rva.wrapping_add(offset);
            // Keep only relocations OUTSIDE the encrypted .text range.
            if target_rva < text_rva || target_rva >= text_end {
                kept.push(target_rva);
            }
        }
        pos += block_size;
    }

    // Rebuild the reloc directory from the kept entries, grouped by 4 KiB page.
    let new_bytes = build_reloc_blocks_pub(&kept);

    // Write the rebuilt directory over the old one. If the new dir is larger,
    // grow the .reloc section; if smaller, leave trailing bytes (SizeOfRawData
    // unchanged, DataDirectory size updated).
    if new_bytes.len() > reloc_size as usize {
        grow_reloc_section(pe, reloc_rva, new_bytes.len() as u32)?;
        // grow_reloc_section may have reallocated; recompute reloc_file.
        let reloc_file = rva_to_file_offset(pe, reloc_rva)
            .ok_or_else(|| anyhow::anyhow!("reloc RVA vanished after grow"))?;
        if reloc_file + new_bytes.len() > pe.len() {
            pe.resize(reloc_file + new_bytes.len(), 0);
        }
        pe[reloc_file..reloc_file + new_bytes.len()].copy_from_slice(&new_bytes);
    } else {
        let reloc_file = rva_to_file_offset(pe, reloc_rva)
            .ok_or_else(|| anyhow::anyhow!("reloc RVA not in any section"))?;
        pe[reloc_file..reloc_file + new_bytes.len()].copy_from_slice(&new_bytes);
    }

    // Update DataDirectory[5].Size.
    let nt = lfanew + 4;
    let opt = nt + 20;
    let new_size = new_bytes.len() as u32;
    pe[opt + 156..opt + 160].copy_from_slice(&new_size.to_le_bytes());

    Ok(())
}

/// Public wrapper around the reloc-block builder (used by merge + strip).
fn build_reloc_blocks_pub(rvas: &[u32]) -> Vec<u8> {
    build_reloc_blocks(rvas)
}

/// Translate the stub DLL's base relocations into the packed image's address
/// space and append them to the packed image's base-relocation directory.
///
/// The stub is compiled as its own DLL with absolute references relative to the
/// stub's preferred base. When its `.text` is injected into the `.raksha`
/// section, those absolute references point at the wrong address unless the OS
/// loader relocates them — which it will only do if the packed image's reloc
/// directory contains entries covering `.raksha`. This function extracts every
/// DIR64 reloc from the stub, translates its RVA
/// (`stub_rva - stub_text_va + raksha_va`), and merges it into the packed
/// image's `.reloc` section as one new reloc block per 4 KiB page.
///
/// `raksha_va` is the `.raksha` section's VirtualAddress (where the stub now
/// lives in the packed image). `stub_text_va` is the stub DLL's `.text`
/// VirtualAddress (the base the stub's RVAs are relative to).
pub fn merge_stub_relocs(
    pe: &mut Vec<u8>,
    stub_dll: &[u8],
    raksha_va: u32,
    stub_text_va: u32,
) -> Result<()> {
    // 1. Collect the stub's DIR64 reloc RVAs, translated into .raksha space.
    let stub_entries = collect_stub_relocs(stub_dll, stub_text_va, raksha_va)?;

    if stub_entries.is_empty() {
        return Ok(()); // stub is fully position-independent; nothing to merge
    }

    // 2. REWRITE the stub's absolute references at pack time. The stub was
    //    compiled against its OWN ImageBase; each DIR64 slot holds a full VA
    //    of the form `stub_imagebase + stub_target_rva`. The loader will later
    //    apply `packed_delta = packed_runtime_base - packed_preferred_base` to
    //    every reloc slot — so for the result to land at the correct `.raksha`
    //    address, each slot must hold `packed_preferred_base + translated_rva`
    //    BEFORE the loader runs. Rewrite accordingly:
    //      new_value = packed_imagebase + (stub_va - stub_imagebase)
    //    where stub_va is the value currently stored in the (now-injected)
    //    image at the translated packed RVA.
    //
    //    This rewrite must happen even when the packed image has no `.reloc`
    //    directory: for a non-relocatable target the image loads at its fixed
    //    preferred base (delta == 0), so the rewritten values are already
    //    correct and no loader relocation is needed.
    let lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let nt = lfanew + 4;
    let opt = nt + 20;
    let packed_imagebase = u64::from_le_bytes(pe[opt + 24..opt + 32].try_into().unwrap());
    let stub_imagebase = u64::from_le_bytes(stub_dll[lfanew_stub(stub_dll) + 24..lfanew_stub(stub_dll) + 32].try_into().unwrap());
    for &packed_rva in &stub_entries {
        if let Some(off) = rva_to_file_offset(pe, packed_rva) {
            if off + 8 <= pe.len() {
                let stored = u64::from_le_bytes(pe[off..off + 8].try_into().unwrap());
                // Only rewrite values that look like stub-ImageBase-relative VAs.
                if stored >= stub_imagebase && stored < stub_imagebase + 0x1_0000_0000 {
                    let stub_target_rva = (stored - stub_imagebase) as u32;
                    let new_value = packed_imagebase + (stub_target_rva as u64);
                    pe[off..off + 8].copy_from_slice(&new_value.to_le_bytes());
                }
            }
        }
    }

    // 3. Locate the packed image's reloc directory (DataDirectory[5]) to append
    //    the stub's new reloc blocks.
    let reloc_rva = u32::from_le_bytes(pe[opt + 112 + 5 * 8..opt + 112 + 5 * 8 + 4].try_into().unwrap());
    let reloc_size = u32::from_le_bytes(pe[opt + 112 + 5 * 8 + 4..opt + 112 + 5 * 8 + 8].try_into().unwrap());
    if reloc_rva == 0 {
        // Non-relocatable target: the image loads at its preferred base
        // (delta == 0), so the rewritten stub refs are already correct and no
        // .reloc directory is needed.
        return Ok(());
    }
    let reloc_file = rva_to_file_offset(pe, reloc_rva)
        .ok_or_else(|| anyhow::anyhow!("packed reloc RVA not in any section"))?;

    // 4. Build new reloc blocks for the stub entries (grouped by 4 KiB page).
    let new_blocks = build_reloc_blocks(&stub_entries);

    // 5. The new blocks must be appended to the reloc directory. The .reloc
    //    section typically has slack (raw size > virtual size), but to be safe
    //    we append the new bytes at the end of the reloc data and, if that
    //    overruns the section, extend the section's raw size. Simplest robust
    //    approach: write the new blocks immediately after the existing reloc
    //    data (at reloc_file + reloc_size), growing the file if needed, then
    //    update DataDirectory[5].Size.
    let append_at = reloc_file + reloc_size as usize;
    let added = new_blocks.len();
    if append_at + added > pe.len() {
        pe.resize(append_at + added, 0);
    }
    pe[append_at..append_at + added].copy_from_slice(&new_blocks);

    // 6. Update the reloc directory size in DataDirectory[5].
    let new_size = reloc_size + added as u32;
    pe[opt + 112 + 5 * 8 + 4..opt + 112 + 5 * 8 + 8].copy_from_slice(&new_size.to_le_bytes());

    // 7. Grow the .reloc section's VirtualSize / SizeOfRawData if the new data
    //    exceeded them.
    grow_reloc_section(pe, reloc_rva, new_size)?;

    Ok(())
}

/// Collect the stub's DIR64 reloc RVAs, translated into `.raksha` space.
fn collect_stub_relocs(
    stub_dll: &[u8],
    stub_text_va: u32,
    raksha_va: u32,
) -> Result<Vec<u32>> {
    let lfanew = u32::from_le_bytes(stub_dll[0x3C..0x40].try_into().unwrap()) as usize;
    let nt = lfanew + 4;
    let opt = nt + 20;
    let reloc_rva = u32::from_le_bytes(stub_dll[opt + 112 + 5 * 8..opt + 112 + 5 * 8 + 4].try_into().unwrap());
    if reloc_rva == 0 {
        return Ok(Vec::new());
    }
    let reloc_size = u32::from_le_bytes(stub_dll[opt + 112 + 5 * 8 + 4..opt + 112 + 5 * 8 + 8].try_into().unwrap());
    let reloc_file = rva_to_file_offset(stub_dll, reloc_rva)
        .ok_or_else(|| anyhow::anyhow!("stub reloc RVA not in any section"))?;

    let mut out = Vec::new();
    let mut pos = reloc_file;
    let end = reloc_file + reloc_size as usize;
    while pos + 8 <= end {
        let page_rva = u32::from_le_bytes(stub_dll[pos..pos + 4].try_into().unwrap());
        let block_size = u32::from_le_bytes(stub_dll[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if block_size < 8 || pos + block_size > end {
            break;
        }
        let n = (block_size - 8) / 2;
        for i in 0..n {
            let entry = u16::from_le_bytes(
                stub_dll[pos + 8 + i * 2..pos + 8 + i * 2 + 2].try_into().unwrap(),
            );
            let typ = (entry >> 12) & 0xF;
            let offset = (entry & 0x0FFF) as u32;
            if typ == 10 {
                // IMAGE_REL_BASED_DIR64. Translate the stub RVA into .raksha.
                let stub_rva = page_rva + offset;
                let raksha_rva = stub_rva.wrapping_sub(stub_text_va).wrapping_add(raksha_va);
                out.push(raksha_rva);
            }
            // type 0 == IMAGE_REL_BASED_ABSOLUTE (padding); skip.
        }
        pos += block_size;
    }
    Ok(out)
}

/// Group translated RVAs into PE reloc blocks (one block per 4 KiB page).
fn build_reloc_blocks(rvas: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rvas.len() {
        let page = rvas[i] & !0xFFF;
        let mut entries: Vec<u16> = Vec::new();
        while i < rvas.len() && (rvas[i] & !0xFFF) == page {
            let offset = rvas[i] & 0x0FFF;
            // DIR64 (type 10) in high nibble, offset in low 12 bits.
            entries.push((10u16 << 12) | offset as u16);
            i += 1;
        }
        // Pad entries to an even count with an IMAGE_REL_BASED_ABSOLUTE (type 0)
        // entry so the block size stays a multiple of 4.
        if entries.len() % 2 == 1 {
            entries.push(0);
        }
        let block_size = (8 + entries.len() * 2) as u32;
        out.extend_from_slice(&page.to_le_bytes());
        out.extend_from_slice(&block_size.to_le_bytes());
        for e in &entries {
            out.extend_from_slice(&e.to_le_bytes());
        }
    }
    out
}

/// Map an RVA to a file offset via the section table.
fn rva_to_file_offset(pe: &[u8], rva: u32) -> Option<usize> {
    let lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let nt = lfanew + 4;
    let num_sections = u16::from_le_bytes(pe[nt + 2..nt + 4].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(pe[nt + 16..nt + 18].try_into().unwrap()) as usize;
    let sect_table = nt + 20 + opt_size;
    for i in 0..num_sections {
        let s = sect_table + i * 40;
        let va = u32::from_le_bytes(pe[s + 12..s + 16].try_into().unwrap());
        let vsize = u32::from_le_bytes(pe[s + 8..s + 12].try_into().unwrap());
        let raw = u32::from_le_bytes(pe[s + 20..s + 24].try_into().unwrap());
        if rva >= va && rva < va + vsize {
            return Some(raw as usize + (rva - va) as usize);
        }
    }
    None
}

/// Grow the `.reloc` section's VirtualSize and SizeOfRawData to cover `new_size`
/// bytes, extending the raw data with zero padding if needed.
fn grow_reloc_section(pe: &mut Vec<u8>, reloc_rva: u32, new_size: u32) -> Result<()> {
    let lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let nt = lfanew + 4;
    let num_sections = u16::from_le_bytes(pe[nt + 2..nt + 4].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(pe[nt + 16..nt + 18].try_into().unwrap()) as usize;
    let sect_table = nt + 20 + opt_size;
    for i in 0..num_sections {
        let s = sect_table + i * 40;
        let va = u32::from_le_bytes(pe[s + 12..s + 16].try_into().unwrap());
        let vsize = u32::from_le_bytes(pe[s + 8..s + 12].try_into().unwrap());
        if reloc_rva >= va && reloc_rva < va + vsize.max(1) {
            // Found the .reloc section header.
            let new_vsize = new_size.max(vsize);
            let raw = u32::from_le_bytes(pe[s + 20..s + 24].try_into().unwrap()) as usize;
            let new_rawsize = align(new_vsize, FILE_ALIGNMENT) as usize;
            // Extend the file with zero padding if the raw region grew.
            if raw + new_rawsize > pe.len() {
                pe.resize(raw + new_rawsize, 0);
            }
            pe[s + 8..s + 12].copy_from_slice(&new_vsize.to_le_bytes());
            pe[s + 16..s + 20].copy_from_slice(&(new_rawsize as u32).to_le_bytes());
            return Ok(());
        }
    }
    bail!(".reloc section not found for reloc RVA {:#x}", reloc_rva);
}
