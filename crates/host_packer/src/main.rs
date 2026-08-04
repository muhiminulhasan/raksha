//! Host-side packer entry point: wires parse -> paginate -> encrypt -> steg ->
//! reconstruct into the pack pipeline.
//!
//! `raksha <in.exe> <out.exe>` reads a PE, encrypts `.text` page-by-page,
//! fragments the payload metadata into the DOS-stub/headers region, and appends
//! a `.raksha` section carrying the *real* `runtime_stub` cdylib `.text`. The
//! stub's `raksha_entry` export supplies the entry offset, so the packed image's
//! entry point lands exactly on the stub entry (which traps `.text` into the
//! VEH). This task verifies the packer produces a structurally valid PE;
//! actually *running* the packed image is Task 18.

use anyhow::{Context, Result};
use host_packer::{cli, encrypt, paginate, parse, reconstruct, steg};

fn main() -> Result<()> {
    let args = cli::parse()?;
    let bytes = std::fs::read(&args.input)?;
    let mut pe = parse::parse(bytes)?;

    // CSPRNG master key (drawn here so it can also seed per-build page
    // boundaries and the stub section name — WS-7 diversification).
    let master_key = {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|e| anyhow::anyhow!("getrandom master key: {e:?}"))?;
        k
    };
    // Every build gets a different page-boundary layout.
    let seed = u64::from_le_bytes(master_key[0..8].try_into().unwrap());

    let mut plan = paginate::paginate(pe.text_vsize, pe.text_rva, &pe.relocs, seed);
    let payload =
        encrypt::encrypt_text(&mut pe.bytes, &mut plan, pe.text_raw, pe.text_vsize, master_key);

    let info = raksha_core::types::PayloadInfo {
        master_key: payload.master_key,
        oep: pe.oep,
        text_rva: pe.text_rva,
        text_vsize: pe.text_vsize,
        page_count: payload.page_entries.len() as u32,
        reloc_table_offset: 0, // set by steg
        reloc_table_size: payload.reloc_table.len() as u32,
        seed,
        preferred_base: pe.preferred_base,
    };

    // Read the compiled runtime_stub cdylib and locate `raksha_entry`'s offset
    // within its `.text` section. The pack pipeline then carries the real stub
    // `.text` (not a placeholder) and repoints the EP onto `raksha_entry`.
    let stub_path = resolve_stub_path();
    let stub_bytes_full = std::fs::read(&stub_path)
        .with_context(|| format!("reading stub dll at {}", stub_path.display()))?;
    let (stub_image, entry_off, stub_text_va) = extract_stub_image(&stub_bytes_full)?;

    // IMPORTANT: append the stub section BEFORE steganography. steg.rs's
    // `choose_metadata_offset` computes the metadata-blob location as
    // `section_table_end = e_lfanew + 24 + opt_size + num_sections*40`. If
    // steganography ran first, the blob would land at the *original*
    // section_table_end and `append_raksha`'s new section header (written at
    // exactly that offset) would overwrite the blob's PayloadInfo. Appending
    // the section first makes num_sections final, so the blob lands past the
    // complete section table.
    //
    // The section name is randomized per build (derived from the master key) so
    // no two packed binaries carry the same recognizable ".raksha" marker.
    let section_name = stub_section_name(&payload.master_key);
    let new_ep = reconstruct::append_raksha(&mut pe.bytes, &stub_image, entry_off, &section_name)?;
    // `.raksha` VA = the new EP minus the entry offset within the stub.
    let raksha_va = new_ep - entry_off;

    // Merge the stub's base relocations into the packed image's reloc dir.
    // The stub DLL was compiled against its own preferred base; its absolute
    // references must be relocated at load time to wherever the packed image
    // actually loads. Without this, the stub faults on its first absolute
    // reference inside `.raksha`. Translate each stub DIR64 reloc RVA into
    // `.raksha` space and append new reloc blocks.
    reconstruct::merge_stub_relocs(&mut pe.bytes, &stub_bytes_full, raksha_va, stub_text_va)?;

    // Strip base-relocations targeting `.text` from the packed reloc dir. With
    // ASLR on, the loader would apply delta to those ciphertext slots,
    // corrupting them before the stub can decrypt cleanly. The stub re-applies
    // `.text` relocs itself per-page after decrypting, so the loader must not
    // touch `.text`. Stub relocs (in `.raksha`, outside `.text`) are preserved.
    reconstruct::strip_text_relocs(&mut pe.bytes, pe.text_rva, pe.text_vsize)?;

    // Clear the packed image's TLS directory. The target's TLS callback code
    // lives in `.text` (now ciphertext); the OS loader invokes TLS callbacks
    // during LdrpCallTlsInitializers BEFORE the stub entry runs, so an
    // un-cleared TLS dir makes the loader jump into ciphertext and crash
    // before we ever get control.
    reconstruct::clear_tls_directory(&mut pe.bytes)?;

    steg::fragment_into(
        &mut pe.bytes,
        &info,
        &payload.reloc_table,
        &payload.page_entries,
    )?;

    std::fs::write(&args.output, &pe.bytes)?;
    println!("packed {} -> {}", args.input.display(), args.output.display());
    Ok(())
}

/// Derive a per-build, innocuous-looking 8-byte section name from the master
/// key. A constant `.raksha` section name is an immediate fingerprint for
/// automated scanners, so each packed binary gets a distinct random-looking
/// name.
fn stub_section_name(master_key: &[u8; 32]) -> [u8; 8] {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut name = [0u8; 8];
    for i in 0..6 {
        name[i] = ALPHA[(master_key[i] as usize) % ALPHA.len()];
    }
    name
}

/// Resolve the `runtime_stub` cdylib path.
///
/// Order: `RAKSHA_STUB` env var (authoritative; the build/test flow sets it),
/// then a workspace-relative fallback (`<workspace>/target/release/runtime_stub.dll`),
/// then a manifest-dir-relative fallback
/// (`<host_packer>/../../target/release/runtime_stub.dll`, which is the same
/// target dir for a workspace). We probe candidates and return the first that
/// exists; if none exist we return the env/workspace value so the subsequent
/// read produces a meaningful "file not found" error.
fn resolve_stub_path() -> std::path::PathBuf {
    const REL: &str = "target/release/runtime_stub.dll";

    if let Ok(p) = std::env::var("RAKSHA_STUB") {
        return std::path::PathBuf::from(p);
    }

    // Workspace-root relative: host_packer lives at crates/host_packer, so the
    // workspace root is two levels up from CARGO_MANIFEST_DIR.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest = std::path::PathBuf::from(&dir);
        candidates.push(manifest.join("../../").join(REL));
        candidates.push(manifest.join(REL));
    }
    candidates.push(std::path::PathBuf::from(REL));

    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    // Nothing found — return the best guess so the read errors clearly.
    candidates.into_iter().next().unwrap_or_else(|| std::path::PathBuf::from(REL))
}

/// Parse the `runtime_stub` cdylib and extract its full loadable image
/// (`.text` + `.rdata` + `.data` + `.pdata` + `.tls`), laid out contiguously
/// starting at the stub's `.text` virtual address, plus the offset of the
/// `raksha_entry` export within `.text`.
///
/// Returns `(image_bytes, entry_offset, stub_text_va)`.
///
/// **Why the whole image, not just `.text`:** the stub's `.text` is
/// position-independent (RIP-relative), but it references `.rdata` (the const
/// hash table, string literals) and `.data` (the entry anchor / globals) via
/// *absolute* addresses. Those references only resolve if the whole image is
/// mapped with its inter-section RVA layout preserved. Injecting just `.text`
/// leaves every absolute ref dangling → STATUS_ACCESS_VIOLATION.
///
/// The image is placed into `.raksha` at `stub_text_va`'s relative layout, so a
/// reference from `.text` to `.rdata` at stub RVA `R` still resolves at
/// `raksha_va + (R - stub_text_va)`. All stub base-relocations translate by the
/// single block offset `raksha_va - stub_text_va` (see `merge_stub_relocs`).
fn extract_stub_image(dll: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    use goblin::pe::PE;

    let pe = PE::parse(dll).context("parsing stub dll as PE")?;

    // `.text\0\0\0` — 8-byte section name, NUL-padded.
    let text = pe
        .sections
        .iter()
        .find(|s| {
            let mut n = [0u8; 8];
            n.copy_from_slice(&s.name);
            &n == b".text\0\0\0"
        })
        .ok_or_else(|| anyhow::anyhow!("stub dll has no .text section"))?;
    let stub_text_va = text.virtual_address;

    // The image spans from the lowest section VA through the highest
    // (VA + VirtualSize), restricted to the loadable code/data sections we care
    // about. We exclude `.reloc` (we translate+merge relocs separately) and any
    // PE metadata. Build the contiguous buffer covering every loadable section,
    // copying each section's raw bytes at its relative RVA offset.
    const EXCLUDE: &[&[u8]] = &[b".reloc"];
    let mut img_lo = u32::MAX;
    let mut img_hi = 0u32;
    for s in &pe.sections {
        let mut name = [0u8; 8];
        name.copy_from_slice(&s.name);
        let end = name.iter().position(|&b| b == 0).unwrap_or(8);
        let nm = &name[..end];
        if EXCLUDE.iter().any(|x| *x == nm) {
            continue;
        }
        let va = s.virtual_address;
        let vs = s.virtual_size;
        if vs == 0 {
            continue;
        }
        img_lo = img_lo.min(va);
        img_hi = img_hi.max(va + vs);
    }
    if img_lo == u32::MAX {
        anyhow::bail!("stub dll has no loadable sections");
    }
    let mut image = vec![0u8; (img_hi - img_lo) as usize];
    for s in &pe.sections {
        let mut name = [0u8; 8];
        name.copy_from_slice(&s.name);
        let end = name.iter().position(|&b| b == 0).unwrap_or(8);
        let nm = &name[..end];
        if EXCLUDE.iter().any(|x| *x == nm) {
            continue;
        }
        let va = s.virtual_address as usize;
        let vs = s.virtual_size as usize;
        let raw = s.pointer_to_raw_data as usize;
        if vs == 0 || raw + vs > dll.len() {
            continue;
        }
        let dst = va - img_lo as usize;
        image[dst..dst + vs].copy_from_slice(&dll[raw..raw + vs]);
    }

    // Strip the stub's export directory from the merged image. The injected
    // stub never needs its own exports at runtime (nothing imports it), but the
    // `#[no_mangle]` symbols (`raksha_entry`, `raksha_veh`, `memcpy`, ...) leave
    // their name strings in the export directory — a stable fingerprint in
    // every packed binary. Zero the whole [rva, rva+size) region (directory +
    // name strings) so no stub symbol is recoverable from the packed file.
    if let Some(optional_header) = &pe.header.optional_header {
        if let Some(export) = optional_header.data_directories.get_export_table() {
            let rva = export.virtual_address as usize;
            let size = export.size as usize;
            if rva >= img_lo as usize {
                let off = rva - img_lo as usize;
                let end = (off + size).min(image.len());
                image[off..end].fill(0);
            }
        }
    }

    // `raksha_entry` is `#[no_mangle] pub extern "system"`, so it appears in the
    // cdylib's export table. goblin's `Export.rva` is the symbol's RVA.
    let mut entry_rva: Option<u32> = None;
    for e in &pe.exports {
        if e.name == Some("raksha_entry") {
            entry_rva = Some(e.rva as u32);
            break;
        }
    }
    let entry_rva =
        entry_rva.ok_or_else(|| anyhow::anyhow!("stub dll has no raksha_entry export"))?;

    let entry_off = entry_rva
        .checked_sub(stub_text_va)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "raksha_entry rva {:#x} precedes .text virtual_address {:#x}",
                entry_rva,
                stub_text_va
            )
        })?;
    if entry_off as usize >= image.len() {
        anyhow::bail!(
            "raksha_entry offset {:#x} outside stub image (len {:#x})",
            entry_off,
            image.len()
        );
    }

    Ok((image, entry_off, stub_text_va))
}
