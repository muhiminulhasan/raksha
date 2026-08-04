//! PE parsing for the host packer: locate `.text`, the OEP, base relocs, IAT.

use anyhow::{Context, Result};
use goblin::pe::{section_table::SectionTable, PE};

/// Parsed view of a target PE needed by the packer.
///
/// Field names are part of the interface consumed by later tasks (crypto,
/// steganography, stub generation) and must not change.
pub struct ParsedPe {
    /// Mutable copy of the whole image.
    pub bytes: Vec<u8>,
    pub text_rva: u32,
    pub text_vsize: u32,
    /// File offset of `.text`.
    pub text_raw: u32,
    /// Original `AddressOfEntryPoint`.
    pub oep: u32,
    /// Optional-header `ImageBase` (reloc delta reference).
    pub preferred_base: u64,
    /// DIR64 reloc target RVAs that fall inside `.text`.
    pub relocs: Vec<u32>,
    /// IAT location (outside `.text`).
    pub iat_rva: Option<u32>,
}

/// Parse a PE image and extract the metadata the packer needs.
pub fn parse(mut bytes: Vec<u8>) -> Result<ParsedPe> {
    // Some real-world targets (e.g. the mingw GUI CRT) emit a TLS directory
    // whose `StartAddressOfRawData` equals the image base (RVA 0), which
    // goblin's eager TLS parse rejects. The packer clears the TLS directory on
    // the output anyway, so zero it up front to keep parsing robust.
    zero_tls_directory(&mut bytes);

    let pe = PE::parse(&bytes).context("not a valid PE")?;
    let sections = pe.sections;

    let text = find_section(&sections, ".text").context("no .text section")?;
    let text_rva = text.virtual_address;
    let text_vsize = text.virtual_size;
    let text_raw = text.pointer_to_raw_data;

    let oep = pe.entry as u32;
    // goblin 0.9's `optional_header` is `Option<OptionalHeader>`; PE32+
    // exposes the ImageBase as `windows_fields.image_base` (a u64).
    let optional_header = pe
        .header
        .optional_header
        .as_ref()
        .context("PE has no optional header")?;
    let preferred_base = optional_header.windows_fields.image_base;

    // IAT lives in data directory index 12. goblin 0.9 has no direct
    // `import_address_table_rva` on `ImportData`, so read the data directory.
    let iat_rva = optional_header
        .data_directories
        .get_import_address_table()
        .map(|dd| dd.virtual_address);

    // Collect DIR64 reloc targets that fall inside .text.
    let mut relocs = Vec::new();
    if let Some(rva) = reloc_table_rva(optional_header) {
        collect_dir64_relocs(&bytes, rva, text_rva, text_vsize, &mut relocs)?;
    }

    // A target may legitimately have no `.text` relocations: either it is a
    // non-relocatable build (no base-reloc directory / no DYNAMIC_BASE) that
    // loads at its fixed preferred base, or its relocs happen to land outside
    // `.text`. In both cases delta is 0 (or `.text` is position-independent),
    // so the packer proceeds with an empty reloc list — the stub applies no
    // relocations and the image works at its preferred base.
    if relocs.is_empty() {
        eprintln!("note: .text has no base relocations; packing as a non-relocatable image");
    }

    Ok(ParsedPe {
        bytes,
        text_rva,
        text_vsize,
        text_raw,
        oep,
        preferred_base,
        relocs,
        iat_rva,
    })
}

/// Resolve the base relocation table RVA from data directory index 5.
fn reloc_table_rva(optional_header: &goblin::pe::optional_header::OptionalHeader) -> Option<u32> {
    optional_header
        .data_directories
        .get_base_relocation_table()
        .map(|dd| dd.virtual_address)
}

/// Walk the PE base relocation table (data directory 5) and push the RVA of
/// every `IMAGE_REL_BASED_DIR64` (type 10) entry that lands inside `.text`.
///
/// goblin 0.9 ships no `BaseReloc` parser, so this parses the table directly.
/// The table is a sequence of blocks; each block is a u32 page RVA, a u32
/// block size (including the 8-byte header), then `(size - 8) / 2` u16
/// entries whose high 4 bits are the type and low 12 bits the offset.
fn collect_dir64_relocs(
    bytes: &[u8],
    table_rva: u32,
    text_rva: u32,
    text_vsize: u32,
    out: &mut Vec<u32>,
) -> Result<()> {
    let file_off = match rva_to_file_offset(bytes, table_rva) {
        Some(o) => o,
        None => return Ok(()),
    };

    let mut pos = file_off;
    while pos + 8 <= bytes.len() {
        let page_rva = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        let block_size = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
        // A zero size would loop forever; a too-small/misaligned block is malformed.
        if block_size < 8 || block_size % 2 != 0 {
            break;
        }
        let entry_count = (block_size - 8) / 2;
        let entries_start = pos + 8;
        if entries_start + entry_count * 2 > bytes.len() {
            break;
        }
        for i in 0..entry_count {
            let p = entries_start + i * 2;
            let entry = u16::from_le_bytes([bytes[p], bytes[p + 1]]);
            let typ = (entry >> 12) & 0xF;
            let offset = entry & 0x0FFF;
            if typ == IMAGE_REL_BASED_DIR64 {
                let rva = page_rva.wrapping_add(offset as u32);
                if rva >= text_rva && rva < text_rva.wrapping_add(text_vsize) {
                    out.push(rva);
                }
            }
        }
        pos += block_size;
        if pos >= bytes.len() {
            break;
        }
    }
    Ok(())
}

/// `IMAGE_REL_BASED_DIR64` (apply the full 64-bit base-reloc delta).
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Translate an RVA to a file offset using the section table.
fn rva_to_file_offset(bytes: &[u8], rva: u32) -> Option<usize> {
    let pe = PE::parse(bytes).ok()?;
    for s in &pe.sections {
        let va = s.virtual_address;
        let vsize = s.virtual_size.max(s.size_of_raw_data);
        if rva >= va && rva < va.wrapping_add(vsize) {
            let delta = rva - va;
            return Some((s.pointer_to_raw_data as usize) + delta as usize);
        }
    }
    None
}

/// Find a section by its 8-byte COFF name.
fn find_section<'a>(sections: &'a [SectionTable], name: &str) -> Option<&'a SectionTable> {
    sections.iter().find(|s| {
        let end = s.name.iter().position(|&b| b == 0).unwrap_or(8);
        &s.name[..end] == name.as_bytes()
    })
}

/// Zero DataDirectory[9] (TLS) in place.
///
/// The optional header is validated first; data directories start at +112 for
/// PE32+ (magic `0x20B`) and +96 for PE32 (`0x10B`). Any malformed header is
/// left untouched — the subsequent goblin parse reports it.
fn zero_tls_directory(bytes: &mut [u8]) {
    if bytes.len() < 0x40 {
        return;
    }
    let Ok(lfanew) = usize::try_from(u32::from_le_bytes(
        bytes[0x3C..0x40].try_into().unwrap(),
    )) else {
        return;
    };
    if lfanew + 4 > bytes.len() || &bytes[lfanew..lfanew + 4] != b"PE\0\0" {
        return;
    }
    let opt = lfanew + 4 + 20;
    if opt + 2 + 9 * 8 > bytes.len() {
        return;
    }
    let magic = u16::from_le_bytes(bytes[opt..opt + 2].try_into().unwrap());
    let dd_off = match magic {
        0x20B => opt + 112, // PE32+
        0x10B => opt + 96,  // PE32
        _ => return,
    };
    let tls_off = dd_off + 9 * 8;
    if tls_off + 8 <= bytes.len() {
        bytes[tls_off..tls_off + 8].fill(0);
    }
}
