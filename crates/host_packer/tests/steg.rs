use raksha_core::types::{PageEntry, PayloadInfo, LOCATOR_OFFSET};
use host_packer::steg::{defragment_from, fragment_into};

/// Minimal fake PE: e_lfanew = 0x80, one section (.text at RVA 0x1000, raw at
/// file 0x400), opt_size = 240 (PE32+).
fn minimal_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 0x800];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    let nt = 0x80usize;
    pe[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes());        // NumberOfSections = 1
    pe[nt + 20..nt + 22].copy_from_slice(&240u16.to_le_bytes());    // SizeOfOptionalHeader
    let sh = nt + 24 + 240;
    pe[sh..sh + 8].copy_from_slice(b".text\0\0\0");
    pe[sh + 8..sh + 12].copy_from_slice(&0x400u32.to_le_bytes());   // VirtualSize
    pe[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    pe[sh + 16..sh + 20].copy_from_slice(&0x400u32.to_le_bytes());  // SizeOfRawData
    pe[sh + 20..sh + 24].copy_from_slice(&0x400u32.to_le_bytes());  // PointerToRawData
    pe
}

#[test]
fn roundtrip_fragments_encrypted_in_last_section() {
    let mut pe = minimal_pe();

    let info = PayloadInfo {
        master_key: [0x11u8; 32], oep: 0x1234, text_rva: 0x1000,
        text_vsize: 0x3000, page_count: 2, reloc_table_offset: 0x300,
        reloc_table_size: 4, seed: 0xCAFEBABE, preferred_base: 0x140000000,
    };
    let reloc = vec![1u8, 2, 3, 4];
    let entries = vec![PageEntry { size: 4096, reloc_count: 1, raw_offset: 0x200 },
                      PageEntry { size: 4096, reloc_count: 1, raw_offset: 0x1200 }];

    fragment_into(&mut pe, &info, &reloc, &entries).unwrap();

    // Locator holds the blob's RVA (inside the section, not the header gap).
    let blob_rva = u32::from_le_bytes(
        pe[LOCATOR_OFFSET..LOCATOR_OFFSET + 4].try_into().unwrap(),
    ) as usize;
    assert!(blob_rva >= 0x1000, "blob RVA {blob_rva:#x} not inside the section");

    // The single section has va=0x1000, raw at 0x400, size 0x400, so the blob
    // file offset = 0x800 (raw + rawsize).
    let blob_off = 0x800usize;
    // Master key is the plaintext bootstrap at blob start.
    assert_eq!(&pe[blob_off..blob_off + 32], &info.master_key);
    // The page-table region (file 0x800+72 .. +92) must NOT be the plaintext
    // page entries (it is encrypted).
    let pt_plain: Vec<u8> = entries
        .iter()
        .flat_map(|e| {
            let mut b = Vec::new();
            b.extend_from_slice(&e.size.to_le_bytes());
            b.extend_from_slice(&e.reloc_count.to_le_bytes());
            b.extend_from_slice(&e.raw_offset.to_le_bytes());
            b
        })
        .collect();
    assert_ne!(&pe[blob_off + 72..blob_off + 72 + pt_plain.len()], &pt_plain[..]);

    let (info2, reloc2, entries2) = defragment_from(&pe).unwrap();
    assert_eq!(info2.master_key, info.master_key);
    assert_eq!(info2.oep, info.oep);
    assert_eq!(info2.preferred_base, info.preferred_base);
    assert_eq!(reloc2, reloc);
    assert_eq!(entries2, entries);
}

#[test]
fn tampering_with_metadata_is_detected() {
    let mut pe = minimal_pe();

    let info = PayloadInfo {
        master_key: [0x33u8; 32], oep: 0x1234, text_rva: 0x1000,
        text_vsize: 0x3000, page_count: 2, reloc_table_offset: 0x300,
        reloc_table_size: 4, seed: 0xCAFEBABE, preferred_base: 0x140000000,
    };
    let reloc = vec![1u8, 2, 3, 4];
    let entries = vec![PageEntry { size: 4096, reloc_count: 1, raw_offset: 0x200 },
                      PageEntry { size: 4096, reloc_count: 1, raw_offset: 0x1200 }];
    fragment_into(&mut pe, &info, &reloc, &entries).unwrap();

    // Flip one byte inside the encrypted page-table region: the integrity tag
    // must fail.
    let blob_off = 0x800usize;
    pe[blob_off + 72 + 3] ^= 0xFF;

    assert!(defragment_from(&pe).is_err(), "tampered blob must be rejected");
}

#[test]
fn large_blob_appends_into_last_section() {
    // A 200-page blob (32 + 40 + 200*10 + 2000 + 32 = 4104 bytes) is appended
    // inside the last section, and the Locator stores its RVA (not file offset).
    let mut pe = minimal_pe();

    let info = PayloadInfo {
        master_key: [0x22u8; 32], oep: 0x5678, text_rva: 0x1000,
        text_vsize: 0x30000, page_count: 200, reloc_table_offset: 0x300,
        reloc_table_size: 2000, seed: 0xDEADBEEF, preferred_base: 0x140000000,
    };
    let reloc: Vec<u8> = (0..2000).map(|i| (i % 251) as u8).collect();
    let entries: Vec<PageEntry> = (0..200)
        .map(|i| PageEntry { size: 0x1000, reloc_count: 0, raw_offset: i * 0x1000 })
        .collect();

    fragment_into(&mut pe, &info, &reloc, &entries).unwrap();

    let blob_rva = u32::from_le_bytes(
        pe[LOCATOR_OFFSET..LOCATOR_OFFSET + 4].try_into().unwrap(),
    ) as usize;
    // Must be inside the (single) section, i.e. beyond the first section RVA.
    assert!(blob_rva >= 0x1000, "blob RVA {blob_rva:#x} not inside the section");

    let (info2, reloc2, entries2) = defragment_from(&pe).unwrap();
    assert_eq!(info2, info);
    assert_eq!(reloc2, reloc);
    assert_eq!(entries2, entries);
}
