use host_packer::reconstruct::append_raksha;

#[test]
fn appends_section_and_sets_ep() {
    let mut pe = vec![0u8; 0x400];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF: NumberOfSections=0 at 0x86, SizeOfOptionalHeader at 0x94, optional hdr after.
    // Section table starts right after optional header. For the test we place a
    // fake optional header of 240 bytes and a section table with room for 2 entries.
    let nt_off = 0x80usize;
    let opt_size = 240u16;
    pe[nt_off + 6..nt_off + 8].copy_from_slice(&1u16.to_le_bytes()); // existing sections
    pe[nt_off + 20..nt_off + 22].copy_from_slice(&opt_size.to_le_bytes());
    let sect_off = nt_off + 24 + opt_size as usize;

    let stub = [0x90u8; 64]; // nops
    let name = *b"k9x2ab\0\0";
    let ep = append_raksha(&mut pe, &stub, 0, &name).unwrap();
    assert!(ep > 0);
    // A new section header was written at sect_off + 40.
    let name_field = &pe[sect_off + 40..sect_off + 48];
    assert_eq!(name_field, &name);
    // Raw stub bytes appended at the section's PointerToRawData (old EOF).
    // The file is then padded up to FILE_ALIGNMENT, so the stub lives at the
    // recorded raw pointer rather than the very last bytes of the file.
    let raw_ptr = u32::from_le_bytes(pe[sect_off + 60..sect_off + 64].try_into().unwrap()) as usize;
    assert_eq!(&pe[raw_ptr..raw_ptr + 64], &stub[..]);
}
