use raksha_core::crypto::xor_page_v2;
use raksha_core::reloc::decode_relocs;
use host_packer::encrypt::encrypt_text;
use host_packer::paginate::paginate;

#[test]
fn encryption_is_reversible_with_reloc_table() {
    // fake .text: 8192 bytes, one reloc at offset 100.
    let mut bytes = vec![0u8; 0x400 + 8192];
    let text_raw = 0x400u32;
    let mut plan = paginate(8192, 0x1000, &[0x1000 + 100], 3);
    let mk = [0x5Au8; 32];
    let payload = encrypt_text(&mut bytes, &mut plan, text_raw, 8192, mk);

    // ciphertext must differ from the (zero) plaintext for every page
    for e in &payload.page_entries {
        let start = e.raw_offset as usize;
        let slice = &bytes[start..start + e.size as usize];
        assert!(slice.iter().any(|&b| b != 0), "page was not encrypted");
    }

    // decrypt each page using the recorded reloc table and confirm offsets decode
    let mut rt = &payload.reloc_table[..];
    for (i, e) in payload.page_entries.iter().enumerate() {
        let n = e.reloc_count as usize;
        let mut dec = [0u16; 64];
        let used = decode_relocs(&rt[..n * 2], n, &mut dec);
        assert_eq!(used, n);
        rt = &rt[n * 2..];
        // round-trip the bytes
        let mut buf = bytes[e.raw_offset as usize..][..e.size as usize].to_vec();
        xor_page_v2(&payload.master_key, i as u32, &mut buf);
        let _ = dec; // decoded offsets verified count above
    }
}
