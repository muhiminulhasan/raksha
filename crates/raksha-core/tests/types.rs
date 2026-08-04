use raksha_core::types::{PageEntry, PayloadInfo};

#[test]
fn page_entry_is_10_bytes_packed() {
    // size(4) + reloc_count(2) + raw_offset(4) = 10
    assert_eq!(core::mem::size_of::<PageEntry>(), 10);
}

#[test]
fn payload_info_serializes_roundtrip() {
    let info = PayloadInfo {
        master_key: [0x42; 32],
        oep: 0x1000,
        text_rva: 0x1000,
        text_vsize: 0x2000,
        page_count: 2,
        reloc_table_offset: 0x400,
        reloc_table_size: 16,
        seed: 0xDEAD_BEEF_CAFE_BABE,
        preferred_base: 0x140000000,
    };
    let bytes = info.to_bytes();
    assert_eq!(bytes.len(), 72);
    let back = PayloadInfo::from_bytes(&bytes);
    assert_eq!(back.master_key, info.master_key);
    assert_eq!(back.oep, info.oep);
    assert_eq!(back.seed, info.seed);
    assert_eq!(back.preferred_base, info.preferred_base);
}
