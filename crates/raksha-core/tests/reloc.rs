use raksha_core::reloc::{decode_relocs, encode_relocs_into};

#[test]
fn roundtrip_empty() {
    let mut out = [0u8; 8];
    let n = encode_relocs_into(&[], &mut out);
    assert_eq!(n, 0);
    let mut dec = [0u16; 8];
    let m = decode_relocs(&out[..n], 0, &mut dec);
    assert_eq!(m, 0);
}

#[test]
fn roundtrip_simple() {
    let offs = [100u16, 250, 800];
    let mut enc = [0u8; 16];
    let n = encode_relocs_into(&offs, &mut enc);
    assert_eq!(n, offs.len() * 2); // 3 deltas * 2 bytes
    let mut dec = [0u16; 3];
    let m = decode_relocs(&enc[..n], 3, &mut dec);
    assert_eq!(m, 3);
    assert_eq!(&dec[..3], offs.as_slice());
}

#[test]
fn roundtrip_with_large_gap() {
    // gap > 255 must be representable: use u16 deltas, not u8.
    let offs = [10u16, 5000];
    let mut enc = [0u8; 16];
    let n = encode_relocs_into(&offs, &mut enc);
    assert_eq!(n, offs.len() * 2); // 2 deltas * 2 bytes = 4
    let mut dec = [0u16; 2];
    let m = decode_relocs(&enc[..n], 2, &mut dec);
    assert_eq!(m, 2);
    assert_eq!(dec, offs);
}
