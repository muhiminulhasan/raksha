//! Simulates the stub's hot path: take plaintext page bytes, "load" them at a
//! different image base (shifting absolute reloc targets), encrypt, then
//! decrypt + re-apply relocs, and confirm the page matches what a real loader
//! would have produced at the runtime base.

use raksha_core::crypto::xor_page_v2;
use raksha_core::reloc::{decode_relocs, encode_relocs_into};

/// The IMAGE_REL_BASED_DIR64 fixup: a 64-bit VA at `offset` gets `delta` added.
fn apply_dir64(page: &mut [u8], offset: usize, delta: i64) {
    let mut v = [0u8; 8];
    v.copy_from_slice(&page[offset..offset + 8]);
    let va = u64::from_le_bytes(v);
    let fixed = (va as i64).wrapping_add(delta) as u64;
    page[offset..offset + 8].copy_from_slice(&fixed.to_le_bytes());
}

#[test]
fn reloc_survives_encrypt_decrypt_cycle() {
    let preferred_base: u64 = 0x140000000;
    let runtime_base: u64 = 0x180000000;
    let delta = runtime_base as i64 - preferred_base as i64;

    // A 64-byte "page" containing two absolute addresses referencing preferred_base.
    let mut original = vec![0u8; 64];
    let offs = [8u16, 40];
    for &o in &offs {
        original[o as usize..o as usize + 8]
            .copy_from_slice(&(preferred_base + 0x1234).to_le_bytes());
    }

    // 1. The OS loader, at runtime_base, would add `delta` to each reloc slot:
    let mut as_loaded = original.clone();
    for &o in &offs {
        apply_dir64(&mut as_loaded, o as usize, delta);
    }

    // 2. But our page is CIPHERTEXT. Encrypt the *original* (preferred-base) bytes:
    let mk = [0x5Au8; 32];
    let mut cipher = original.clone();
    xor_page_v2(&mk, 0, &mut cipher);

    // 3. Stub: decrypt in place.
    let mut page = cipher;
    xor_page_v2(&mk, 0, &mut page);

    // 4. Stub: re-apply this page's relocs using the same delta.
    let mut enc = [0u8; 16];
    let n = encode_relocs_into(&offs, &mut enc);
    let mut dec = [0u16; 2];
    decode_relocs(&enc[..n], 2, &mut dec);
    for &o in &dec {
        apply_dir64(&mut page, o as usize, delta);
    }

    // 5. Result must equal what the OS loader produced.
    assert_eq!(page, as_loaded);
}
