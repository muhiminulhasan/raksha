//! Diagnostic: read a packed PE, decrypt page 0 with the stored master key,
//! and compare against the original (unpacked) PE's `.text` page 0.
//! Proves whether host-side encrypt/decrypt round-trips — isolating whether
//! the runtime crash is a host-side (key/storage) bug or a stub-side bug.
//!
//! Run: cargo run --release --example verify_decrypt -- <packed.exe> <orig.exe>

use std::convert::TryInto;

fn main() {
    let packed_path = std::env::args().nth(1).expect("usage: verify_decrypt <packed.exe> <orig.exe>");
    let orig_path = std::env::args().nth(2).expect("usage: verify_decrypt <packed.exe> <orig.exe>");
    let packed = std::fs::read(&packed_path).unwrap();
    let orig = std::fs::read(&orig_path).unwrap();

    // Read blob_off from Locator at 0x50.
    let blob_off = u32::from_le_bytes(packed[0x50..0x54].try_into().unwrap()) as usize;
    // master_key = blob[0..32]
    let mut mk = [0u8; 32];
    mk.copy_from_slice(&packed[blob_off..blob_off + 32]);

    // Page 0 entry at blob_off+72: [u32 size][u16 reloc_count][u32 raw_offset]
    let pe0 = blob_off + 72;
    let size = u32::from_le_bytes(packed[pe0..pe0 + 4].try_into().unwrap()) as usize;
    let raw = u32::from_le_bytes(packed[pe0 + 6..pe0 + 10].try_into().unwrap()) as usize;

    println!("blob_off=0x{:X} master_key[0..4]={:02X?}", blob_off, &mk[0..4]);
    println!("page0 size=0x{:X} raw_off=0x{:X}", size, raw);

    // Decrypt the packed page 0 ciphertext in place (xor_page is an involution).
    let mut buf = packed[raw..raw + size].to_vec();
    raksha_core::crypto::xor_page(&mk, 0, &mut buf);

    // Original .text page 0 is at the same raw offset in the ORIGINAL exe.
    let orig_page0 = &orig[raw..raw + size];

    let match_count = buf.iter().zip(orig_page0.iter()).filter(|(a, b)| a == b).count();
    println!("decrypted vs original: {}/{} bytes match", match_count, size);
    println!("decrypted[0x662 (the fault offset within page0)..+16] = {:02X?}", &buf[0x662..0x662 + 16]);
    println!("original [0x662..+16]                                  = {:02X?}", &orig_page0[0x662..0x662 + 16]);

    if buf == orig_page0 {
        println!("PASS: host-side decrypt recovers the original. Bug is in the STUB runtime.");
    } else {
        println!("FAIL: host-side decrypt does NOT match. Bug is in HOST encrypt/key storage.");
    }

    // Expected value for the probe_keyderiv stub diagnostic: the first 4 bytes
    // of derive_page_key(master_key, 0), as a u32 LE (== the stub's exit code).
    let k0 = raksha_core::crypto::derive_page_key(&mk, 0);
    let expected_code = u32::from_le_bytes([k0[0], k0[1], k0[2], k0[3]]);
    println!("EXPECTED stub probe exit code (derive_page_key(mk,0)[0..4]): 0x{:08X} (= {})", expected_code, expected_code);
}
