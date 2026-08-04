//! Runtime relocation application. Mirrors the host-side codec in
//! `raksha-core::reloc`.
//!
//! `apply_dir64` is the per-fixup primitive called by the hot path after a page
//! is decrypted: it re-applies one `IMAGE_REL_BASED_DIR64` base relocation
//! (add the runtime load-delta to a 64-bit value at a fixed within-page offset).

/// Add `delta` to the 64-bit value at `page + offset`
/// (`IMAGE_REL_BASED_DIR64`). `delta` is the signed runtime relocation delta
/// (`image_base_runtime - preferred_base`); `wrapping_add` handles both ASLR-up
/// and ASLR-down loads. Reads and writes exactly 8 bytes, little-endian.
///
/// # Safety
/// `page..page+offset+8` must be a valid, writable 8-byte-aligned region
/// (the caller has just `VirtualProtect`'d the page to `PAGE_READWRITE`).
pub unsafe fn apply_dir64(page: *mut u8, offset: usize, delta: i64) {
    let p = page.add(offset) as *mut u64;
    let v = *p as i64;
    *p = v.wrapping_add(delta) as u64;
}
