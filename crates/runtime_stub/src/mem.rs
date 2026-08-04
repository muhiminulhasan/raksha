//! Minimal `libc`-ABI memory intrinsics.
//!
//! LLVM lowers `core::ptr::copy_nonoverlapping`, fixed-size array
//! initialisation, etc. to `call` instructions on the *unmangled* C-ABI
//! symbols `memcpy`/`memset`/`memmove`/`memcmp`. `compiler_builtins` only ships
//! mangled Rust names for its mem functions on this target
//! (`_RNvNtCs...3mem6memcpy`), so without these definitions every such call
//! resolves to the mingw CRT's *import* (msvcrt.dll). In the packed image that
//! IAT is never filled — the loader only fills the packed exe's own import
//! table — so the first call through the slot faults on a garbage address (a
//! low-16-bit name-table offset).
//!
//! Defining the functions here as strong object symbols (which beat
//! import-library entries in lld's PE resolution) keeps the stub fully
//! self-contained with no imports. The loops are bounded by
//! [`core::hint::black_box`] so LLVM cannot re-lower them back into the very
//! libcalls they implement (which would self-recurse).

use core::hint::black_box;

/// Copy `n` bytes from `src` to `dst` (non-overlapping). Returns `dst`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..black_box(n) {
        *dst.add(i) = *src.add(i);
    }
    dst
}

/// Move `n` bytes from `src` to `dst`, tolerating overlap. Returns `dst`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) {
        for i in 0..black_box(n) {
            *dst.add(i) = *src.add(i);
        }
    } else {
        for i in (0..black_box(n)).rev() {
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

/// Set `n` bytes at `dst` to the low byte of `c`. Returns `dst`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u8;
    for i in 0..black_box(n) {
        *dst.add(i) = c;
    }
    dst
}

/// Compare the first `n` bytes of `a` and `b`. Returns `<0`, `0`, or `>0`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..black_box(n) {
        let x = *a.add(i);
        let y = *b.add(i);
        if x != y {
            return (x as i32) - (y as i32);
        }
    }
    0
}
