//! The page-fault hot path: given a faulting address inside the trapped `.text`
//! range, locate its page, decrypt it in place, re-apply that page's base
//! relocations using the runtime load-delta, and flip it back to executable —
//! then return `true` so the VEH resumes the faulting instruction.
//!
//! Every STATUS_ACCESS_VIOLATION on a trapped `.text` page flows through here,
//! so this is the most performance/correctness-critical code in the stub. The
//! logic is verified by inspection + the host-side simulation in
//! `raksha-core/tests/sim_roundtrip.rs`; the live faulting-process test is
//! Task 18.
//!
//! Page-table layout (matches `host_packer::steg`): after the stub decrypts the
//! encrypted metadata blob in place, the page table is
//!   `[PayloadInfo fields (40 B)] [PageEntry table (N*10 bytes)] [reloc table]`
//! and each `PageEntry` is `[u32 size][u16 reloc_count][u32 raw_offset]`
//! (`#[repr(C, packed)]`, 10 bytes). The page table therefore lives at
//! `state.blob_off + 72`; entry `i` is read at `state.blob_off + 72 + i*10`.
//!
//! Two hardening layers live here (WS-4/WS-1):
//!   - Once the page containing the original entry point is decrypted, the
//!     DOS-stub locator is zeroed so a live-memory scan no longer finds it.
//!   - Decrypted pages are tracked in a bounded LRU working set; when the set
//!     is full the least-recently-used page is re-encrypted and re-trapped, so
//!     a single memory dump does not capture the whole image.

use crate::reloc::apply_dir64;
use crate::resolver::ApiTable;
use raksha_core::crypto::xor_page_v2;
use raksha_core::reloc::decode_relocs;
use raksha_core::types::{PayloadInfo, LOCATOR_OFFSET};

/// `Win32` memory protection constant: no access (trap).
const PAGE_NOACCESS: u32 = 0x01;
/// `Win32` memory protection constant: read/write.
const PAGE_READWRITE: u32 = 0x04;
/// `Win32` memory protection constant: execute/read.
const PAGE_EXECUTE_READ: u32 = 0x20;

/// Maximum number of simultaneously-decrypted pages (WS-1). 64 pages ≈ 256 KiB
/// of live plaintext; once this is exceeded the LRU victim is re-encrypted.
pub const WS_CAP: usize = 64;

/// Whether the working-set LRU *eviction* (re-encrypt + re-trap the LRU page)
/// is enabled.
///
/// Default OFF: re-encrypting a page that another thread is executing from
/// races with that thread's instruction fetches (a torn page executes as an
/// illegal instruction). The GUI fixture (8 threads) demonstrated this
/// instability. Re-encryption is only safe when the process is effectively
/// single-threaded during page decryption; enable for such targets. The
/// `WorkingSet` tracking still runs either way (it is the state a future,
/// serialized eviction would use).
pub const WS_EVICT: bool = false;

/// Empty-slot sentinel for [`WorkingSet::pages`].
const WS_EMPTY: u32 = u32::MAX;

/// Bounded LRU working set of decrypted pages (WS-1).
///
/// A fixed-size array of page indices plus a monotonic "last use" counter per
/// slot. `touch(page_index)` records the use and, when the set is full, returns
/// the page index to evict (the least-recently-used slot — never the page just
/// touched, which is by construction the most recent). All fields are plain
/// integers so the struct is `Copy`-able by hand like the rest of `StubState`.
pub struct WorkingSet {
    pages: [u32; WS_CAP],
    last_use: [u32; WS_CAP],
    counter: u32,
}

impl WorkingSet {
    /// Empty working set.
    pub const fn new() -> Self {
        Self {
            pages: [WS_EMPTY; WS_CAP],
            last_use: [0; WS_CAP],
            counter: 0,
        }
    }

    /// Record use of `page_index`. Returns `Some(victim)` if the set was full
    /// and a page must be evicted to make room.
    pub fn touch(&mut self, page_index: u32) -> Option<u32> {
        self.counter = self.counter.wrapping_add(1);
        let mut lru = u32::MAX;
        let mut lru_slot = 0usize;
        let mut empty = None;
        let mut found = false;
        for s in 0..WS_CAP {
            if self.pages[s] == page_index {
                self.last_use[s] = self.counter;
                found = true;
                break;
            }
            if self.pages[s] == WS_EMPTY && empty.is_none() {
                empty = Some(s);
            }
            if self.last_use[s] < lru {
                lru = self.last_use[s];
                lru_slot = s;
            }
        }
        if found {
            return None;
        }
        if let Some(slot) = empty {
            self.pages[slot] = page_index;
            self.last_use[slot] = self.counter;
            return None;
        }
        // Full: evict the least-recently-used slot (never the page just
        // touched — it is now the most recent and is not yet inserted).
        let victim = self.pages[lru_slot];
        self.pages[lru_slot] = page_index;
        self.last_use[lru_slot] = self.counter;
        Some(victim)
    }
}

/// Immutable stub state, constructed once at entry (Task 16) before any fault
/// can occur. All fields are plain integers / references / fixed arrays so the
/// struct is `Copy`-able by hand and safe to hold behind a `static mut` in
/// `veh.rs`.
pub struct StubState {
    pub info: PayloadInfo,
    /// Actual runtime load address of the image (post-ASLR).
    pub image_base: usize,
    /// File offset of the metadata blob inside the image. At load time the
    /// image is mapped such that file offset == RVA relative to `image_base`,
    /// so `image_base + blob_off` addresses the blob in memory.
    pub blob_off: usize,
    /// The delta-encoded per-page relocation table, viewed as a flat byte
    /// slice that points directly into the mapped image. Set at entry.
    pub reloc_table: &'static [u8],
    /// Placeholder for a future cursor cache (Phase 3 optimisation). A
    /// zero-length array is a no-op ZST today; left in to keep the struct
    /// shape stable across tasks.
    pub reloc_table_cursor_cache: [usize; 0],
    /// Bounded LRU working set of decrypted pages (WS-1).
    pub ws: WorkingSet,
}

/// Handle one access violation. Returns `true` iff the fault was on a trapped
/// `.text` page and the page has been decrypted + relocated + re-protected to
/// `PAGE_EXECUTE_READ` (so the VEH should `EXCEPTION_CONTINUE_EXECUTION`).
///
/// # Safety
/// Reads/writes raw memory inside the live image and calls `VirtualProtect`.
/// `state` and `api` must point at valid, fully-initialised structures (set by
/// `veh::set_state` / `veh::set_api` before the first fault).
#[allow(clippy::too_many_lines)]
pub unsafe fn handle_fault(state: &mut StubState, fault_addr: usize, api: &ApiTable) -> bool {
    // `PayloadInfo` is `Copy`; take a copy so we can mutate `state.ws` below
    // without a lingering borrow.
    let info = state.info;

    // 1. Is the fault inside the trapped `.text` range? Half-open [start, end).
    let text_start = state.image_base + info.text_rva as usize;
    let text_end = text_start + info.text_vsize as usize;
    if !(fault_addr >= text_start && fault_addr < text_end) {
        return false;
    }

    // `VirtualProtect(lpaddr, dwsize, new, *old)`. Stored in the API table as
    // a raw `usize` function pointer (resolved by PEB-walking); transmute to
    // its real signature to call it.
    let vprot: extern "system" fn(usize, usize, u32, *mut u32) -> i32 =
        core::mem::transmute(api.virtual_protect);

    // 2. Walk the page table to find the page containing fault_addr. The
    //    table is small (page_count is bounded by text_vsize / page_size), so
    //    a linear scan is fine; a binary search / cached cursor is a Phase-3
    //    optimisation. `cursor` tracks the byte offset into the shared reloc
    //    table where this page's `reloc_count` deltas begin (each delta is a
    //    u16, so each page contributes `reloc_count * 2` bytes).
    let base = state.image_base as *const u8;
    let mut cursor = 0usize;
    let mut page_base = text_start;
    for i in 0..info.page_count {
        // Read PageEntry i from the blob. Layout: [u32 size][u16 reloc_count]
        // at blob_off + 72 + i*10. Copy into fixed arrays then decode LE —
        // avoids the fragile `slice.try_into().unwrap_unchecked()` form.
        let e_off = state.blob_off + 72 + (i as usize) * 10;
        let mut sz = [0u8; 4];
        core::ptr::copy_nonoverlapping(base.add(e_off), sz.as_mut_ptr(), 4);
        let size = u32::from_le_bytes(sz) as usize;

        let mut rc_b = [0u8; 2];
        core::ptr::copy_nonoverlapping(base.add(e_off + 4), rc_b.as_mut_ptr(), 2);
        let rc = u16::from_le_bytes(rc_b) as usize;

        if fault_addr >= page_base && fault_addr < page_base + size {
            // --- Found the faulting page. Decrypt + relocate in place. ---

            // (a) -> PAGE_READWRITE so we can write plaintext.
            let mut old = 0u32;
            if vprot(page_base, size, PAGE_READWRITE, &mut old) == 0 {
                return false;
            }

            // (b) Decrypt in place. xor_page_v2 is its own inverse (ChaCha20
            //     keystream XOR), so this both encrypts and decrypts.
            xor_page_v2(
                &info.master_key,
                i,
                core::slice::from_raw_parts_mut(page_base as *mut u8, size),
            );

            // (c) Re-apply this page's base relocations using the *signed*
            //     runtime delta. ASLR can load the image above OR below the
            //     preferred base, so the delta must be signed.
            let delta = state.image_base as i64 - info.preferred_base as i64;

            // Decode this page's `rc` deltas into absolute within-page u16
            // offsets. 256 is a generous upper bound on fixups per page (a
            // page holds at most page_size/8 absolute pointers).
            let mut offs = [0u16; 256];
            if rc > offs.len() {
                // Defensive: should never happen for sane pages. Bail without
                // re-protecting so the process faults loudly rather than
                // corrupting the stack.
                return false;
            }
            let n = decode_relocs(&state.reloc_table[cursor..], rc, &mut offs);
            for k in 0..n {
                apply_dir64(page_base as *mut u8, offs[k] as usize, delta);
            }

            // (d) -> PAGE_EXECUTE_READ and resume.
            let mut old2 = 0u32;
            vprot(page_base, size, PAGE_EXECUTE_READ, &mut old2);

            // (e) Working-set cap (WS-1): record this page; if the set is full
            //     AND eviction is enabled, re-encrypt + re-trap the
            //     least-recently-used page so a memory dump cannot capture the
            //     whole image at once. (Eviction is off by default: see
            //     `WS_EVICT` for the multi-thread race rationale.)
            if let Some(victim) = state.ws.touch(i) {
                if WS_EVICT {
                    re_encrypt_page(state, vprot, victim);
                }
            }

            // (f) Post-OEP cleanup (WS-4): once the page containing the
            //     original entry point has been decrypted, zero the DOS-stub
            //     locator so a live-memory scan no longer finds the metadata
            //     pointer. Best-effort.
            let oep_addr = state.image_base + info.oep as usize;
            if oep_addr >= page_base && oep_addr < page_base + size {
                cleanup_locator(state, vprot);
            }

            return true;
        }

        cursor += rc * 2;
        page_base += size;
    }

    false
}

/// Re-encrypt the given (previously-decrypted) page and re-trap it with
/// `PAGE_NOACCESS`. `xor_page_v2` is an involution, so the page returns to its
/// original on-disk ciphertext and decrypts correctly on the next fault.
///
/// Only safe when the process is effectively single-threaded during decryption
/// (see `WS_EVICT`); currently dead code with `WS_EVICT = false`.
///
/// # Safety
/// `state`/`api` must be valid; the page must currently be decrypted. A page
/// being executed by another thread would fault again on its next fetch and be
/// re-decrypted by the VEH — the standard trap/resume model, so this is safe.
#[allow(dead_code)]
unsafe fn re_encrypt_page(
    state: &mut StubState,
    vprot: extern "system" fn(usize, usize, u32, *mut u32) -> i32,
    page_index: u32,
) {
    let info = state.info;
    let base = state.image_base as *const u8;
    let mut page_base = state.image_base + info.text_rva as usize;
    let e_off = state.blob_off + 72 + (page_index as usize) * 10;
    let mut sz = [0u8; 4];
    core::ptr::copy_nonoverlapping(base.add(e_off), sz.as_mut_ptr(), 4);
    let size = u32::from_le_bytes(sz) as usize;
    // Walk to the victim's base (linear, bounded by page_count).
    for j in 0..(page_index as usize) {
        let o = state.blob_off + 72 + j * 10;
        let mut s = [0u8; 4];
        core::ptr::copy_nonoverlapping(base.add(o), s.as_mut_ptr(), 4);
        page_base += u32::from_le_bytes(s) as usize;
    }

    let mut old = 0u32;
    if vprot(page_base, size, PAGE_READWRITE, &mut old) == 0 {
        return;
    }
    xor_page_v2(
        &info.master_key,
        page_index,
        core::slice::from_raw_parts_mut(page_base as *mut u8, size),
    );
    let mut old2 = 0u32;
    vprot(page_base, size, PAGE_NOACCESS, &mut old2);
}

/// Best-effort WS-4 cleanup: zero the 4-byte metadata locator in the DOS stub.
/// The header page is typically mapped read-only, so make it writable, zero the
/// locator, and restore the original protection. Never called again after this
/// point, so any failure is silent.
///
/// # Safety
/// `state` must be valid; `LOCATOR_OFFSET` lies within the mapped image.
#[cold]
unsafe fn cleanup_locator(
    state: &StubState,
    vprot: extern "system" fn(usize, usize, u32, *mut u32) -> i32,
) {
    let header_page = state.image_base & !0xFFF;
    let mut old = 0u32;
    if vprot(header_page, 0x1000, PAGE_READWRITE, &mut old) != 0 {
        let loc = (state.image_base as *mut u8).add(LOCATOR_OFFSET) as *mut u32;
        core::ptr::write_volatile(loc, 0u32);
        let mut old2 = 0u32;
        vprot(header_page, 0x1000, old, &mut old2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_evicts_least_recently_used_when_full() {
        let mut ws = WorkingSet::new();
        // Fill the set with distinct pages 0..WS_CAP.
        let mut evicted = Vec::new();
        for p in 0..(WS_CAP as u32) {
            if let Some(v) = ws.touch(p) {
                evicted.push(v);
            }
        }
        assert!(evicted.is_empty(), "set should accept WS_CAP pages");
        // The next distinct touch must evict page 0 (the oldest).
        assert_eq!(ws.touch(WS_CAP as u32), Some(0));
        // Re-touching a page already resident must not evict anything.
        assert_eq!(ws.touch(5), None);
        // The evicted victim is the LRU: page 1 is now the oldest.
        assert_eq!(ws.touch((WS_CAP + 1) as u32), Some(1));
    }

    #[test]
    fn ws_touching_resident_page_updates_recency() {
        let mut ws = WorkingSet::new();
        for p in 0..(WS_CAP as u32) {
            ws.touch(p);
        }
        // Make page 0 the most recent, then fill one more: page 1 must go.
        ws.touch(0);
        assert_eq!(ws.touch(WS_CAP as u32), Some(1));
    }
}
