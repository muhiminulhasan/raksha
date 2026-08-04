//! Vectored exception handler (VEH). Phase-2 MVP: exactly one real handler
//! (`raksha_veh`) that the host installs via `AddVectoredExceptionHandler`
//! before the first trapped `.text` page is touched.
//!
//! On a `STATUS_ACCESS_VIOLATION` the handler pulls the faulting virtual
//! address out of the exception record, hands it to [`handle_fault`], and — if
//! the fault was on a page we own — returns `EXCEPTION_CONTINUE_EXECUTION`
//! (`-1`) so the OS resumes the faulting instruction on the now-decrypted,
//! executable page. Anything we don't own falls through with
//! `EXCEPTION_CONTINUE_SEARCH` (`0`) so the next handler / the default
//! unhandled-exception filter gets it.

use crate::hot_path::{handle_fault, StubState};
use crate::resolver::ApiTable;

// Win32 exception-continuation results (windows-sys exposes these under
// `Win32::System::Diagnostics::Debug`, but they're trivial i32 constants; we
// re-declare them locally so this module is self-contained and the values are
// visible right where they're used.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// `STATUS_ACCESS_VIOLATION`. The only exception code this handler cares about.
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// # Faulting-address extraction (x64 `EXCEPTION_RECORD`)
///
/// For a `STATUS_ACCESS_VIOLATION` the OS fills `ExceptionInformation` with
/// exactly two `ULONG_PTR` values:
///   - `[0]` = the read/write flag (`0` = read, `1` = write, `8` = execute)
///   - `[1]` = the faulting virtual address
///
/// The x64 `EXCEPTION_RECORD` is `#[repr(C)]` (confirmed against the
/// `windows-sys` 0.59 definition):
///
/// ```text
///  +0x00  ExceptionCode        : u32
///  +0x04  ExceptionFlags       : u32
///  +0x08  ExceptionRecord      : *mut   (8 bytes)
///  +0x10  ExceptionAddress     : *mut   (8 bytes)
///  +0x18  NumberParameters     : u32
///  +0x1C  (4 bytes alignment padding to 8-byte align the next field)
///  +0x20  ExceptionInformation : [usize; 15]
/// ```
///
/// So `ExceptionInformation` starts at `+0x20`, and the faulting *address* —
/// `ExceptionInformation[1]` — lives at `EXCEPTION_RECORD base + 0x28`.
///
/// NB: the task brief's `veh.rs` draft reads `exc+0x10` and treats it as the
/// faulting address. That offset is actually `ExceptionAddress` (the faulting
/// *instruction* pointer), and for a missing-page access violation that is NOT
/// the page we need to decrypt — `ExceptionInformation[1]` is. We therefore
/// cast to the typed `EXCEPTION_RECORD` struct and read
/// `ExceptionInformation[1]` rather than any hardcoded offset, which is both
/// clearer and provably correct.
#[repr(C)]
#[derive(Clone, Copy)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: *mut core::ffi::c_void,
    number_parameters: u32,
    exception_information: [usize; 15],
}

/// `EXCEPTION_POINTERS`: what `AddVectoredExceptionHandler` passes us.
#[repr(C)]
#[derive(Clone, Copy)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut core::ffi::c_void,
}

// Global singletons. Set exactly once at stub entry (Task 16 builds the
// `StubState` and resolves the `ApiTable`, then calls `set_state` / `set_api`
// *before* trapping the `.text` pages and jumping to OEP — so the first fault
// finds both populated). `static mut` + `Option` is the no_std-friendly way to
// hold mutable globals without an allocator; access is confined to the VEH,
// which runs single-threaded with respect to the faulting thread.
static mut STATE: Option<StubState> = None;
static mut API: Option<ApiTable> = None;

/// Install the stub state. Must be called once, before the first fault.
///
/// # Safety
/// Mutates a `static mut`. Must not race with another writer or with a VEH
/// read on another thread — the stub guarantees single-threaded init.
pub unsafe fn set_state(s: StubState) {
    STATE = Some(s);
}

/// Install the resolved API table. Must be called once, before the first fault.
///
/// # Safety
/// Mutates a `static mut`. Must not race with another writer or with a VEH
/// read on another thread — the stub guarantees single-threaded init.
pub unsafe fn set_api(a: ApiTable) {
    API = Some(a);
}

/// The VEH entry point. Signature matches `PVECTORED_EXCEPTION_HANDLER`:
/// `extern "system" fn(*mut EXCEPTION_POINTERS) -> i32`. We take the pointer
/// as `*mut u8` and cast internally to keep the FFI boundary opaque.
///
/// Returns `EXCEPTION_CONTINUE_EXECUTION` (-1) if we decrypted the faulting
/// page, `EXCEPTION_CONTINUE_SEARCH` (0) otherwise.
#[no_mangle]
pub extern "system" fn raksha_veh(info: *mut u8) -> i32 {
    // # Safety: the OS hands us a valid `EXCEPTION_POINTERS`; we only read it.
    unsafe {
        let ep = &*(info as *const ExceptionPointers);
        let exc = match (ep.exception_record).as_ref() {
            Some(e) => e,
            None => return EXCEPTION_CONTINUE_SEARCH,
        };

        // Only act on access violations; everything else is not ours.
        if exc.exception_code != STATUS_ACCESS_VIOLATION {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // The faulting *address* is ExceptionInformation[1] (see the struct
        // doc above). [0] is the read/write/execute flag, which we don't need
        // — we decrypt the page regardless of access type.
        if exc.number_parameters < 2 {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let fault_addr = exc.exception_information[1];

        // Read the globals through raw pointers rather than forming references
        // to the `static mut`s (which would trip the `static_mut_refs` lint and,
        // under the 2024 aliasing model, be UB if another reference is live).
        // The VEH runs single-threaded with respect to the faulting thread and
        // both globals are set once before any fault can occur, so this read is
        // safe.
        let state_ptr = core::ptr::addr_of_mut!(STATE);
        let api_ptr = core::ptr::addr_of_mut!(API);
        if let (Some(state), Some(api)) = ((*state_ptr).as_mut(), (*api_ptr).as_ref()) {
            if handle_fault(state, fault_addr, api) {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        EXCEPTION_CONTINUE_SEARCH
    }
}

// ---------------------------------------------------------------------------
// Decoy VEH handlers (WS-5)
//
// The real handler is registered among `DECOY_COUNT` decoys in a randomized
// order, so an analyst breakpointing the VEH chain cannot assume the first
// (or any fixed) handler is the real one. Every decoy returns
// `EXCEPTION_CONTINUE_SEARCH`, so the chain always falls through to the real
// handler; a decoy never claims an exception it cannot service.
//
// The bodies are intentionally shaped slightly differently (different trivial
// computations on the pointer) so the decoys do not all disassemble to the
// same bytes.
// ---------------------------------------------------------------------------

/// Number of decoy handlers registered alongside the real one.
pub const DECOY_COUNT: usize = 7;

#[inline(never)]
extern "system" fn decoy_0(_ep: *mut u8) -> i32 {
    EXCEPTION_CONTINUE_SEARCH
}

#[inline(never)]
extern "system" fn decoy_1(ep: *mut u8) -> i32 {
    let _ = ep as usize;
    EXCEPTION_CONTINUE_SEARCH
}

#[inline(never)]
extern "system" fn decoy_2(ep: *mut u8) -> i32 {
    let a = ep as usize;
    let _ = a.wrapping_add(0x1234_5678);
    EXCEPTION_CONTINUE_SEARCH
}

#[inline(never)]
extern "system" fn decoy_3(ep: *mut u8) -> i32 {
    let a = ep as usize;
    let _ = a.rotate_left(13);
    EXCEPTION_CONTINUE_SEARCH
}

#[inline(never)]
extern "system" fn decoy_4(ep: *mut u8) -> i32 {
    let a = ep as usize;
    let _ = a ^ a;
    EXCEPTION_CONTINUE_SEARCH
}

#[inline(never)]
extern "system" fn decoy_5(_ep: *mut u8) -> i32 {
    let mut x: i32 = 0;
    x = x.wrapping_add(0);
    x
}

#[inline(never)]
extern "system" fn decoy_6(ep: *mut u8) -> i32 {
    let _ = (ep as usize) >> 4;
    EXCEPTION_CONTINUE_SEARCH
}

/// The decoy handler table. Index `i` maps to registration order slot `i + 1`
/// (slot 0 is the real handler).
pub static DECOY_HANDLERS: [extern "system" fn(*mut u8) -> i32; DECOY_COUNT] = [
    decoy_0, decoy_1, decoy_2, decoy_3, decoy_4, decoy_5, decoy_6,
];
