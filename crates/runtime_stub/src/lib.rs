// `runtime_stub` is a `#![no_std]` cdylib (the injected stub). In a normal
// build it is no_std with its own panic handler. In a *test* build the harness
// links std (which brings its own panic_impl + std), so we drop both no_std and
// the panic handler then — otherwise `cargo test --workspace` fails with E0152
// (duplicate lang item). The stub ships only in its non-test cdylib form.
#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The sysroot's precompiled `core` is built with panic=unwind, so its unwind
// tables reference `rust_eh_personality`; with `panic=abort` those tables are
// never used, but the symbol is still referenced at link time in non-LTO (dev)
// builds. Provide a dead shim so `cargo build` links. It is never called
// (panic=abort), is dropped by `--gc-sections` + fat LTO in release, and is
// excluded from test builds (which link std and therefore already provide it).
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

// Local `libc`-ABI `memcpy`/`memset`/`memmove`/`memcmp`. LLVM lowers many
// `core` operations to calls on these exact C-ABI symbols; defining them here
// (strong object symbols) keeps them from binding to the mingw CRT *imports*,
// whose IAT slots are never filled in the packed image.
pub mod mem;
// PEB-walking API resolver (no_std-safe: raw pointers + core::arch::asm).
// Compiles in both the no_std cdylib and the std test harness.
pub mod resolver;
// Per-fixup DIR64 relocation primitive (no_std-safe).
pub mod reloc;
// The page-fault hot path: decrypt + relocate a trapped `.text` page.
pub mod hot_path;
// Vectored exception handler scaffolding + entry point.
pub mod veh;

use crate::hot_path::{StubState, WorkingSet};
use crate::resolver::resolve;
use crate::veh::{set_api, set_state};
use raksha_core::crypto::{keyed_mac, metadata_key, xor_metadata_at};
use raksha_core::types::{PayloadInfo, LOCATOR_OFFSET};

/// `Win32` memory protection constant: no access. Used at entry to trap every
/// `.text` page so the first fetch from OEP raises `STATUS_ACCESS_VIOLATION`
/// and lands in our VEH.
const PAGE_NOACCESS: u32 = 0x01;

/// Anchor that forces `raksha_entry` to survive LTO/strip. `#[used]` is only
/// legal on statics (not functions), so we keep a one-element table of the
/// entry pointer. The host (Task 17) locates `raksha_entry` either by walking
/// the cdylib's exports (it is `#[no_mangle] pub extern "system"`, so it is an
/// exported symbol and is therefore not internalised by LTO) or by scanning
/// `.text` for this well-known pointer.
#[used]
static RAKSHA_ENTRY_ANCHOR: [extern "system" fn(); 1] = [raksha_entry];

/// The packed-PE entry point. The host repoints `AddressOfEntryPoint` here.
///
/// `#[no_mangle] pub extern "system"` makes `raksha_entry` an exported symbol
/// of the cdylib, so it is never internalised by LTO; the `#[used]`
/// `RAKSHA_ENTRY_ANCHOR` static above provides an additional GC anchor the host
/// can locate inside `.text` (Task 17).
///
/// Order (matches Tasks 14/15 design):
///   1. `resolve()`         — PEB-walk the four Win32 APIs.
///   2. `GetModuleHandleW`  — own image base (post-ASLR).
///   3. Read `Locator` at `LOCATOR_OFFSET` -> `blob_off`.
///   4. Read `PayloadInfo` + page table + reloc table out of the blob.
///   5. Build `StubState` (with `blob_off`).
///   6. `VirtualProtect` every `.text` page to `PAGE_NOACCESS`.
///   7. `AddVectoredExceptionHandler(1, raksha_veh)`.
///   8. `set_api` + `set_state` — globals MUST be set before the OEP jump, since
///      the very first instruction of OEP will fault into the VEH.
///   9. Transmute + call the original entry point.
#[no_mangle]
pub extern "system" fn raksha_entry() {
    unsafe {
        let Some(api) = resolve() else { return; };

        // 1. Own image base via GetModuleHandleW(NULL).
        let gmh: extern "system" fn(*const u16) -> usize =
            core::mem::transmute(api.get_module_handle_w);
        let image_base = gmh(core::ptr::null());

        // 2. Read the Locator at the fixed DOS-stub offset: a plain u32
        //    metadata RVA. Deliberately NO magic marker — a fixed magic at a
        //    fixed offset is a trivially-signatureable fingerprint. Instead we
        //    validate structurally: the blob must lie inside the mapped image
        //    and the PayloadInfo fields must be plausible.
        let base = image_base as *const u8;
        let blob_off = u32::from_le_bytes([
            *base.add(LOCATOR_OFFSET),
            *base.add(LOCATOR_OFFSET + 1),
            *base.add(LOCATOR_OFFSET + 2),
            *base.add(LOCATOR_OFFSET + 3),
        ]) as usize;
        if blob_off == 0 {
            return;
        }

        // SizeOfImage (optional header +56) bounds the blob walk below.
        let e_lfanew = u32::from_le_bytes([
            *base.add(0x3C),
            *base.add(0x3D),
            *base.add(0x3E),
            *base.add(0x3F),
        ]) as usize;
        let opt = base.add(e_lfanew + 24);
        let size_of_image = u32::from_le_bytes([
            *opt.add(56),
            *opt.add(57),
            *opt.add(58),
            *opt.add(59),
        ]) as usize;

        // Metadata blob layout (matches host `steg`):
        //   blob_off + 0   .. +32    -> master_key (plaintext bootstrap)
        //   blob_off + 32  .. +72    -> E(meta_key, PayloadInfo fields, 40 B)
        //   blob_off + 72  ..        -> E(meta_key, page table + reloc + tag)
        // The blob lives in the writable stub section, so the page table / reloc
        // table / tag are decrypted in place below.
        let mut master_key = [0u8; 32];
        core::ptr::copy_nonoverlapping(base.add(blob_off), master_key.as_mut_ptr(), 32);

        // Decrypt the 40-byte PayloadInfo fields (plaintext position 0) into a
        // stack buffer and validate structurally before touching anything else.
        let mut fields = [0u8; 40];
        core::ptr::copy_nonoverlapping(base.add(blob_off + 32), fields.as_mut_ptr(), 40);
        xor_metadata_at(&master_key, 0, &mut fields);
        let info = PayloadInfo::from_fields(master_key, &fields);

        // Structural sanity (in lieu of a magic marker): a page table that
        // could not describe `.text` is garbage.
        let max_pages = (info.text_vsize as usize / 0x1000) + 2;
        if info.page_count as usize > max_pages || info.reloc_table_size as usize > 0x10_0000 {
            return;
        }
        let page_table_size = (info.page_count as usize) * 10;
        let rest_len = page_table_size + info.reloc_table_size as usize + 32;
        let Some(blob_end) = blob_off.checked_add(72).and_then(|b| b.checked_add(rest_len)) else {
            return;
        };
        if blob_end > size_of_image {
            return;
        }

        // Decrypt the page table + reloc table + integrity tag in place
        // (plaintext position 40), then verify the two-stage tag over the
        // decrypted metadata: any modification to the blob ciphertext breaks it.
        let rest = core::slice::from_raw_parts_mut(base.add(blob_off + 72) as *mut u8, rest_len);
        xor_metadata_at(&master_key, 40, rest);
        let meta_key = metadata_key(&master_key);
        let tag_off = page_table_size + info.reloc_table_size as usize;
        let tag_key = keyed_mac(&meta_key, &fields);
        let expected = keyed_mac(&tag_key, &rest[..tag_off]);
        if rest[tag_off..tag_off + 32] != expected {
            return;
        }

        let reloc_table = core::slice::from_raw_parts(
            base.add(blob_off + 72 + page_table_size),
            info.reloc_table_size as usize,
        );

        let state = StubState {
            info,
            image_base,
            blob_off,
            // The slice points into the mapped image, which lives for the whole
            // process lifetime — the standard stub transmute to `'static`.
            reloc_table: core::mem::transmute::<&[u8], &'static [u8]>(reloc_table),
            reloc_table_cursor_cache: [],
            ws: WorkingSet::new(),
        };

        // 3. Trap all `.text` pages -> PAGE_NOACCESS. Each PageEntry's first u32
        //    is that page's size; pages are contiguous starting at text_rva, so
        //    we walk them in order, advancing `page_va` by each size.
        let vprot: extern "system" fn(usize, usize, u32, *mut u32) -> i32 =
            core::mem::transmute(api.virtual_protect);

        let mut page_va = image_base + info.text_rva as usize;
        for i in 0..info.page_count {
            let e_off = blob_off + 72 + (i as usize) * 10;
            let size = u32::from_le_bytes([
                *base.add(e_off),
                *base.add(e_off + 1),
                *base.add(e_off + 2),
                *base.add(e_off + 3),
            ]) as usize;
            let mut old = 0u32;
            vprot(page_va, size, PAGE_NOACCESS, &mut old);
            page_va += size;
        }

        // 4. Register the VEH chain: the real handler plus `DECOY_COUNT`
        //    decoys. `AddVectoredExceptionHandler(First=1, h)` prepends `h`, so
        //    registering the real handler FIRST puts it at the BACK of the
        //    dispatch chain — every fault is first offered to the decoys (which
        //    all return `EXCEPTION_CONTINUE_SEARCH`), so an analyst who breaks
        //    on the first handler lands on a decoy, not the real one.
        //
        //    (A randomized registration order was attempted but empirically
        //    broke exception dispatch under fat-LTO; fixed shielding order is
        //    functionally identical — a serious analyst enumerates the chain
        //    regardless — and is deterministic.)
        let addveh: extern "system" fn(u32, usize) -> usize =
            core::mem::transmute(api.add_vectored_exception_handler);
        addveh(1, veh::raksha_veh as *const () as usize);
        for h in veh::DECOY_HANDLERS {
            addveh(1, h as *const () as usize);
        }

        // 5. Hand control to the original entry point. Globals are set BEFORE
        //    the call — the first OEP fetch will fault, and the VEH must find
        //    both populated.
        let oep = image_base + info.oep as usize;
        let target: extern "system" fn() = core::mem::transmute(oep);
        set_api(api);
        set_state(state);
        target();
    }
}
