//! PEB-walking API resolver. Resolves the handful of Win32 functions the stub
//! needs, without the stub importing anything (no IAT for `.raksha`).
//!
//! Technique: PEB (`gs:[0x60]`) -> `Ldr.InLoadOrderModuleList` -> walk modules,
//! match `kernel32.dll`/`ntdll.dll` by a rolling djb2 hash of the (uppercased)
//! UTF-16 basename, then walk each module's export table matching function
//! names by the same hash.
//!
//! This is classic "shellcode" API resolution. The stub compiles as a `cdylib`
//! with no IAT, so the `.raksha` section stays self-contained and stealthy.
//!
//! All offsets are the canonical Windows x64 values. `resolve()` reads live
//! process state and therefore cannot be meaningfully unit-tested — only
//! `hash_str` (a pure function) is tested here. The real end-to-end check is
//! Task 18 (running the packed PE).
//!
//! # Canonical x64 offsets used
//!
//! - PEB pointer: `gs:[0x60]`
//! - `PEB.Ldr`: PEB + 0x18
//! - `PEB_LDR_DATA.InLoadOrderModuleList`: Ldr + 0x10 (LIST_ENTRY; the flink
//!   at +0 points at the first `LdrDataTableEntry.InLoadOrderLinks`, i.e. at
//!   the start of the entry — so all entry offsets below are relative to the
//!   flink pointer itself).
//! - `LdrDataTableEntry.DllBase`: entry + 0x30
//! - `LdrDataTableEntry.BaseDllName` (UNICODE_STRING): `Length` at entry + 0x58,
//!   `Buffer` (pointer to UTF-16) at entry + 0x60.
//! - PE export table walk: DOS `e_lfanew` at DllBase + 0x3C; NT signature at
//!   DllBase + e_lfanew; optional header at DllBase + e_lfanew + 24; export
//!   directory RVA at optional_header + 0x70 (112, `DataDirectory[0]`);
//!   `NumberOfNames` at export_dir + 0x18 (24); `AddressOfFunctions` at +0x1C
//!   (28); `AddressOfNames` at +0x20 (32); `AddressOfNameOrdinals` at +0x24
//!   (36). Function address = DllBase + `AddressOfFunctions[ordinal[i]]`.

// djb2 string hash over a byte slice. Stable, cheap, good enough for short
// API names. Uppercases ASCII so callers can pass any-case strings and still
// hit the same const. `const` so the precomputed name hashes below evaluate at
// compile time.
pub const fn hash_str(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let up = if c >= b'a' && c <= b'z' { c - 32 } else { c }; // ASCII upper
        h = h.wrapping_mul(33).wrapping_add(up as u32);
        i += 1;
    }
    h
}

#[derive(Default, Clone, Copy)]
pub struct ApiTable {
    pub virtual_protect: usize,
    pub add_vectored_exception_handler: usize,
    pub get_module_handle_w: usize,
    pub rtl_exit_user_process: usize,
}

// Precomputed name hashes. Kept as `const`s so they're evaluated at compile
// time and the only thing visible in the binary is opaque integers (no string
// references to "VirtualProtect" etc.).
const H_KERNEL32_DLL: u32 = hash_str(b"kernel32.dll");
const H_NTDLL_DLL: u32 = hash_str(b"ntdll.dll");
// KERNELBASE: modern Windows forwards many kernel32 exports (VirtualProtect,
// GetModuleHandleW, AddVectoredExceptionHandler) here as the real
// implementations. We resolve its exports too so forwarded APIs land on code,
// not on forwarder strings.
const H_KERNELBASE_DLL: u32 = hash_str(b"kernelbase.dll");
const H_VIRTUALPROTECT: u32 = hash_str(b"VirtualProtect");
const H_ADDVECTOREDEXCEPTIONHANDLER: u32 = hash_str(b"AddVectoredExceptionHandler");
const H_GETMODULEHANDLEW: u32 = hash_str(b"GetModuleHandleW");
const H_RTL_EXIT_USER_PROCESS: u32 = hash_str(b"RtlExitUserProcess");
// On modern Windows `AddVectoredExceptionHandler` is a *forwarder* in both
// kernel32 and KernelBase to `NTDLL.RtlAddVectoredExceptionHandler`. The
// forwarder-skip logic in `resolve_exports` skips those stub entries, so the
// real implementation must be found by walking ntdll under its own name.
const H_RTL_ADDVECTOREDEXCEPTIONHANDLER: u32 = hash_str(b"RtlAddVectoredExceptionHandler");

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

/// Resolve the API set. `unsafe` — touches raw process memory. Returns
/// `Some(tbl)` only if **all four** APIs were resolved, otherwise `None`.
pub unsafe fn resolve() -> Option<ApiTable> {
    // PEB at gs:[0x60]; Ldr at PEB + 0x18; InLoadOrderModuleList at Ldr + 0x10.
    let peb: *mut u8;
    core::arch::asm!(
        "mov {peb}, gs:[0x60]",
        peb = out(reg) peb,
        options(nostack, nomem, preserves_flags),
    );
    if peb.is_null() {
        return None;
    }
    let ldr = *(peb.add(0x18) as *mut *mut u8);
    if ldr.is_null() {
        return None;
    }
    // The list head: a LIST_ENTRY embedded in PEB_LDR_DATA at +0x10. `flink`
    // from the head points at the first entry's InLoadOrderLinks — i.e. at the
    // start of the LdrDataTableEntry.
    let head = (ldr.add(0x10)) as *const ListEntry;

    let mut tbl = ApiTable::default();
    let mut cur = (*head).flink;
    while !cur.is_null() && cur != (head as *mut _) {
        // DllBase at entry + 0x30; BaseDllName.Length at entry + 0x58 (u16,
        // bytes), BaseDllName.Buffer at entry + 0x60 (pointer to UTF-16).
        let dll_base = *((cur as *const u8).add(0x30) as *const *mut u8);
        let name_len = *((cur as *const u8).add(0x58) as *const u16) as usize;
        let name_buf = *((cur as *const u8).add(0x60) as *const *const u16);

        if !dll_base.is_null() && !name_buf.is_null() && name_len >= 2 {
            // Hash the UTF-16 basename. We only read the low byte of each u16
            // (ASCII assumption), which is correct for kernel32.dll/ntdll.dll.
            let chars = name_len / 2; // Length is in bytes
            let mut h: u32 = 5381;
            for i in 0..chars {
                let c = *name_buf.add(i) as u8; // ASCII path
                let up = if c >= b'a' && c <= b'z' { c - 32 } else { c };
                h = h.wrapping_mul(33).wrapping_add(up as u32);
            }
            if h == H_KERNEL32_DLL || h == H_NTDLL_DLL || h == H_KERNELBASE_DLL {
                resolve_exports(dll_base, &mut tbl);
            }
        }
        cur = (*cur).flink;
    }

    if tbl.virtual_protect != 0
        && tbl.add_vectored_exception_handler != 0
        && tbl.get_module_handle_w != 0
        && tbl.rtl_exit_user_process != 0
    {
        Some(tbl)
    } else {
        None
    }
}

/// Walk one module's export name table, hashing each name and recording the
/// addresses of the four APIs we care about. Bails harmlessly on a bad MZ/PE
/// signature or a missing export directory.
unsafe fn resolve_exports(dll_base: *mut u8, tbl: &mut ApiTable) {
    let dos = dll_base as *const u8;
    if *dos != b'M' || *dos.add(1) != b'Z' {
        return;
    }
    let e_lfanew = *(dos.add(0x3C) as *const i32) as isize;
    if e_lfanew <= 0 {
        return;
    }
    let nt = dos.offset(e_lfanew);
    // "PE\0\0"
    if *nt != b'P' || *nt.add(1) != b'E' {
        return;
    }
    let opt = nt.add(24);
    let export_rva = *(opt.add(0x70) as *const u32) as usize; // DataDirectory[0].VirtualAddress
    if export_rva == 0 {
        return;
    }
    // The export directory SIZE lives in the optional header's DataDirectory[0]
    // (NOT in the export-dir struct — that has no size field). Needed for
    // forwarded-export detection: a forwarder's RVA points INSIDE
    // [export_rva, export_rva+size] at a "DLL.func" string, not at code.
    let export_dir_size = *(opt.add(0x74) as *const u32) as usize; // DataDirectory[0].Size
    let export_dir = dll_base.add(export_rva);
    let count = *(export_dir.add(0x18) as *const u32) as usize; // NumberOfNames
    let funcs_rva = *(export_dir.add(0x1C) as *const u32) as usize; // AddressOfFunctions
    let names_rva = *(export_dir.add(0x20) as *const u32) as usize; // AddressOfNames
    let ords_rva = *(export_dir.add(0x24) as *const u32) as usize; // AddressOfNameOrdinals
    if count == 0 || funcs_rva == 0 || names_rva == 0 || ords_rva == 0 {
        return;
    }
    // AddressOfNames is an array of 32-bit NAME RVAs (NOT pointers). Each entry
    // is a u32 RVA into the module; the actual name string is at
    // dll_base + rva. Reading as `*const *const u8` (8-byte pointers) would
    // concatenate two adjacent u32 RVAs into one garbage 64-bit value — a real
    // bug that faulted the resolver. Index by u32 and resolve to a pointer.
    let names = dll_base.add(names_rva) as *const u32;
    let ords = dll_base.add(ords_rva) as *const u16;
    let funcs = dll_base.add(funcs_rva) as *const u32;

    for i in 0..count {
        let name_rva = *names.add(i) as usize;
        if name_rva == 0 {
            continue;
        }
        let name = dll_base.add(name_rva) as *const u8;
        // Hash the C-string export name, uppercase ASCII.
        let mut h: u32 = 5381;
        let mut p = name;
        while *p != 0 {
            let c = *p;
            let up = if c >= b'a' && c <= b'z' { c - 32 } else { c };
            h = h.wrapping_mul(33).wrapping_add(up as u32);
            p = p.add(1);
        }
        let ord = *ords.add(i) as usize;
        let fn_rva = *funcs.add(ord) as usize;
        // Forwarded-export detection: a forwarded export's RVA points INSIDE
        // the export directory (export_rva..export_rva+export_size) at a string
        // like "NTDLL.RtlExitUserProcess", not at code. Calling such an address
        // jumps into the export-dir/IAT region and faults. Skip forwarders — the
        // real implementation lives in the module named by the forwarder string
        // (e.g. kernel32 forwards to KernelBase/ntdll), which we resolve when we
        // walk THAT module's exports.
        if fn_rva >= export_rva && fn_rva < export_rva + export_dir_size {
            continue;
        }
        let addr = dll_base.add(fn_rva);
        match h {
            H_VIRTUALPROTECT => tbl.virtual_protect = addr as usize,
            H_ADDVECTOREDEXCEPTIONHANDLER => tbl.add_vectored_exception_handler = addr as usize,
            H_RTL_ADDVECTOREDEXCEPTIONHANDLER => tbl.add_vectored_exception_handler = addr as usize,
            H_GETMODULEHANDLEW => tbl.get_module_handle_w = addr as usize,
            H_RTL_EXIT_USER_PROCESS => tbl.rtl_exit_user_process = addr as usize,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground-truth djb2 values, computed independently of this file's consts
    // (so this is a real check, not a tautology). Constants:
    //   hash_str(b"kernel32.dll")                  = 0x6DDB9555 (1843107157)
    //   hash_str(b"ntdll.dll")                     = 0x1EDAB0ED ( 517648621)
    //   hash_str(b"VirtualProtect")                = 0xE857500D (3898036237)
    //   hash_str(b"AddVectoredExceptionHandler")   = 0x277409F7 ( 661916151)
    //   hash_str(b"GetModuleHandleW")              = 0xD908E1EE (3641237998)
    //   hash_str(b"RtlExitUserProcess")            = 0x0057C72F (   5752623)
    #[test]
    fn hash_str_matches_ground_truth_literals() {
        assert_eq!(hash_str(b"kernel32.dll"), 0x6DDB9555);
        assert_eq!(hash_str(b"ntdll.dll"), 0x1EDAB0ED);
        assert_eq!(hash_str(b"VirtualProtect"), 0xE857500D);
        assert_eq!(hash_str(b"AddVectoredExceptionHandler"), 0x277409F7);
        assert_eq!(hash_str(b"GetModuleHandleW"), 0xD908E1EE);
        assert_eq!(hash_str(b"RtlExitUserProcess"), 0x0057C72F);
        assert_eq!(hash_str(b"RtlAddVectoredExceptionHandler"), 0x2DF06C89);
    }

    // And the consts must agree with the runtime function — guards against an
    // accidental future edit to one without the other.
    #[test]
    fn consts_match_runtime_function() {
        assert_eq!(H_KERNEL32_DLL, hash_str(b"kernel32.dll"));
        assert_eq!(H_NTDLL_DLL, hash_str(b"ntdll.dll"));
        assert_eq!(H_VIRTUALPROTECT, hash_str(b"VirtualProtect"));
        assert_eq!(H_ADDVECTOREDEXCEPTIONHANDLER, hash_str(b"AddVectoredExceptionHandler"));
        assert_eq!(H_GETMODULEHANDLEW, hash_str(b"GetModuleHandleW"));
        assert_eq!(H_RTL_EXIT_USER_PROCESS, hash_str(b"RtlExitUserProcess"));
        assert_eq!(
            H_RTL_ADDVECTOREDEXCEPTIONHANDLER,
            hash_str(b"RtlAddVectoredExceptionHandler")
        );
    }

    // djb2 is case-insensitive-by-uppercase here, so any-case input must hash
    // to the same value as the lowercase/canonical form.
    #[test]
    fn hash_str_is_ascii_case_insensitive() {
        assert_eq!(hash_str(b"virtualprotect"), hash_str(b"VirtualProtect"));
        assert_eq!(hash_str(b"VIRTUALPROTECT"), hash_str(b"VirtualProtect"));
        assert_eq!(hash_str(b"KERNEL32.DLL"), hash_str(b"kernel32.dll"));
    }

    // The empty string is the djb2 seed.
    #[test]
    fn hash_str_empty_is_seed() {
        assert_eq!(hash_str(b""), 5381);
    }
}
