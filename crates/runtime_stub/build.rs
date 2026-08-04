// Build script for `runtime_stub`. The stub cdylib must be fully
// self-contained: the host extracts its image, injects it into the packed
// exe's `.raksha` section, and repoints the entry point at `raksha_entry`. The
// mingw CRT startup objects (`crt2.o`/`dllcrt2.o`) would *never* run in that
// context, but their import references (CriticalSection/TLS from kernel32,
// `_initterm`/`fwrite`/`__iob_func`/... from msvcrt) still produce an import
// table whose IAT slots the loader never fills — and any reachable call
// through such a slot (e.g. LLVM lowering `[0u16; 256]` zeroing to a `memset`
// import) faults on the garbage IAT value.
//
// `-nostartfiles` drops the CRT startup objects (and the std-runtime glue they
// keep alive), so no kernel32/msvcrt imports are emitted at all; the few
// remaining libc intrinsics (`memcpy`/`memset`/...) are satisfied by
// `compiler_builtins` or the stub's own definitions. `--entry=raksha_entry`
// points the DLL entry at the exported stub entry (it reads no locator in a
// bare DLL and returns), satisfying the linker without any CRT entry thunk.
//
// The flags are scoped to the cdylib target so `cargo test` (which links a
// normal test binary from the same crate) is unaffected.
fn main() {
    // lld-native (rustc drives its bundled ld.lld directly on this target, so
    // gcc-driver flags like `-nostartfiles` are rejected). Repointing the entry
    // at `raksha_entry` orphans the mingw `dllcrt2.o` startup object; with
    // `--gc-sections` already on the link line, the startup (and the
    // std-runtime glue + kernel32/msvcrt imports it keeps alive) is dropped
    // from the final image.
    println!("cargo::rustc-cdylib-link-arg=--entry=raksha_entry");
}
