# raksha

A **JIT page-fault PE packer for Windows x64**, written entirely in Rust.

> **About the name:** *raksha* (रक्षा / রক্ষা, from Sanskrit and Bangla) means
> **protection** or **defense**.

`raksha` takes a normal 64-bit Windows `.exe`, encrypts its `.text` section page
by page, and appends a small self-contained runtime stub that decrypts each page
**on first execution** via a vectored exception handler. The packed image on
disk contains no directly executable application code - code pages and their
relocation information are reconstructed lazily at runtime as execution reaches
them.

> **Educational / security-research tool.** This is not a commercial software
> protector. It demonstrates PE steganography, VEH-based JIT decryption,
> import-free injected code, and relocation handling on x64 Windows. Use it on
> software you own. See [Threat model & limitations](#threat-model--limitations).

## Features

- **Page-fault JIT decryption.** Pages decrypt lazily on first touch; the hot
  path (running decrypted code) has near-zero overhead, and all defensive logic
  lives on the cold path (first-call decryption, relocation, page transitions).
- **Variable-size encrypted pages.** Page boundaries are drawn deterministically
  from a per-build seed, so no two packed binaries share a page layout.
- **Self-contained, detection-free ChaCha20.** A from-scratch RFC 8439
  implementation - no `cpufeatures`/`cpuid` lazy statics that would fault in
  injected/detached code. The identical `xor_page` call encrypts on the host and
  decrypts in the stub.
- **Per-page key derivation.** Each page is encrypted under a key derived from
  the master key via a two-input ChaCha20 PRF, so a recovered page key does not
  expose the others.
- **Import-free `no_std` stub.** The stub PEB-walks for `VirtualProtect`,
  `GetModuleHandleW`, and `AddVectoredExceptionHandler` - no IAT, no imports.
  It defines its own C-ABI `memcpy`/`memset`/`memmove`/`memcmp` so the mingw
  CRT's msvcrt imports never appear in the running path.
- **Loader-safe relocation.** `.text` relocations are stripped from the packed
  reloc directory so the Windows loader cannot mutate ciphertext before the stub
  runs; the stub re-applies them per page after decryption, using the runtime
  load delta. Non-relocatable (no-ASLR) targets are supported.
- **Encrypted metadata with integrity MAC.** The `PayloadInfo`, page table, and
  relocation stream are stored in an encrypted blob (master key excluded - the
  stub needs it to bootstrap) with a keyed chaining MAC that detects
  modification.
- **Per-build diversification.** Randomized stub-section name, no fixed locator
  magic (structural validation instead), stub export strings stripped, and a
  page-boundary seed derived from the master key.
- **Defensive runtime layers.** Decoy VEH handlers shield the real handler;
  the DOS-stub locator is zeroed once control reaches the original entry point;
  a bounded LRU working-set tracks decrypted pages (re-encryption eviction is
  implemented but disabled by default - see the roadmap).

## How it works

### Pack time (`host_packer`)

1. **Parse** the target PE (goblin): `.text` RVA/size, relocations, preferred
   base, original entry point.
2. **Paginate & encrypt.** `.text` is split into variable-sized pages; each page
   body is XORed with a ChaCha20 keystream under a per-page key derived from a
   random master key.
3. **Hide metadata.** The page table, relocation stream, and payload info are
   assembled into a single ChaCha20-encrypted blob (with an integrity tag),
   placed inside the injected stub section. A small locator in the DOS stub
   points at it; it carries no constant magic marker.
4. **Reconstruct.** A stub section (name randomized per build) is appended
   carrying the stub's full image (`.text`/`.rdata`/`.data`/`.pdata`), laid out
   so its RIP-relative cross-section references still resolve. The stub's DIR64
   relocations are merged into the image's reloc directory and translated into
   the stub section's address space. The entry point is repointed at the stub
   entry.

### Run time (`runtime_stub`)

1. **No imports.** The stub resolves Win32 APIs itself by walking the PEB and
   hashing export names.
2. **Bootstrap.** Reads the locator, decrypts and verifies the metadata blob,
   and builds the page/reloc tables.
3. **Trap.** Every `.text` page is set to `PAGE_NOACCESS`.
4. **Fault → decrypt.** The first fetch from any page raises
   `STATUS_ACCESS_VIOLATION`, caught by the registered VEH. The handler maps the
   faulting address to its page, decrypts it in place, re-applies that page's
   delta-encoded relocations, restores the page to `PAGE_EXECUTE_READ`, and
   returns `EXCEPTION_CONTINUE_EXECUTION` - the OS resumes the exact faulting
   instruction.
5. **OEP.** Control reaches the original entry point and runs normally; every
   page decrypts lazily on first touch.

## Requirements

- **Windows x64** (10/11).
- Rust toolchain for `x86_64-pc-windows-gnu` (the stub is a `no_std` cdylib
  linked against the mingw CRT). Built and tested with rustc 1.97.
- [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or another mingw-w64 toolchain
  if you want to rebuild the `hello.exe` fixture from source.

## Quick start

```powershell
# 1. Build everything (including the runtime stub cdylib)
cargo build --release

# 2. (first time) Rebuild the fixture, since *.exe is gitignored
bash ./fixtures/build_hello.sh   # needs an x86_64-w64-mingw32-gcc cross toolchain

# 3. Pack a PE
cargo run --release -p host_packer --bin raksha -- fixtures/hello.exe fixtures/hello_packed.exe

# 4. Run the packed image
.\fixtures\hello_packed.exe
```

The packer locates the stub DLL (`target/release/runtime_stub.dll`) via the
`RAKSHA_STUB` environment variable, then workspace-relative fallbacks. If it is
missing, rebuild it first:

```powershell
cargo build --release -p runtime_stub
```

### Rebuilding the fixture

`fixtures/hello.exe` is built from `fixtures/hello.c` with:

```bash
./fixtures/build_hello.sh   # x86_64-w64-mingw32-gcc -O2 -o hello.exe hello.c
```

## Testing

```powershell
cargo test --workspace
```

The suite covers the ChaCha20 implementation (involution, key independence,
metadata MAC), the page-fault sim round-trip, pagination/alignment invariants,
encryption/reloc round-trips, steg blob placement + tamper detection, and the
stub's LRU working-set logic.

## Workspace layout

| Crate           | Role                                                                                                 |
| --------------- | ---------------------------------------------------------------------------------------------------- |
| `host_packer`   | CLI (`raksha` binary): parses the target PE, encrypts `.text`, hides metadata, rebuilds the image.   |
| `runtime_stub`  | `#![no_std]` cdylib injected into the packed image. PEB-walk API resolution, VEH registration, JIT page decryption + relocation. |
| `raksha-core`   | Shared, dependency-free core: types, detection-free ChaCha20, and the delta-encoded reloc codec.     |

## Threat model & limitations

This is a **research / educational project**, not a commercial protector. Its
goal is to raise the cost of casual static and naive dynamic analysis - **not**
to make the payload unrecoverable. Read this before trusting it with anything
valuable.

**What it protects against**

- Static inspection of the packed file: `.text` ciphertext, no obvious
  plaintext code, per-build randomized artifacts.
- Naive "run it, then dump the image" memory forensics: pages decrypt lazily on
  first touch, and the metadata blob is encrypted.

**What it does NOT protect against**

- A debugger / memory dumper that hooks `VirtualProtect`, the VEH dispatch, or
  the decryption path and collects pages as they decrypt.
- A privileged observer (kernel debugger, EDR, admin) - user-mode code that the
  CPU must execute can always be observed.
- The master key: the stub must be able to decrypt, so the key (or its
  equivalent) exists in process memory once execution begins. "No usable keys on
  disk" is true *on disk only*.
- Tampering: integrity checks raise the cost of patching, but a determined
  analyst can patch them out.
- TLS callbacks / `__declspec(thread)` (the TLS directory is cleared), and
  `x86`/`ARM64` targets (x64 PE only).

The realistic score against experienced analysts is low; treat it as a
foundation for learning, not as software protection.

## Roadmap

Implemented hardening:

- Per-build artifact diversification (section name, page-boundary seed, no
  fixed locator magic, stripped stub export strings).
- Two-input per-page key derivation.
- Encrypted metadata blob with an integrity MAC.
- Decoy VEH handlers (registered so decoys sit at the front of the dispatch
  chain).
- Post-OEP locator cleanup.
- LRU working-set tracking with bounded re-encryption. **Eviction is disabled by
  default** (`WS_EVICT` in `crates/runtime_stub/src/hot_path.rs`) because
  re-encrypting a page another thread is executing from races with its
  instruction fetches (torn pages → illegal instruction). Enable it for
  single-threaded targets.

Not yet implemented:

- Self-modifying prologue mutation on first fault.
- Probabilistic cold-path anti-debug checks.
- LLVM control-flow-flattening / MBA / string-encryption pass for the stub.
- Full per-build stub generation (today the stub binary is identical across
  builds; only its surrounding artifacts vary).

## License

MIT License. See [LICENSE](LICENSE).
