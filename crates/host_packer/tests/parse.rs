use host_packer::parse::parse;
use std::process::Command;

/// Return the fixture path if present, attempting to build it via
/// `build_hello.sh` first. `None` if it cannot be produced in this environment
/// (e.g. CI without a mingw gcc) — callers skip rather than fail.
fn ensure_fixture() -> Option<std::path::PathBuf> {
    let exe = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/hello.exe");
    if exe.exists() {
        return Some(exe);
    }
    let s = exe.parent().unwrap().join("build_hello.sh");
    match Command::new("bash").arg(&s).status() {
        Ok(status) if status.success() && exe.exists() => Some(exe),
        _ => None,
    }
}

#[test]
fn parses_text_section_and_relocs() {
    let Some(exe) = ensure_fixture() else {
        eprintln!("skipping: fixtures/hello.exe not available (needs mingw gcc)");
        return;
    };
    let bytes = std::fs::read(&exe).unwrap();
    let pe = parse(bytes).unwrap();
    assert!(pe.text_vsize > 0);
    assert!(pe.text_raw > 0x200);
    assert!(!pe.relocs.is_empty(), "fixture should have base relocs");
    // IAT must not be inside .text.
    if let Some(iat) = pe.iat_rva {
        assert!(iat < pe.text_rva || iat >= pe.text_rva + pe.text_vsize);
    }
}
