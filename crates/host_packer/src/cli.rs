//! Minimal command-line parsing for the host packer.
//!
//! Usage: `raksha <in.exe> <out.exe>`. No flags — Phase 1 keeps the surface
//! tiny; Phase 2 (Task 17) may extend this when the real stub lands.

use std::path::PathBuf;

pub struct Args {
    pub input: PathBuf,
    pub output: PathBuf,
}

pub fn parse() -> anyhow::Result<Args> {
    let mut args = std::env::args().skip(1);
    let input = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: raksha <in.exe> <out.exe>"))?;
    let output = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: raksha <in.exe> <out.exe>"))?;
    Ok(Args {
        input: input.into(),
        output: output.into(),
    })
}
