//! Shared, `#![no_std]` core for Project Raksha.
//!
//! Holds the types, cryptographic primitives, and relocation codec used by
//! both the host-side packer and the runtime stub, so encryption logic is
//! implemented exactly once.

#![no_std]

pub mod crypto;
pub mod reloc;
pub mod types;
