//! Core data types shared by host and stub.

// fixed-size slice conversions are infallible
#![allow(clippy::unwrap_used)]

/// One packed page of `.text`.
///
/// Serialized exactly as `[u32 size][u16 reloc_count][u32 raw_offset]` (10 bytes).
/// `reloc_count` gives the number of per-page relocation offsets that the stub
/// must re-apply after decrypting this page; the offsets themselves live in a
/// separate delta-encoded table addressed by `PayloadInfo.reloc_table_*`.
///
/// `#[repr(C, packed)]` removes the trailing two bytes of alignment padding a
/// bare `#[repr(C)]` would insert after `reloc_count`, yielding exactly 10
/// bytes — the layout the stub reads back at a fixed file offset.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageEntry {
    pub size: u32,
    pub reloc_count: u16,
    pub raw_offset: u32,
}

/// Everything the stub needs to decrypt and run the payload. Fragmented across
/// PE header slack by `host_packer::steg` and reassembled by the stub.
///
/// `preferred_base` is the image's preferred load address (optional-header
/// `ImageBase`). The stub computes the relocation delta at runtime as
/// `image_base_runtime - preferred_base` and uses it to re-apply base relocs
/// to each decrypted page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadInfo {
    pub master_key: [u8; 32],
    pub oep: u32,
    pub text_rva: u32,
    pub text_vsize: u32,
    pub page_count: u32,
    pub reloc_table_offset: u32,
    pub reloc_table_size: u32,
    pub seed: u64,
    pub preferred_base: u64,
}

impl PayloadInfo {
    /// Fixed-width serialization. Layout is private to this crate.
    pub fn to_bytes(&self) -> [u8; 72] {
        let mut o = [0u8; 72];
        o[0..32].copy_from_slice(&self.master_key);
        o[32..36].copy_from_slice(&self.oep.to_le_bytes());
        o[36..40].copy_from_slice(&self.text_rva.to_le_bytes());
        o[40..44].copy_from_slice(&self.text_vsize.to_le_bytes());
        o[44..48].copy_from_slice(&self.page_count.to_le_bytes());
        o[48..52].copy_from_slice(&self.reloc_table_offset.to_le_bytes());
        o[52..56].copy_from_slice(&self.reloc_table_size.to_le_bytes());
        o[56..64].copy_from_slice(&self.seed.to_le_bytes());
        o[64..72].copy_from_slice(&self.preferred_base.to_le_bytes());
        o
    }
    pub fn from_bytes(b: &[u8]) -> PayloadInfo {
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&b[0..32]);
        PayloadInfo {
            master_key: mk,
            oep: u32::from_le_bytes(b[32..36].try_into().unwrap()),
            text_rva: u32::from_le_bytes(b[36..40].try_into().unwrap()),
            text_vsize: u32::from_le_bytes(b[40..44].try_into().unwrap()),
            page_count: u32::from_le_bytes(b[44..48].try_into().unwrap()),
            reloc_table_offset: u32::from_le_bytes(b[48..52].try_into().unwrap()),
            reloc_table_size: u32::from_le_bytes(b[52..56].try_into().unwrap()),
            seed: u64::from_le_bytes(b[56..64].try_into().unwrap()),
            preferred_base: u64::from_le_bytes(b[64..72].try_into().unwrap()),
        }
    }

    /// Serialize all fields EXCEPT `master_key` (40 bytes). Used inside the
    /// encrypted metadata blob: the master key is stored separately (plaintext,
    /// at `BLOB_KEY_OFFSET`) so the stub can bootstrap decryption.
    pub fn to_fields(&self) -> [u8; 40] {
        let mut o = [0u8; 40];
        o[0..4].copy_from_slice(&self.oep.to_le_bytes());
        o[4..8].copy_from_slice(&self.text_rva.to_le_bytes());
        o[8..12].copy_from_slice(&self.text_vsize.to_le_bytes());
        o[12..16].copy_from_slice(&self.page_count.to_le_bytes());
        o[16..20].copy_from_slice(&self.reloc_table_offset.to_le_bytes());
        o[20..24].copy_from_slice(&self.reloc_table_size.to_le_bytes());
        o[24..32].copy_from_slice(&self.seed.to_le_bytes());
        o[32..40].copy_from_slice(&self.preferred_base.to_le_bytes());
        o
    }

    /// Reassemble a `PayloadInfo` from the plaintext master key and the 40-byte
    /// fields blob (see [`PayloadInfo::to_fields`]).
    pub fn from_fields(master_key: [u8; 32], b: &[u8; 40]) -> PayloadInfo {
        PayloadInfo {
            master_key,
            oep: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            text_rva: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            text_vsize: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            page_count: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            reloc_table_offset: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            reloc_table_size: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            seed: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            preferred_base: u64::from_le_bytes(b[32..40].try_into().unwrap()),
        }
    }
}

/// Fixed-location pointer (stored at `LOCATOR_OFFSET` in the DOS stub) that
/// tells the stub where the `PayloadInfo` fragments live. 4 bytes.
///
/// Deliberately **no magic field**: a constant `magic` at a fixed offset is a
/// trivially signature-able marker (the RE-review flagged `LOCATOR_MAGIC` as an
/// immediate YARA hit). The stub instead reads the offset and validates it
/// structurally (it must point inside the image at a plausible `PayloadInfo`),
/// so a packed file carries no recognizable locator constant.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locator {
    pub metadata_offset: u32,
}

/// Byte offset inside the PE image where the `Locator` is written.
/// 0x4C sits in the DOS stub region (0x40..e_lfanew), safe to overwrite.
pub const LOCATOR_OFFSET: usize = 0x4C;

// --- Encrypted metadata blob layout (WS-3) ---
//
// The blob is `master_key[32] || E(meta_key, fields[40] || page_table[N*10] ||
// reloc_table[R] || tag[32])`. The master key is plaintext (it is the
// bootstrap — the stub must read it before it can derive the metadata key);
// everything else is encrypted with ChaCha20 under `metadata_key(master_key)`.
// The page table lands at offset 72 (32 key + 40 fields), which keeps the
// page-table offsets the stub uses unchanged.

/// Offset of the plaintext master key within the metadata blob.
pub const BLOB_KEY_OFFSET: usize = 0;
/// Offset of the (encrypted) `PayloadInfo` fields (all fields except the
/// master key — 40 bytes) within the metadata blob.
pub const BLOB_FIELDS_OFFSET: usize = 32;
/// Offset of the (encrypted) page table within the metadata blob.
pub const BLOB_PAGE_TABLE_OFFSET: usize = 72;
/// Size of the integrity tag appended to (and encrypted with) the metadata.
pub const BLOB_TAG_SIZE: usize = 32;
