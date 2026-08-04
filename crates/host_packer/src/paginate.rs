//! Variable-size page partitioning of `.text`, with per-page reloc bucketing.
//!
//! `.text` is split greedily into pages whose sizes are drawn from
//! `{4096, 8192}` by a deterministic SplitMix64 PRNG seeded by `seed`. Every
//! page boundary is kept `0x1000`-aligned: sizes are drawn only from multiples
//! of `0x1000` and the tail page is rounded *up* to the next aligned boundary,
//! because the stub's `VirtualProtect` calls operate on whole pages — a page
//! with an unaligned start or end would round to a region larger than the XOR'd
//! bytes, leaving ciphertext executable or re-faulting a decrypted page.
//! `.text` base-relocation RVAs are bucketed into the page whose
//! `[page_rva, page_rva+size)` range contains them, with the offset stored
//! relative to the page start as a `u16`. This feeds Task 10's per-page
//! encryption.

use raksha_core::types::PageEntry;

/// Page sizes chosen by the PRNG (all `0x1000`-multiples so page boundaries
/// stay aligned). The tail page is rounded up to the next `0x1000` boundary.
const SIZES: [u32; 2] = [4096, 8192];

/// Result of partitioning `.text`: the page table entries plus, per page, the
/// within-page relocation offsets the stub must re-apply after decryption.
pub struct PagePlan {
    pub entries: Vec<PageEntry>,
    /// Within-page (relative to `page_rva`) relocation offsets, per page.
    pub per_page_relocs: Vec<Vec<u16>>,
}

/// Deterministically partition `.text` into variable-size pages and bucket
/// the relocation offsets.
///
/// - `text_vsize`: virtual (unpadded) size of `.text`.
/// - `text_rva`:   RVA where `.text` is mapped.
/// - `text_reloc_rvas`: absolute RVAs of `.text` base relocations.
/// - `seed`:       PRNG seed; same seed always yields the same plan.
///
/// Page sizes are drawn from `SIZES`; the tail page is rounded up to a
/// `0x1000` boundary, so the page boundaries always stay page-aligned even
/// though the sizes sum to slightly more than `text_vsize`.
pub fn paginate(text_vsize: u32, text_rva: u32, text_reloc_rvas: &[u32], seed: u64) -> PagePlan {
    let mut entries = Vec::new();
    let mut per_page_relocs: Vec<Vec<u16>> = Vec::new();
    let mut rng = SplitMix64 { state: seed };

    let mut off: u32 = 0;
    while off < text_vsize {
        let remaining = text_vsize - off;
        // pick a size that fits; if remaining < chosen, round the tail up to a
        // 0x1000 multiple (at least one page) so its boundary stays aligned.
        let mut size = SIZES[(rng.next() as usize) % SIZES.len()];
        if size > remaining {
            size = (remaining + 0xFFF) & !0xFFF;
        }
        let page_rva = text_rva + off;

        // bucket relocs whose RVA falls in [page_rva, page_rva+size)
        let mut page_relocs: Vec<u16> = text_reloc_rvas
            .iter()
            .copied()
            .filter(|r| *r >= page_rva && *r < page_rva + size)
            .map(|r| (r - page_rva) as u16)
            .collect();
        page_relocs.sort_unstable();

        entries.push(PageEntry {
            size,
            reloc_count: page_relocs.len() as u16,
            raw_offset: 0,
        });
        per_page_relocs.push(page_relocs);
        off += size;
    }

    PagePlan {
        entries,
        per_page_relocs,
    }
}

/// Fast, simple deterministic PRNG for page-size selection (not crypto).
///
/// Standard SplitMix64: the state is advanced by the golden-gamma constant
/// and the output is mixed via the standard xmxmx*mxm sequence.
struct SplitMix64 {
    state: u64,
}
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same seed must yield the same plan.
    #[test]
    fn deterministic() {
        let a = paginate(0x9000, 0x1000, &[], 42);
        let b = paginate(0x9000, 0x1000, &[], 42);
        let sizes_a: Vec<u32> = a.entries.iter().map(|e| e.size).collect();
        let sizes_b: Vec<u32> = b.entries.iter().map(|e| e.size).collect();
        assert_eq!(sizes_a, sizes_b);
    }

    /// Relocs must not be dropped or duplicated across pages.
    #[test]
    fn relocs_fully_partitioned() {
        // spread relocs across the whole .text range
        let relocs: Vec<u32> = (0..16).map(|i| 0x1000 + i * 0x400).collect();
        let plan = paginate(0x5000, 0x1000, &relocs, 99);
        let total: usize = plan.per_page_relocs.iter().map(|v| v.len()).sum();
        assert_eq!(total, relocs.len());
    }
}
