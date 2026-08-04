use host_packer::paginate::paginate;

#[test]
fn pages_cover_all_of_text() {
    let plan = paginate(0x5000, 0x1000, &[], 1);
    let total: u32 = plan.entries.iter().map(|e| e.size).sum();
    // Tail page rounds UP to a 0x1000 boundary, so coverage may exceed vsize.
    assert!(total >= 0x5000);
}

#[test]
fn page_boundaries_stay_0x1000_aligned() {
    let plan = paginate(0xb4d8, 0x1000, &[], 1);
    let mut off = 0x1000u32;
    for e in &plan.entries {
        let size = e.size;
        assert_eq!(off % 0x1000, 0, "page start unaligned at rva {off:#x}");
        assert!(size % 0x1000 == 0, "page size {size:#x} not 0x1000-multiple");
        off += size;
    }
    assert!(off >= 0x1000 + 0xb4d8);
}

#[test]
fn page_sizes_are_from_allowed_set() {
    let plan = paginate(0x10000, 0x1000, &[], 1);
    for e in &plan.entries {
        // PageEntry is #[repr(C, packed)]; copy the field out before borrowing.
        let size = e.size;
        assert!([4096u32, 8192].contains(&size));
    }
}

#[test]
fn relocs_partitioned_into_correct_pages() {
    // three relocs spread across the first two pages.
    let relocs = [0x1000u32 + 10, 0x1000 + 4096 + 4, 0x1000 + 4096 + 200];
    let plan = paginate(8192, 0x1000, &relocs, 7);
    assert_eq!(plan.per_page_relocs.len(), plan.entries.len());
    // every reloc must land in exactly one page, bucketed by RVA range, with
    // offsets stored relative to its page start.
    let mut total = 0usize;
    let mut off = 0x1000u32;
    for (i, e) in plan.entries.iter().enumerate() {
        let size = e.size;
        for &r in &relocs {
            let in_this = r >= off && r < off + size;
            let bucketed = plan.per_page_relocs[i].iter().any(|&o| off + o as u32 == r);
            assert_eq!(in_this, bucketed, "reloc {r:#x} mis-bucketed for page {i}");
        }
        total += plan.per_page_relocs[i].len();
        off += size;
    }
    assert_eq!(total, relocs.len());
}
