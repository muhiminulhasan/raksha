use raksha_core::crypto::{
    derive_page_key, derive_page_key_v2, keyed_mac, metadata_key, page_nonce, xor_metadata,
    xor_metadata_at, xor_page, xor_page_v2,
};

#[test]
fn page_key_is_deterministic() {
    let mk = [7u8; 32];
    assert_eq!(derive_page_key(&mk, 0), derive_page_key(&mk, 0));
}

#[test]
fn page_key_differs_per_index() {
    let mk = [7u8; 32];
    assert_ne!(derive_page_key(&mk, 0), derive_page_key(&mk, 1));
}

#[test]
fn nonce_is_index_zero_padded_to_12() {
    let n = page_nonce(0x01020304);
    assert_eq!(&n[0..4], &[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(&n[4..12], &[0u8; 8]);
}

#[test]
fn xor_page_is_an_involution() {
    let mk = [0xAB; 32];
    let original = [0x10u8, 0x20, 0x30, 0x40, 0x50];
    let mut buf = original;
    xor_page(&mk, 3, &mut buf); // encrypt
    assert_ne!(buf, original);
    xor_page(&mk, 3, &mut buf); // decrypt
    assert_eq!(buf, original);
}

#[test]
fn xor_page_distinguishes_pages() {
    let mk = [0xAB; 32];
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    xor_page(&mk, 0, &mut a);
    xor_page(&mk, 1, &mut b);
    assert_ne!(a, b); // different page -> different keystream
}

// --- v2 per-page derivation ---

#[test]
fn v2_page_key_is_deterministic() {
    let mk = [0x2Au8; 32];
    assert_eq!(derive_page_key_v2(&mk, 0), derive_page_key_v2(&mk, 0));
    assert_eq!(derive_page_key_v2(&mk, 7), derive_page_key_v2(&mk, 7));
}

#[test]
fn v2_page_key_differs_per_index() {
    let mk = [0x2Au8; 32];
    for i in 0..8 {
        for j in (i + 1)..9 {
            assert_ne!(derive_page_key_v2(&mk, i), derive_page_key_v2(&mk, j));
        }
    }
}

#[test]
fn v2_differs_from_v1() {
    let mk = [0x2Au8; 32];
    assert_ne!(derive_page_key_v2(&mk, 0), derive_page_key(&mk, 0));
    assert_ne!(derive_page_key_v2(&mk, 3), derive_page_key(&mk, 3));
}

#[test]
fn v2_page_keys_do_not_follow_an_obvious_ladder() {
    // With a single-input PRF the difference between adjacent page keys is
    // predictable given one key; v2's two-input XOR construction should make
    // adjacent keys unrelated (best-effort structural check).
    let mk = [0x2Au8; 32];
    let k0 = derive_page_key_v2(&mk, 0);
    let k1 = derive_page_key_v2(&mk, 1);
    let mut delta = [0u8; 32];
    for i in 0..32 {
        delta[i] = k0[i] ^ k1[i];
    }
    // delta must not be all zeros and must not equal either key (i.e. the two
    // keys share no fixed, trivial relation like k1 == k0 or k1 == !k0).
    assert!(delta.iter().any(|&b| b != 0));
    assert_ne!(delta, k0);
    assert_ne!(delta, k1);
}

#[test]
fn v2_xor_page_is_an_involution() {
    let mk = [0xCDu8; 32];
    let original = [0x11u8, 0x22, 0x33, 0x44, 0x55];
    let mut buf = original;
    xor_page_v2(&mk, 5, &mut buf);
    assert_ne!(buf, original);
    xor_page_v2(&mk, 5, &mut buf);
    assert_eq!(buf, original);
}

#[test]
fn v2_xor_page_distinguishes_pages() {
    let mk = [0xCDu8; 32];
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    xor_page_v2(&mk, 0, &mut a);
    xor_page_v2(&mk, 1, &mut b);
    assert_ne!(a, b);
}

// --- metadata encryption + integrity (WS-3) ---

#[test]
fn metadata_key_is_distinct_from_master_and_page_keys() {
    let mk = [0x55u8; 32];
    let key = metadata_key(&mk);
    assert_ne!(key, mk);
    assert_ne!(key, derive_page_key_v2(&mk, 0));
    // deterministic
    assert_eq!(key, metadata_key(&mk));
}

#[test]
fn keyed_mac_differs_across_keys_and_inputs() {
    let k1 = metadata_key(&[0x55u8; 32]);
    let k2 = metadata_key(&[0x56u8; 32]);
    let data_a = b"metadata page table";
    let data_b = b"metadata page tabl_"; // one byte off
    assert_ne!(keyed_mac(&k1, data_a), keyed_mac(&k2, data_a));
    assert_ne!(keyed_mac(&k1, data_a), keyed_mac(&k1, data_b));
    // deterministic
    assert_eq!(keyed_mac(&k1, data_a), keyed_mac(&k1, data_a));
}

#[test]
fn keyed_mac_is_order_sensitive() {
    let k = metadata_key(&[0x77u8; 32]);
    let a = b"AB";
    let b = b"BA";
    assert_ne!(keyed_mac(&k, a), keyed_mac(&k, b));
}

#[test]
fn xor_metadata_is_an_involution() {
    let mk = [0x77u8; 32];
    let mut buf = (0..200u8).collect::<Vec<u8>>();
    let orig = buf.clone();
    xor_metadata(&mk, &mut buf); // encrypt
    assert_ne!(buf, orig);
    xor_metadata(&mk, &mut buf); // decrypt
    assert_eq!(buf, orig);
}

#[test]
fn xor_metadata_at_matches_whole_buffer() {
    // Decrypting the whole buffer in two sub-ranges (fields at 0, rest at 40)
    // must equal one pass over the whole buffer — mirrors the stub bootstrap.
    let mk = [0x99u8; 32];
    let mut whole = (0u32..500).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
    xor_metadata(&mk, &mut whole);

    let mut split = whole.clone();
    let (fields, rest) = split.split_at_mut(40);
    xor_metadata_at(&mk, 0, fields);
    xor_metadata_at(&mk, 40, rest);

    assert_eq!(split, (0u32..500).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
}

#[test]
fn keyed_mac_breaks_when_plaintext_changes() {
    let k = metadata_key(&[0x5Au8; 32]);
    let tag1 = keyed_mac(&k, b"hello");
    let tag2 = keyed_mac(&k, b"hellp");
    assert_ne!(tag1, tag2);
}
