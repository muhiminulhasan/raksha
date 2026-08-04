//! Cryptographic primitives shared by host and stub.
//!
//! Per-page key derivation and page-body encryption both use a **self-contained
//! ChaCha20** (RFC 8439) implementation — no external crates. This matters
//! because the runtime stub is injected no_std *shellcode*: the `blake3` and
//! `chacha20` crates rely on `cpufeatures` runtime CPU detection (lazy statics
//! that call `__cpuid` and select AVX2/SSE backends), which is unsafe in
//! detached code (the `cpuid`/SIMD instructions fault). A from-scratch,
//! detection-free implementation keeps the hot path correct and safe in the
//! injected context, while staying identical between host and stub so the same
//! `xor_page` call encrypts and decrypts.
//!
//! All three public functions keep their original signatures (downstream tasks
//! and the stub call them by name).

/// The ChaCha20 quarterround, operating on the 16-word state in place.
#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Run the 20 ChaCha rounds (10 column + 10 diagonal) on the state in place.
#[inline]
fn chacha20_rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        // Column rounds.
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

/// Generate one 64-byte ChaCha20 keystream block.
///
/// `key` is the 256-bit key (8 words), `counter` the 32-bit block counter, and
/// `nonce` the 96-bit nonce (3 words). Layout follows RFC 8439 §2.3.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    // Constants "expand 32-byte k".
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    // Key words (little-endian).
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut working = state;
    chacha20_rounds(&mut working);
    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&working[i].to_le_bytes());
    }
    out
}

/// XOR `buf` in place with the ChaCha20 keystream under `(key, nonce)`, starting
/// at block counter 0 and incrementing per 64-byte block. This is the standard
/// ChaCha20 encryption == decryption transform (symmetric).
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8]) {
    let mut counter = 0u32;
    let mut pos = 0;
    while pos < buf.len() {
        let block = chacha20_block(key, counter, nonce);
        let take = (buf.len() - pos).min(64);
        for j in 0..take {
            buf[pos + j] ^= block[j];
        }
        pos += take;
        counter = counter.wrapping_add(1);
    }
}

/// Derive a 32-byte page key from the master key and page index.
///
/// Uses ChaCha20 as a PRF: the keystream of 32 zero bytes under
/// `(master_key, nonce = page_index LE u32 zero-padded to 12)` *is* the page
/// key. Deterministic, keyed, and detection-free — no BLAKE3 needed.
///
/// This is the v1 derivation, kept for reference and host-side tooling. The
/// packer and stub use [`derive_page_key_v2`].
pub fn derive_page_key(master_key: &[u8; 32], page_index: u32) -> [u8; 32] {
    let nonce = page_nonce(page_index);
    let mut out = [0u8; 32];
    chacha20_xor(master_key, &nonce, &mut out);
    out
}

/// Derive a page key from two *different* ChaCha20 PRF outputs XORed together.
///
/// `page_key(i) = ChaCha20(master, i) XOR ChaCha20(master, i ^ 0x9E37_79B9)`.
/// Recovering a single page key does not reveal the master key, and knowing one
/// page key gives no information about any other (each is derived through two
/// independent PRF evaluations). Still pure, detection-free ChaCha20 — no new
/// dependencies, identical code path in the injected stub.
pub fn derive_page_key_v2(master_key: &[u8; 32], page_index: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    chacha20_xor(master_key, &page_nonce(page_index), &mut a);
    let mut b = [0u8; 32];
    chacha20_xor(master_key, &page_nonce(page_index ^ 0x9E37_79B9), &mut b);
    for i in 0..32 {
        a[i] ^= b[i];
    }
    a
}

/// 12-byte nonce = page index (little-endian u32) zero-padded to 12 bytes.
pub fn page_nonce(page_index: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&page_index.to_le_bytes());
    n
}

/// XOR `buf` in place with the ChaCha20 keystream for `page_index`. The page is
/// encrypted under a per-page key (derived from the master key) with the page
/// index as nonce. Self-inverse: calling it twice returns the original.
///
/// v1 — retained for reference/tooling; the packer and stub use [`xor_page_v2`].
pub fn xor_page(master_key: &[u8; 32], page_index: u32, buf: &mut [u8]) {
    let key = derive_page_key(master_key, page_index);
    let nonce = page_nonce(page_index);
    chacha20_xor(&key, &nonce, buf);
}

/// XOR `buf` in place under the v2 per-page key (see [`derive_page_key_v2`]).
/// Self-inverse; the page body nonce is the page index (unique per page).
pub fn xor_page_v2(master_key: &[u8; 32], page_index: u32, buf: &mut [u8]) {
    let key = derive_page_key_v2(master_key, page_index);
    let nonce = page_nonce(page_index);
    chacha20_xor(&key, &nonce, buf);
}

// ---------------------------------------------------------------------------
// Metadata encryption + integrity (WS-3)
//
// The packed metadata blob is `master_key[32] || E(meta_key, fields || page
// table || reloc table || tag[32])`. `master_key` is the bootstrap (the stub
// must read it before it can derive anything); everything else is hidden from
// static inspection. All keys/nonces are derived from the master key itself so
// the stub carries no fixed constants (a constant nonce would be a
// fingerprint).
// ---------------------------------------------------------------------------

/// 12-byte nonce drawn from 12 bytes of the master key at `shift`. Distinct
/// shifts yield distinct, random-looking nonces with no constants in the stub.
fn meta_nonce(master_key: &[u8; 32], shift: usize) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&master_key[shift..shift + 12]);
    n
}

/// The metadata encryption/decryption key, derived from the master key.
pub fn metadata_key(master_key: &[u8; 32]) -> [u8; 32] {
    let nonce = meta_nonce(master_key, 0);
    let mut out = [0u8; 32];
    chacha20_xor(master_key, &nonce, &mut out);
    out
}

/// 32-byte integrity tag over `data`, keyed by the metadata key.
///
/// ChaCha20-based keyed chaining MAC: each 64-byte block is XORed with a
/// keystream block keyed by the *running accumulator*, so the result is
/// deterministic, keyed, and order-sensitive. Not a standard construction
/// (ChaCha20 is a stream cipher, not a hash), but sound for tamper-evidence of
/// our own metadata: any modification to the plaintext changes the tag. An
/// attacker who extracts the master key can always re-MAC, which is the
/// fundamental user-mode limit acknowledged in the threat model.
pub fn keyed_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let nonce = meta_nonce(key, 12);
    let mut acc = *key;
    let mut pos = 0;
    while pos < data.len() {
        let n = core::cmp::min(64, data.len() - pos);
        let mut block = [0u8; 64];
        block[..n].copy_from_slice(&data[pos..pos + n]);
        let ks = chacha20_block(&acc, 0, &nonce);
        for i in 0..64 {
            block[i] ^= ks[i];
        }
        let mut next = [0u8; 32];
        for i in 0..32 {
            next[i] = acc[i] ^ block[i] ^ block[i + 32];
        }
        acc = next;
        pos += n;
    }
    // Finalization: absorb the accumulator once more so the length is bound in.
    let mut fin = [0u8; 64];
    fin[..32].copy_from_slice(&acc);
    let ks = chacha20_block(&acc, 0, &nonce);
    for i in 0..64 {
        fin[i] ^= ks[i];
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = fin[i] ^ fin[i + 32];
    }
    out
}

/// Encrypt/decrypt `buf` in place with the metadata key (self-inverse stream
/// cipher), starting at plaintext position 0 of the encrypted region.
pub fn xor_metadata(master_key: &[u8; 32], buf: &mut [u8]) {
    xor_metadata_at(master_key, 0, buf);
}

/// Encrypt/decrypt `buf` in place with the metadata key, starting at absolute
/// plaintext position `start` within the encrypted region. Enables the stub to
/// bootstrap: it decrypts the 40-byte `PayloadInfo` fields at position 0, then
/// decrypts the page table / reloc table / tag at position 40.
pub fn xor_metadata_at(master_key: &[u8; 32], start: usize, buf: &mut [u8]) {
    let key = metadata_key(master_key);
    let nonce = meta_nonce(master_key, 16);
    chacha20_xor_at(&key, &nonce, start, buf);
}

/// XOR `buf` in place with the ChaCha20 keystream under `(key, nonce)`, starting
/// at absolute byte position `start` (block counter = start / 64). Used to
/// decrypt a sub-range of the metadata region without materializing the whole
/// buffer.
fn chacha20_xor_at(key: &[u8; 32], nonce: &[u8; 12], start: usize, buf: &mut [u8]) {
    let mut counter = (start / 64) as u32;
    let mut off = start % 64;
    let mut idx = 0;
    while idx < buf.len() {
        let block = chacha20_block(key, counter, nonce);
        let take = core::cmp::min(64 - off, buf.len() - idx);
        for j in 0..take {
            buf[idx + j] ^= block[off + j];
        }
        idx += take;
        off = 0;
        counter = counter.wrapping_add(1);
    }
}
