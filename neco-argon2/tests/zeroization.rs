#![cfg(feature = "alloc")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use neco_argon2::{argon2id_hash_into, argon2id_hash_with_secret, Argon2Params};

const MAX_SCANNED_BLOCK: usize = 64 * 1024;
const MAX_PATTERNS: usize = 8;
const MAX_PATTERN_LEN: usize = 32;
const PASSWORD: &[u8] = b"argon2-canary-password-012345678";
const SECRET: &[u8] = b"argon2-canary-secret-01234567890";
const SALT: &[u8] = b"salt-for-the-canary-test";
const ASSOCIATED_DATA: &[u8] = b"associated data";

const REFERENCE_H0_M64_T1_P1: &str =
    "616a9aafa1c29e8ac57f0a01a4558e38bd09e84b9d3f89add0697ce841451573";
const REFERENCE_SEED_M64_BLOCK_0: &str =
    "700cc04f9a354807ffbb447a17b7a8f1a99105255f34dffd4faae4b5dc651b53";
const REFERENCE_SEED_M64_BLOCK_1: &str =
    "5f04d1b5a57059f5abc017e7df8a1cbfeda172c1c4bf0c39551d4e0ee483f1cb";
const REFERENCE_H0_M256_T3_P4: &str =
    "ba771d0b97990ad3461b5c877f1a4057a7ce03e47e347fed527f1177062571bf";
const REFERENCE_H0_WITH_SECRET: &str =
    "270696656199c8fa09d551dd3553283e70691856c0b8d51cabd75f64a70381d9";
const REFERENCE_SEED_WITH_SECRET_BLOCK_0: &str =
    "1712ab9ed765b2c60083c5c7d9efa1d14794407464bda6f0752fe1c20a062462";

#[derive(Clone, Copy)]
struct Pattern {
    len: usize,
    bytes: [u8; MAX_PATTERN_LEN],
}

const NO_PATTERN: Pattern = Pattern {
    len: 0,
    bytes: [0; MAX_PATTERN_LEN],
};

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    static PATTERNS: Cell<[Pattern; MAX_PATTERNS]> = const { Cell::new([NO_PATTERN; MAX_PATTERNS]) };
    static LEAKS: Cell<usize> = const { Cell::new(0) };
}

struct ProbeAllocator;

fn contains(block: &[u8], needle: &[u8]) -> bool {
    block.windows(needle.len()).any(|window| window == needle)
}

fn scan_freed_block(block: &[u8]) {
    for pattern in PATTERNS.with(Cell::get) {
        if pattern.len > 0 && contains(block, &pattern.bytes[..pattern.len]) {
            LEAKS.with(|leaks| leaks.set(leaks.get() + 1));
        }
    }
}

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.with(Cell::get) && layout.size() <= MAX_SCANNED_BLOCK {
            scan_freed_block(std::slice::from_raw_parts(ptr, layout.size()));
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn watch<T>(patterns: &[&[u8]], action: impl FnOnce() -> T) -> (T, usize) {
    assert!(
        patterns.len() <= MAX_PATTERNS,
        "the probe watches at most {MAX_PATTERNS} patterns"
    );
    assert!(
        patterns
            .iter()
            .all(|pattern| pattern.len() <= MAX_PATTERN_LEN),
        "the probe compares at most {MAX_PATTERN_LEN} bytes of a pattern"
    );
    let mut set = [NO_PATTERN; MAX_PATTERNS];
    for (slot, pattern) in set.iter_mut().zip(patterns) {
        slot.len = pattern.len();
        slot.bytes[..pattern.len()].copy_from_slice(pattern);
    }
    PATTERNS.with(|cell| cell.set(set));
    LEAKS.with(|leaks| leaks.set(0));
    WATCHING.with(|flag| flag.set(true));
    let result = action();
    WATCHING.with(|flag| flag.set(false));
    (result, LEAKS.with(Cell::get))
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex digit pair"))
        .collect()
}

fn with_secret_params() -> Argon2Params {
    Argon2Params {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
        output_len: 32,
    }
}

#[test]
fn probe_detects_an_unwiped_heap_buffer() {
    assert_eq!(PASSWORD.len(), 32);
    assert_eq!(SECRET.len(), 32);
    let ((), leaks) = watch(&[PASSWORD], || {
        let copy = black_box(PASSWORD.to_vec());
        drop(copy);
    });
    assert!(leaks >= 1, "the probe must see a canary in a freed block");
}

#[test]
#[should_panic(expected = "watches at most 8 patterns")]
fn probe_refuses_more_patterns_than_it_watches() {
    let patterns = [PASSWORD; MAX_PATTERNS + 1];
    let ((), leaks) = watch(&patterns, || ());
    assert_eq!(leaks, 0);
}

#[test]
fn hash_into_leaves_no_secret_in_freed_heap_blocks() {
    let h0_small = unhex(REFERENCE_H0_M64_T1_P1);
    let seed_0 = unhex(REFERENCE_SEED_M64_BLOCK_0);
    let seed_1 = unhex(REFERENCE_SEED_M64_BLOCK_1);
    let h0_wide = unhex(REFERENCE_H0_M256_T3_P4);
    let cases: [(u32, u32, u32, Vec<&[u8]>); 2] = [
        (64, 1, 1, vec![&h0_small, &seed_0, &seed_1]),
        (256, 3, 4, vec![&h0_wide]),
    ];

    for (m_cost, t_cost, p_cost, reference) in &cases {
        let (m_cost, t_cost, p_cost) = (*m_cost, *t_cost, *p_cost);
        let mut expected = [0u8; 32];
        argon2id_hash_into(PASSWORD, SALT, m_cost, t_cost, p_cost, &mut expected).expect("hash");

        let mut patterns: Vec<&[u8]> = vec![PASSWORD, &expected];
        patterns.extend(reference.iter().copied());
        let mut out = [0u8; 32];
        let (result, leaks) = watch(&patterns, || {
            argon2id_hash_into(PASSWORD, SALT, m_cost, t_cost, p_cost, &mut out)
        });
        result.expect("hash");
        assert_eq!(out, expected);
        assert_eq!(leaks, 0, "m={m_cost}, t={t_cost}, p={p_cost}");
    }
}

#[test]
fn hash_with_secret_leaves_no_secret_in_freed_heap_blocks() {
    let h0 = unhex(REFERENCE_H0_WITH_SECRET);
    let seed = unhex(REFERENCE_SEED_WITH_SECRET_BLOCK_0);

    let (result, leaks) = watch(&[PASSWORD, SECRET, &h0, &seed], || {
        argon2id_hash_with_secret(
            PASSWORD,
            SALT,
            with_secret_params(),
            SECRET,
            ASSOCIATED_DATA,
        )
    });
    let hash = result.expect("hash");
    assert_eq!(hash.len(), 32);
    assert_eq!(leaks, 0);

    let (result, leaks) = watch(&[PASSWORD, &hash, &h0, &seed], || {
        argon2id_hash_with_secret(
            PASSWORD,
            SALT,
            with_secret_params(),
            SECRET,
            ASSOCIATED_DATA,
        )
    });
    assert_eq!(result.expect("hash again"), hash);
    assert_eq!(leaks, 0, "the returned hash is owned by the caller");
}
