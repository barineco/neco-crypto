use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const MAX_SCANNED_BLOCK: usize = 64 * 1024;
const MAX_PATTERNS: usize = 4;
const MAX_PATTERN_LEN: usize = 32;

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

pub fn watch<T>(patterns: &[&[u8]], action: impl FnOnce() -> T) -> (T, usize) {
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
