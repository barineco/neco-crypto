use crate::argon2id::{AllocationOperation, Argon2Error};
use zeroize::{Zeroize, Zeroizing};

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], m: &[u64; 16], t: [u64; 2], last_block: bool) {
    let mut v = [0u64; 16];
    v[0..8].copy_from_slice(h);
    v[8] = IV[0];
    v[9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = IV[4] ^ t[0];
    v[13] = IV[5] ^ t[1];
    v[14] = if last_block { IV[6] ^ u64::MAX } else { IV[6] };
    v[15] = IV[7];

    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

struct Blake2b {
    h: [u64; 8],
    counter: [u64; 2],
    block: Zeroizing<[u8; 128]>,
    used: usize,
}

impl Blake2b {
    fn new(key: &[u8], output_len: usize) -> Result<Self, Argon2Error> {
        if !(1..=64).contains(&output_len) {
            return Err(Argon2Error::InvalidParameter("blake2b_output_len"));
        }
        if key.len() > 64 {
            return Err(Argon2Error::InvalidParameter("blake2b_key"));
        }
        let mut h = IV;
        h[0] ^= 0x0101_0000u64 ^ ((key.len() as u64) << 8) ^ output_len as u64;
        let mut state = Self {
            h,
            counter: [0, 0],
            block: Zeroizing::new([0; 128]),
            used: 0,
        };
        if !key.is_empty() {
            state.block[..key.len()].copy_from_slice(key);
            state.used = 128;
        }
        Ok(state)
    }

    fn add_count(&mut self, amount: usize) {
        let old = self.counter[0];
        self.counter[0] = old.wrapping_add(amount as u64);
        if self.counter[0] < old {
            self.counter[1] = self.counter[1].wrapping_add(1);
        }
    }

    fn compress_buffer(&mut self, last: bool) {
        self.add_count(self.used);
        let words = bytes_to_words(&self.block);
        compress(&mut self.h, &words, self.counter, last);
        self.block.zeroize();
        self.used = 0;
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.used == 128 {
                self.compress_buffer(false);
            }
            let take = (128 - self.used).min(input.len());
            self.block[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            input = &input[take..];
        }
    }

    fn finish(mut self, out: &mut [u8]) {
        self.compress_buffer(true);
        let mut full = Zeroizing::new([0u8; 64]);
        for (chunk, word) in full.chunks_exact_mut(8).zip(self.h) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out.copy_from_slice(&full[..out.len()]);
        self.h.zeroize();
    }
}

fn bytes_to_words(block: &[u8; 128]) -> [u64; 16] {
    let mut words = [0u64; 16];
    for (word, chunk) in words.iter_mut().zip(block.chunks_exact(8)) {
        let mut le = [0u8; 8];
        le.copy_from_slice(chunk);
        *word = u64::from_le_bytes(le);
    }
    words
}

pub(crate) fn blake2b_into(parts: &[&[u8]], key: &[u8], out: &mut [u8]) -> Result<(), Argon2Error> {
    let mut state = Blake2b::new(key, out.len())?;
    for part in parts {
        state.update(part);
    }
    state.finish(out);
    Ok(())
}

pub(crate) fn blake2b_long_into(input: &[u8], out: &mut [u8]) -> Result<(), Argon2Error> {
    let output_len =
        u32::try_from(out.len()).map_err(|_| Argon2Error::InvalidParameter("output_len"))?;
    if output_len == 0 {
        return Err(Argon2Error::InvalidParameter("output_len"));
    }
    let prefix = output_len.to_le_bytes();
    if out.len() <= 64 {
        return blake2b_into(&[&prefix, input], &[], out);
    }

    let rounds = out
        .len()
        .checked_add(31)
        .ok_or(Argon2Error::CapacityOverflow {
            operation: AllocationOperation::OutputBytes,
            required: out.len(),
        })?
        / 32
        - 2;
    let mut previous = Zeroizing::new([0u8; 64]);
    blake2b_into(&[&prefix, input], &[], &mut previous[..])?;
    out[..32].copy_from_slice(&previous[..32]);
    let mut written = 32;

    for _ in 1..rounds {
        let mut next = Zeroizing::new([0u8; 64]);
        blake2b_into(&[&previous[..]], &[], &mut next[..])?;
        out[written..written + 32].copy_from_slice(&next[..32]);
        written += 32;
        previous = next;
    }

    blake2b_into(&[&previous[..]], &[], &mut out[written..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[test]
    fn test_blake2b_rfc7693_abc() {
        let mut result = [0u8; 64];
        blake2b_into(&[b"abc"], &[], &mut result).unwrap();
        let expected = hex_to_bytes(
            "ba80a53f981c4d0d6a2797b69f12f6e9\
             4c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc95\
             18d38aa8dbf1925ab92386edd4009923",
        );
        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn test_blake2b_empty() {
        let mut result = [0u8; 64];
        blake2b_into(&[], &[], &mut result).unwrap();
        let expected = hex_to_bytes(
            "786a02f742015903c6c6fd852552d272\
             912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b\
             903a685b1448b755d56f701afe9be2ce",
        );
        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn split_parts_match_contiguous_input() {
        let mut split = [0u8; 64];
        let mut contiguous = [0u8; 64];
        blake2b_into(&[b"a", b"bc"], &[], &mut split).unwrap();
        blake2b_into(&[b"abc"], &[], &mut contiguous).unwrap();
        assert_eq!(split, contiguous);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..compact.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
            .collect()
    }
}
