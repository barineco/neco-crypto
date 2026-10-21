//! RFC 3174 に基づく SHA-1 ハッシュ関数。

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline(always)]
fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&block[i * 4..i * 4 + 4]);
        w[i] = u32::from_be_bytes(bytes);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;

    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => (ch(b, c, d), 0x5A827999u32),
            20..=39 => (parity(b, c, d), 0x6ED9EBA1u32),
            40..=59 => (maj(b, c, d), 0x8F1BBCDCu32),
            _ => (parity(b, c, d), 0xCA62C1D6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// SHA-1 が受け付けるメッセージの最大のバイト数。RFC 3174 はメッセージ長を 2^64 ビット未満と定める。
pub const MAX_MESSAGE_BYTES: u64 = (1 << 61) - 1;

/// SHA-1 の入力の失敗。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha1Error {
    /// 追加した入力により、メッセージ長が `maximum` バイトを超える。
    MessageTooLong {
        processed: u64,
        appended: usize,
        maximum: u64,
    },
}

impl core::fmt::Display for Sha1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MessageTooLong {
                processed,
                appended,
                maximum,
            } => write!(
                f,
                "SHA-1 message exceeds {maximum} bytes: {processed} bytes processed, {appended} bytes appended"
            ),
        }
    }
}

impl core::error::Error for Sha1Error {}

/// RFC 3174 に基づく SHA-1 の状態。`update` で入力を追加し、`finalize` で 20 バイトのハッシュ値を取り出す。
pub struct Sha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha1 {
    /// 初期状態を返す。
    pub fn new() -> Self {
        Self {
            state: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// 入力を追加する。複数回呼び出せる。入力の累計が `MAX_MESSAGE_BYTES` を超える場合は `MessageTooLong` を返し、状態を呼び出し前のまま保つ。
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha1Error> {
        let appended = u64::try_from(data.len()).ok();
        self.total_len = match appended.and_then(|n| self.total_len.checked_add(n)) {
            Some(total) if total <= MAX_MESSAGE_BYTES => total,
            _ => {
                return Err(Sha1Error::MessageTooLong {
                    processed: self.total_len,
                    appended: data.len(),
                    maximum: MAX_MESSAGE_BYTES,
                })
            }
        };
        self.absorb(data);
        Ok(())
    }

    fn absorb(&mut self, data: &[u8]) {
        let mut data = data;

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block: [u8; 64] = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            compress(&mut self.state, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// パディングを施し、20 バイトのハッシュ値を返す。`self` を消費する。
    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len * 8;

        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..].fill(0);
            let block: [u8; 64] = self.buf;
            compress(&mut self.state, &block);
            self.buf = [0u8; 64];
            self.buf_len = 0;
        }

        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block: [u8; 64] = self.buf;
        compress(&mut self.state, &block);

        let mut digest = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// 入力全体の SHA-1 のハッシュ値を一度に計算する。失敗の条件は `update` と同じ。
    pub fn digest(data: &[u8]) -> Result<[u8; 20], Sha1Error> {
        let mut h = Self::new();
        h.update(data)?;
        Ok(h.finalize())
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::String, vec};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn empty() {
        assert_eq!(
            hex(&Sha1::digest(b"").unwrap()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex(&Sha1::digest(b"abc").unwrap()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq() {
        assert_eq!(
            hex(
                &Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").unwrap()
            ),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn million_a() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&Sha1::digest(&data).unwrap()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn streaming_equals_oneshot() {
        let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let oneshot = Sha1::digest(data).unwrap();
        let mut h = Sha1::new();
        for chunk in data.chunks(7) {
            h.update(chunk).unwrap();
        }
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn block_boundary_55_bytes() {
        let data = vec![b'a'; 55];
        let oneshot = Sha1::digest(&data).unwrap();
        let mut h = Sha1::new();
        h.update(&data).unwrap();
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn block_boundary_56_bytes() {
        let data = vec![b'a'; 56];
        let oneshot = Sha1::digest(&data).unwrap();
        let mut h = Sha1::new();
        h.update(&data[..28]).unwrap();
        h.update(&data[28..]).unwrap();
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn message_length_limit() {
        let mut h = Sha1::new();
        h.total_len = MAX_MESSAGE_BYTES - 1;
        assert_eq!(h.update(b"a"), Ok(()));
        assert_eq!(
            h.update(b"b"),
            Err(Sha1Error::MessageTooLong {
                processed: MAX_MESSAGE_BYTES,
                appended: 1,
                maximum: MAX_MESSAGE_BYTES,
            })
        );
        assert_eq!(h.total_len, MAX_MESSAGE_BYTES);
        assert_eq!(h.update(b""), Ok(()));
    }
}
