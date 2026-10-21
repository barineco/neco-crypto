const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn gamma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn gamma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&block[i * 4..i * 4 + 4]);
        w[i] = u32::from_be_bytes(bytes);
    }
    for i in 16..64 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let t1 = h
            .wrapping_add(sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-256 が受け付けるメッセージの最大のバイト数。RFC 6234 はメッセージ長を 2^64 ビット未満と定める。
pub const MAX_MESSAGE_BYTES: u64 = (1 << 61) - 1;

/// SHA-256 の入力の失敗。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha256Error {
    /// 追加した入力により、メッセージ長が `maximum` バイトを超える。
    MessageTooLong {
        processed: u64,
        appended: usize,
        maximum: u64,
    },
}

impl core::fmt::Display for Sha256Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MessageTooLong {
                processed,
                appended,
                maximum,
            } => write!(
                f,
                "SHA-256 message exceeds {maximum} bytes: {processed} bytes processed, {appended} bytes appended"
            ),
        }
    }
}

impl core::error::Error for Sha256Error {}

/// RFC 6234 と FIPS 180-4 に基づく SHA-256 の状態。入力を順に追加し、最後に 32 バイトのハッシュ値を得る。
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
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
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha256Error> {
        let appended = u64::try_from(data.len()).ok();
        self.total_len = match appended.and_then(|n| self.total_len.checked_add(n)) {
            Some(total) if total <= MAX_MESSAGE_BYTES => total,
            _ => {
                return Err(Sha256Error::MessageTooLong {
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

    /// パディングを施し、32 バイトのハッシュ値を返す。`self` を消費する。
    pub fn finalize(mut self) -> [u8; 32] {
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

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// 入力全体の SHA-256 のハッシュ値を一度に計算する。失敗の条件は `update` と同じ。
    pub fn digest(data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        let mut h = Self::new();
        h.update(data)?;
        Ok(h.finalize())
    }

    pub(crate) fn with_prefix(prefix: &[u8; 64]) -> Self {
        let mut h = Self::new();
        h.total_len = 64;
        h.absorb(prefix);
        h
    }

    pub(crate) fn digest_prefixed<const N: usize>(prefix: &[u8; 64], data: &[u8; N]) -> [u8; 32] {
        const {
            assert!(64 + N as u64 <= MAX_MESSAGE_BYTES);
        }
        let mut h = Self::new();
        h.total_len = 64 + N as u64;
        h.absorb(prefix);
        h.absorb(data);
        h.finalize()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::String, vec};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn empty() {
        assert_eq!(
            hex(&Sha256::digest(b"").unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex(&Sha256::digest(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq() {
        assert_eq!(
            hex(
                &Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
                    .unwrap()
            ),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu(
    ) {
        assert_eq!(
            hex(&Sha256::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").unwrap()),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn million_a() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&Sha256::digest(&data).unwrap()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_equals_oneshot() {
        let data = b"hello world this is a test of streaming vs oneshot hashing";
        let oneshot = Sha256::digest(data).unwrap();
        let mut h = Sha256::new();
        for chunk in data.chunks(7) {
            h.update(chunk).unwrap();
        }
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn single_byte() {
        assert_eq!(
            hex(&Sha256::digest(b"\xbd").unwrap()),
            "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b"
        );
    }

    #[test]
    fn two_bytes() {
        assert_eq!(
            hex(&Sha256::digest(b"\xc9\x8c\x8e\x55").unwrap()),
            "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504"
        );
    }

    #[test]
    fn block_boundary_55_bytes() {
        let data = vec![0x61u8; 55];
        let result = Sha256::digest(&data).unwrap();
        let mut h = Sha256::new();
        h.update(&data).unwrap();
        assert_eq!(h.finalize(), result);
    }

    #[test]
    fn block_boundary_56_bytes() {
        let data = vec![0x61u8; 56];
        let result = Sha256::digest(&data).unwrap();
        let mut h = Sha256::new();
        h.update(&data[..28]).unwrap();
        h.update(&data[28..]).unwrap();
        assert_eq!(h.finalize(), result);
    }

    #[test]
    fn nist_two_block_message() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(msg.len(), 56);
        assert_eq!(
            hex(&Sha256::digest(msg).unwrap()),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn message_length_limit() {
        let mut h = Sha256::new();
        h.total_len = MAX_MESSAGE_BYTES - 1;
        assert_eq!(h.update(b"a"), Ok(()));
        assert_eq!(
            h.update(b"b"),
            Err(Sha256Error::MessageTooLong {
                processed: MAX_MESSAGE_BYTES,
                appended: 1,
                maximum: MAX_MESSAGE_BYTES,
            })
        );
        assert_eq!(h.total_len, MAX_MESSAGE_BYTES);
        assert_eq!(h.update(b""), Ok(()));
    }
}
