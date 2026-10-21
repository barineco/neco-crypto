use crate::sha256::{Sha256, Sha256Error};

const BLOCK_SIZE: usize = 64;

/// RFC 2104 に基づく HMAC-SHA256 の状態。
pub struct Hmac {
    inner: Sha256,
    outer_key: [u8; BLOCK_SIZE],
}

fn pad(key: &[u8; BLOCK_SIZE], byte: u8) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    for (o, k) in out.iter_mut().zip(key) {
        *o = k ^ byte;
    }
    out
}

fn key_block<const K: usize>(key: &[u8; K]) -> [u8; BLOCK_SIZE] {
    const {
        assert!(K <= BLOCK_SIZE);
    }
    let mut k = [0u8; BLOCK_SIZE];
    k[..K].copy_from_slice(key);
    k
}

impl Hmac {
    /// 鍵から HMAC-SHA256 の状態を作る。64 バイトを超える鍵は SHA-256 のハッシュ値へ変換して使う。鍵が `MAX_MESSAGE_BYTES` を超える場合は `Sha256Error` を返す。
    pub fn new(key: &[u8]) -> Result<Self, Sha256Error> {
        let mut k = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            k[..32].copy_from_slice(&Sha256::digest(key)?);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        Ok(Self::from_key_block(&k))
    }

    pub(crate) fn with_key<const K: usize>(key: &[u8; K]) -> Self {
        Self::from_key_block(&key_block(key))
    }

    fn from_key_block(k: &[u8; BLOCK_SIZE]) -> Self {
        Self {
            inner: Sha256::with_prefix(&pad(k, 0x36)),
            outer_key: pad(k, 0x5c),
        }
    }

    /// 入力を追加し、この状態への可変参照を返す。入力の累計が `MAX_MESSAGE_BYTES` から 64 を引いた値を超える場合は `Sha256Error` を返す。
    pub fn update(&mut self, data: &[u8]) -> Result<&mut Self, Sha256Error> {
        self.inner.update(data)?;
        Ok(self)
    }

    /// 状態を消費して 32 バイトの認証コードを返す。
    pub fn finalize(self) -> [u8; 32] {
        Sha256::digest_prefixed(&self.outer_key, &self.inner.finalize())
    }

    /// 鍵と入力から 32 バイトの HMAC-SHA256 認証コードを計算する。失敗の条件は `new` と `update` と同じ。
    pub fn mac(key: &[u8], data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        let mut h = Self::new(key)?;
        h.update(data)?;
        Ok(h.finalize())
    }

    pub(crate) fn mac_fixed<const K: usize, const N: usize>(
        key: &[u8; K],
        data: &[u8; N],
    ) -> [u8; 32] {
        let k = key_block(key);
        let inner = Sha256::digest_prefixed(&pad(&k, 0x36), data);
        Sha256::digest_prefixed(&pad(&k, 0x5c), &inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::String, vec::Vec};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn rfc4231_tc1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        assert_eq!(
            hex(&Hmac::mac(&key, data).unwrap()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_tc2() {
        assert_eq!(
            hex(&Hmac::mac(b"Jefe", b"what do ya want for nothing?").unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_tc3() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        assert_eq!(
            hex(&Hmac::mac(&key, &data).unwrap()),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn rfc4231_tc4() {
        let key: Vec<u8> = (0x01..=0x19u8).collect();
        let data = [0xcdu8; 50];
        assert_eq!(
            hex(&Hmac::mac(&key, &data).unwrap()),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn rfc4231_tc5() {
        let key = [0x0cu8; 20];
        let data = b"Test With Truncation";
        assert_eq!(
            hex(&Hmac::mac(&key, data).unwrap()),
            "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5"
        );
    }

    #[test]
    fn rfc4231_tc6() {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hex(&Hmac::mac(&key, data).unwrap()),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn rfc4231_tc7() {
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        assert_eq!(
            hex(&Hmac::mac(&key, data).unwrap()),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }
}
