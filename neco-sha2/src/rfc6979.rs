use crate::Hmac;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rfc6979Error {
    InvalidOrder,
    InvalidSecretKey,
}

impl fmt::Display for Rfc6979Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrder => f.write_str("RFC 6979 requires a 256-bit group order"),
            Self::InvalidSecretKey => {
                f.write_str("secret key must be between zero and the group order")
            }
        }
    }
}

impl core::error::Error for Rfc6979Error {}

pub fn generate_k(
    secret: &[u8; 32],
    digest: &[u8; 32],
    order: &[u8; 32],
) -> Result<[u8; 32], Rfc6979Error> {
    if order[0] & 0x80 == 0 {
        return Err(Rfc6979Error::InvalidOrder);
    }
    if secret.iter().all(|b| *b == 0) || secret >= order {
        return Err(Rfc6979Error::InvalidSecretKey);
    }
    let mut h1 = *digest;
    if digest >= order {
        let mut borrow = false;
        for (byte, modulus) in h1.iter_mut().rev().zip(order.iter().rev()) {
            let (value, first) = byte.overflowing_sub(*modulus);
            let (value, second) = value.overflowing_sub(u8::from(borrow));
            *byte = value;
            borrow = first || second;
        }
    }
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    k = update(&k, &v, secret, &h1, 0x00);
    v = Hmac::mac_fixed(&k, &v);
    k = update(&k, &v, secret, &h1, 0x01);
    v = Hmac::mac_fixed(&k, &v);
    loop {
        v = Hmac::mac_fixed(&k, &v);
        if v.iter().any(|byte| *byte != 0) && &v < order {
            return Ok(v);
        }
        let mut data = [0u8; 33];
        data[..32].copy_from_slice(&v);
        k = Hmac::mac_fixed(&k, &data);
        v = Hmac::mac_fixed(&k, &v);
    }
}

fn update(
    k: &[u8; 32],
    v: &[u8; 32],
    secret: &[u8; 32],
    digest: &[u8; 32],
    marker: u8,
) -> [u8; 32] {
    let mut data = [0u8; 97];
    data[..32].copy_from_slice(v);
    data[32] = marker;
    data[33..65].copy_from_slice(secret);
    data[65..].copy_from_slice(digest);
    Hmac::mac_fixed(k, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sha256;

    fn bytes(s: &str) -> [u8; 32] {
        let mut out = [0; 32];
        for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        out
    }

    fn order() -> [u8; 32] {
        bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    }

    #[test]
    fn rfc6979_appendix_a_2_5_sha256() {
        let secret = bytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        for (message, expected) in [
            (
                b"sample".as_slice(),
                "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
            ),
            (
                b"test".as_slice(),
                "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
            ),
        ] {
            assert_eq!(
                generate_k(&secret, &Sha256::digest(message).unwrap(), &order()).unwrap(),
                bytes(expected)
            );
        }
    }

    #[test]
    fn digest_at_order_reduces_to_zero() {
        let secret = bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let q = order();
        assert_eq!(
            generate_k(&secret, &q, &q),
            generate_k(&secret, &[0; 32], &q)
        );
        let mut next = q;
        next[31] += 1;
        assert_eq!(
            generate_k(&secret, &next, &q),
            generate_k(&secret, &secret, &q)
        );
    }

    #[test]
    fn rejects_invalid_inputs() {
        let q = order();
        assert_eq!(
            generate_k(&[0; 32], &[0; 32], &q),
            Err(Rfc6979Error::InvalidSecretKey)
        );
        assert_eq!(
            generate_k(&q, &[0; 32], &q),
            Err(Rfc6979Error::InvalidSecretKey)
        );
        let mut above_order = q;
        above_order[31] += 1;
        assert_eq!(
            generate_k(&above_order, &[0; 32], &q),
            Err(Rfc6979Error::InvalidSecretKey)
        );
        let mut short_order = [0xff; 32];
        short_order[0] = 0x7f;
        assert_eq!(
            generate_k(&[1; 32], &[0; 32], &short_order),
            Err(Rfc6979Error::InvalidOrder)
        );
        assert_eq!(
            generate_k(&[1; 32], &[0; 32], &[0; 32]),
            Err(Rfc6979Error::InvalidOrder)
        );
    }
}
