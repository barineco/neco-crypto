//! P-256 の ECDSA による、ハッシュ値への署名と検証を提供します。

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod curve;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::curve::{P256Field, P256Order};
use neco_galois::{FieldContext, FieldError, Fp, KnownPrimeModulus, U256};
use neco_sha2::rfc6979::{generate_k, Rfc6979Error};

type FpField = Fp<P256Field>;

fn curve_a(field: &FieldContext<P256Field>) -> FpField {
    let (a_val, _) = U256::sub(P256Field::MODULUS, U256::from_u64(3));
    field.reduce(a_val)
}

fn curve_b(field: &FieldContext<P256Field>) -> FpField {
    field.reduce(U256::from_be_bytes([
        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86,
        0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2,
        0x60, 0x4b,
    ]))
}

fn generator_x(field: &FieldContext<P256Field>) -> FpField {
    field.reduce(U256::from_be_bytes([
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ]))
}

fn generator_y(field: &FieldContext<P256Field>) -> FpField {
    field.reduce(U256::from_be_bytes([
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ]))
}

fn order_u256() -> U256 {
    P256Order::MODULUS
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AffinePoint {
    x: FpField,
    y: FpField,
}

#[derive(Clone, Copy, Debug)]
struct ProjectivePoint {
    x: FpField,
    y: FpField,
    z: FpField,
    is_infinity: bool,
}

impl ProjectivePoint {
    fn infinity(field: &FieldContext<P256Field>) -> Self {
        ProjectivePoint {
            x: field.zero(),
            y: field.zero(),
            z: field.zero(),
            is_infinity: true,
        }
    }

    fn from_affine(field: &FieldContext<P256Field>, p: AffinePoint) -> Self {
        ProjectivePoint {
            x: p.x,
            y: p.y,
            z: field.one(),
            is_infinity: false,
        }
    }
}

fn point_double(field: &FieldContext<P256Field>, p: ProjectivePoint) -> ProjectivePoint {
    if p.is_infinity {
        return ProjectivePoint::infinity(field);
    }

    let x = p.x;
    let y = p.y;
    let z = p.z;

    let z2 = field.square(z);
    let xmz2 = field.sub(x, z2);
    let xpz2 = field.add(x, z2);
    let m_part = field.mul(xmz2, xpz2);
    let two_m = field.add(m_part, m_part);
    let m = field.add(two_m, m_part);

    let y2 = field.square(y);
    let xy = field.mul(x, y2);
    let two_xy = field.add(xy, xy);
    let s = field.add(two_xy, two_xy);

    let m2 = field.square(m);
    let two_s = field.add(s, s);
    let x_new = field.sub(m2, two_s);

    let s_minus_x = field.sub(s, x_new);
    let my = field.mul(m, s_minus_x);
    let y4 = field.square(y2);
    let eight_y4 = {
        let two = field.add(y4, y4);
        let four = field.add(two, two);
        field.add(four, four)
    };
    let y_new = field.sub(my, eight_y4);

    let yz = field.mul(y, z);
    let z_new = field.add(yz, yz);

    ProjectivePoint {
        x: x_new,
        y: y_new,
        z: z_new,
        is_infinity: false,
    }
}

fn point_add(
    field: &FieldContext<P256Field>,
    p: ProjectivePoint,
    q: ProjectivePoint,
) -> ProjectivePoint {
    if p.is_infinity {
        return q;
    }
    if q.is_infinity {
        return p;
    }

    let x1 = p.x;
    let y1 = p.y;
    let z1 = p.z;
    let x2 = q.x;
    let y2 = q.y;
    let z2 = q.z;

    let z1_sq = field.square(z1);
    let z2_sq = field.square(z2);
    let u1 = field.mul(x1, z2_sq);
    let u2 = field.mul(x2, z1_sq);

    let s1 = field.mul(y1, field.mul(z2, z2_sq));
    let s2 = field.mul(y2, field.mul(z1, z1_sq));

    let h = field.sub(u2, u1);
    let r = field.sub(s2, s1);

    if FpField::is_zero(h) {
        if FpField::is_zero(r) {
            return point_double(field, p);
        } else {
            return ProjectivePoint::infinity(field);
        }
    }

    let h2 = field.square(h);
    let h3 = field.mul(h, h2);
    let u1h2 = field.mul(u1, h2);

    let r2 = field.square(r);
    let two_u1h2 = field.add(u1h2, u1h2);
    let x3 = field.sub(field.sub(r2, h3), two_u1h2);

    let u1h2_minus_x3 = field.sub(u1h2, x3);
    let s1h3 = field.mul(s1, h3);
    let y3 = field.sub(field.mul(r, u1h2_minus_x3), s1h3);

    let z3 = field.mul(h, field.mul(z1, z2));

    ProjectivePoint {
        x: x3,
        y: y3,
        z: z3,
        is_infinity: false,
    }
}

fn to_affine(
    field: &FieldContext<P256Field>,
    p: ProjectivePoint,
) -> Result<Option<AffinePoint>, FieldError> {
    if p.is_infinity {
        return Ok(None);
    }
    let z_inv = field.invert(p.z)?;
    let z_inv2 = field.square(z_inv);
    let z_inv3 = field.mul(z_inv, z_inv2);
    let x = field.mul(p.x, z_inv2);
    let y = field.mul(p.y, z_inv3);
    Ok(Some(AffinePoint { x, y }))
}

fn scalar_mul(field: &FieldContext<P256Field>, k: U256, p: AffinePoint) -> ProjectivePoint {
    let mut r0 = ProjectivePoint::infinity(field);
    let mut r1 = ProjectivePoint::from_affine(field, p);

    for i in (0..256u32).rev() {
        if U256::bit(k, i) {
            r0 = point_add(field, r0, r1);
            r1 = point_double(field, r1);
        } else {
            r1 = point_add(field, r0, r1);
            r0 = point_double(field, r0);
        }
    }
    r0
}

fn is_on_curve(field: &FieldContext<P256Field>, p: AffinePoint) -> bool {
    let x = p.x;
    let y = p.y;
    let a = curve_a(field);
    let b = curve_b(field);

    let y2 = field.square(y);
    let x3 = field.mul(field.square(x), x);
    let ax = field.mul(a, x);
    let rhs = field.add(field.add(x3, ax), b);

    FpField::eq(y2, rhs)
}

fn encode_sec1_compressed(field: &FieldContext<P256Field>, p: AffinePoint) -> [u8; 33] {
    let x_bytes = field.to_u256(p.x).to_be_bytes();
    let y_val = field.to_u256(p.y);
    let prefix = if y_val.l0 & 1 == 1 { 0x03u8 } else { 0x02u8 };
    let mut out = [0u8; 33];
    out[0] = prefix;
    out[1..].copy_from_slice(&x_bytes);
    out
}

fn decode_sec1_compressed(
    field: &FieldContext<P256Field>,
    bytes: &[u8],
) -> Result<Option<AffinePoint>, FieldError> {
    if bytes.len() != 33 {
        return Ok(None);
    }
    let prefix = bytes[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Ok(None);
    }
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[1..]);
    let x_u256 = U256::from_be_bytes(x_bytes);

    if !matches!(
        U256::cmp(x_u256, P256Field::MODULUS),
        core::cmp::Ordering::Less
    ) {
        return Ok(None);
    }

    let x = field.try_from_u256(x_u256)?;
    let a = curve_a(field);
    let b = curve_b(field);

    let x3 = field.mul(field.square(x), x);
    let ax = field.mul(a, x);
    let rhs = field.add(field.add(x3, ax), b);

    let Some(y) = field.sqrt(rhs)? else {
        return Ok(None);
    };
    let y_u256 = field.to_u256(y);

    let y_odd = y_u256.l0 & 1 == 1;
    let want_odd = prefix == 0x03;
    let y_final = if y_odd == want_odd { y } else { field.neg(y) };
    let point = AffinePoint { x, y: y_final };

    if !is_on_curve(field, point) {
        return Ok(None);
    }

    Ok(Some(point))
}

fn normalize_s(s: U256, n: U256) -> U256 {
    let half_n = U256::shr1(n);
    if let core::cmp::Ordering::Greater = U256::cmp(s, half_n) {
        let (ns, _) = U256::sub(n, s);
        ns
    } else {
        s
    }
}

fn ecdsa_sign(secret_bytes: &[u8; 32], digest: &[u8; 32]) -> Result<Option<[u8; 64]>, P256Error> {
    let field = FieldContext::<P256Field>::new()?;
    let scalar_field = FieldContext::<P256Order>::new()?;
    let n = order_u256();
    let g = AffinePoint {
        x: generator_x(&field),
        y: generator_y(&field),
    };

    let d = U256::from_be_bytes(*secret_bytes);
    let nonce = generate_k(secret_bytes, digest, &n.to_be_bytes()).map_err(P256Error::Nonce)?;
    let k = U256::from_be_bytes(nonce);
    let r_proj = scalar_mul(&field, k, g);
    let Some(r_affine) = to_affine(&field, r_proj)? else {
        return Ok(None);
    };

    let rx = field.to_u256(r_affine.x);
    let r = if matches!(U256::cmp(rx, n), core::cmp::Ordering::Less) {
        rx
    } else {
        U256::sub(rx, n).0
    };
    if U256::is_zero(r) {
        return Ok(None);
    }

    let e_scalar = scalar_field.reduce(U256::from_be_bytes(*digest));
    let k_scalar = scalar_field.try_from_u256(k)?;
    let k_inv = scalar_field.invert(k_scalar)?;
    let r_scalar = scalar_field.try_from_u256(r)?;
    let d_scalar = scalar_field.try_from_u256(d)?;

    let rd = scalar_field.mul(r_scalar, d_scalar);
    let e_plus_rd = scalar_field.add(e_scalar, rd);
    let s_scalar = scalar_field.mul(k_inv, e_plus_rd);
    let s = scalar_field.to_u256(s_scalar);

    if U256::is_zero(s) {
        return Ok(None);
    }

    let s = normalize_s(s, n);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r.to_be_bytes());
    out[32..].copy_from_slice(&s.to_be_bytes());
    Ok(Some(out))
}

fn ecdsa_verify(
    pubkey_sec1: &[u8; 33],
    digest: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<bool, P256Error> {
    let field = FieldContext::<P256Field>::new()?;
    let scalar_field = FieldContext::<P256Order>::new()?;
    let n = order_u256();
    let g = AffinePoint {
        x: generator_x(&field),
        y: generator_y(&field),
    };

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig_bytes[32..]);
    let r = U256::from_be_bytes(r_bytes);
    let s = U256::from_be_bytes(s_bytes);

    if U256::is_zero(r) || U256::is_zero(s) {
        return Ok(false);
    }
    if !matches!(U256::cmp(r, n), core::cmp::Ordering::Less)
        || !matches!(U256::cmp(s, n), core::cmp::Ordering::Less)
    {
        return Ok(false);
    }

    let half_n = U256::shr1(n);
    if matches!(U256::cmp(s, half_n), core::cmp::Ordering::Greater) {
        return Ok(false);
    }

    let Some(pubkey) = decode_sec1_compressed(&field, pubkey_sec1)? else {
        return Ok(false);
    };
    let e_scalar = scalar_field.reduce(U256::from_be_bytes(*digest));
    let s_scalar = scalar_field.try_from_u256(s)?;
    let w_scalar = scalar_field.invert(s_scalar)?;
    let r_scalar = scalar_field.try_from_u256(r)?;

    let u1 = scalar_field.to_u256(scalar_field.mul(e_scalar, w_scalar));
    let u2 = scalar_field.to_u256(scalar_field.mul(r_scalar, w_scalar));
    let u1g = scalar_mul(&field, u1, g);
    let u2q = scalar_mul(&field, u2, pubkey);
    let r_point = point_add(&field, u1g, u2q);
    let Some(r_affine) = to_affine(&field, r_point)? else {
        return Ok(false);
    };

    let r_x = field.to_u256(r_affine.x);
    let r_x_mod_n = if matches!(U256::cmp(r_x, n), core::cmp::Ordering::Less) {
        r_x
    } else {
        U256::sub(r_x, n).0
    };

    Ok(U256::cmp(r_x_mod_n, r) == core::cmp::Ordering::Equal)
}

/// P-256 の鍵と署名の生成、復元、検証が返す失敗です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P256Error {
    /// `neco-galois` の素体の演算が失敗しました。
    Field(FieldError),
    /// `neco-sha2` による RFC 6979 のノンスの導出が失敗しました。
    Nonce(Rfc6979Error),
    /// OS の乱数源が失敗を返しました。
    RandomUnavailable,
    /// 入力の `input_len` バイトから求めた hex 文字列の長さが、扱える範囲を超えています。
    CapacityOverflow { input_len: usize },
    /// hex の変換で、`required` バイトの確保に失敗しました。
    AllocationFailed { required: usize },
    /// 秘密鍵が範囲外であるか、公開鍵を導出できません。
    InvalidSecretKey,
    /// 公開鍵のバイト列の長さ、接頭辞、x 座標の範囲のいずれかが不正であるか、曲線上の点に復元できません。
    InvalidPublicKey,
    /// 検証が失敗したか、署名の生成で有効な値が得られませんでした。
    InvalidSignature,
    /// hex 文字列の長さまたは文字が不正です。値は不正の内容を示す文言です。
    InvalidHex(&'static str),
}

impl fmt::Display for P256Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(error) => write!(f, "field arithmetic failed: {error}"),
            Self::Nonce(error) => write!(f, "RFC 6979 nonce generation failed: {error}"),
            Self::RandomUnavailable => f.write_str("random source unavailable"),
            Self::CapacityOverflow { input_len } => {
                write!(f, "hex capacity overflows for input length {input_len}")
            }
            Self::AllocationFailed { required } => {
                write!(f, "allocation failed for {required} bytes")
            }
            Self::InvalidSecretKey => f.write_str("invalid secret key"),
            Self::InvalidPublicKey => f.write_str("invalid public key"),
            Self::InvalidSignature => f.write_str("invalid signature"),
            Self::InvalidHex(message) => f.write_str(message),
        }
    }
}

impl core::error::Error for P256Error {}

impl From<FieldError> for P256Error {
    fn from(error: FieldError) -> Self {
        Self::Field(error)
    }
}

impl From<Rfc6979Error> for P256Error {
    fn from(error: Rfc6979Error) -> Self {
        Self::Nonce(error)
    }
}

#[cfg(feature = "alloc")]
fn hex_encode(bytes: &[u8]) -> Result<String, P256Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let required = bytes
        .len()
        .checked_mul(2)
        .ok_or(P256Error::CapacityOverflow {
            input_len: bytes.len(),
        })?;
    if required > isize::MAX as usize {
        return Err(P256Error::CapacityOverflow {
            input_len: bytes.len(),
        });
    }
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(required)
        .map_err(|_| P256Error::AllocationFailed { required })?;
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

#[cfg(feature = "alloc")]
fn hex_decode(hex: &str) -> Result<Vec<u8>, P256Error> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return Err(P256Error::InvalidHex("odd length"));
    }

    let required = hex.len() / 2;
    let mut out = Vec::new();
    out.try_reserve_exact(required)
        .map_err(|_| P256Error::AllocationFailed { required })?;
    for pair in hex.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

#[cfg(feature = "alloc")]
fn hex_nibble(byte: u8) -> Result<u8, P256Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(P256Error::InvalidHex("invalid character")),
    }
}

fn validate_secret_key(bytes: &[u8; 32]) -> bool {
    let d = U256::from_be_bytes(*bytes);
    if U256::is_zero(d) {
        return false;
    }
    matches!(U256::cmp(d, order_u256()), core::cmp::Ordering::Less)
}

/// P-256 の 32 バイト秘密鍵です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// 呼び出し側が渡した乱数源から有効な秘密鍵を生成します。
    pub fn generate_with_rng<F>(rng: &mut F) -> Result<Self, P256Error>
    where
        F: FnMut(&mut [u8]) -> Result<(), P256Error>,
    {
        loop {
            let mut bytes = [0u8; 32];
            rng(&mut bytes)?;
            if validate_secret_key(&bytes) {
                return Ok(Self { bytes });
            }
        }
    }

    /// OS の乱数源から有効な秘密鍵を生成します。
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Result<Self, P256Error> {
        Self::generate_with_rng(&mut |bytes| {
            getrandom::getrandom(bytes).map_err(|_| P256Error::RandomUnavailable)
        })
    }

    /// 64 文字の hex 文字列から秘密鍵を作ります。値が 0 または曲線の位数以上の場合は失敗します。
    #[cfg(feature = "alloc")]
    pub fn from_hex(hex: &str) -> Result<Self, P256Error> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(P256Error::InvalidHex("expected 64 hex characters"));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(arr)
    }

    /// 32 バイトの配列から秘密鍵を作ります。値が 0 または曲線の位数以上の場合は失敗します。
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, P256Error> {
        if !validate_secret_key(&bytes) {
            return Err(P256Error::InvalidSecretKey);
        }
        Ok(Self { bytes })
    }

    /// 秘密鍵を 64 文字の hex 文字列で返します。
    #[cfg(feature = "alloc")]
    pub fn to_hex(&self) -> Result<String, P256Error> {
        hex_encode(&self.bytes)
    }

    /// 秘密鍵を 32 バイトの配列で返します。
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// 秘密鍵に対応する公開鍵を導出します。
    pub fn public_key(&self) -> Result<PublicKey, P256Error> {
        let field = FieldContext::<P256Field>::new()?;
        let d = U256::from_be_bytes(self.bytes);
        let g = AffinePoint {
            x: generator_x(&field),
            y: generator_y(&field),
        };
        let q_proj = scalar_mul(&field, d, g);
        let q = to_affine(&field, q_proj)?.ok_or(P256Error::InvalidSecretKey)?;
        let sec1_bytes = encode_sec1_compressed(&field, q);
        Ok(PublicKey { sec1_bytes })
    }

    /// RFC 6979 の決定論的ノンスを用い、32 バイトのハッシュ値に対する low-S の ECDSA 署名を生成します。署名を作れない場合は失敗します。
    pub fn sign_ecdsa_prehash(&self, digest32: [u8; 32]) -> Result<EcdsaSignature, P256Error> {
        let sig_bytes = ecdsa_sign(&self.bytes, &digest32)?.ok_or(P256Error::InvalidSignature)?;
        Ok(EcdsaSignature { bytes: sig_bytes })
    }
}

/// SEC1 の圧縮形式による 33 バイトの P-256 公開鍵です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    sec1_bytes: [u8; 33],
}

impl PublicKey {
    /// 66 文字の hex 文字列から公開鍵を作ります。失敗の条件は `from_sec1_bytes` と同じです。
    #[cfg(feature = "alloc")]
    pub fn from_hex(hex: &str) -> Result<Self, P256Error> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 33 {
            return Err(P256Error::InvalidHex("expected 66 hex characters"));
        }
        Self::from_sec1_bytes(&bytes)
    }

    /// SEC1 の圧縮形式の 33 バイトから公開鍵を作ります。入力長、接頭辞、x 座標の範囲が無効な場合、または曲線上の点に復元できない場合は失敗します。
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
        if bytes.len() != 33 {
            return Err(P256Error::InvalidPublicKey);
        }
        let field = FieldContext::<P256Field>::new()?;
        let point = decode_sec1_compressed(&field, bytes)?.ok_or(P256Error::InvalidPublicKey)?;
        let sec1_bytes = encode_sec1_compressed(&field, point);
        Ok(Self { sec1_bytes })
    }

    /// 公開鍵を 66 文字の hex 文字列で返します。
    #[cfg(feature = "alloc")]
    pub fn to_hex(&self) -> Result<String, P256Error> {
        hex_encode(&self.sec1_bytes)
    }

    /// 公開鍵を SEC1 の圧縮形式の 33 バイトで返します。
    pub fn to_sec1_bytes(&self) -> [u8; 33] {
        self.sec1_bytes
    }

    /// 32 バイトのハッシュ値に対する ECDSA 署名を検証します。範囲外の成分を持つ署名や high-S の署名を含め、検証できない署名に対しては失敗します。
    pub fn verify_ecdsa_prehash(
        &self,
        digest32: [u8; 32],
        sig: &EcdsaSignature,
    ) -> Result<(), P256Error> {
        if ecdsa_verify(&self.sec1_bytes, &digest32, &sig.bytes)? {
            Ok(())
        } else {
            Err(P256Error::InvalidSignature)
        }
    }
}

/// 32 バイトの r と 32 バイトの s を連結した、64 バイト固定長 ( raw compact ) の ECDSA 署名です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaSignature {
    bytes: [u8; 64],
}

impl EcdsaSignature {
    /// 128 文字の hex 文字列から署名を作ります。
    #[cfg(feature = "alloc")]
    pub fn from_hex(hex: &str) -> Result<Self, P256Error> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 64 {
            return Err(P256Error::InvalidHex("expected 128 hex characters"));
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }

    /// 64 バイトの配列から署名を作ります。成分の範囲は `PublicKey::verify_ecdsa_prehash` が検査します。
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }

    /// 署名を 128 文字の hex 文字列で返します。
    #[cfg(feature = "alloc")]
    pub fn to_hex(&self) -> Result<String, P256Error> {
        hex_encode(&self.bytes)
    }

    /// 署名を 64 バイトの配列で返します。
    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        SecretKey::from_bytes(bytes).unwrap()
    }

    fn deterministic_rng(bytes: &mut [u8]) -> Result<(), P256Error> {
        bytes.fill(0);
        bytes[31] = 1;
        Ok(())
    }

    fn hex_to_bytes32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn generator_on_curve() {
        let field = FieldContext::<P256Field>::new().unwrap();
        let g = AffinePoint {
            x: generator_x(&field),
            y: generator_y(&field),
        };
        assert!(is_on_curve(&field, g), "generator G must be on P-256 curve");
    }

    #[test]
    fn secret_key_validation() {
        assert!(SecretKey::from_bytes([0u8; 32]).is_err());
        let n_bytes = order_u256().to_be_bytes();
        assert!(SecretKey::from_bytes(n_bytes).is_err());
        let (n_minus_1, _) = U256::sub(order_u256(), U256::ONE);
        assert!(SecretKey::from_bytes(n_minus_1.to_be_bytes()).is_ok());
    }

    #[test]
    fn public_key_derivation_k1() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 1;
        let sk = SecretKey::from_bytes(sk_bytes).unwrap();
        let pk = sk.public_key().unwrap();
        let sec1 = pk.to_sec1_bytes();
        let field = FieldContext::<P256Field>::new().unwrap();
        let gx = field.to_u256(generator_x(&field)).to_be_bytes();
        assert_eq!(&sec1[1..], &gx, "1*G should have generator x");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = test_secret();
        let pk = sk.public_key().unwrap();
        let digest = [0x42u8; 32];
        let sig = sk.sign_ecdsa_prehash(digest).unwrap();
        pk.verify_ecdsa_prehash(digest, &sig).unwrap();
    }

    #[test]
    fn verify_wrong_message_fails() {
        let sk = test_secret();
        let pk = sk.public_key().unwrap();
        let sig = sk.sign_ecdsa_prehash([0x11; 32]).unwrap();
        assert!(pk.verify_ecdsa_prehash([0x22; 32], &sig).is_err());
    }

    #[test]
    fn low_s_normalization() {
        let sk = test_secret();
        let digest = [0x77u8; 32];
        let sig = sk.sign_ecdsa_prehash(digest).unwrap();
        let s = U256::from_be_bytes(sig.to_bytes()[32..].try_into().unwrap());
        let n = order_u256();
        let half_n = U256::shr1(n);
        assert!(
            matches!(
                U256::cmp(s, half_n),
                core::cmp::Ordering::Less | core::cmp::Ordering::Equal
            ),
            "s must be <= n/2"
        );
    }

    #[test]
    fn high_s_rejected_in_verify() {
        let sk = test_secret();
        let pk = sk.public_key().unwrap();
        let digest = [0x77u8; 32];
        let sig = sk.sign_ecdsa_prehash(digest).unwrap();

        let mut bytes = sig.to_bytes();
        let s = U256::from_be_bytes(bytes[32..].try_into().unwrap());
        let n = order_u256();
        let (high_s, _) = U256::sub(n, s);
        bytes[32..].copy_from_slice(&high_s.to_be_bytes());

        let high_s_sig = EcdsaSignature::from_bytes(bytes);
        let half_n = U256::shr1(n);
        if let core::cmp::Ordering::Greater = U256::cmp(high_s, half_n) {
            assert!(
                pk.verify_ecdsa_prehash(digest, &high_s_sig).is_err(),
                "high-S should be rejected"
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn hex_roundtrip() {
        let sk = test_secret();
        let pk = sk.public_key().unwrap();
        let sig = sk.sign_ecdsa_prehash([0x55; 32]).unwrap();

        assert_eq!(SecretKey::from_hex(&sk.to_hex().unwrap()).unwrap(), sk);
        assert_eq!(PublicKey::from_hex(&pk.to_hex().unwrap()).unwrap(), pk);
        assert_eq!(
            EcdsaSignature::from_hex(&sig.to_hex().unwrap()).unwrap(),
            sig
        );
    }

    #[test]
    fn deterministic_signatures() {
        let sk_bytes =
            hex_to_bytes32("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let sk = SecretKey::from_bytes(sk_bytes).unwrap();
        let digest = [0x42u8; 32];
        let sig1 = sk.sign_ecdsa_prehash(digest).unwrap();
        let sig2 = sk.sign_ecdsa_prehash(digest).unwrap();
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn point_double_equals_point_add_self() {
        let field = FieldContext::<P256Field>::new().unwrap();
        let g = AffinePoint {
            x: generator_x(&field),
            y: generator_y(&field),
        };
        let g_proj = ProjectivePoint::from_affine(&field, g);
        let two_g_double = to_affine(&field, point_double(&field, g_proj))
            .unwrap()
            .unwrap();
        let two_g_add = to_affine(&field, point_add(&field, g_proj, g_proj))
            .unwrap()
            .unwrap();
        assert_eq!(field.to_u256(two_g_double.x), field.to_u256(two_g_add.x));
        assert_eq!(field.to_u256(two_g_double.y), field.to_u256(two_g_add.y));
    }

    #[test]
    fn sec1_roundtrip() {
        let sk = test_secret();
        let pk = sk.public_key().unwrap();
        let sec1 = pk.to_sec1_bytes();
        let pk2 = PublicKey::from_sec1_bytes(&sec1).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn caller_rng_generates_core_key() {
        let key = SecretKey::generate_with_rng(&mut deterministic_rng).unwrap();
        assert_eq!(key, test_secret());
    }

    #[test]
    fn caller_rng_failure_is_preserved() {
        let expected = P256Error::InvalidSecretKey;
        let result = SecretKey::generate_with_rng(&mut |_| Err(expected.clone()));
        assert_eq!(result, Err(expected));
    }

    #[test]
    fn unavailable_rng_returns_dedicated_failure() {
        assert_eq!(
            SecretKey::generate_with_rng(&mut |_| Err(P256Error::RandomUnavailable)),
            Err(P256Error::RandomUnavailable)
        );
    }

    #[test]
    fn caller_rng_retries_invalid_scalar() {
        let mut calls = 0usize;
        let key = SecretKey::generate_with_rng(&mut |bytes| {
            calls += 1;
            bytes.fill(0);
            if calls == 2 {
                bytes[31] = 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(key, test_secret());
    }
}
