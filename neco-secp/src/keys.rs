#[cfg(feature = "alloc")]
use crate::hex::{hex_decode, hex_encode};
use crate::{EcdsaSignature, SchnorrSignature, SecpError};

use crate::curve::{Secp256k1Field, Secp256k1Order};
use neco_galois::{FieldContext, Fp, KnownPrimeModulus, U256};
use neco_sha2::rfc6979::generate_k;
use neco_sha2::Sha256;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

type FpField = Fp<Secp256k1Field>;

fn curve_b(field: &FieldContext<Secp256k1Field>) -> FpField {
    field.reduce(U256::from_u64(7))
}

fn generator_x(field: &FieldContext<Secp256k1Field>) -> FpField {
    field.reduce(U256::from_be_bytes([
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ]))
}

fn generator_y(field: &FieldContext<Secp256k1Field>) -> FpField {
    field.reduce(U256::from_be_bytes([
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
        0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10,
        0xD4, 0xB8,
    ]))
}

fn generator(field: &FieldContext<Secp256k1Field>) -> AffinePoint {
    AffinePoint {
        x: generator_x(field),
        y: generator_y(field),
    }
}

fn order_u256() -> U256 {
    Secp256k1Order::MODULUS
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AffinePoint {
    pub(crate) x: FpField,
    pub(crate) y: FpField,
}

#[derive(Clone, Copy, Debug)]
struct ProjectivePoint {
    x: FpField,
    y: FpField,
    z: FpField,
    is_infinity: bool,
}

impl ProjectivePoint {
    fn infinity(field: &FieldContext<Secp256k1Field>) -> Self {
        ProjectivePoint {
            x: field.zero(),
            y: field.zero(),
            z: field.zero(),
            is_infinity: true,
        }
    }

    fn from_affine(field: &FieldContext<Secp256k1Field>, p: AffinePoint) -> Self {
        ProjectivePoint {
            x: p.x,
            y: p.y,
            z: field.one(),
            is_infinity: false,
        }
    }
}

fn point_double(field: &FieldContext<Secp256k1Field>, p: ProjectivePoint) -> ProjectivePoint {
    if p.is_infinity {
        return ProjectivePoint::infinity(field);
    }

    let x = p.x;
    let y = p.y;
    let z = p.z;

    let x2 = field.square(x);
    let two_x2 = field.add(x2, x2);
    let m = field.add(two_x2, x2);

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
    field: &FieldContext<Secp256k1Field>,
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
    field: &FieldContext<Secp256k1Field>,
    p: ProjectivePoint,
) -> Result<Option<AffinePoint>, SecpError> {
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

fn scalar_mul(field: &FieldContext<Secp256k1Field>, k: U256, p: AffinePoint) -> ProjectivePoint {
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

fn is_on_curve(field: &FieldContext<Secp256k1Field>, p: AffinePoint) -> bool {
    let y2 = field.square(p.y);
    let x3 = field.mul(field.square(p.x), p.x);
    let rhs = field.add(x3, curve_b(field));
    FpField::eq(y2, rhs)
}

fn encode_sec1_compressed(field: &FieldContext<Secp256k1Field>, p: AffinePoint) -> [u8; 33] {
    let x_bytes = field.to_u256(p.x).to_be_bytes();
    let y_val = field.to_u256(p.y);
    let prefix = if y_val.l0 & 1 == 1 { 0x03u8 } else { 0x02u8 };
    let mut out = [0u8; 33];
    out[0] = prefix;
    out[1..].copy_from_slice(&x_bytes);
    out
}

fn decode_sec1_compressed(
    field: &FieldContext<Secp256k1Field>,
    bytes: &[u8],
) -> Result<Option<AffinePoint>, SecpError> {
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
        U256::cmp(x_u256, Secp256k1Field::MODULUS),
        core::cmp::Ordering::Less
    ) {
        return Ok(None);
    }

    let x = field.try_from_u256(x_u256)?;
    let b = curve_b(field);
    let x3 = field.mul(field.square(x), x);
    let rhs = field.add(x3, b);
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

fn ecdsa_sign(secret_bytes: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 64], SecpError> {
    let field = FieldContext::<Secp256k1Field>::new()?;
    let scalar_field = FieldContext::<Secp256k1Order>::new()?;
    let n = order_u256();
    let g = generator(&field);
    let d = U256::from_be_bytes(*secret_bytes);
    let k = U256::from_be_bytes(generate_k(secret_bytes, digest, &n.to_be_bytes())?);
    let r_proj = scalar_mul(&field, k, g);
    let r_affine = to_affine(&field, r_proj)?.ok_or(SecpError::InvalidSignature)?;
    let rx = field.to_u256(r_affine.x);
    let r = if let core::cmp::Ordering::Less = U256::cmp(rx, n) {
        rx
    } else {
        let (value, _) = U256::sub(rx, n);
        value
    };
    if U256::is_zero(r) {
        return Err(SecpError::InvalidSignature);
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
        return Err(SecpError::InvalidSignature);
    }

    let s = normalize_s(s, n);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r.to_be_bytes());
    out[32..].copy_from_slice(&s.to_be_bytes());
    Ok(out)
}

fn ecdsa_verify(
    pubkey_sec1: &[u8; 33],
    digest: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<bool, SecpError> {
    let field = FieldContext::<Secp256k1Field>::new()?;
    let scalar_field = FieldContext::<Secp256k1Order>::new()?;
    let n = order_u256();
    let g = generator(&field);

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig_bytes[32..]);
    let r = U256::from_be_bytes(r_bytes);
    let s = U256::from_be_bytes(s_bytes);

    if U256::is_zero(r) || U256::is_zero(s) {
        return Ok(false);
    }
    if !matches!(U256::cmp(r, n), core::cmp::Ordering::Less) {
        return Ok(false);
    }
    if !matches!(U256::cmp(s, n), core::cmp::Ordering::Less) {
        return Ok(false);
    }
    let half_n = U256::shr1(n);
    if let core::cmp::Ordering::Greater = U256::cmp(s, half_n) {
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
    let r_x_mod_n = if let core::cmp::Ordering::Less = U256::cmp(r_x, n) {
        r_x
    } else {
        let (value, _) = U256::sub(r_x, n);
        value
    };

    Ok(U256::cmp(r_x_mod_n, r) == core::cmp::Ordering::Equal)
}

fn tagged_hash(tag: &[u8], data: &[u8]) -> Result<[u8; 32], SecpError> {
    let tag_hash = Sha256::digest(tag)?;
    let mut h = Sha256::new();
    h.update(&tag_hash)?;
    h.update(&tag_hash)?;
    h.update(data)?;
    Ok(h.finalize())
}

fn lift_x(
    field: &FieldContext<Secp256k1Field>,
    x_bytes: &[u8; 32],
) -> Result<Option<AffinePoint>, SecpError> {
    let x_u256 = U256::from_be_bytes(*x_bytes);
    if !matches!(
        U256::cmp(x_u256, Secp256k1Field::MODULUS),
        core::cmp::Ordering::Less
    ) {
        return Ok(None);
    }

    let x = field.try_from_u256(x_u256)?;
    let b = curve_b(field);
    let x3 = field.mul(field.square(x), x);
    let rhs = field.add(x3, b);
    let Some(y) = field.sqrt(rhs)? else {
        return Ok(None);
    };
    let y_u256 = field.to_u256(y);
    let y_final = if y_u256.l0 & 1 == 1 { field.neg(y) } else { y };

    Ok(Some(AffinePoint { x, y: y_final }))
}

fn schnorr_sign_with_aux(
    secret: &[u8; 32],
    digest: &[u8; 32],
    aux: &[u8; 32],
) -> Result<[u8; 64], SecpError> {
    let field = FieldContext::<Secp256k1Field>::new()?;
    let scalar_field = FieldContext::<Secp256k1Order>::new()?;
    let n = order_u256();
    let d0 = U256::from_be_bytes(*secret);
    if U256::is_zero(d0) || !matches!(U256::cmp(d0, n), core::cmp::Ordering::Less) {
        return Err(SecpError::InvalidSecretKey);
    }

    let g = generator(&field);
    let p_proj = scalar_mul(&field, d0, g);
    let p_affine = to_affine(&field, p_proj)?.ok_or(SecpError::InvalidSignature)?;
    let py = field.to_u256(p_affine.y);
    let d = if py.l0 & 1 == 1 {
        let (negated, _) = U256::sub(n, d0);
        negated
    } else {
        d0
    };
    let px_bytes = field.to_u256(p_affine.x).to_be_bytes();

    let t = tagged_hash(b"BIP0340/aux", aux)?;
    let d_bytes = d.to_be_bytes();
    let mut rand = [0u8; 32];
    for index in 0..32 {
        rand[index] = d_bytes[index] ^ t[index];
    }

    let mut nonce_input = [0u8; 96];
    nonce_input[..32].copy_from_slice(&rand);
    nonce_input[32..64].copy_from_slice(&px_bytes);
    nonce_input[64..].copy_from_slice(digest);
    let nonce_hash = tagged_hash(b"BIP0340/nonce", &nonce_input)?;
    let k0 = scalar_field.to_u256(scalar_field.reduce(U256::from_be_bytes(nonce_hash)));
    if U256::is_zero(k0) {
        return Err(SecpError::InvalidSignature);
    }

    let r_proj = scalar_mul(&field, k0, g);
    let r_affine = to_affine(&field, r_proj)?.ok_or(SecpError::InvalidSignature)?;
    let ry = field.to_u256(r_affine.y);
    let k = if ry.l0 & 1 == 1 {
        let (negated, _) = U256::sub(n, k0);
        negated
    } else {
        k0
    };
    let rx_bytes = field.to_u256(r_affine.x).to_be_bytes();

    let mut challenge_input = [0u8; 96];
    challenge_input[..32].copy_from_slice(&rx_bytes);
    challenge_input[32..64].copy_from_slice(&px_bytes);
    challenge_input[64..].copy_from_slice(digest);
    let e_hash = tagged_hash(b"BIP0340/challenge", &challenge_input)?;
    let e_scalar = scalar_field.reduce(U256::from_be_bytes(e_hash));
    let d_scalar = scalar_field.try_from_u256(d)?;
    let k_scalar = scalar_field.try_from_u256(k)?;
    let s = scalar_field.to_u256(scalar_field.add(k_scalar, scalar_field.mul(e_scalar, d_scalar)));

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&rx_bytes);
    signature[32..].copy_from_slice(&s.to_be_bytes());
    Ok(signature)
}

fn schnorr_verify(
    pubkey_x: &[u8; 32],
    digest: &[u8; 32],
    sig: &[u8; 64],
) -> Result<bool, SecpError> {
    let field = FieldContext::<Secp256k1Field>::new()?;
    let scalar_field = FieldContext::<Secp256k1Order>::new()?;
    let n = order_u256();

    let mut rx_bytes = [0u8; 32];
    rx_bytes.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let s = U256::from_be_bytes(s_bytes);
    if !matches!(U256::cmp(s, n), core::cmp::Ordering::Less) {
        return Ok(false);
    }
    let s = scalar_field.to_u256(scalar_field.try_from_u256(s)?);
    let Some(public_key) = lift_x(&field, pubkey_x)? else {
        return Ok(false);
    };

    let mut challenge_input = [0u8; 96];
    challenge_input[..32].copy_from_slice(&rx_bytes);
    challenge_input[32..64].copy_from_slice(pubkey_x);
    challenge_input[64..].copy_from_slice(digest);
    let e_hash = tagged_hash(b"BIP0340/challenge", &challenge_input)?;
    let e = scalar_field.to_u256(scalar_field.reduce(U256::from_be_bytes(e_hash)));
    let g = generator(&field);
    let sg = scalar_mul(&field, s, g);
    let (neg_e, _) = U256::sub(n, e);
    let neg_ep = scalar_mul(&field, neg_e, public_key);
    let r_proj = point_add(&field, sg, neg_ep);
    let Some(r_affine) = to_affine(&field, r_proj)? else {
        return Ok(false);
    };
    if field.to_u256(r_affine.y).l0 & 1 == 1 {
        return Ok(false);
    }

    let rx = U256::from_be_bytes(rx_bytes);
    Ok(field.to_u256(r_affine.x) == rx)
}

#[cfg(any(feature = "nip04", feature = "nip44"))]
pub(crate) fn ecdh_raw(secret: &[u8; 32], pubkey: AffinePoint) -> Result<[u8; 32], SecpError> {
    let field = FieldContext::<Secp256k1Field>::new()?;
    let d = U256::from_be_bytes(*secret);
    let n = order_u256();
    if U256::is_zero(d) || !matches!(U256::cmp(d, n), core::cmp::Ordering::Less) {
        return Err(SecpError::InvalidSecretKey);
    }
    let shared = scalar_mul(&field, d, pubkey);
    let shared = to_affine(&field, shared)?.ok_or(SecpError::InvalidPublicKey)?;
    Ok(field.to_u256(shared.x).to_be_bytes())
}

fn validate_secret_key(bytes: &[u8; 32]) -> bool {
    let d = U256::from_be_bytes(*bytes);
    if U256::is_zero(d) {
        return false;
    }
    matches!(U256::cmp(d, order_u256()), core::cmp::Ordering::Less)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// secp256k1 の 32 バイト秘密鍵。
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// OS の乱数源から有効な秘密鍵を生成する。乱数を取得できない場合は失敗する。
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Result<Self, SecpError> {
        Self::generate_with_rng(&mut |bytes| {
            getrandom::getrandom(bytes).map_err(|_| SecpError::RandomUnavailable)
        })
    }

    /// 呼び出し側が渡すバイト供給関数から有効な秘密鍵を生成する。供給関数が返したエラーはそのまま返す。
    pub fn generate_with_rng<F>(fill: &mut F) -> Result<Self, SecpError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        loop {
            let mut bytes = [0u8; 32];
            fill(&mut bytes)?;
            if validate_secret_key(&bytes) {
                return Ok(Self { bytes });
            }
        }
    }

    /// 64 桁の 16 進文字列から秘密鍵を作る。文字列の長さや 16 進文字が不正な場合、または値が 0 もしくは曲線の位数以上の場合は失敗する。
    #[cfg(feature = "alloc")]
    pub fn from_hex(hex: &str) -> Result<Self, SecpError> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(SecpError::InvalidHex("expected 64 hex characters"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(arr)
    }

    /// 32 バイトの配列から秘密鍵を作る。値が 0 または曲線の位数以上の場合は失敗する。
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecpError> {
        if !validate_secret_key(&bytes) {
            return Err(SecpError::InvalidSecretKey);
        }
        Ok(Self { bytes })
    }

    /// 秘密鍵を小文字の 16 進文字列で返す。
    #[cfg(feature = "alloc")]
    pub fn to_hex(&self) -> Result<String, SecpError> {
        hex_encode(&self.bytes)
    }

    /// 秘密鍵の 32 バイトを返す。
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// 圧縮 SEC1 公開鍵を導出する。座標の計算で有限体の演算が失敗した場合は `SecpError::Field` を返す。
    pub fn public_key(&self) -> Result<PublicKey, SecpError> {
        let field = FieldContext::<Secp256k1Field>::new()?;
        let d = U256::from_be_bytes(self.bytes);
        let g = generator(&field);
        let q_proj = scalar_mul(&field, d, g);
        let q = to_affine(&field, q_proj)?.ok_or(SecpError::InvalidSecretKey)?;
        let sec1_bytes = encode_sec1_compressed(&field, q);
        Ok(PublicKey { sec1_bytes })
    }

    /// x-only 公開鍵を導出する。座標の計算で有限体の演算が失敗した場合は `SecpError::Field` を返す。
    pub fn xonly_public_key(&self) -> Result<XOnlyPublicKey, SecpError> {
        let field = FieldContext::<Secp256k1Field>::new()?;
        let d = U256::from_be_bytes(self.bytes);
        let g = generator(&field);
        let q_proj = scalar_mul(&field, d, g);
        let q = to_affine(&field, q_proj)?.ok_or(SecpError::InvalidSecretKey)?;
        let x_bytes = field.to_u256(q.x).to_be_bytes();
        Ok(XOnlyPublicKey { bytes: x_bytes })
    }

    /// OS の乱数源から得た補助乱数で、32 バイトのハッシュ値へ BIP340 Schnorr 署名を付与する。署名を作れない場合は失敗する。
    #[cfg(feature = "getrandom")]
    pub fn sign_schnorr_prehash(&self, digest32: [u8; 32]) -> Result<SchnorrSignature, SecpError> {
        self.sign_schnorr_prehash_with_rng(digest32, &mut |bytes| {
            getrandom::getrandom(bytes).map_err(|_| SecpError::RandomUnavailable)
        })
    }

    /// 呼び出し側が渡す補助乱数で、32 バイトのハッシュ値へ BIP340 Schnorr 署名を付与する。
    pub fn sign_schnorr_prehash_with_aux(
        &self,
        digest32: [u8; 32],
        aux: [u8; 32],
    ) -> Result<SchnorrSignature, SecpError> {
        let bytes = schnorr_sign_with_aux(&self.bytes, &digest32, &aux)?;
        Ok(SchnorrSignature { bytes })
    }

    /// バイト供給関数から得た補助乱数で、32 バイトのハッシュ値へ BIP340 Schnorr 署名を付与する。
    pub fn sign_schnorr_prehash_with_rng<F>(
        &self,
        digest32: [u8; 32],
        fill: &mut F,
    ) -> Result<SchnorrSignature, SecpError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let mut aux = [0u8; 32];
        fill(&mut aux)?;
        self.sign_schnorr_prehash_with_aux(digest32, aux)
    }

    /// 補助乱数を全零にした決定的な BIP340 Schnorr 署名を返す。同じ秘密鍵とハッシュ値からは同じ署名を返す。フォールト攻撃 ( 署名の演算に誤りを起こさせて秘密鍵を推定する攻撃 ) への対策には、補助乱数を使う [`Self::sign_schnorr_prehash_with_rng`] などで署名する。
    pub fn sign_schnorr_prehash_deterministic(
        &self,
        digest32: [u8; 32],
    ) -> Result<SchnorrSignature, SecpError> {
        self.sign_schnorr_prehash_with_aux(digest32, [0u8; 32])
    }

    /// 32 バイトのハッシュ値に対する ECDSA 署名を返す。署名の s は、曲線の位数の半分以下に正規化する ( low-S ) 。署名を作れない場合は失敗する。
    pub fn sign_ecdsa_prehash(&self, digest32: [u8; 32]) -> Result<EcdsaSignature, SecpError> {
        let bytes = ecdsa_sign(&self.bytes, &digest32)?;
        Ok(EcdsaSignature { bytes })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// 圧縮 SEC1 形式の secp256k1 公開鍵。
pub struct PublicKey {
    sec1_bytes: [u8; 33],
}

impl PublicKey {
    /// 66 桁の 16 進文字列から圧縮 SEC1 公開鍵を作る。形式または曲線点が無効な場合は失敗する。
    #[cfg(feature = "alloc")]
    pub fn from_hex(hex: &str) -> Result<Self, SecpError> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 33 {
            return Err(SecpError::InvalidHex("expected 66 hex characters"));
        }
        Self::from_sec1_bytes(&bytes)
    }

    /// 33 バイトの圧縮 SEC1 値から公開鍵を作る。接頭辞、座標、または曲線点が無効な場合は失敗する。
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, SecpError> {
        if bytes.len() != 33 {
            return Err(SecpError::InvalidPublicKey);
        }
        let field = FieldContext::<Secp256k1Field>::new()?;
        let point = decode_sec1_compressed(&field, bytes)?.ok_or(SecpError::InvalidPublicKey)?;
        let sec1_bytes = encode_sec1_compressed(&field, point);
        Ok(Self { sec1_bytes })
    }

    #[cfg(feature = "alloc")]
    pub fn to_hex(&self) -> Result<String, SecpError> {
        hex_encode(&self.sec1_bytes)
    }

    pub fn to_sec1_bytes(&self) -> [u8; 33] {
        self.sec1_bytes
    }

    /// 32 バイトのハッシュ値に対する ECDSA 署名を検証する。署名が無効な場合は失敗する。
    pub fn verify_ecdsa_prehash(
        &self,
        digest32: [u8; 32],
        sig: &EcdsaSignature,
    ) -> Result<(), SecpError> {
        if ecdsa_verify(&self.sec1_bytes, &digest32, &sig.bytes)? {
            Ok(())
        } else {
            Err(SecpError::InvalidSignature)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// x 座標だけで表す BIP340 の secp256k1 公開鍵で、x-only 公開鍵と呼ぶ。
pub struct XOnlyPublicKey {
    bytes: [u8; 32],
}

impl XOnlyPublicKey {
    /// 64 桁の 16 進文字列から x-only 公開鍵を作る。文字列の長さや 16 進文字が不正な場合、または x 座標が曲線上の点を表さない場合は失敗する。
    #[cfg(feature = "alloc")]
    pub fn from_hex(hex: &str) -> Result<Self, SecpError> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(SecpError::InvalidHex("expected 64 hex characters"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(arr)
    }

    /// 32 バイトの x 座標から公開鍵を作る。曲線点を復元できない場合は失敗する。
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecpError> {
        let field = FieldContext::<Secp256k1Field>::new()?;
        lift_x(&field, &bytes)?.ok_or(SecpError::InvalidPublicKey)?;
        Ok(Self { bytes })
    }

    #[cfg(feature = "alloc")]
    pub fn to_hex(&self) -> Result<String, SecpError> {
        hex_encode(&self.bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// 32 バイトのハッシュ値に対する BIP340 署名を検証する。署名が無効な場合は失敗する。
    pub fn verify_schnorr_prehash(
        &self,
        digest32: [u8; 32],
        sig: &SchnorrSignature,
    ) -> Result<(), SecpError> {
        if schnorr_verify(&self.bytes, &digest32, &sig.bytes)? {
            Ok(())
        } else {
            Err(SecpError::InvalidSignature)
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for XOnlyPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = self.to_hex().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&encoded)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for XOnlyPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        Self::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

#[cfg(any(feature = "nip04", feature = "nip44"))]
pub(crate) fn decode_xonly_pubkey(pubkey: &XOnlyPublicKey) -> Result<AffinePoint, SecpError> {
    let field = FieldContext::<Secp256k1Field>::new()?;
    lift_x(&field, &pubkey.bytes)?.ok_or(SecpError::InvalidPublicKey)
}
