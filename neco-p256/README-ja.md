# neco-p256

[English](README.md)

neco-p256 は、楕円曲線 P-256 による ECDSA で、ハッシュ値に署名し、署名を検証する crate です。

- 曲線: NIST が定める P-256 ( secp256r1 )
- 署名の成分 s の範囲: 署名では、s を曲線の位数の半分以下 ( low-S ) に正規化し、検証では、s が半分を超える署名 ( high-S ) を拒否する
- 公開鍵の形式: SEC1 の圧縮形式。y 座標の偶奇を示す 1 バイトの接頭辞と、32 バイトの x 座標から成る 33 バイト
- 全て safe Rust ( コンパイラがメモリ安全性を検査する範囲の Rust ) で実装

署名に使う演算は、三つの crate に分けて実装しています。

- 素体 ( Fp ) の演算: `neco-galois`
- P-256 の曲線の定数と、曲線点の演算 ( 加算、2 倍算、スカラー倍算、SEC1 の形式との相互変換 ) : この crate
- RFC 6979 による ECDSA のノンスの導出: `neco-sha2`

## feature

| feature | 既定 | 有効にするもの |
|---------|------|----------------|
| `std` | 有効 | 標準ライブラリへのリンク ( 依存する crate を含む ) と `alloc` |
| `alloc` | 有効 ( `std` 経由 ) | 16 進数の文字列 ( hex 文字列 ) との変換 |
| `getrandom` | 有効 | OS の乱数源による鍵の生成 |

`SecretKey::generate_with_rng` は、呼び出し側が渡すクロージャ ( 受け取ったバッファを乱数のバイト列で埋める関数 ) から鍵を生成します。OS の乱数源が無い組み込み環境では、この関数で鍵を生成できます。

## 使い方

署名と検証の例です。

```rust
use neco_p256::{EcdsaSignature, P256Error, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate()?;
    let public = secret.public_key()?;
    let hash: [u8; 32] = [0x42; 32]; // SHA-256 のハッシュ値

    let sig: EcdsaSignature = secret.sign_ecdsa_prehash(hash)?;
    public.verify_ecdsa_prehash(hash, &sig)?;
    Ok(())
}
```

鍵は hex 文字列とも変換できます。この変換には `alloc` が必要です。

```rust
use neco_p256::{P256Error, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate()?;
    let hex = secret.to_hex()?;
    let restored = SecretKey::from_hex(&hex)?;
    assert_eq!(secret, restored);
    Ok(())
}
```

公開鍵は、SEC1 の圧縮形式のバイト列へ変換し、元の値へ復元できます。

```rust
use neco_p256::{P256Error, PublicKey, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate()?;
    let public = secret.public_key()?;
    let bytes: [u8; 33] = public.to_sec1_bytes();
    let restored = PublicKey::from_sec1_bytes(&bytes)?;
    assert_eq!(public, restored);
    Ok(())
}
```

呼び出し側が渡すクロージャから鍵を生成する例です。

```rust
use neco_p256::{P256Error, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate_with_rng(&mut |bytes: &mut [u8]| {
        bytes.fill(0x7a); // 実際のクロージャは予測できないバイト列を書き込む
        Ok(())
    })?;
    let _ = secret;
    Ok(())
}
```

## API

`SecretKey` と `PublicKey` の値は、入力を検証する構築関数だけで作られます。

### `SecretKey`

| メソッド | 説明 |
|---------|------|
| `generate() -> Result<Self, P256Error>` | OS の乱数源から鍵を生成する |
| `generate_with_rng(rng: &mut F) -> Result<Self, P256Error>` | 呼び出し側が渡すクロージャから鍵を生成する |
| `from_bytes(bytes: [u8; 32]) -> Result<Self, P256Error>` | 32 バイト配列から作る |
| `from_hex(hex: &str) -> Result<Self, P256Error>` | 64 文字の hex 文字列から作る |
| `to_bytes() -> [u8; 32]` | 32 バイト配列を返す |
| `to_hex() -> Result<String, P256Error>` | hex 文字列を返す |
| `public_key() -> Result<PublicKey, P256Error>` | 対応する公開鍵を導出する |
| `sign_ecdsa_prehash(digest32: [u8; 32]) -> Result<EcdsaSignature, P256Error>` | RFC 6979 のノンスで署名し、low-S に正規化する |

### `PublicKey`

| メソッド | 説明 |
|---------|------|
| `from_sec1_bytes(bytes: &[u8]) -> Result<Self, P256Error>` | SEC1 の圧縮形式から作る |
| `from_hex(hex: &str) -> Result<Self, P256Error>` | 66 文字の hex 文字列から作る |
| `to_sec1_bytes() -> [u8; 33]` | SEC1 の圧縮形式のバイト列を返す |
| `to_hex() -> Result<String, P256Error>` | hex 文字列を返す |
| `verify_ecdsa_prehash(digest32: [u8; 32], sig: &EcdsaSignature) -> Result<(), P256Error>` | high-S の署名を拒否して検証する |

### `EcdsaSignature`

32 バイトの r と 32 バイトの s を連結した、64 バイト固定長 ( raw compact ) の ECDSA 署名です。

| メソッド | 説明 |
|---------|------|
| `from_bytes(bytes: [u8; 64]) -> Self` | 64 バイト配列から作る |
| `from_hex(hex: &str) -> Result<Self, P256Error>` | 128 文字の hex 文字列から作る |
| `to_bytes() -> [u8; 64]` | 64 バイト配列を返す |
| `to_hex() -> Result<String, P256Error>` | hex 文字列を返す |

### `P256Error`

| バリアント | 説明 |
|-----------|------|
| `Field(FieldError)` | `neco-galois` の素体の演算が失敗した |
| `Nonce(Rfc6979Error)` | `neco-sha2` による RFC 6979 のノンスの導出が失敗した |
| `RandomUnavailable` | OS の乱数源が失敗を返した |
| `CapacityOverflow { input_len }` | 入力の `input_len` バイトから求めた hex 文字列の長さが、扱える範囲を超えた |
| `AllocationFailed { required }` | hex の変換で `required` バイトの確保に失敗した |
| `InvalidSecretKey` | 秘密鍵が範囲外である、または公開鍵を導出できない |
| `InvalidPublicKey` | 公開鍵のバイト列の長さ、接頭辞、x 座標の範囲のいずれかが不正であるか、曲線上の点に復元できない |
| `InvalidSignature` | 検証が失敗した、または署名の生成で有効な値が得られなかった |
| `InvalidHex(&'static str)` | hex 文字列の長さまたは文字が不正 |

## ライセンス

MIT
