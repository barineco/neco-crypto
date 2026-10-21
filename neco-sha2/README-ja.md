# neco-sha2

[English](README.md)

neco-sha2 は、SHA-256 のハッシュ関数と、それを基にした認証、鍵導出、ノンスの導出を実装した crate です。

- SHA-256: ハッシュ関数。RFC 6234 と FIPS 180-4 に準拠
- HMAC-SHA256: SHA-256 を使う、鍵付きのメッセージ認証コード。RFC 2104 に準拠
- HKDF-SHA256: HMAC-SHA256 を使う鍵導出関数。RFC 5869 に準拠
- RFC 6979 の決定論的ノンス: ECDSA などの署名で一度だけ使う秘密の値 ( ノンス ) を、秘密鍵とメッセージのハッシュ値から導出する。入力と出力はバイト配列

実装には、Rust に組み込みの `core` と `alloc` だけを使います。

## 使い方

```rust
use neco_sha2::{Hkdf, Hmac, Sha256};

fn examples() -> Result<(), Box<dyn std::error::Error>> {
    // SHA-256 を一度に計算する
    let hash = Sha256::digest(b"hello")?;

    // SHA-256 に分割した入力を順に渡す
    let mut h = Sha256::new();
    h.update(b"hel")?;
    h.update(b"lo")?;
    assert_eq!(h.finalize(), hash);

    // HMAC-SHA256
    let mut h = Hmac::new(b"key")?;
    h.update(b"message")?;
    let mac = h.finalize();

    // HKDF-SHA256
    let prk = Hkdf::extract(b"salt", b"input keying material")?;
    let okm = prk.expand(b"info", 32)?;
    Ok(())
}
```

分割した入力を渡す関数は、ハッシュと HMAC で戻り値が異なり、呼び出し方も変わります。

```text
Sha256::update(&mut self, data: &[u8]) -> Result<(), Sha256Error>
Hmac::update(&mut self, data: &[u8]) -> Result<&mut Self, Sha256Error>
Hmac::finalize(self) -> [u8; 32]
```

- `Sha256::update`: 成功時の戻り値が `()` のため、呼び出しを文ごとに分ける
- `Hmac::update`: 成功時に自身への参照を返すため、`?` を挟んで呼び出しを連鎖できる
- `Hmac::finalize`: 値を消費するため、連鎖とは別の文で呼ぶ

## 入力長の上限

RFC 6234 が SHA-256 のメッセージ長を 2^64 ビット未満と定めているため、受け付ける入力の上限は、定数 `MAX_MESSAGE_BYTES` が示す 2^61 - 1 バイトです。

入力が上限を超えると `Sha256Error::MessageTooLong` が返ります。上限と比べる入力の長さは、関数によって変わります。

- `Sha256::update`: 入力の累計が上限を超える場合。失敗を返した後も、状態は呼び出し前のまま保たれる
- `Sha256::digest`: 一度に渡した入力が上限を超える場合

HMAC の内側のハッシュは、64 バイトの鍵のブロックに入力を連結して計算します。また、64 バイトを超える鍵は、SHA-256 でハッシュ値へ変換してから使います。このため、鍵の上限と入力の上限は異なる値です。

- 鍵: `MAX_MESSAGE_BYTES` と同じ
- 入力: 累計で、`MAX_MESSAGE_BYTES` から 64 を引いた値

HMAC の関数も、鍵か入力がそれぞれの上限を超えると `Sha256Error::MessageTooLong` を返します。

- `Hmac::new`: 鍵が上限を超える
- `Hmac::update`: 入力の累計が上限を超える
- `Hmac::mac`: 鍵または入力が上限を超える

## HKDF の出力長と失敗

導出した鍵材料は、呼び出し側のバッファへ書き込むか、確保したバッファで受け取るかを選べます。

- `Prk::expand_into`: 呼び出し側のバッファだけを使って書き込む
- `Prk::expand`: 確保したバッファで結果を返す。feature の `alloc` が必要

```rust
use neco_sha2::{Hkdf, HkdfError};

fn derive() -> Result<(), HkdfError> {
    let prk = Hkdf::extract(b"salt", b"input keying material")?;

    let mut okm = [0u8; 32];
    prk.expand_into(b"info", &mut okm)?;

    let okm = prk.expand(b"info", 32)?;
    Ok(())
}
```

HKDF の関数は、失敗を `HkdfError` で返します。RFC 5869 は、出力長の上限を 32 バイトのハッシュ長の 255 倍、つまり 8160 バイトと定めています。

- `HkdfError::OutputTooLong { requested, maximum }`: 要求した長さが 8160 バイトを超える
- `HkdfError::AllocationFailed { required }`: 出力バッファの確保に失敗した。`required` は確保を試みたバイト数
- `HkdfError::Hash(Sha256Error)`: HMAC の鍵か入力が上限を超える。抽出では、ソルトが鍵になり、入力の鍵材料が入力になる。展開では、出力の 32 バイトごとに、直前に出力したブロック、付加情報、1 バイトのブロック番号を連結した値が入力になる

## RFC 6979 の決定論的ノンス

`rfc6979::generate_k` は、ECDSA などの署名に使う決定論的なノンスを導出します。対象は位数が 256 ビットの楕円曲線です。呼び出し側は、秘密鍵、メッセージのハッシュ値、曲線の位数を、それぞれビッグエンディアンの 32 バイト配列で渡します。

- 位数 ( `order` ): 最上位ビットが 1 の 256 ビットの値
- 秘密鍵 ( `secret` ): `0 < secret < order` を満たす値
- ハッシュ値 ( `digest` ): `generate_k` が内部で位数を法として縮約する ( bits2octets ) 。呼び出し側は縮約前の値を渡す

戻り値は `Result<[u8; 32], Rfc6979Error>` です。

- `Rfc6979Error::InvalidOrder`: 位数が 256 ビット未満である
- `Rfc6979Error::InvalidSecretKey`: 秘密鍵が 0、または位数以上である

同じ秘密鍵、ハッシュ値、位数からは、常に同じノンスが得られます。

次の例では、秘密鍵を 1 とし、`b"sample"` の SHA-256 のハッシュ値からノンスを導出します。

```rust
use neco_sha2::{rfc6979::generate_k, Sha256};

fn nonce_for_sample(order: &[u8; 32]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let hash = Sha256::digest(b"sample")?;
    Ok(generate_k(&secret, &hash, order)?)
}
```

## feature

| feature | 有効にするもの |
|---------|----------------|
| `std` ( 既定 ) | 標準ライブラリへのリンクと `alloc` |
| `alloc` | `Prk::expand` |

次の型と関数は `core` だけで動作し、どの feature の組み合わせでも使えます。

- `Sha256`
- `Hmac`
- `Hkdf::extract`
- `Prk::expand_into`
- `Prk::from_bytes`
- `Prk::as_bytes`
- `rfc6979::generate_k`

標準ライブラリへのリンクを外すと、組み込み環境やベアメタル向けの `no_std` 構成でビルドできます。

## ライセンス

MIT
