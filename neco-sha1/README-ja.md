# neco-sha1

[English](README.md)

neco-sha1 は、RFC 3174 に準拠する SHA-1 のハッシュ関数を実装した crate です。

この crate は、SHA-1 を要求する既存のプロトコルとの相互運用に使います。SHA-1 の衝突耐性には既知の弱点があります。

このため、衝突耐性が必要な新しい用途には、[neco-sha2](https://docs.rs/neco-sha2) の SHA-256 のような現代的なハッシュ関数が適しています。

## 使い方

```rust
use neco_sha1::{Sha1, Sha1Error};

fn hash_examples() -> Result<(), Sha1Error> {
    // 一度に計算する
    let hash = Sha1::digest(b"hello")?;

    // 分割した入力を順に渡す
    let mut h = Sha1::new();
    h.update(b"hel")?;
    h.update(b"lo")?;
    assert_eq!(h.finalize(), hash);
    Ok(())
}
```

`update` は、任意の長さの断片で何度でも呼び出せます。`finalize` は状態を消費し、20 バイトのハッシュ値を返します。

RFC 3174 がメッセージ長を 2^64 ビット未満と定めているため、受け付ける入力の上限は、定数 `MAX_MESSAGE_BYTES` が示す 2^61 - 1 バイトです。

上限を超える入力に対して `Sha1Error::MessageTooLong` を返す条件は、関数ごとに異なります。

- `update`: 入力の累計が上限を超える場合。失敗を返した後も、状態は呼び出し前のまま保たれる
- `digest`: 一度に渡した入力が上限を超える場合

## feature

| feature | 有効にするもの |
|---------|----------------|
| `std` ( 既定 ) | 標準ライブラリへのリンク |

ハッシュの計算は、`core` と固定長のバッファだけで実装しています。このため、既定の feature を無効にすると、組み込み環境やベアメタル向けの `no_std` 構成でビルドできます。

## ライセンス

MIT
