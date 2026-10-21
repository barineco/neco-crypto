# neco-base64

[English](README.md)

neco-base64 は、Base64 の符号化と復号を行う crate です。

対応するアルファベットは、RFC 4648 が定める標準のアルファベットと、URL セーフのアルファベット ( 62 番と 63 番の文字に `-` と `_` を使う ) です。

実装には `core` と `alloc` だけを使います。

## 使い方

```rust
use neco_base64::{decode, decode_url, encode, encode_url, Base64Error};

fn examples() -> Result<(), Base64Error> {
    let encoded = encode(b"hello")?; // "aGVsbG8="
    let decoded = decode(&encoded)?; // b"hello"

    let url_encoded = encode_url(b"hello")?; // "aGVsbG8"
    let url_decoded = decode_url(&url_encoded)?; // b"hello"
    Ok(())
}
```

全ての関数は、失敗を `Base64Error` で返します。符号化と復号では、出力の長さを先に正確に計算し、その長さだけを確保します。出力の長さが扱える範囲を超える場合と、確保に失敗した場合は、それぞれ別のバリアントを返します。

## API

### 符号化

| 関数 | 返す値 |
|------|--------|
| `encode(input: &[u8])` | パディング付きの標準 Base64 |
| `encode_url(input: &[u8])` | パディングなしの URL セーフ Base64 |
| `encode_url_padded(input: &[u8])` | パディング付きの URL セーフ Base64 |

各関数の戻り値の型は `Result<String, Base64Error>` です。

### 復号

| 関数 | 受け付ける入力 |
|------|----------------|
| `decode(input: &str)` | 標準 Base64 |
| `decode_url(input: &str)` | URL セーフ Base64 |
| `decode_url_strict(input: &str)` | パディングなしで、余りビットが 0 の URL セーフ Base64 |

各関数の戻り値の型は `Result<Vec<u8>, Base64Error>` です。

- `decode`、`decode_url`: 入力の末尾のパディングは、あっても無くてもよい。最後の文字のうち、出力のバイトに入らない下位のビット ( 余りビット ) は検査しない
- `decode_url_strict`: `=` を含む入力を拒否し、最後の文字の余りビットが 0 であることを検査する

余りビット ( RFC 4648 の語では pad bits ) の検査は、3.5 節に従います。3.5 節では、符号化する側に余りビットを 0 にすることを求め、復号する側には余りビットが 0 でない入力の拒否を認めています。

一方、`=` の拒否は、パディングを省いた形だけを受け付けるという、この crate の選択です。RFC 4648 の 5 節では、データの長さが暗黙に分かる場合に、URL セーフ Base64 のパディングを省けるとしています。

## 失敗の型

```rust
pub enum Base64Error {
    InvalidCharacter,
    InvalidLength,
    NonZeroPaddingBits,
    CapacityOverflow { input_len: usize },
    AllocationFailed { required: usize },
}
```

| バリアント | 意味 |
|------------|------|
| `InvalidCharacter` | アルファベットの外の文字、または関数が受け付けない位置の `=` を含む |
| `InvalidLength` | パディングを除いた長さを 4 で割った余りが 1 である |
| `NonZeroPaddingBits` | `decode_url_strict` で、最後の文字の余りビットに 0 以外がある |
| `CapacityOverflow` | 出力の長さが扱える範囲を超える。`input_len` は入力の長さで、復号ではパディングを除いた長さ |
| `AllocationFailed` | 出力バッファの確保に失敗した。`required` は要求したバイト数 |

## feature

| feature | 有効にするもの |
|---------|----------------|
| `std` ( 既定 ) | 標準ライブラリへのリンクと `alloc` |
| `alloc` | 符号化と復号の各関数 |

`Base64Error` は `core` だけで定義されているため、どの feature の組み合わせでも使えます。

標準ライブラリへのリンクを外すと、組み込み環境向けの `no_std` 構成でビルドできます。

## ライセンス

MIT
