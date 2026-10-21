# neco-argon2

[English](README.md)

neco-argon2 は、Argon2id によるパスワードハッシュの計算と鍵導出を提供します。内部のハッシュ関数には Blake2b を使います。

- Argon2id: RFC 9106 に準拠 ( バージョン 19 )
- Blake2b: RFC 7693 に準拠
- PHC 形式の文字列: アルゴリズム、バージョン、引数、ソルト、ハッシュ値を `$` で区切った一つの文字列 ( `$argon2id$v=19$m=...,t=...,p=...$...` )
- 失敗の型: 不正な引数、扱える範囲の超過、確保の失敗、乱数源の失敗、PHC 形式の文字列の Base64 の失敗を、`Argon2Error` の別々のバリアントで返す

## feature

| feature | 有効にするもの |
|---------|----------------|
| `std` ( 既定 ) | 標準ライブラリへのリンクと `alloc` |
| `alloc` | 作業メモリを確保する Argon2id の API の全体 |
| `phc` ( 既定 ) | PHC 形式の文字列を扱う関数 |
| `getrandom` ( 既定 ) | `argon2id_hash_encoded` が使う、OS の乱数源によるソルト |

## 使い方

```rust
use neco_argon2::{argon2id_hash_encoded, argon2id_verify, Argon2Error, Argon2Params};

fn run() -> Result<(), Argon2Error> {
    let password = b"hunter2";
    let params = Argon2Params::default(); // m=19456, t=2, p=1

    let encoded = argon2id_hash_encoded(password, params)?;
    // => "$argon2id$v=19$m=19456,t=2,p=1$<salt_b64>$<hash_b64>"

    assert!(argon2id_verify(&encoded, password)?);
    assert!(!argon2id_verify(&encoded, b"wrong")?);
    Ok(())
}
```

- `argon2id_hash_encoded`: OS の乱数源から 16 バイトのソルトを得て、PHC 形式の文字列を返す
- `argon2id_verify`: パスワードが一致しない場合は `Ok(false)` を返す

### 低水準の API

`argon2id_hash_into` は、導出したバイト列を呼び出し側のバッファへ書き込みます。

```rust
use neco_argon2::{argon2id_hash_into, Argon2Error};

fn run() -> Result<(), Argon2Error> {
    let mut key = [0u8; 32];
    argon2id_hash_into(
        b"password",
        b"randomsalt12345!", // 8 バイト以上
        65536,               // m_cost ( KiB )
        3,                   // t_cost ( 反復回数 )
        4,                   // p_cost ( 並列度 )
        &mut key,
    )?;
    Ok(())
}
```

`argon2id_hash` は、出力のバッファを確保し、導出したバイト列を `Vec` で返す関数です。

```rust
use neco_argon2::{argon2id_hash, Argon2Error};

fn run() -> Result<(), Argon2Error> {
    let hash = argon2id_hash(
        b"password",
        b"randomsalt12345!", // 8 バイト以上
        19456,               // m_cost ( KiB )
        2,                   // t_cost ( 反復回数 )
        1,                   // p_cost ( 並列度 )
        32,                  // 出力長 ( バイト )
    )?;
    Ok(())
}
```

`argon2id_hash_with_secret` は、コストと出力長を `Argon2Params` で受け取り、秘密値と関連データを入力に加えます。

```rust
use neco_argon2::{argon2id_hash_with_secret, Argon2Error, Argon2Params};

fn run() -> Result<(), Argon2Error> {
    let params = Argon2Params { m_cost: 19456, t_cost: 2, p_cost: 1, output_len: 32 };
    let hash = argon2id_hash_with_secret(
        b"password",
        b"randomsalt12345!", // 8 バイト以上
        params,
        b"secret",
        b"associated data",
    )?;
    Ok(())
}
```

### ソルトの渡し方を選べる PHC の関数

PHC 形式の文字列を返す関数は三つあり、ソルトの供給元が異なります。

| 関数 | ソルトの供給元 |
|------|----------------|
| `argon2id_hash_encoded_with_salt` | 呼び出し側が渡す 16 バイト配列 |
| `argon2id_hash_encoded_with_rng` | 呼び出し側が渡す、ソルトを書き込むクロージャ |
| `argon2id_hash_encoded` | `argon2id_hash_encoded_with_rng` を経由して読む OS の乱数源 |

`argon2id_hash_encoded_with_rng` に渡すクロージャは、ソルトを書き込むバッファを受け取り、`Result` を返す関数です。

```text
FnMut(&mut [u8]) -> Result<(), Argon2Error>
```

クロージャが `Err` を返すと、この関数はその失敗をそのまま返します。

## 引数の検査と失敗

各関数は、作業メモリを確保する前に引数を検査します。

| 引数 | 違反の条件 | 結果 |
|------|------------|------|
| `p_cost` | 1 未満、または 2^24 − 1 超 ( RFC 9106 §3.1 ) | `InvalidParameter` |
| `t_cost` | 1 未満 | `InvalidParameter` |
| `m_cost` | 並列度の 8 倍未満 | `InvalidParameter` |
| `m_cost` | 作業メモリのバイト数が扱える範囲を超える | `CapacityOverflow` |
| `output_len` | 4 バイト未満 | `InvalidParameter` |
| `output_len` | 4,294,967,295 バイト超で、扱える範囲の内側 | `InvalidParameter` |
| `output_len` | 扱える範囲を超える | `CapacityOverflow` |
| `salt` | 8 バイト未満 | `InvalidParameter` |
| `salt` | 4,294,967,295 バイト超 | `InvalidParameter` |
| `password` | 4,294,967,295 バイト超 | `InvalidParameter` |
| `secret` | 4,294,967,295 バイト超 | `InvalidParameter` |
| `associated_data` | 4,294,967,295 バイト超 | `InvalidParameter` |

`InvalidParameter` の値は、条件に違反した引数の名前です。

要求した量が扱える範囲を超えた場合と、アロケータが確保を拒否した場合は、別のバリアントを返します。どちらも、確保しようとした量の種類を `AllocationOperation` で示します。

| `AllocationOperation` | 対象の量 |
|------------------------|----------|
| `MemoryBlocks` | 作業メモリのブロック数 |
| `OutputBytes` | ハッシュの出力のバイト数 |
| `PhcBytes` | PHC 形式の文字列のバイト数 |

| `Argon2Error` のバリアント | 意味 |
|----------------------------|------|
| `CapacityOverflow { operation, required }` | 要求した量が扱える範囲を超える |
| `AllocationFailed { operation, required }` | グローバルアロケータが確保を拒否した |
| `RandomUnavailable` | OS の乱数源が失敗を返した |
| `Base64(Base64Error)` | PHC 形式の文字列の Base64 の符号化または復号で、出力の長さが扱える範囲を超えたか、確保に失敗した |

`Base64` は、`phc` を有効にした場合に定義されるバリアントです。

`argon2id_hash_encoded` は、低水準の API と同じ失敗に加えて、ソルトの取得と PHC 形式の文字列の作成で起きる失敗を返します。

| 失敗の原因 | バリアント |
|------------|------------|
| OS の乱数源が失敗した | `RandomUnavailable` |
| PHC 形式の文字列の長さが扱える範囲を超える | `CapacityOverflow` ( `PhcBytes` ) |
| PHC 形式の文字列の確保が失敗した | `AllocationFailed` ( `PhcBytes` ) |
| ソルトとハッシュ値の Base64 の符号化が失敗した | `Base64` |

`argon2id_verify` は、パスワードが一致しない場合に加えて、PHC 形式に従わない文字列と、引数が不正な文字列 ( 8 バイト未満のソルトを含む ) にも `Ok(false)` を返します。
一方、扱える範囲の超過と確保の失敗は、PHC 形式の文字列の Base64 の復号で起きたものを含めて、`Err` として返ります。

## PHC 形式の文字列の Base64

| 性質 | 値 |
|------|-----|
| アルファベット | 標準 ( `+` と `/` ) |
| パディング | 符号化では除く。復号では省略でき、付いていても受け付ける |
| 使う関数 | neco-base64 の標準の `encode` と `decode` |
| URL セーフアルファベット ( `-`、`_` ) | PHC 形式に従わない文字列として扱う |

## 消去

作業メモリは、`try_reserve_exact` でヒープに確保するブロックの行列です。ハッシュの計算を終えると、成功と失敗のどちらの場合も、この行列を消去します。

計算の途中の固定長の値は、スタック上で `zeroize::Zeroizing` に包み、破棄の時に消去します。

- 初期ハッシュと、その計算に使うヘッダ
- 各レーンの種ブロックと、その導出の入力
- 最終ブロックと、そのバイト列

PHC の関数は、ハッシュのバイト列も `Zeroizing` に包みます。消去の時点は、PHC 形式の文字列へ符号化した後です。

作業メモリも、途中の値と同じく `Zeroizing` に包まれており、その値の破棄の時に内容が消去されます。このため、終了の種類によって、消去の結果が変わります。

- 巻き戻しを伴う panic: 巻き戻しの途中で `Zeroizing` の値が破棄され、内容を消去する
- `panic = "abort"` やプロセスの異常終了: 破棄の処理が実行される前に処理が終わり、内容が残る

この crate は、パスワード、ソルト、秘密値、関連データを、計算の全体を通じて呼び出し側のスライスのまま借用し、ハッシュ関数へ直接渡します。

出力には実際のハッシュの結果が入るため、出力の消去は呼び出し側の責務です。

- `argon2id_hash_into`: 呼び出し側が渡すバッファ
- `argon2id_hash`: 戻り値の `Vec<u8>`
- `argon2id_hash_with_secret`: 戻り値の `Vec<u8>`

## 既定値

| 引数 | `Argon2Params::default()` の値 |
|------|--------------------------------|
| `m_cost` ( メモリコスト、KiB ) | 19456 ( 19 MiB ) |
| `t_cost` ( 反復回数 ) | 2 |
| `p_cost` ( 並列度 ) | 1 |
| `output_len` ( 出力長、バイト ) | 32 |

## 依存する crate

| crate | 役割 |
|-------|------|
| [`zeroize`](https://docs.rs/zeroize) | 作業メモリとヒープ上のバッファの消去 |
| [`getrandom`](https://docs.rs/getrandom) | `argon2id_hash_encoded` のソルトの生成 |
| [`neco-base64`](https://docs.rs/neco-base64) | `phc` を有効にした時の、PHC 形式の文字列の符号化と復号 |

## ライセンス

MIT
