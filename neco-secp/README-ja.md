# neco-secp

[English](README.md)

neco-secp は、secp256k1 の鍵と署名、および Nostr のイベントの署名を少ない依存で実装した crate です。

この crate は全て Rust で実装しており、Nostr のクライアントやツールの作成に使うことができます。

署名の方式は 2 つあり、Nostr のイベントの署名と検証には Schnorr 署名を使います。

- Schnorr 署名: BIP340 ( Bitcoin の Schnorr 署名の仕様 ) による署名
- ECDSA ( 楕円曲線デジタル署名アルゴリズム ) : RFC 6979 で導出したノンスによる署名

ストレージ、ブラウザーとの連携、鍵の隔離の方針は、この crate の利用者が決める事柄です。

鍵を表す型は 3 つあり、いずれもバイト列を非公開のフィールドに収めています。このため、値は下の [鍵](#鍵) の表にある、値を検証するコンストラクタでのみ作ることができます。

- `SecretKey`: 秘密鍵
- `PublicKey`: 圧縮 SEC1 形式の公開鍵
- `XOnlyPublicKey`: x 座標だけで表す公開鍵 ( x-only 公開鍵 )

圧縮 SEC1 形式は、楕円曲線暗号の標準規格 SEC 1 が定める公開鍵の符号化の一つです。y 座標の偶奇を表す 1 バイトの接頭辞に x 座標の 32 バイトを続け、33 バイトで公開鍵を表します。

## feature

| feature | 既定 | 有効になる内容 |
|---------|------|----------------|
| `std`     | 有効 | この crate と依存先で標準ライブラリ ( std ) を使う ( `alloc` を含む ) |
| `alloc`   | 有効 ( `std` 経由 ) | ヒープに確保した値 ( 文字列や可変長の配列 ) を返す API。鍵と 16 進文字列 ( hex ) の変換と、イベントの型を含む |
| `getrandom` | 有効 | OS の乱数源を使う鍵生成、署名、鍵の探索 ( マイニング ) 、暗号化 |
| `nostr`   | 有効 | Nostr のイベントの構築、署名、検証、JSON の書き出しと解析と、NIP-42 の認証イベント |
| `nip19`   | 無効 | Nostr の仕様 NIP-19 の文字列 ( npub など ) の符号化と復号 |
| `nip04`   | 無効 | NIP-04 によるイベント本文の暗号化と復号 |
| `nip44`   | 無効 | NIP-44 v2 の会話鍵の導出と、イベント本文の暗号化と復号 |
| `nip17`   | 無効 | NIP-17 のダイレクトメッセージの作成と復号 ( [NIP-17](#nip-17-封印とギフトラップによるダイレクトメッセージ) を参照 ) |
| `batch`   | 無効 | 鍵の一括生成とマイニング |
| `serde`   | 無効 | 下記の型の Serde によるシリアライズとデシリアライズ |

NIP-19 の文字列には、値だけを Bech32 ( 誤りを検出できる英数字の符号化方式 ) で符号化する形式 ( ベア形式 ) と、型、長さ、値の組を並べて符号化する形式 ( TLV 形式 ) があります。`nip19` が対応する接頭辞は、表す値と形式の異なる 7 種類です。

- `npub`: 公開鍵 ( ベア形式 )
- `nsec`: 秘密鍵 ( ベア形式 )
- `note`: イベント ID ( ベア形式 )
- `nprofile`: 公開鍵とリレー ( TLV 形式 )
- `nevent`: イベント ID、リレー、作成者、種別 ( TLV 形式 )
- `naddr`: 識別子、リレー、作成者、種別 ( TLV 形式 )
- `nrelay`: リレー ( TLV 形式 )

`serde` を有効にすると、イベントとその部品の型を Serde でシリアライズ、デシリアライズできます。値の表し方は、型に応じて 16 進文字列か構造体のどちらかです。

- `EventId`: 16 進文字列
- `XOnlyPublicKey`: 16 進文字列
- `SchnorrSignature`: 16 進文字列
- `UnsignedEvent`: フィールド名をキーとする構造体
- `SignedEvent`: フィールド名をキーとする構造体
- `Rumor`: フィールド名をキーとする構造体

署名、鍵生成、マイニング、暗号化では、OS の乱数源の代わりに、呼び出し側が渡す関数でバイト列を乱数で埋めることもできます。以下、この関数をバイト供給関数と呼びます。

バイト供給関数を受け取る関数の名前は、OS の乱数源を使う関数の名前の末尾に `_with_rng` を付けたものです。例えば、鍵の生成には `generate_with_rng` を使います。各関数は、下の [API](#api) の表で確認できます。

## Nostr イベントの形

Nostr のイベントを表す 3 つの型は、同じ形の規則に従います。

- `UnsignedEvent`: 未署名のイベント
- `SignedEvent`: 署名済みのイベント
- `Rumor`: NIP-17 のダイレクトメッセージで、暗号化して送るメッセージを表す未署名のイベント ( [NIP-17](#nip-17-封印とギフトラップによるダイレクトメッセージ) を参照 )

規則はフィールドごとに定まっており、JSON の解析と書き出し、署名、検証のそれぞれで検査します。

- `kind`: イベントの種別を表す u32 型の値で、許される範囲は `0..=65535`
- `tags`: 外側の配列は 0 件以上
- `tags` の内側の各配列: 1 件以上の文字列
- `created_at`: `u64` 型の Unix タイムスタンプ

検査に失敗した場合の戻り値は、失敗した規則に対応する `SecpError` のバリアント ( 列挙型の値の種類 ) です。

- `InvalidEventKind { kind }`: `kind` が 65535 を超える
- `EmptyEventTag { index }`: 位置 `index` の内側のタグが空

NIP-19 の TLV 形式の値にも、種別を含むものがあります。この種別には、上記の範囲に限らず `u32` の範囲全体の値が入ります。

- `NAddr`: 種別の型は `u32`
- `NEvent`: 種別は省略でき、型は `Option<u32>`

## 使い方

### イベントの署名と検証

```rust
use neco_secp::{nostr, SecretKey, SecpError, UnsignedEvent};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let event = UnsignedEvent {
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "hello".to_string(),
    };

    let signed = nostr::finalize_event(event, &secret)?;
    nostr::verify_event(&signed)
}
```

### 鍵ペア

秘密鍵と x-only 公開鍵の組を、以下、鍵ペアと呼びます。鍵ペアを表す型は `KeyBundle` です。

```rust
use neco_secp::{KeyBundle, SecpError};

fn run() -> Result<(), SecpError> {
    let bundle = KeyBundle::generate()?;
    let secret = bundle.secret();
    let xonly = bundle.xonly_public_key();
    let _ = (secret, xonly);
    Ok(())
}
```

OS の乱数源の代わりにバイト供給関数を使う場合は、`KeyBundle::generate_with_rng` で鍵ペアを生成します。

```rust
use neco_secp::{KeyBundle, SecpError};

fn run() -> Result<(), SecpError> {
    let bundle = KeyBundle::generate_with_rng(&mut |bytes: &mut [u8]| {
        bytes.fill(0x7a); // 実際の供給関数は予測できないバイト列で埋める
        Ok(())
    })?;
    let _ = bundle;
    Ok(())
}
```

`nip19` feature を有効にすると、鍵ペアから npub と nsec の文字列を取得できます。

```rust
use neco_secp::{KeyBundle, SecpError};

fn run() -> Result<(), SecpError> {
    let bundle = KeyBundle::generate()?;
    let npub = bundle.npub()?;
    let nsec = bundle.nsec()?;
    let _ = (npub, nsec);
    Ok(())
}
```

### マイニング

`batch` feature を有効にすると、鍵ペアを一括で生成できるほか、x-only 公開鍵の先頭のニブル ( 16 進数 1 桁に当たる 4 ビット ) が指定した数だけ 0 になる鍵を探せます。

以下、この探索を PoW ( Proof of Work、作業証明 ) マイニングと呼びます。

```rust
use neco_secp::{KeyBundle, SecpError, mine_pow};

fn run() -> Result<(), SecpError> {
    // 鍵ペアの一括生成
    let bundles = KeyBundle::generate_batch(100)?;

    // PoW マイニング: x-only 公開鍵の先頭 4 ニブルが 0 の鍵を探す
    let bundle = mine_pow(4, 1_000_000)?;
    let _ = (bundles, bundle);
    Ok(())
}
```

指定した文字列で始まる npub を持つ鍵を探すには、`batch` と `nip19` の両方の feature が必要です。

`mine_vanity_npub` は、接頭辞の引数を `npub1` の後ろのデータ部と照合します。使える文字は、Bech32 のデータ部の文字集合です。

```text
qpzry9x8gf2tvdw0s3jn54khce6mua7l
```

- 大文字を含め、これ以外の文字を含む接頭辞を渡すと `SecpError::InvalidNip19` を返す
- 試行回数 `max_attempts` を使い切ると `SecpError::ExhaustedAttempts` を返す

```rust
use neco_secp::{mine_vanity_npub, SecpError};

fn run() -> Result<(), SecpError> {
    // npub が "npub1qq" で始まる鍵を探す
    let bundle = mine_vanity_npub("qq", 1_000_000)?;
    let _ = bundle;
    Ok(())
}
```

### NIP-19

`nip19` feature を有効にすると、秘密鍵や `NProfile` などの値を NIP-19 の文字列に符号化し、その文字列から復号できます。

```rust
use neco_secp::{nip19, NProfile, SecretKey, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let nsec = nip19::encode_nsec(&secret)?;
    let decoded = nip19::decode(&nsec)?;

    assert!(matches!(decoded, neco_secp::Nip19::Nsec(_)));

    let profile = NProfile {
        pubkey: secret.xonly_public_key()?,
        relays: vec!["wss://relay.example".to_string()],
    };
    let nprofile = nip19::encode_nprofile(&profile)?;
    let decoded = nip19::decode(&nprofile)?;

    assert!(matches!(decoded, neco_secp::Nip19::NProfile(_)));
    Ok(())
}
```

### NIP-44 と NIP-04

`nip44` feature では、自分の秘密鍵と相手の公開鍵から、二者が共通に使う会話鍵を導出し、その会話鍵でイベント本文を暗号化します。

```rust
use neco_secp::{nip44, SecretKey, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::from_bytes([0x11; 32])?;
    let peer = SecretKey::from_bytes([0x22; 32])?;
    let peer_pubkey = peer.xonly_public_key()?;
    let conversation_key = nip44::get_conversation_key(&secret, &peer_pubkey)?;
    let payload = nip44::encrypt("hello", &conversation_key, Some([0x33; 32]))?;
    let plaintext = nip44::decrypt(&payload, &conversation_key)?;

    assert_eq!(plaintext, "hello");
    Ok(())
}
```

NIP-04 の暗号化と復号は、`nip04` feature で使うことができます。

```rust
use neco_secp::{nip04, SecretKey, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::from_bytes([0x11; 32])?;
    let peer = SecretKey::from_bytes([0x22; 32])?;
    let peer_pubkey = peer.xonly_public_key()?;
    let payload = nip04::encrypt(&secret, &peer_pubkey, "hello", Some([0x44; 16]))?;
    let plaintext = nip04::decrypt(&peer, &secret.xonly_public_key()?, &payload)?;

    assert_eq!(plaintext, "hello");
    Ok(())
}
```

## JSON のシリアライズ

`nostr` feature を有効にすると、署名済みイベントと Rumor を JSON として書き出し、解析することができます。

```rust
use neco_secp::{nostr, SecretKey, SecpError, UnsignedEvent};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let event = UnsignedEvent {
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "hello".to_string(),
    };
    let signed = nostr::finalize_event(event, &secret)?;

    let json = nostr::serialize_signed_event(&signed)?;
    let parsed = nostr::parse_signed_event(&json)?;
    assert_eq!(parsed, signed);
    Ok(())
}
```

解析では、上記のイベントの形を検査します。重複を検査する対象は、イベントのフィールドとして既知の 7 つのキーです。

```
id, pubkey, created_at, kind, tags, content, sig
```

未知のキーは、重複の有無にかかわらず受理します。

### `EventJsonError`

JSON の構造に関する解析の失敗は、`EventJsonError` を `SecpError::Json` に包んで返します。

表の `ParseError` と `StringDecodeError` は、依存先の neco-json が定める型です。

| バリアント | 説明 |
|-----------|------|
| `Syntax(ParseError)` | 入力が JSON として構文的に不正 |
| `Decode(StringDecodeError)` | 文字列の値の復号の失敗 ( 容量超過、メモリ確保の失敗、誤ったエスケープなどの不正な文字のいずれか ) |
| `MissingField(&'static str)` | 必須のイベントフィールドが無い |
| `DuplicateField { field, position }` | 既知のイベントフィールドが重複する |
| `InvalidField { field, position }` | 値の JSON の型が不正 ( 例: 数値で書いた id ) |
| `InvalidNumber { field, position }` | 数値のフィールドの値が、整数でないか、上記の形で定めた型の範囲を超える |

JSON の型が正しくても値が不正な場合は、不正の内容に応じた `SecpError` のバリアントを返します。

- `InvalidEvent`: 文字列の形式か、Rumor のフィールドの構成が不正
  - id、pubkey、sig の文字列の長さか、16 進数の文字が不正
  - Rumor の JSON に sig のフィールドがある
- `InvalidPublicKey`: pubkey が曲線上の点の x 座標を表さない
- `InvalidEventKind` / `EmptyEventTag`: 上記のイベントの形の検査に失敗した

## NIP-17: 封印とギフトラップによるダイレクトメッセージ

NIP-17 では、未署名の `Rumor` を署名済みイベントで封印し、その封印を受信者に向けて暗号化して、2 つ目の署名済みイベントで包みます。以下、1 つ目のイベントを封印、2 つ目のイベントをギフトラップと呼びます。

- 必要な feature: `nostr` と `nip44`
- 両方を有効にする feature: `nip17`
- 封印のイベントの種別: 13
- ギフトラップのイベントの種別: 1059
- `Rumor`: `UnsignedEvent` の 4 フィールドに id と pubkey を加えた、計 6 フィールドの未署名のイベント

```
Rumor { id, pubkey, created_at, kind, tags, content }
```

走査鍵は、受信者が署名鍵とは別に持つ鍵です。`create_gift_wrap_with_scan_tag` には、受信者の公開鍵に加えて、走査鍵の公開鍵を渡します。この関数は、ギフトラップの一時鍵と走査鍵から HMAC ( 鍵付きのハッシュ ) で 16 バイトの値を導出し、ギフトラップと一緒に返します。以下、この値を走査タグと呼びます。走査鍵の秘密鍵を持つ受信者は、ギフトラップの一時公開鍵から `compute_scan_tag` で同じ値を計算して照合し、自分宛てのギフトラップかを復号する前に確かめることができます。

| 項目 | 説明 |
|------|------|
| `create_seal` / `create_seal_with_rng` | 呼び出し側が渡す未署名イベントから Rumor を作り、封印して署名する |
| `open_seal` | 封印を復号し、中の Rumor を解析して、Rumor の pubkey が封印の署名鍵と一致するかを確かめる |
| `create_gift_wrap` / `create_gift_wrap_with_rng` | 新しい一時鍵で、封印を受信者に向けて包む |
| `create_gift_wrap_with_scan_tag` / `..._with_rng` | 封印を包み、受信者の走査鍵に向けた走査タグも返す |
| `GiftWrapWithScanTag` | `create_gift_wrap_with_scan_tag` の戻り値で、ギフトラップと走査タグの組 |
| `open_gift_wrap` | 受信者の秘密鍵でギフトラップと封印を復号し、中の `Rumor` を返す |
| `compute_scan_tag` | 走査鍵の秘密鍵と、ギフトラップの一時公開鍵から走査タグを導出する |

封印とギフトラップを作る関数のうち、名前が `_with_rng` で終わるものはバイト供給関数を受け取ります。それ以外の関数は OS の乱数源を使うため、既定で有効な `getrandom` feature も必要です。

```rust
use neco_secp::{nip17, SecretKey, SecpError, UnsignedEvent};

fn run() -> Result<(), SecpError> {
    let sender = SecretKey::generate()?;
    let recipient = SecretKey::generate()?;
    let recipient_pub = recipient.xonly_public_key()?;

    let inner = UnsignedEvent {
        created_at: 1_700_000_000,
        kind: 14,
        tags: vec![],
        content: "hello".to_string(),
    };

    let seal = nip17::create_seal(inner, &sender, &recipient_pub, 1_700_000_000)?;
    let gift_wrap = nip17::create_gift_wrap(&seal, &recipient_pub, 1_700_000_000)?;

    let rumor = nip17::open_gift_wrap(&gift_wrap, &recipient)?;
    assert_eq!(rumor.content, "hello");
    Ok(())
}
```

封印とギフトラップのタイムスタンプには、呼び出し側が渡す基準時刻から 0 秒以上 2 日以下の秒数を乱数で選んで引いた値を、それぞれ使います。引いた結果が 0 を下回る場合の値は 0 ( Unix エポック ) です。

## テスト

通常の実行では、`#[ignore]` を付けた 5 件のマイニングのテストを省きます。

これらのテストは、公開しているマイニングの関数 ( `mine_pow_with_rng` や `mine_vanity_npub_with_rng` など ) を対象とし、鍵空間を探索するため時間がかかります。

```bash
# 通常のテスト
cargo test -p neco-secp

# ignore を付けたマイニングのテストも実行
cargo test -p neco-secp --features "batch nip19" -- --ignored
```

## ECDSA 署名

ECDSA の署名と検証には、専用の関数を使います。対象の曲線は secp256k1 です。

- `SecretKey::sign_ecdsa_prehash`: RFC 6979 で導出したノンスで署名し、s を曲線の位数の半分以下の値 ( low-S ) に正規化する
- `PublicKey::verify_ecdsa_prehash`: s が位数の半分を超える署名 ( high-S ) を拒否して検証する

```rust
use neco_secp::{SecretKey, EcdsaSignature, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let public = secret.public_key()?;
    let hash: [u8; 32] = [0x42; 32]; // SHA-256 のハッシュ値

    let sig: EcdsaSignature = secret.sign_ecdsa_prehash(hash)?;
    public.verify_ecdsa_prehash(hash, &sig)
}
```

## API

表の括弧内は、その項目に必要な feature です。

### 鍵

署名と検証のメソッドの名前にある prehash は、呼び出し側が計算した 32 バイトのハッシュ値 ( 引数 `digest32` ) を受け取ることを表します。`SecretKey` は、検証済みの 32 バイトの secp256k1 の秘密鍵です。

| メソッド | 説明 |
|----------|------|
| `generate()` | OS の乱数源から鍵を生成する ( `getrandom` ) |
| `generate_with_rng(fill)` | バイト供給関数から鍵を生成する |
| `from_bytes(bytes)` | 32 バイトの配列から作る。0 または曲線の位数以上の値は `InvalidSecretKey` |
| `from_hex(hex)` | 64 桁の 16 進文字列から作る ( `alloc` ) 。値の範囲の検査は同じ |
| `to_bytes()` / `to_hex()` | 32 バイトの配列、または小文字の 16 進文字列を返す |
| `public_key()` | 圧縮 SEC1 形式の `PublicKey` を導出する |
| `xonly_public_key()` | BIP340 の `XOnlyPublicKey` を導出する |
| `sign_schnorr_prehash(digest32)` | OS の乱数源から得た補助乱数で BIP340 署名する ( `getrandom` ) |
| `sign_schnorr_prehash_with_aux(digest32, aux)` | 呼び出し側が渡す補助乱数で BIP340 署名する |
| `sign_schnorr_prehash_with_rng(digest32, fill)` | バイト供給関数から得た補助乱数で BIP340 署名する |
| `sign_schnorr_prehash_deterministic(digest32)` | 全て 0 の補助乱数で BIP340 署名する |
| `sign_ecdsa_prehash(digest32)` | ECDSA で署名し、low-S に正規化する |

`PublicKey` は、検証済みの 33 バイトの圧縮 SEC1 形式の公開鍵を表し、ECDSA 署名の検証に使います。

| メソッド | 説明 |
|----------|------|
| `from_sec1_bytes(bytes)` | 33 バイトの圧縮 SEC1 値から作る。長さ、接頭辞、点が無効なら `InvalidPublicKey` |
| `from_hex(hex)` | 66 桁の 16 進文字列から作る ( `alloc` ) |
| `to_sec1_bytes()` / `to_hex()` | 33 バイトの SEC1 値、または 16 進文字列を返す |
| `verify_ecdsa_prehash(digest32, sig)` | high-S を拒否して ECDSA 署名を検証する |

`XOnlyPublicKey` は、検証済みの 32 バイトの BIP340 の x-only 公開鍵です。

| メソッド | 説明 |
|----------|------|
| `from_bytes(bytes)` | 32 バイトの x 座標から作る。曲線上の点の x 座標でない値は `InvalidPublicKey` |
| `from_hex(hex)` | 64 桁の 16 進文字列から作る ( `alloc` ) |
| `to_bytes()` / `to_hex()` | 32 バイトの配列、または 16 進文字列を返す |
| `verify_schnorr_prehash(digest32, sig)` | BIP340 署名を検証する |

### 署名

署名の型は、いずれも r と s を連結した 64 バイトの形式 ( compact 形式 ) で署名を表します。

| 項目 | 説明 |
|------|------|
| `SchnorrSignature` | BIP340 の署名 |
| `EcdsaSignature` | ECDSA の署名 |
| `EcdsaSignature::from_bytes(bytes)` | 64 バイトの配列から ECDSA 署名を作る |
| `to_bytes()` | 両方の型で、署名の 64 バイトの配列を返す |

### 鍵ペア

`KeyBundle` は、検証済みの秘密鍵と x-only 公開鍵の組を表す型です。一括生成のメソッドには `batch` feature が必要です。

| メソッド | 説明 |
|----------|------|
| `generate()` | OS の乱数源から鍵ペアを生成する ( `getrandom` ) |
| `generate_with_rng(fill)` | バイト供給関数から鍵ペアを生成する |
| `secret()` / `xonly_public_key()` | 秘密鍵と x-only 公開鍵を参照で返す |
| `npub()` | npub の文字列を返す ( `nip19` ) |
| `nsec()` | nsec の文字列を返す ( `nip19` ) |
| `generate_batch(n)` | OS の乱数源から n 個の鍵ペアを生成する ( `getrandom` ) |
| `generate_batch_with_rng(n, fill)` | バイト供給関数から n 個の鍵ペアを生成する |

### マイニング

マイニングの関数には `batch` feature が必要で、npub の接頭辞で探す関数とその候補の型には `nip19` も必要です。

引数 n は試行の最大の回数です。鍵ペアを返す関数は、n 回の試行を終えた時点で条件を満たす鍵が 0 個の場合に `ExhaustedAttempts` を返します。一方、候補を返す関数は、この場合に空の一覧を返します。

| 項目 | 説明 |
|------|------|
| `mine_pow(d, n)` | x-only 公開鍵の先頭 d ニブルが 0 の鍵を探し、最初に見つけた鍵ペアを返す ( `getrandom` ) |
| `mine_pow_with_rng(d, n, fill)` | `mine_pow` と同じ探索を、バイト供給関数で行う |
| `mine_pow_best(d, n)` | n 回の試行を全て行い、先頭の 0 のニブルが d 個以上の鍵のうち最も多い鍵ペアと、そのニブルの数を返す ( `getrandom` ) |
| `mine_pow_best_with_rng(d, n, fill)` | `mine_pow_best` と同じ探索を、バイト供給関数で行う |
| `mine_vanity_npub(p, n)` | npub1 の後ろのデータ部が p で始まる鍵を探し、最初に見つけた鍵ペアを返す ( `getrandom` ) |
| `mine_vanity_npub_with_rng(p, n, fill)` | `mine_vanity_npub` と同じ探索を、バイト供給関数で行う |
| `mine_vanity_npub_candidates(p, n, k)` | n 回の試行を全て行い、データ部の先頭が p と 1 文字以上一致した鍵を、一致した文字数の多い順に最大 k 個返す ( `getrandom` ) |
| `mine_vanity_npub_candidates_with_rng(p, n, k, fill)` | `mine_vanity_npub_candidates` と同じ探索を、バイト供給関数で行う |
| `VanityCandidate` | `mine_vanity_npub_candidates` が返す候補 |
| `VanityCandidate::bundle()` | 候補の鍵ペアを返す |
| `VanityCandidate::matched_len()` | p と一致した先頭の文字数を返す |

### Nostr のイベント

イベントの型には `alloc` feature が、イベントを扱う関数には `nostr` feature が必要です。

クライアントがリレーに自分を認証する NIP-42 のイベントは、nip42 のモジュールで作成し、検証します。

| 項目 | 説明 |
|------|------|
| `UnsignedEvent` | 未署名の Nostr のイベント ( `alloc` ) |
| `SignedEvent` | 署名済みの Nostr のイベント ( `alloc` ) |
| `Rumor` | NIP-17 の封印の中身に使う未署名のイベント ( `alloc` ) |
| `EventId` | 32 バイトの Nostr のイベント ID ( `alloc` ) |
| `hex::hex_encode(bytes)` | バイト列を小文字の 16 進文字列に変換する ( `alloc` ) |
| `hex::hex_decode(hex)` | 16 進文字列 ( 大文字も可 ) をバイト列に変換する ( `alloc` ) |
| `nostr::serialize_event` | イベント ID の計算に使う、NIP-01 の形式の JSON の配列を書き出す |
| `nostr::compute_event_id` | その JSON の SHA-256 のハッシュ値を、イベント ID として返す |
| `nostr::finalize_event` | イベント ID を計算し、OS の乱数源から得た補助乱数で署名する ( `getrandom` ) |
| `nostr::finalize_event_with_rng` | バイト供給関数から得た補助乱数で署名する |
| `nostr::finalize_event_with_aux` | 呼び出し側が渡す補助乱数で署名する |
| `nostr::finalize_event_deterministic` | 全て 0 の補助乱数で署名する |
| `nostr::verify_event` | イベント ID と署名を検証する |
| `nostr::create_rumor` | 未署名イベントと公開鍵からイベント ID を計算し、Rumor を作る |
| `nostr::serialize_signed_event` / `parse_signed_event` | 署名済みイベントを JSON として書き出し、解析する |
| `nostr::serialize_rumor` / `parse_rumor` | 封印の中身のイベントを JSON として書き出し、解析する |
| `nostr::verify_rumor` | Rumor の id が内容のハッシュ値と一致するかを確かめる |
| `EventJsonError` | イベントと Rumor の JSON の解析の失敗 |
| `nip42::create_auth_event` | リレーの URL とチャレンジ文字列をタグに持つ認証イベント ( 種別 22242 ) を作り、署名する ( `getrandom` ) |
| `nip42::create_auth_event_with_rng` | `create_auth_event` と同じイベントを、バイト供給関数から得た補助乱数で署名する |
| `nip42::validate_auth_event` | 署名、種別、リレーとチャレンジのタグを検証し、署名者の公開鍵を返す |

### NIP-19、NIP-04、NIP-44

モジュール nip19, nip04, nip44 は、それぞれ同じ名前の feature で有効になります。

封印とギフトラップの関数は、[NIP-17](#nip-17-封印とギフトラップによるダイレクトメッセージ) の表で確認できます。

| 関数 | 説明 |
|------|------|
| `nip19::encode_npub` | 公開鍵を npub の文字列に符号化する |
| `nip19::encode_nsec` | 秘密鍵を nsec の文字列に符号化する |
| `nip19::encode_note` | イベント ID を note の文字列に符号化する |
| `nip19::encode_nprofile` | `NProfile` を nprofile の文字列に符号化する |
| `nip19::encode_nevent` | `NEvent` を nevent の文字列に符号化する |
| `nip19::encode_naddr` | `NAddr` を naddr の文字列に符号化する |
| `nip19::encode_nrelay` | `NRelay` を nrelay の文字列に符号化する |
| `nip19::decode` | NIP-19 の文字列を復号し、接頭辞に応じた `Nip19` の値を返す |
| `nip04::encrypt` / `encrypt_with_rng` | 自分の秘密鍵と相手の公開鍵から得た共有鍵で、本文を暗号化する |
| `nip04::decrypt` | 同じ共有鍵で、本文を復号する |
| `nip44::get_conversation_key` | 自分の秘密鍵と相手の公開鍵から、会話鍵を導出する |
| `nip44::encrypt` / `encrypt_with_rng` | 会話鍵で本文を暗号化する |
| `nip44::decrypt` | 会話鍵で本文を復号する |
| `nip44::calc_padded_len` | NIP-44 のパディングの規則で、平文の長さからパディング後の長さを計算する |

### `SecpError`

依存する crate と下位の処理の失敗は、由来ごとのバリアントに包んで返します。括弧内は、そのバリアントを有効にする feature です。

| 由来 | 包まれる形 |
|------|-----------|
| 曲線点の計算で使う `neco-galois` の有限体 ( Fp ) の演算 | `Field` |
| `neco-sha2` による RFC 6979 のノンスの導出 | `Nonce` |
| `neco-sha2` の SHA-256 と HMAC | `Hash` |
| `EventJsonError` ( nostr ) | `Json` |
| Base64 による本文の処理 ( nip04 か nip44 ) | `Base64` |
| NIP-44 の鍵導出関数による鍵の導出 ( nip04 か nip44 ) | `Hkdf` |

署名、暗号化、イベント ID の計算で使う SHA-256 と HMAC の失敗は、`Hash` に包んで返します。

- Schnorr の署名と検証: BIP340 のタグ付きハッシュ ( tagged hash )
- NIP-44 の暗号化と復号: 本文の HMAC
- NIP-17 の走査タグの導出: HMAC
- Nostr のイベントの署名と検証: イベント ID の SHA-256

乱数とメモリ確保に関する失敗は、それぞれ専用のバリアントで返します。

- `RandomUnavailable`: OS の乱数源が失敗した
- `EntropyRequired`: getrandom を無効にした構成で、暗号化の値に `None` を渡した
  - NIP-04 の IV ( 初期化ベクトル )
  - NIP-44 のノンス
- `CapacityOverflow { input_len }`: バッファの大きさの計算が桁あふれした
- `AllocationFailed { required }`: `required` 個の要素のメモリ確保に失敗した

## ライセンス

MIT
