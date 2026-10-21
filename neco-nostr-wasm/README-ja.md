# neco-nostr-wasm

[English](README.md)

neco-nostr-wasm は、[neco-secp](../neco-secp) と [neco-vault](../neco-vault) の WebAssembly バインディングです。

JavaScript からは、`wasm-bindgen` を通じて、Nostr クライアントが鍵と署名を扱うための機能を使えます。

- Nostr の署名
- 保管庫 ( vault ) による暗号化
- NIP ( Nostr の仕様を定める文書 ) に従う補助関数
- 鍵のマイニング ( 条件に合う公開鍵が見つかるまで鍵を生成する探索 ) の補助関数

JavaScript と Rust の間で受け渡す値は、主に hex 文字列 ( バイト列を 16 進数で表した文字列 ) と JSON の文字列、暗号化済みのバイト列です。

## JavaScript バインディング

- `NostrSigner`: アカウント管理、署名、NIP-04/44、NIP-17、NIP-42、暗号化したインポートとエクスポート、セキュリティ設定をまとめた保管庫のラッパー
- 自由関数 ( モジュールの直下に公開した関数 ) : Bech32 と NIP-19 の補助関数、公開鍵の変換、イベントの補助関数 ( 確定、検証、直列化、イベント ID の計算、NIP-42 の検証 ) 、マイニングと鍵生成の補助関数、旧形式の暗号化データの移行

`decode_nsec` という名前のバインディングは二つあります。

- 自由関数 `decode_nsec(nsec)`: 秘密鍵を hex 文字列で返す
- メソッド `NostrSigner.decode_nsec(nsec, label)`: 秘密鍵を、指定したラベルのアカウントとして保管庫に取り込む。戻り値は undefined

## 受け渡す値の形式

- 鍵: hex 文字列
- イベント: JSON 文字列
- 暗号化エクスポート: `Uint8Array`
- エラー: 文字列のメッセージを持つ `JsValue` ( 時刻の取得の失敗だけは、後述の `Error` オブジェクト )
- 平文の秘密鍵の返却: 自由関数 `decode_nsec` と、バニティマイニング ( npub が指定の文字列で始まる鍵の探索 ) の結果。JavaScript 側で平文の秘密鍵を受け取る必要がある場合に使う
- 平文の秘密鍵の拒否: `generate_secret_key` は常に次の固定の失敗を返す

```text
plaintext secret export is disabled; use vanity mining output if needed
```

## イベントと NIP-19 の識別子の JSON

イベントの補助関数と、NIP-19 の識別子を符号化する関数は、同じ方法で JSON を読み書きします。

- 入力: JSON の文字列を借用したまま解析する
- 出力: 必要なバイト数を先に数え、ちょうどその容量を確保してから書き込む。数えた長さが扱える範囲を超える場合と、確保に失敗した場合は、失敗を返す

未署名イベントは、四つのフィールドから成る JSON オブジェクトです。

- `created_at`: 作成時刻 ( Unix 秒 )
- `kind`: イベント種別の数値
- `content`: 本文の文字列
- `tags`: タグ ( 文字列配列の配列 )

公開鍵も必要とする関数は、さらに `pubkey` を読みます。

NIP-19 の識別子を構築する関数は、それぞれ一つの JSON オブジェクトを受け取ります。下の表記の各行は、一つのフィールドに使える名前を、優先する順に並べています。

- 優先順位: フィールドの有無だけで決まる。下の表記で先に挙げた名前のフィールドがあれば、その値が `null` や誤った型でも、そのフィールドを採用する
- 採用したフィールドの値が `null` や誤った型の場合: 呼び出しが失敗する。例外は `encode_nevent` の作成者とイベント種別で、この二つは値なしとして扱う
- `encode_nevent` のイベント種別の範囲: 4,294,967,296 以上で 2^64 未満の整数は、`kind out of range` で失敗する
- 同じキーの重複: 同じ JSON オブジェクトの中では、最後に現れた方が残る

```text
encode_nevent:   id_hex > id,  author_hex > author,  kind > event_kind
encode_nprofile: pubkey_hex > pubkey
encode_naddr:    author_hex > author > pubkey_hex > pubkey,  kind > event_kind
```

`encode_naddr` では、文字列のフィールド `identifier` も必須です。

`relays` はどの関数でも省略でき、省略すると空の配列になります。

`decode_bech32` が返すオブジェクトのフィールドの組は、識別子の種類に応じた 6 通りです。

```text
npub:     kind, pubkey_hex
note:     kind, id_hex
nprofile: kind, pubkey_hex, relays
nevent:   kind, id_hex, author_hex ( 文字列または null ), event_kind ( 数値または null ), relays
naddr:    kind, identifier, author_hex, event_kind ( 数値 ), relays
nrelay:   kind, relay
```

出力の `kind` は、入力の `kind` と異なり、識別子の種類を表します。

- `kind`: 識別子の種類を表す文字列
- `event_kind`: イベント種別の数値

`decode_bech32` に `nsec` の文字列を渡すと、呼び出しは常に同じ文言のエラーで失敗します。

```text
nsec decode is disabled in wasm boundary
```

`nsec` から平文の秘密鍵を読む関数は、自由関数の `decode_nsec` です。

## 時刻

アカウントの追加、署名、暗号化と復号、キャッシュの期限切れの処理を行う `NostrSigner` のメソッドは、実行環境から現在時刻を読みます。一方、自由関数が使う時刻は、入力の JSON にある値だけです。

- 保管庫は、この時刻を各アカウントの最終使用時刻として記録する
- `clear_expired_cache` は、この時刻を `cache_timeout_seconds` と比べる
- `create_auth_event` と `create_sealed_dm` は、作るイベントにもこの時刻を使う

現在時刻の取得元は、ビルドの対象によって異なります。`wasm32` での取得元は、Unix 秒を計算する次のインラインの JavaScript です。

```js
const milliseconds = Date.now();
if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) {
  throw new Error("invalid system clock");
}
return BigInt(milliseconds) / 1000n;
```

時計の値が検査で不正と判定されると、このコードは JavaScript の `Error` を投げます。`#[wasm_bindgen(catch)]` を付けた宣言がこの例外を捕捉し、メソッドはその例外のオブジェクトを失敗として返します。

`wasm32` 以外の対象 ( ネイティブ環境でのテスト実行 ) では標準ライブラリの `SystemTime` を使い、Unix エポックより前の時刻には次の失敗を返します。

```text
system clock precedes Unix epoch
```

## エラー

この crate は、Rust 側のエラー型の表示文言を 512 バイトの固定長のスタックバッファの中で整形してから、JavaScript の文字列として返します。

- 整形した文字列が 512 バイトに収まる場合: その文字列をそのまま返す
- 整形が 512 バイトを超える場合、または書き込んだバイト列が有効な UTF-8 でない場合: 次の代わりのメッセージを返す

```text
error message could not be formatted in 512 bytes
error message contains invalid UTF-8
```

512 バイトの上限は、メッセージの整形に適用されます。値の変換に伴う次の確保は、wasm-bindgen が生成したコードと JavaScript 実行環境が、値の大きさに応じて行います。

- JavaScript から渡した引数を Rust 側の値へ変換する確保
- Rust 側の出力やエラーを JavaScript の値へ変換する確保、および JavaScript エンジン側の確保

## マイニング

マイニングと鍵生成の各関数は、`neco-secp` の鍵の生成と探索の関数を呼び出し、その結果を JSON に符号化して返します。

- `generate_keypair` は `KeyBundle::generate` を使う
- `generate_keypairs_batch` は `KeyBundle::generate_batch` を使う
- `mine_pow_batch` は `mine_pow_best` を使う
- `mine_vanity_batch` は `mine_vanity_npub` を使う
- `mine_vanity_with_candidates` は `mine_vanity_npub_candidates` を使う

生成した鍵の公開鍵は、どの関数の結果でも三つのフィールドで表します。

- `npub`: NIP-19 の npub 形式の文字列
- `pubkey_hex`: x 座標だけの形式 ( 32 バイト ) の hex 文字列
- `public_key_hex`: SEC1 の圧縮形式 ( 33 バイト ) の hex 文字列

- `generate_keypair` と `generate_keypairs_batch`: 公開鍵のフィールドだけを返し、生成した秘密鍵は呼び出しの終了時に破棄する
- `mine_pow_batch`: 公開鍵のフィールドと `difficulty`。この値は、見つけた最良の鍵の公開鍵を x 座標だけの形式で表したバイト列について、先頭から続く 0 のニブル ( 4 ビット ) の数
- `mine_vanity_batch`: 公開鍵のフィールドと `secret_hex`
- `mine_vanity_with_candidates`: 候補のオブジェクトの配列
  - 各候補: 公開鍵のフィールド、`secret_hex`、一致した長さ `matched_len`

バニティマイニングでは、指定した接頭辞を、npub のうち `npub1` に続くデータ部と照合します。接頭辞に使える文字は、Bech32 のデータ部の 32 文字です。

```text
qpzry9x8gf2tvdw0s3jn54khce6mua7l
```

- それ以外の文字を含む接頭辞は `invalid npub vanity prefix` で失敗する
- `mine_vanity_batch` は、一致する前に試行回数を使い切ると `exhausted attempts` で失敗する
- `mine_pow_batch` は、すべての試行が要求した難易度を下回る場合に `exhausted attempts` で失敗する

## 暗号化したインポートとエクスポート

- `encrypt_secret_key`: 105 バイトの v3 形式の暗号化データを `Uint8Array` で返す
- `add_account`: v3 の形式だけを受け付ける
- 旧形式 ( v1、v2 ) の暗号化データ: `legacy encrypted format` で始まるメッセージの例外で拒否する
- `migrate_legacy_encrypted`: 旧形式の暗号化データを、メモリ上で v3 形式の暗号化データへ変換する
- 新しいパスフレーズ: 呼び出し側が `String.prototype.normalize("NFKC")` で正規化し、書き出しと読み込みで同じ形を使う
- 旧形式データの旧パスフレーズ: 旧形式は入力のままのパスフレーズで書かれているため、呼び出し側はまず無加工で渡す
- 旧パスフレーズの再試行: `migrate_legacy_encrypted` は、受け取ったバイト列で 1 回だけ復号を試す
- 認証に失敗した場合: 呼び出し側が NFC、NFD、NFKC の形を順に渡して呼び直す
- 旧形式データの真正性: 旧形式には改ざんを検出する認証が無いため、移行後の公開鍵を、別に記録した値 ( 例: npub ) と照合する
- 線形メモリ ( wasm モジュールが使う連続したメモリ領域 ) の作業領域: Argon2id の作業領域は鍵導出のポリシーの上限に従う。読み込む暗号化データでは上限の 262,144 KiB まで、書き出しと移行で作る暗号化データでは 65,536 KiB を使う
- 線形メモリの追加の量: wasm モジュール内のメモリアロケータがどれだけ解放領域を再利用するかに依存する
- 線形メモリのページ数: 増える方向にだけ変わる

`migrate_legacy_encrypted` は、他の自由関数と同じく Rust の名前で公開されます。次の例では、旧パスフレーズを無加工の形で試し、続けて正規化した各形で試します。

```js
import init, { migrate_legacy_encrypted } from "./pkg/neco_nostr_wasm.js";

await init();

const candidates = [
  oldPassphrase,
  oldPassphrase.normalize("NFC"),
  oldPassphrase.normalize("NFD"),
  oldPassphrase.normalize("NFKC"),
];
let v3;
for (const candidate of candidates) {
  try {
    v3 = migrate_legacy_encrypted(legacyBytes, candidate, newPassphrase.normalize("NFKC"));
    break;
  } catch (error) {
    if (!String(error).startsWith("authentication failed")) throw error;
  }
}
```

失敗のメッセージは、保管庫のエラー型の表示文言です。

- 誤ったパスフレーズ、または改ざんされた暗号化データ

  ```text
  authentication failed: wrong passphrase or modified data
  ```

- `add_account` に渡した旧形式の暗号化データ ( v1 と v2 で 1 行ずつ。どちらも `legacy encrypted format` で始まり、形式のバージョンが続く )

  ```text
  legacy encrypted format ( v1, SHA-256 key ); convert it with migrate_legacy_encrypted
  legacy encrypted format ( v2, scrypt key ); convert it with migrate_legacy_encrypted
  ```

- `migrate_legacy_encrypted` に渡した、旧形式の形 ( 64 バイト、または先頭が 02 の 100 バイト ) と異なる入力

  ```text
  data is not in a legacy encrypted format
  ```

- 空のパスフレーズ

  ```text
  passphrase is empty
  ```

## 使い方

まず `wasm-pack build --target web` でビルドし、生成されたパッケージを JavaScript からインポートします。

自由関数と `NostrSigner` のメソッドは、どれも同期関数です。

```js
import init, { NostrSigner, encode_npub, mine_vanity_batch } from "./pkg/neco_nostr_wasm.js";

await init();

const signer = new NostrSigner(300n);
signer.add_account_with_plaintext("main", "<secret-hex>");

const signed = signer.sign_event(
  JSON.stringify({
    created_at: 1,
    kind: 1,
    tags: [],
    content: "hello",
  }),
);

const npub = encode_npub(signer.get_public_key("main"));
const vanity = JSON.parse(mine_vanity_batch("ac", 100000));
```

## API

| 項目 | 説明 |
|------|------|
| `NostrSigner` | 保管庫を使って署名と暗号化を行うラッパー |
| `encode_npub`, `encode_note` | 公開鍵とイベント ID の hex 文字列を、NIP-19 の識別子へ符号化する |
| `encode_nsec` | 秘密鍵の hex 文字列を、NIP-19 の `nsec` へ符号化する |
| `encode_nevent`, `encode_nprofile` | JSON のオブジェクトから、イベントとプロフィールの NIP-19 の識別子を作る |
| `encode_naddr` | JSON のオブジェクトから、作成者、種別、`identifier` の組を指す NIP-19 の識別子を作る |
| `decode_nsec` | `nsec` を復号し、平文の秘密鍵を hex 文字列で返す |
| `decode_bech32` | `nsec` 以外の NIP-19 の識別子を復号し、JSON のオブジェクトで返す |
| `encode_lnurl` | 入力文字列をそのまま Bech32 ( 接頭辞 `lnurl` ) で符号化する関数。URL の妥当性検査は呼び出し側が行う |
| `generate_secret_key` | 常に固定の失敗を返す |
| `derive_public_key`, `derive_public_key_sec1` | 秘密鍵から、x 座標だけの形式 ( x-only ) と SEC1 形式の公開鍵を求める |
| `parse_public_key_hex` | 公開鍵の hex 文字列を検証し、hex 文字列で返す |
| `finalize_event`, `verify_event` | Nostr イベントへの署名と、署名の検証 |
| `serialize_event`, `get_event_hash` | イベント ID の計算に使う直列化の文字列と、イベント ID を返す |
| `validate_auth_event` | NIP-42 の認証イベントを検証する |
| `generate_keypair`, `generate_keypairs_batch` | 鍵を生成し、公開鍵のフィールドだけを返す |
| `mine_pow_batch` | プルーフオブワークのマイニング。公開鍵のフィールドと `difficulty` を返す |
| `mine_vanity_batch`, `mine_vanity_with_candidates` | バニティマイニング。秘密鍵の hex 文字列を含む結果を返す |
| `migrate_legacy_encrypted` | 旧形式の暗号化データを v3 形式の暗号化データへ変換する |

### `NostrSigner` のメソッド

| メソッド | 説明 |
|----------|------|
| `new(cache_timeout_seconds)` | キャッシュの期限 ( 秒 ) を指定して、空の保管庫を作る |
| `add_account_with_plaintext(label, secret_hex)` | 秘密鍵の hex 文字列を、ラベルを付けたアカウントとして取り込む |
| `add_account(label, encrypted, passphrase)` | v3 形式の暗号化データを復号し、アカウントとして取り込む |
| `decode_nsec(nsec, label)` | `nsec` を復号し、アカウントとして取り込む |
| `remove_account(label)` | アカウントを削除する |
| `get_accounts()` | 全アカウントのラベルを、整列した JSON の文字列配列で返す |
| `get_active_account()` | アクティブアカウントのラベルを返す。アクティブアカウントが無い場合は undefined |
| `set_active_account(label)` | アクティブアカウントを切り替える |
| `get_public_key(label)` | アカウントの公開鍵を hex 文字列で返す |
| `encrypt_secret_key(label, passphrase)` | アカウントの秘密鍵を、v3 形式の暗号化データで返す |
| `sign_event(json)`, `sign_event_with(label, json)` | 未署名イベントに、アクティブアカウントまたは指定したアカウントで署名する |
| `nip04_encrypt`, `nip04_decrypt` | アクティブアカウントの秘密鍵と相手の公開鍵による、NIP-04 の暗号化と復号 |
| `nip44_encrypt`, `nip44_decrypt` | アクティブアカウントの秘密鍵と相手の公開鍵による、NIP-44 の暗号化と復号 |
| `create_sealed_dm(content, recipient_hex)` | アクティブアカウントから受信者へのダイレクトメッセージを、NIP-17 のギフトラップとして作る |
| `open_gift_wrap(json)` | ギフトラップをアクティブアカウントで開き、包まれたイベントを JSON の文字列で返す |
| `create_auth_event(challenge, relay_url)` | アクティブアカウントで署名した NIP-42 の認証イベントを作る |
| `clear_cache()`, `clear_expired_cache()` | 全アカウント、または期限を過ぎたアカウントを破棄する |
| `set_security_config(json)` | 秘密鍵の利用の前後に加える保護の処理を、JSON で選ぶ |

`set_security_config` に渡す JSON では、各処理の有無を真偽値で指定します。省略したフィールドは、下の既定値になります。

- `enable_constant_time`: 最適化で省かれない形で秘密鍵のバイト列を読み出す処理。既定値は true
- `enable_random_delay`: 乱数で回数を決めた待ち時間。既定値は false
- `enable_dummy_operations`: ダミーの署名と暗号化。既定値は false

## ライセンス

MIT
