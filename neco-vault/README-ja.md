# neco-vault

[English](README.md)

neco-vault は、Nostr クライアントアプリが署名用の秘密鍵をメモリ上の保管庫 ( vault ) に保持したまま、イベントに署名するための crate です。
署名と、Nostr の暗号化と復号には `neco-secp` を使います。

公開 API では、署名、Nostr の暗号化と復号、公開鍵の参照、アカウント ( ラベルを付けて保持する秘密鍵 ) の追加・切り替え・削除ができます。また、グループでのやり取りに向けて、グループ鍵 ( メンバーがメッセージの暗号化に共通して使う 32 バイトの鍵 ) の生成、受信者に向けたグループ鍵の暗号化と復号、鍵の世代 ( エポック ) の更新を行う関数もあります。保管庫は、秘密鍵を使う操作をすべて内部で行い、署名済みイベント、暗号文、平文、公開鍵などの結果だけを返します。

## feature

| feature | 有効にするもの |
|---------|----------------|
| `std` ( 既定 ) | 標準ライブラリへのリンク。alloc も有効にする |
| `alloc` | crate のすべての API。ラベルとアカウントをヒープのコレクションで保持する。これだけを有効にすると no_std の構成になる |
| `getrandom` ( 既定 ) | OS の乱数源を読む通常形の関数。通常形は、名前に `_with_rng` を付けない形 ( [乱数源](#乱数源-通常形と-_with_rng-形) を参照 ) |
| `nostr` ( 既定 ) | neco-secp を経由するイベントの署名と、NIP-42 の認証イベント ( リレーへの認証に使うイベント ) |
| `nip04` | 保管庫を経由する NIP-04 の暗号化と復号 |
| `nip44` | 保管庫を経由する NIP-44 の暗号化と復号 |
| `nip17` | NIP-17 のギフトラップ ( 封印したメッセージをさらに暗号化して包む形式 ) によるダイレクトメッセージ ( DM ) 。nip44 と nostr も有効にする |
| `dm-epoch` | エポック鍵の導出と、グループ鍵の補助関数。エポック鍵は、会話鍵 ( 自分の秘密鍵と相手の公開鍵から NIP-44 で導出する二者の共通鍵 ) から世代ごとに導出する鍵。nip44 も有効にする |
| `encrypted` | Argon2id と XChaCha20-Poly1305 による認証付きの暗号化エクスポートとインポート |
| `legacy-migration` | 旧形式 ( v1、v2 ) の暗号化データから v3 への一方向の移行。encrypted も有効にする。次の互換性を壊す版 ( 0.3.0 ) で削除する |
| `security-hardening` | 秘密鍵の利用の前後に加える、個別に有効にできるフック ( 秘密鍵のバイト列の読み出し、擬似遅延、ダミー演算 ) |
| `wasm` | getrandom の js バックエンド。wasm32 のターゲットで、通常形の関数がブラウザーなどの JavaScript ホスト上で動く |

`wasm` を有効にすると、getrandom も有効になります。

## 使い方

### 基本的な署名

```rust
use neco_secp::{SecretKey, UnsignedEvent};
use neco_vault::{Vault, VaultConfig, VaultError};

fn sign_hello() -> Result<(), VaultError> {
    let mut vault = Vault::new(VaultConfig::default())?;
    let secret = SecretKey::generate()?;

    vault.import_plaintext("main", secret, 100)?;

    let signed = vault.sign_event(
        "main",
        UnsignedEvent {
            created_at: 101,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        },
        102,
    )?;

    assert_eq!(signed.kind, 1);
    Ok(())
}
```

### アクティブアカウント

呼び出し側は、`set_active` でアカウントの 1 つをアクティブアカウントに設定できます。
名前に `_active` を含む関数 ( `sign_event_active` など ) は、ラベルの代わりにアクティブアカウントを使います。空の保管庫へ最初にインポートしたアカウントは、自動的にアクティブアカウントになります。

```rust
use neco_secp::{SecretKey, UnsignedEvent};
use neco_vault::{Vault, VaultError};

fn use_active_account(
    vault: &mut Vault,
    secret: SecretKey,
    event: UnsignedEvent,
) -> Result<(), VaultError> {
    vault.import_plaintext("alice", secret, 100)?;
    // 空の保管庫へ最初にインポートした場合は、"alice" がアクティブになる

    vault.set_active("alice")?;
    let _label = vault.active_label(); // Some("alice")

    let _signed = vault.sign_event_active(event, 102)?;
    Ok(())
}
```

アクティブアカウントを削除すると、`active_label()` は `None` を返します。

```rust
use neco_vault::{Vault, VaultError};

fn remove_active_account(vault: &mut Vault) -> Result<(), VaultError> {
    vault.remove("alice")?;
    assert_eq!(vault.active_label(), None);
    Ok(())
}
```

`labels()` は、保存済みの全ラベルを整列して返す関数です。

### キャッシュの期限

保管庫は、インポートしたアカウントをメモリ上のキャッシュとして保持し、アカウントごとに最後に使った時刻を記録します。記録する時刻は、次の呼び出しに呼び出し側が渡す Unix 時刻です。

- インポート: `import_plaintext`、`import_encrypted`
- 署名と NIP-42 の呼び出し
- NIP-04、NIP-44、NIP-17 の呼び出し

期限を過ぎたアカウントと全アカウントは、それぞれ別の関数で破棄できます。どちらの関数でアクティブアカウントを破棄した場合も、その後の `active_label()` は `None` を返します。

- `clear_expired_cache(now)`: 最後に使った時刻から `now` までの経過がキャッシュの期限を超えたアカウントを破棄する
- `clear_cache`: 全アカウントを破棄する

期限は `VaultConfig` の `cache_timeout_seconds` に秒単位で指定し、既定値は 300 秒です。

### 乱数源: 通常形と `_with_rng` 形

乱数を使う操作には、それぞれ 2 つの形があります。乱数の用途は、署名の補助乱数 ( BIP340 の署名で秘密鍵に混ぜる 32 バイト ) 、暗号化のノンス、鍵導出のソルト、一時鍵などです。

- 通常形 ( `sign_event`、`export_encrypted` など ) : getrandom feature で OS の乱数源からバイト列を読む
- `_with_rng` 形: 呼び出し側が渡すクロージャから乱数を得る。getrandom を外した構成や、環境に固有の乱数源 ( 例: ブラウザーの `crypto.getRandomValues` ) に向けた形

クロージャは、受け取ったバッファを乱数で埋めます。クロージャが返す失敗の型は、乱数を使う実装に合わせて `SecpError` か `VaultError` になります。
以下、この型ごとの関数の群を、`SecpError` の系列、`VaultError` の系列と呼びます。

- `SecpError` の系列: neco-secp へ委譲する次の操作
  - 署名と NIP-42 の認証イベント
  - NIP-04、NIP-44、NIP-17 の暗号化と復号
  - dm-epoch のグループ鍵の暗号化 ( `encrypt_group_key_with_rng` ) : 一時鍵と NIP-44 のノンスを neco-secp の関数で作る
- `VaultError` の系列: 保管庫が自身で乱数を使う次の関数
  - `export_encrypted_with_rng`: 暗号化エクスポート
  - `migrate_legacy_encrypted_with_rng`: 旧形式の移行
  - `create_group_key_with_rng`: グループ鍵の生成
  - `encrypt_with_epoch_with_rng`、`encrypt_group_message_with_rng`: エポック鍵による暗号化

乱数源が欠けている場合、呼び出し側はクロージャから、それぞれの失敗の型の `EntropyRequired` を返します。呼び出し元へ返る値の形は、失敗の型の系列によって異なります。

- `VaultError` の系列: そのまま `VaultError::EntropyRequired` が返る
- `SecpError` の系列: バリアントに包まれ、`Crypto(SecpError::EntropyRequired)` が返る

通常形が返す OS の乱数源の失敗も、同じ二つの形です。

- `VaultError` の系列: `VaultError::RandomUnavailable`
- `SecpError` の系列: `Crypto(SecpError::RandomUnavailable)`

```rust
use neco_vault::{Vault, VaultError};

fn group_key_from(source: &[u8]) -> Result<[u8; 32], VaultError> {
    Vault::create_group_key_with_rng(&mut |buf| {
        source
            .get(..buf.len())
            .ok_or(VaultError::EntropyRequired)
            .map(|bytes| buf.copy_from_slice(bytes))
    })
}
```

通常形を使うには、`getrandom` feature が必要です。ただし復号の関数はクロージャを security-hardening の擬似遅延にだけ使うため、getrandom を外した次の構成でも通常形を使えます。

- NIP-04 と NIP-44 の復号: getrandom と security-hardening をどちらも外した構成にも通常形がある
  - `nip04_decrypt`、`nip04_decrypt_active`
  - `nip44_decrypt`、`nip44_decrypt_active`
- NIP-17 の復号: 通常形の `open_gift_wrap_dm` は、nip17 を有効にしたすべての構成にある

getrandom を外した構成では、これらの通常形は、`SecpError::EntropyRequired` を返すクロージャを `_with_rng` 形へ渡します。

### 暗号化エクスポートとインポート ( `encrypted` feature )

`export_encrypted` は、全体を認証した 105 バイトの暗号化データを返します。
`import_encrypted` はこの形式を読み、新しいラベルで秘密鍵をインポートします。
既存のラベルを渡した場合は、鍵導出の前に `DuplicateLabel` で失敗します。また、誤ったパスフレーズと、認証付き暗号 ( AEAD ) のタグの検証で見つかる暗号化データの改ざんは、どちらも `AuthenticationFailed` になります。

```rust
use neco_vault::{Vault, VaultError};

fn export_and_import(vault: &mut Vault) -> Result<(), VaultError> {
    let blob = vault.export_encrypted("alice", b"passphrase")?;
    vault.import_encrypted("bob", b"passphrase", &blob, 200)?;
    Ok(())
}
```

読み込みに失敗した場合、ラベルとアクティブアカウントは呼び出し前の状態のまま残ります。

### 形式 ( v3 )

暗号化データは 105 バイトの固定長で、整数はリトルエンディアンで書きます。

| オフセット | 長さ | 名前 | 内容 |
|-----------|------|------|------|
| 0 | 4 | `magic` | ASCII の `NVLT` |
| 4 | 1 | `version` | `03` |
| 5 | 4 | `m_cost` | u32、KiB 単位 |
| 9 | 4 | `t_cost` | u32 |
| 13 | 4 | `p_cost` | u32 |
| 17 | 16 | `salt` | 鍵導出のソルト。選択した乱数源のバイト |
| 33 | 24 | `nonce` | 暗号化のノンス。選択した乱数源のバイト |
| 57 | 32 | `ciphertext` | 暗号化した秘密鍵 |
| 89 | 16 | `tag` | Poly1305 タグ |

暗号化データを作る時は、パスフレーズから鍵を導出し、その鍵で秘密鍵を暗号化します。

- 鍵導出: Argon2id の版 0x13、出力 32 バイト。省略できる入力である秘密値 ( secret ) と関連データ ( associated data ) は空
- 暗号化: XChaCha20-Poly1305。鍵には Argon2id の出力を直接使う
- 暗号化の関連データ ( 暗号化せずに認証だけを行うデータ ) : ヘッダの 57 バイト ( オフセット 0 から 56 まで )
- 平文: 32 バイトの秘密鍵

### 鍵導出のポリシー

書き出しでは鍵導出の既定のコスト ( メモリ量、反復回数、並列度 ) を使い、読み込みでは鍵導出の前に、暗号化データに書かれたコストを検査します。コストの上限は、メモリ 256 MiB、反復 8 回、並列 8 レーンです。範囲を外れると `KdfParamsOutOfPolicy` を返し、暗号化データに書かれた 3 つの値をこの失敗に添えます。

| パラメータ | 下限 | 上限 | 既定 |
|-----------|------|------|------|
| `m_cost` ( KiB ) | 19,456 | 262,144 | 65,536 |
| `t_cost` | 2 | 8 | 3 |
| `p_cost` | 1 | 8 | 4 |

### パスフレーズ

- 形式: パスフレーズはバイト列で、渡されたまま使う。NUL と UTF-8 でないバイトも受け付ける。Unicode の正規化と文字コードの検査を行うかは、呼び出し側が決める
- 空のパスフレーズ: `EmptyPassphrase` で拒否する
- 1,024 バイトを超えるパスフレーズ: `PassphraseTooLong` で拒否する
- v3 の暗号化データの正規化: 書き出しと読み込みでは、呼び出し側が同じ正規化形のパスフレーズを渡す。JavaScript から渡す場合は `String.prototype.normalize("NFKC")` で正規化する
- 旧形式の暗号化データの正規化: 旧形式は正規化しないパスフレーズで書かれているため、旧パスフレーズは入力のまま渡す。移行に失敗した場合は、呼び出し側が NFC、NFD、NFKC に正規化した形を順に渡して試す

### 旧形式の移行 ( `legacy-migration` feature )

`migrate_legacy_encrypted` は、旧形式の暗号化データを v3 形式の暗号化データへ変換する関数です。
この関数は、`Vault` を作らずに呼び出せます。メモリ上のバイト列を受け取って変換後のバイト列を返すため、ファイルの読み書きは呼び出し側が行います。
旧形式の種別は、入力の長さと先頭のバイトで決まります。

- v2: 先頭のバイトが `0x02` の 100 バイト
- v1: 64 バイト

```rust
use neco_vault::{migrate_legacy_encrypted, VaultError};

fn migrate(legacy: &[u8]) -> Result<Vec<u8>, VaultError> {
    migrate_legacy_encrypted(legacy, b"old passphrase", b"new passphrase")
}
```

- 旧形式の復号の失敗 ( パディング、平文の長さ、秘密鍵の範囲 ): すべて `AuthenticationFailed`
- 旧パスフレーズ: 空でもよく、長さも任意。neco-sha2 の SHA-256 の入力の上限を超える旧パスフレーズは `Hash` を返す
- 新パスフレーズ: 上のパスフレーズの規則に従う
- v2 の鍵導出のコスト: v2 の暗号化データは、パスフレーズから鍵を導出する関数 scrypt の元のコスト ( `log_n=15, r=8, p=1` ) でだけ受理する。他のコストは `MalformedEncrypted(LegacyParams)` を返す
- scrypt の作業領域: 容量を検査してから 32 MiB を確保する。確保を拒否された場合は `AllocationFailed` を返す
- 移行後の検証: 新しい暗号化データを新パスフレーズで開き直す。認証の失敗と公開鍵の不一致は `MigrationVerificationFailed`
- 旧形式でない入力: 上の 2 つの旧形式に当たらない入力は `NotLegacyFormat`。v3 の暗号化データもこれに当たる
- 移行後の公開鍵の照合: 旧形式には改ざんを検出する認証タグが含まれないため、移行後の公開鍵を、別に記録しておいた値 ( 例: NIP-19 で公開鍵を表す npub の文字列 ) と照合してから信頼する
- 新パスフレーズの選び方: 露出した可能性のある旧暗号化データには、旧形式で使ったことのない新パスフレーズを選ぶ

`legacy-migration` は 0.3.0 で削除します。移行は 0.3.0 へ更新する前に済ませてください。

ファイルで暗号化データを保管する呼び出し側は、次の手順で移行してください。

1. バックアップを作る: 旧暗号化データを別の名前で複製し、複製が元と同じ内容であることを確認する。
2. 変換する: 旧暗号化データ、旧パスフレーズ、新パスフレーズを `migrate_legacy_encrypted` へ渡す。失敗したら止め、旧暗号化データをそのまま残す。
3. 一時ファイルを書く: 旧暗号化データと同じディレクトリに作り、新しい暗号化データを書いて、ディスクへ同期する。
4. 検証する: 一時ファイルを読み直し、新パスフレーズで空の保管庫へ読み込み、`public_key` が移行前に記録した公開鍵と一致することを確認する。
5. 置き換える: 一時ファイルを同じディレクトリ内で旧暗号化データの上へ改名する。これは原子的な置換になる。
6. バックアップを消す: 新しい暗号化データを読み込めることを確認してから削除する。旧パスフレーズで開く旧暗号化データは弱い保護の暗号文なので、複製も含めて消す。

### 保管庫を経由する NIP-04 と NIP-44

NIP-44 の関数を使うには、`nip44` feature が必要です。
NIP-04 の関数は、`nip04` feature を有効にすると使え、NIP-44 の関数と同じ引数を取ります。

```rust
use neco_vault::{Vault, VaultError};

fn roundtrip_nip44(vault: &mut Vault) -> Result<(), VaultError> {
    let bob = vault.public_key("bob")?;
    let payload = vault.nip44_encrypt_active(&bob, "hello", 101)?;
    let text = vault.nip44_decrypt_active(&bob, &payload, 102)?;
    assert_eq!(text, "hello");
    Ok(())
}
```

### セキュリティ強化 ( `security-hardening` feature )

`SecurityConfig` では、3 つのフックを個別に有効にできます。

- `enable_dummy_operations`: 固定入力のダミー署名を実行する。暗号化と復号の呼び出しでは、呼び出しの NIP に応じたダミー暗号化も加える
  - NIP-04 の呼び出し: NIP-04 のダミー暗号化
  - NIP-44 と NIP-17 の呼び出し: NIP-44 のダミー暗号化
- `enable_random_delay`: 呼び出しの乱数源から得た 1 バイトで回数を決め、`core::hint::spin_loop` を 64 回から 127 回まで回す
- `enable_constant_time`: 秘密鍵のバイト列を読み出し、`core::hint::black_box` に通す
  - 効果の範囲: コンパイラが最適化でこの読み出しを消すことを防ぐだけで、周囲の処理の実行時間は neco-secp の演算で決まる

保管庫は、署名用秘密鍵を使う次の呼び出しの前後で、有効にしたフックを実行します。

- 署名と NIP-42 の認証イベント
- NIP-04、NIP-44、NIP-17 の暗号化と復号

実行時に設定を置き換えるには、`set_security_config` を使います。
`SecurityConfig::default()` では、`enable_constant_time` だけが有効です。

サイドチャネルへの防御としての 3 つのフックの効果は、未実証です。

## 失敗

`VaultError` は、今後の版で失敗の種類を追加できるように `#[non_exhaustive]` を付けた列挙型です。

| 失敗 | 発生条件 |
|------|----------|
| `DuplicateLabel` | ラベルが既に存在する |
| `MissingLabel` | ラベルが存在しない |
| `NoActiveAccount` | アクティブアカウントが無い |
| `Crypto(error)` | neco-secp の失敗。SecpError を返すクロージャの失敗を含む |
| `MalformedEncrypted(kind)` | 長さの不一致、`magic` の不一致、最小の長さに満たない入力、形の不正な内容、移行で受理する値と異なる旧 v2 の scrypt のコスト |
| `UnsupportedEncryptedVersion { found }` | `magic` が一致し、版が 3 以外 |
| `KdfParamsOutOfPolicy { m_cost, t_cost, p_cost }` | パラメータがポリシーの範囲の外にある |
| `LegacyFormat(kind)` | 旧 v1 または旧 v2 の暗号化データ |
| `EmptyPassphrase` | パスフレーズが空 |
| `PassphraseTooLong { max }` | 書き出しと読み込みのパスフレーズ、または移行の新パスフレーズが 1,024 バイトを超える |
| `AuthenticationFailed` | 誤ったパスフレーズ、または構造検査を通る暗号化データの改ざん |
| `InvalidSecretKey` | 認証後の平文が有効な秘密鍵でない |
| `RandomUnavailable` | VaultError の系列の通常形で、OS の乱数源が失敗した |
| `CapacityOverflow { required }` | ラベル、アカウント、出力バッファが `isize::MAX` バイトを超える要求になる |
| `AllocationFailed { required }` | `try_reserve_exact` で、要求した要素数の分を確保できなかった |
| `EntropyRequired` | VaultError を返すクロージャに乱数源が無い |
| `SealFailed` | AEAD の暗号化段階が失敗した |
| `NotLegacyFormat` | `migrate_legacy_encrypted` の入力が旧形式でない |
| `MigrationVerificationFailed` | 移行した暗号化データの検証に失敗した |
| `Argon2(error)` | エクスポート、インポート、移行の Argon2id の鍵導出が失敗した |
| `Hkdf(error)` | エポック鍵の導出、またはグループのエポックの更新で、鍵導出関数 HKDF の展開が失敗した |
| `Hash(error)` | 旧形式の鍵導出の入力が、SHA-256 の入力の上限を超えた |

下位の crate の失敗をそのまま包むバリアントは、対応する feature を有効にした構成にだけあります。

- `VaultError::Argon2`: `encrypted`
- `VaultError::Hkdf`: `dm-epoch`
- `VaultError::Hash`: `legacy-migration`

暗号化データの構造と鍵導出のポリシーの検査で返す失敗は、暗号化データと呼び出し側の入力だけで決まります。

- `MalformedEncrypted`、`UnsupportedEncryptedVersion`: 構造の検査
- `KdfParamsOutOfPolicy`: 鍵導出のポリシーの検査

一方、次の失敗の原因は、要求の大きさか実行環境です。

- `CapacityOverflow`: 要求した量が `isize::MAX` バイトを超える
- `RandomUnavailable`: 乱数源が失敗した
- `AllocationFailed`: 要求した容量を確保できなかった
- `SealFailed`: 暗号化の段階が失敗した

`legacy-migration` を有効にした構成では、`LegacyFormat` の表示に移行関数の名前も含めます。

`MalformedKind` は、構造の失敗の種別を表す型です。

- `Magic`: `magic` が一致しない
- `Length { expected, actual }`: 長さが形式と一致しない
- `TooShort { minimum, actual }`: エポックの暗号文、または暗号化したグループ鍵が最小の長さに満たない
- `Payload`: 内容の形が不正
- `LegacyParams`: 旧 v2 の暗号化データの scrypt のコストが `log_n=15, r=8, p=1` と異なる

`LegacyKind` は、旧形式の種別を表します。

- `V1Sha256`: パスフレーズの SHA-256 のハッシュ値を鍵に使う 64 バイトの形式
- `V2ScryptCbc`: scrypt で導出した鍵を使う 100 バイトの形式

`dm-epoch` の補助関数も、同じ型で失敗を返します。

- `create_group_key`: 乱数を得られない場合は `RandomUnavailable`
- `encrypt_with_epoch`: ノンスの乱数を得られない場合は `RandomUnavailable`
- `encrypt_with_epoch`: 暗号化に失敗した場合は `SealFailed`
- `encrypt_group_key`: 乱数源または NIP-44 の失敗は `Crypto`
- `decrypt_with_epoch`: 28 バイト未満の入力は `MalformedEncrypted`
- `decrypt_with_epoch`: 誤った鍵と改ざんは `AuthenticationFailed`
- `decrypt_group_key`: ラベルが存在しない場合は `MissingLabel`
- `decrypt_group_key`: 33 バイト未満の入力と形の不正な内容は `MalformedEncrypted`
- `decrypt_group_key`: 会話鍵の導出、NIP-44 の復号、16 進文字列の復号の失敗は `Crypto`
- `derive_epoch_key`: ラベルが存在しない場合は `MissingLabel`
- `derive_epoch_key`: 会話鍵の導出の失敗は `Crypto`
- `derive_epoch_key`: HKDF の展開の失敗は `Hkdf`
- `rotate_group_epoch`: HKDF の展開の失敗は `Hkdf`

## 安全性の範囲

### 保証すること

- 秘密鍵の機密性: 32 バイトの秘密鍵を XChaCha20-Poly1305 で暗号化する
- 暗号化データ全体の完全性: 57 バイトのヘッダを関連データとして認証し、ヘッダを含む暗号化データのどこを改ざんしても拒否する
- 認証の失敗の種類: 誤ったパスフレーズと、AEAD のタグの検証で見つかる暗号化データの改ざんは、どちらも `AuthenticationFailed`。タグの検証を通過した上で復号結果が有効な秘密鍵でない場合は、代わりに `InvalidSecretKey`
- 資源の上限: 鍵導出のコストを、導出の前に、メモリ 256 MiB、反復 8 回、並列 8 レーンまでに制限する
- 確保の上限: ラベル、アカウント、出力を保持する前に必要な容量を計算し、`try_reserve_exact` でその分だけを確保する
- 上限を超えた要求: `isize::MAX` バイトを超える要求は `CapacityOverflow`
- 確保の拒否: 確保自体の拒否は `AllocationFailed`。どちらの失敗も必要な件数を添える
- 乱数の失敗: 乱数源を使えない場合は `RandomUnavailable` で失敗する
- 消去: 導出した鍵、平文の複製、AEAD のバッファ、Argon2id の作業メモリを、成功と失敗のどちらでも上書きする
- 旧形式の移行での消去: 旧形式の鍵 ( v1 の SHA-256 のハッシュ値、v2 の scrypt の出力 ) 、scrypt の作業領域、復号した旧形式の平文を `Zeroizing` で包む
- 旧形式の移行での Salsa20 の内部状態の消去: 依存先 salsa20 の `zeroize` feature により、解放時に上書きされる
- 診断出力: 保管庫の `Debug` の出力は、秘密鍵の代わりに `<redacted>` を表示する

### 呼び出し側と実行環境に委ねること

- パスフレーズの強度と Unicode の正規化
- 試行回数の制限とロックアウト
- ロールバックと再生の検出: 暗号化データは世代を表す値を含まない
- 保管庫が保持する秘密鍵のメモリの消去 ( `SecretKey` は `Copy` を実装した型 )
- panic 時の消去: スタックの巻き戻しを伴う panic では、解放時の処理が同じ上書きを行う。`panic = "abort"` の設定とプロセスの終了では、上書きの前に処理が終わる
- メモリの外部への露出: スワップ、コアダンプ、ハイバネーション、コールドブート攻撃、`mlock` によるページの固定
- `chacha20poly1305` のタグの定数時間の比較の外にあるサイドチャネル: security-hardening の 3 つのフックは、効果が未実証の補助にとどまる
- スタック上の一時値とレジスタの消去
- 旧形式の移行が使う AES の内部状態と SHA-256/HMAC の内部状態の消去
- 鍵への束縛 ( key commitment ) : 暗号化データは、暗号化に使った鍵を一つに確定する値を含まない。このため攻撃者は、細工した暗号化データを使い、1 回の問い合わせで複数のパスフレーズを試せる。信頼できない相手が `import_encrypted` を呼べるようにする場合は、呼び出し側で試行回数を制限する
- ラベルへの束縛: 暗号化データはラベルを含まず、任意のラベルで読み込める
- ブラウザーのメモリ: 鍵導出で使う作業領域は、上の鍵導出のポリシー表に従う。wasm インスタンスの線形メモリはそれに合わせて増え、ページ数は増える方向だけに動く

## API

表の乱数の列が「あり」の関数には、すべて名前に `_with_rng` を付けた形もあります。この形は、乱数源の節で説明したクロージャを受け取ります。署名、暗号化エクスポート、旧形式の移行でクロージャを渡す場合は、以下の `_with_rng` 形を呼び出します。

- `Vault::sign_event_with_rng`、`Vault::sign_event_active_with_rng`: 署名
- `Vault::export_encrypted_with_rng`: 暗号化エクスポート
- `migrate_legacy_encrypted_with_rng`: 旧形式の移行

乱数源の節に挙げた復号の関数を除き、「あり」の関数の通常形には、OS の乱数源を読むための `getrandom` feature が必要です。

NIP-17 の関数の一部は、走査鍵と走査タグを使います。走査鍵は、受信者が署名鍵とは別に持つ鍵です。送信者は `create_sealed_dm_with_scan_tag` に、受信者の公開鍵に加えて、走査鍵の公開鍵を渡します。走査タグは、ギフトラップの一時鍵と走査鍵から HMAC ( 鍵付きのハッシュ ) で導出する 16 バイトの値です。受信者は、走査鍵の秘密鍵を `compute_scan_tag` に渡して同じ値を計算し、自分宛てのギフトラップかを照合できます。

| 項目 | feature | 乱数 | 説明 |
|------|---------|------|------|
| `SecurityConfig` | | | 秘密鍵を使う呼び出しの前後に加えるフックの設定 |
| `VaultConfig` | | | キャッシュの期限とフックの設定 |
| `Vault` | | | 秘密鍵をメモリ上に保持し、署名などの操作を行う保管庫 |
| `VaultError` | | | 保管庫の操作が返す失敗の型 |
| `MalformedKind` | | | `VaultError::MalformedEncrypted` の構造の失敗の種別 |
| `LegacyKind` | | | `VaultError::LegacyFormat` の旧形式の種別 |
| `SealedDmResult` | `nip17` | | ギフトラップのイベントと、受信者が自分宛てかを判定するための走査タグ |
| `Vault::new` | | | 空の保管庫を作る |
| `Vault::import_plaintext` | | | ラベルに紐付けて秘密鍵をインポートする |
| `Vault::contains` | | | ラベルの有無を返す |
| `Vault::remove` | | | ラベルでアカウントを削除する |
| `Vault::labels` | | | 保存済みの全ラベルを整列して返す |
| `Vault::set_active` | | | アクティブアカウントを設定する |
| `Vault::active_label` | | | アクティブアカウントのラベルを返す |
| `Vault::public_key` | | | 指定したラベルの x-only 公開鍵 ( BIP340 の 32 バイトの公開鍵 ) を返す |
| `Vault::public_key_active` | | | アクティブアカウントの x-only 公開鍵を返す |
| `Vault::set_security_config` | | | 実行時にフックの設定を置き換える |
| `Vault::security_config` | | | 現在のフックの設定を返す |
| `Vault::clear_cache` | | | 全アカウントを破棄する |
| `Vault::clear_expired_cache` | | | 最後に使った時刻からキャッシュの期限を超えたアカウントを破棄する |
| `Vault::sign_event` | `nostr` | あり | 指定したアカウントで Nostr イベントに署名する |
| `Vault::sign_event_active` | `nostr` | あり | アクティブアカウントで Nostr イベントに署名する |
| `Vault::create_auth_event` | `nostr` | あり | 指定したアカウントで NIP-42 の認証イベントを作る |
| `Vault::create_auth_event_active` | `nostr` | あり | アクティブアカウントで NIP-42 の認証イベントを作る |
| `Vault::nip04_encrypt` | `nip04` | あり | 指定したアカウントで NIP-04 の暗号化を行う |
| `Vault::nip04_decrypt` | `nip04` | あり | 指定したアカウントで NIP-04 の復号を行う |
| `Vault::nip04_encrypt_active` | `nip04` | あり | アクティブアカウントで NIP-04 の暗号化を行う |
| `Vault::nip04_decrypt_active` | `nip04` | あり | アクティブアカウントで NIP-04 の復号を行う |
| `Vault::nip44_encrypt` | `nip44` | あり | 指定したアカウントで NIP-44 の暗号化を行う |
| `Vault::nip44_decrypt` | `nip44` | あり | 指定したアカウントで NIP-44 の復号を行う |
| `Vault::nip44_encrypt_active` | `nip44` | あり | アクティブアカウントで NIP-44 の暗号化を行う |
| `Vault::nip44_decrypt_active` | `nip44` | あり | アクティブアカウントで NIP-44 の復号を行う |
| `Vault::create_sealed_dm` | `nip17` | あり | ギフトラップした NIP-17 の DM を作る |
| `Vault::create_sealed_dm_with_scan_tag` | `nip17` | あり | ギフトラップした NIP-17 の DM を作り、受信者の走査鍵に向けた走査タグも返す |
| `Vault::compute_scan_tag` | `nip17` | | 呼び出し側が渡す走査鍵の秘密鍵と、ギフトラップの一時公開鍵から走査タグを計算する |
| `Vault::open_gift_wrap_dm` | `nip17` | あり | ギフトラップを開き、未署名イベント ( Rumor ) を返す |
| `Vault::derive_epoch_key` | `dm-epoch` | | 会話鍵からエポック鍵を導出する |
| `Vault::encrypt_with_epoch` | `dm-epoch` | あり | エポック鍵で認証付きの暗号化を行う |
| `Vault::decrypt_with_epoch` | `dm-epoch` | | エポック鍵で認証付きの復号を行う |
| `Vault::create_group_key` | `dm-epoch` | あり | 乱数で作った 32 バイトのグループ鍵を返す |
| `Vault::encrypt_group_key` | `dm-epoch` | あり | NIP-44 でグループ鍵を暗号化する |
| `Vault::decrypt_group_key` | `dm-epoch` | | NIP-44 でグループ鍵を復号する |
| `Vault::encrypt_group_message` | `dm-epoch` | あり | エポック鍵でグループのメッセージを暗号化する |
| `Vault::decrypt_group_message` | `dm-epoch` | | エポック鍵でグループのメッセージを復号する |
| `Vault::rotate_group_epoch` | `dm-epoch` | | 次のグループのエポック鍵を導出する |
| `Vault::export_encrypted` | `encrypted` | あり | 秘密鍵を v3 形式の暗号化データとしてエクスポートする |
| `Vault::import_encrypted` | `encrypted` | | v3 形式の暗号化データから秘密鍵をインポートする |
| `migrate_legacy_encrypted` | `legacy-migration` | あり | 旧形式の暗号化データを v3 形式の暗号化データへ変換する |

## ライセンス

MIT
