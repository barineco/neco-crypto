# neco crypto

[English](README.md)

neco crypto は、暗号学的ハッシュ、鍵導出、楕円曲線による署名、署名鍵の保管を行う Rust の crate 群です。

## crate 一覧

| crate | 説明 |
|---|---|
| [`neco-sha1`](neco-sha1) | SHA-1 のハッシュ関数 |
| [`neco-sha2`](neco-sha2) | SHA-256 によるハッシュ、メッセージ認証コード、鍵導出と、RFC 6979 による決定論的なノンスの導出 |
| [`neco-base64`](neco-base64) | 標準と URL セーフのアルファベットによる Base64 の符号化と復号 |
| [`neco-p256`](neco-p256) | 楕円曲線 P-256 による ECDSA の署名と検証 |
| [`neco-secp`](neco-secp) | 楕円曲線 secp256k1 による署名と、Nostr イベントの署名 |
| [`neco-argon2`](neco-argon2) | Argon2id によるパスワードハッシュと鍵導出 |
| [`neco-vault`](neco-vault) | Nostr クライアント向けに、署名鍵をメモリ上だけに保持する保管庫 ( vault ) |
| [`neco-nostr-wasm`](neco-nostr-wasm) | 署名と、保管庫による暗号化を JavaScript から使うための WebAssembly バインディング |

各 crate の README では、使い方、feature、公開 API を説明します。

feature は、Cargo の設定で有効にするかを選ぶ、機能や依存のまとまりに付けた名前です。

## 対象範囲

このリポジトリには、曲線の定数、ノンスの導出、ハッシュ、署名の実装と、それらを基に構築した Nostr と WebAssembly の応用が含まれます。汎用の構成要素には、別のリポジトリにある二つの crate を使います。

- 有限体の演算: [neco-algebra](https://github.com/barineco/neco-algebra) の `neco-galois`
- JSON の文法と文字列のエスケープ: [neco-parser](https://github.com/barineco/neco-parser) の `neco-json`

## セキュリティ

- [報告の手順と制約](SECURITY.md)

## ライセンス

[MIT](LICENSE)
