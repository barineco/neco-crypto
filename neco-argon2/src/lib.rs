//! RFC 9106 に準拠した Argon2id ( PHC のバージョン 19 ) によるパスワードハッシュの計算と鍵導出を提供します。

//! `alloc` は、Argon2id の API の全体を有効にします。
//! `phc` は PHC 形式の文字列を扱う関数を、`getrandom` は OS の乱数源によるソルトの生成を有効にします。

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "alloc")]
mod argon2id;
#[cfg(feature = "alloc")]
mod blake2b;

#[cfg(all(feature = "phc", feature = "getrandom"))]
pub use argon2id::argon2id_hash_encoded;
#[cfg(feature = "alloc")]
pub use argon2id::{
    argon2id_hash, argon2id_hash_into, argon2id_hash_with_secret, AllocationOperation, Argon2Error,
    Argon2Params,
};
#[cfg(feature = "phc")]
pub use argon2id::{
    argon2id_hash_encoded_with_rng, argon2id_hash_encoded_with_salt, argon2id_verify,
};
