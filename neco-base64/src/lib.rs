//! Zero-dependency Base64 encoder and decoder.
//!
//! Supports the standard (RFC 4648 section 4) and URL-safe (RFC 4648 section 5) alphabets; URL-safe encoding is available with or without padding.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(feature = "alloc")]
mod decode;
#[cfg(feature = "alloc")]
mod encode;
mod error;

#[cfg(feature = "alloc")]
pub use decode::{decode, decode_url, decode_url_strict};
#[cfg(feature = "alloc")]
pub use encode::{encode, encode_url, encode_url_padded};
pub use error::Base64Error;
