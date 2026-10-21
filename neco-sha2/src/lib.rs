#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod hkdf;
mod hmac;
pub mod rfc6979;
mod sha256;

pub use hkdf::{Hkdf, HkdfError, Prk};
pub use hmac::Hmac;
pub use sha256::{Sha256, Sha256Error, MAX_MESSAGE_BYTES};
