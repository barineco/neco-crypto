pub mod probe;

pub fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit pair"))
        .collect()
}

pub fn test_entropy(bytes: &mut [u8]) -> Result<(), neco_vault::VaultError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let counter = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut state = counter.wrapping_add(0x9e37_79b9_7f4a_7c15);
    for byte in bytes.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    if bytes.len() >= 8 {
        let start = bytes.len() - 8;
        bytes[start..].copy_from_slice(&counter.to_le_bytes());
    }
    Ok(())
}

pub const KAT_A_PASSPHRASE: &[u8] = b"correct horse battery staple";
pub const KAT_A_BLOB: &str = concat!(
    "4e564c5403000001000300000004000000101112131415161718191a1b1c1d1e",
    "1f303132333435363738393a3b3c3d3e3f4041424344454647d72f1f93066908",
    "4f637a6bf01e878f71a8cccc64768d2f6410f140a0558a86a4836ecafe7d2f01",
    "2de8b77f7485d47fa7",
);

pub const LEGACY_PASSPHRASE: &[u8] = b"legacy passphrase";
pub const LEGACY_V2_BLOB: &str = concat!(
    "020f0801404142434445464748494a4b4c4d4e4f505152535455565758595a5b",
    "5c5d5e5f707172737475767778797a7b7c7d7e7feae62227360ab5cf874d7c74",
    "26c053376f489ed02560a92e65015c88f078406b845494532f04a8efe8cfe797",
    "2d2bf7f0",
);
pub const LEGACY_V1_BLOB: &str = concat!(
    "707172737475767778797a7b7c7d7e7f1205bc8a534b6481ddc4accf6b1b0c7e",
    "d4770f6606d745f524b0093e7ddbdd9d803bee4b793612d7dd1e87a818fc30b5",
);

pub const SECRET_1: &str = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";
pub const PUBLIC_1: &str = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
