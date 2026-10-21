use std::vec::Vec;

pub(crate) fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit pair"))
        .collect()
}

pub(crate) const SECRET_1: &str =
    "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";
pub(crate) const PUBLIC_1: &str =
    "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
pub(crate) const SALT: &str = "101112131415161718191a1b1c1d1e1f";
pub(crate) const NONCE: &str = "303132333435363738393a3b3c3d3e3f4041424344454647";

pub(crate) const KAT_A_PASSPHRASE: &[u8] = b"correct horse battery staple";
pub(crate) const KAT_A_KEY: &str =
    "1cd84e588c72f1d0bb3041fdd8a32de5ec738487c23ac9c5d84f119e05858bf8";
pub(crate) const KAT_A_BLOB: &str = concat!(
    "4e564c5403000001000300000004000000101112131415161718191a1b1c1d1e",
    "1f303132333435363738393a3b3c3d3e3f4041424344454647d72f1f93066908",
    "4f637a6bf01e878f71a8cccc64768d2f6410f140a0558a86a4836ecafe7d2f01",
    "2de8b77f7485d47fa7",
);

pub(crate) const KAT_B_PASSPHRASE: &str = "70c3a4737377c3b6726420f09f9491";
pub(crate) const KAT_B_BLOB: &str = concat!(
    "4e564c5403004c00000200000001000000101112131415161718191a1b1c1d1e",
    "1f303132333435363738393a3b3c3d3e3f4041424344454647d240964fa5b102",
    "782388d913b97fd9ee3055b796ecff19e57a1708d1c32e723ebf136c788992b9",
    "4e3d5fbacdd9e600af",
);

pub(crate) const KAT_C_PASSPHRASE: &[u8] = b"kat-c";
pub(crate) const KAT_C_KEY: &str =
    "546d78c758163d187ed6f9ca06bf7ef549992cefcdfc718774e1a79e52dc4c34";
pub(crate) const KAT_C_BLOB: &str = concat!(
    "4e564c5403400000000100000001000000101112131415161718191a1b1c1d1e",
    "1f303132333435363738393a3b3c3d3e3f40414243444546474d984f7df2ddef",
    "2a41e69b9cb3ea8a14b46a0548162659d4fa309258f09893fc0ecce9bbfc7ce1",
    "c73911b282fafe5041",
);

pub(crate) const XCHACHA_KEY: &str =
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
pub(crate) const XCHACHA_NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
pub(crate) const XCHACHA_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
pub(crate) const XCHACHA_PLAINTEXT: &str = concat!(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
    "637265656e20776f756c642062652069742e",
);
pub(crate) const XCHACHA_CIPHERTEXT: &str = concat!(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
    "21f9664c97637da9768812f615c68b13b52e",
);
pub(crate) const XCHACHA_TAG: &str = "c0875924c1c7987947deafd8780acf49";

#[cfg(feature = "legacy-migration")]
pub(crate) const LEGACY_PASSPHRASE: &[u8] = b"legacy passphrase";
#[cfg(feature = "legacy-migration")]
pub(crate) const LEGACY_V1_BLOB: &str = concat!(
    "707172737475767778797a7b7c7d7e7f1205bc8a534b6481ddc4accf6b1b0c7e",
    "d4770f6606d745f524b0093e7ddbdd9d803bee4b793612d7dd1e87a818fc30b5",
);
