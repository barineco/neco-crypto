use crate::VaultError;
use neco_sha2::Hmac;
use salsa20::{
    cipher::{typenum::U4, StreamCipherCore},
    SalsaCore,
};
use zeroize::Zeroizing;

const BLOCK_BYTES: usize = 1024;
const BLOCK_COUNT: usize = 32768;

pub(crate) fn derive(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut block = Zeroizing::new([0u8; BLOCK_BYTES]);
    for (counter, output) in (1u32..=32).zip(block.chunks_exact_mut(32)) {
        let mut hmac = Hmac::new(passphrase)?;
        hmac.update(salt)?.update(&counter.to_be_bytes())?;
        let result = Zeroizing::new(hmac.finalize());
        output.copy_from_slice(&result[..]);
    }
    let mut work = Zeroizing::new(crate::vector::<[u8; BLOCK_BYTES]>(BLOCK_COUNT)?);
    work.resize(BLOCK_COUNT, [0u8; BLOCK_BYTES]);
    for stored in work.iter_mut() {
        stored.copy_from_slice(&block[..]);
        block_mix(&mut block);
    }
    for _ in 0..BLOCK_COUNT {
        let index = usize::from(u16::from_le_bytes([block[960], block[961]])) & (BLOCK_COUNT - 1);
        for (byte, stored) in block.iter_mut().zip(&work[index]) {
            *byte ^= stored;
        }
        block_mix(&mut block);
    }
    let mut hmac = Hmac::new(passphrase)?;
    hmac.update(&block[..])?.update(&1u32.to_be_bytes())?;
    Ok(Zeroizing::new(hmac.finalize()))
}

fn block_mix(block: &mut [u8; BLOCK_BYTES]) {
    let mut last = Zeroizing::new([0u8; 64]);
    last.copy_from_slice(&block[BLOCK_BYTES - 64..]);
    let mut output = Zeroizing::new([0u8; BLOCK_BYTES]);
    for (index, chunk) in block.chunks_exact(64).enumerate() {
        let mut words = Zeroizing::new([0u32; 16]);
        for (word, (left, right)) in words
            .iter_mut()
            .zip(last.chunks_exact(4).zip(chunk.chunks_exact(4)))
        {
            *word = u32::from_le_bytes([
                left[0] ^ right[0],
                left[1] ^ right[1],
                left[2] ^ right[2],
                left[3] ^ right[3],
            ]);
        }
        let mut salsa = SalsaCore::<U4>::from_raw_state(*words);
        salsa.write_keystream_block((&mut *last).into());
        let offset = if index % 2 == 0 {
            index / 2 * 64
        } else {
            (index / 2 + 8) * 64
        };
        output[offset..offset + 64].copy_from_slice(&last[..]);
    }
    block.copy_from_slice(&output[..]);
}
