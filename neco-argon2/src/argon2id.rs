use crate::blake2b::{blake2b_into, blake2b_long_into};
#[cfg(any(feature = "phc", test))]
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "phc")]
use core::fmt::Write;
#[cfg(feature = "phc")]
use neco_base64::{decode, encode, Base64Error};
use zeroize::{DefaultIsZeroes, Zeroize, Zeroizing};

/// Argon2id の引数です。
/// 既定値は、メモリ量 19456 KiB、反復回数 2、並列度 1、出力長 32 バイトです。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// メモリ量 ( KiB ) です。`p_cost` の 8 倍以上を指定します。
    pub m_cost: u32,
    /// 反復回数です。1 以上を指定します。
    pub t_cost: u32,
    /// 並列度 ( レーン数 ) です。1 以上 2^24 − 1 ( 16,777,215 ) 以下を指定します。
    pub p_cost: u32,
    /// ハッシュの出力長 ( バイト ) です。4 以上を指定します。
    pub output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
            output_len: 32,
        }
    }
}

/// 確保しようとした量の種類です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationOperation {
    /// 1,024 バイトの作業メモリのブロック数です。
    MemoryBlocks,
    /// ハッシュの出力のバイト数です。
    OutputBytes,
    /// PHC 形式の文字列のバイト数です。
    PhcBytes,
}

impl AllocationOperation {
    fn description(self) -> &'static str {
        match self {
            Self::MemoryBlocks => "memory blocks",
            Self::OutputBytes => "output bytes",
            Self::PhcBytes => "PHC bytes",
        }
    }
}

/// Argon2id の各関数が返す失敗です。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Argon2Error {
    /// 引数が条件に違反しています。値は違反した引数の名前です。
    InvalidParameter(&'static str),
    /// 要求した量が扱える範囲を超えています。
    CapacityOverflow {
        operation: AllocationOperation,
        required: usize,
    },
    /// アロケータが要求した量の確保を拒否しました。
    AllocationFailed {
        operation: AllocationOperation,
        required: usize,
    },
    /// OS の乱数源が失敗を返しました。
    RandomUnavailable,
    /// PHC 文字列の Base64 の符号化または復号が失敗しました。
    #[cfg(feature = "phc")]
    Base64(Base64Error),
}

impl core::fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParameter(name) => write!(f, "invalid Argon2 parameter: {name}"),
            Self::CapacityOverflow {
                operation,
                required,
            } => write!(
                f,
                "Argon2 capacity exceeds the addressable range for {required} {}",
                operation.description()
            ),
            Self::AllocationFailed {
                operation,
                required,
            } => write!(
                f,
                "Argon2 allocation failed for {required} {}",
                operation.description()
            ),
            Self::RandomUnavailable => f.write_str("Argon2 random source unavailable"),
            #[cfg(feature = "phc")]
            Self::Base64(error) => write!(f, "Argon2 PHC Base64 failure: {error}"),
        }
    }
}

impl core::error::Error for Argon2Error {}

#[cfg(feature = "phc")]
impl From<Base64Error> for Argon2Error {
    fn from(error: Base64Error) -> Self {
        Self::Base64(error)
    }
}

const BLOCK_BYTES: usize = 1024;
const BLOCK_WORDS: usize = BLOCK_BYTES / 8;
const VERSION: u32 = 0x13;
const ARGON2ID_TYPE: u32 = 2;
const ADDRESSES_IN_BLOCK: usize = 128;

#[derive(Clone, Copy)]
struct Block([u64; BLOCK_WORDS]);

impl Default for Block {
    fn default() -> Self {
        Block([0u64; BLOCK_WORDS])
    }
}

impl DefaultIsZeroes for Block {}

impl Block {
    #[inline]
    fn xor_assign(&mut self, other: &Block) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a ^= b;
        }
    }

    fn write_bytes(&self, out: &mut [u8; BLOCK_BYTES]) {
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.0.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut block = Block::default();
        for (word, chunk) in block.0.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut le = [0u8; 8];
            le.copy_from_slice(chunk);
            *word = u64::from_le_bytes(le);
        }
        block
    }
}

impl core::ops::BitXorAssign<&Block> for Block {
    fn bitxor_assign(&mut self, rhs: &Block) {
        self.xor_assign(rhs);
    }
}

macro_rules! permute_step {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        const TRUNC: u64 = u32::MAX as u64;
        $a = $a
            .wrapping_add($b)
            .wrapping_add(2u64.wrapping_mul($a & TRUNC).wrapping_mul($b & TRUNC));
        $d = ($d ^ $a).rotate_right(32);
        $c = $c
            .wrapping_add($d)
            .wrapping_add(2u64.wrapping_mul($c & TRUNC).wrapping_mul($d & TRUNC));
        $b = ($b ^ $c).rotate_right(24);
        $a = $a
            .wrapping_add($b)
            .wrapping_add(2u64.wrapping_mul($a & TRUNC).wrapping_mul($b & TRUNC));
        $d = ($d ^ $a).rotate_right(16);
        $c = $c
            .wrapping_add($d)
            .wrapping_add(2u64.wrapping_mul($c & TRUNC).wrapping_mul($d & TRUNC));
        $b = ($b ^ $c).rotate_right(63);
    }};
}

#[inline(always)]
fn permute16(v: &mut [u64; 16]) {
    permute_step!(v[0], v[4], v[8], v[12]);
    permute_step!(v[1], v[5], v[9], v[13]);
    permute_step!(v[2], v[6], v[10], v[14]);
    permute_step!(v[3], v[7], v[11], v[15]);
    permute_step!(v[0], v[5], v[10], v[15]);
    permute_step!(v[1], v[6], v[11], v[12]);
    permute_step!(v[2], v[7], v[8], v[13]);
    permute_step!(v[3], v[4], v[9], v[14]);
}

fn permute16_indexed(q: &mut [u64; BLOCK_WORDS], indices: [usize; 16]) {
    let mut tmp = [
        q[indices[0]],
        q[indices[1]],
        q[indices[2]],
        q[indices[3]],
        q[indices[4]],
        q[indices[5]],
        q[indices[6]],
        q[indices[7]],
        q[indices[8]],
        q[indices[9]],
        q[indices[10]],
        q[indices[11]],
        q[indices[12]],
        q[indices[13]],
        q[indices[14]],
        q[indices[15]],
    ];
    permute16(&mut tmp);
    for (k, &idx) in indices.iter().enumerate() {
        q[idx] = tmp[k];
    }
}

fn compress(rhs: &Block, lhs: &Block) -> Block {
    let mut r = *rhs;
    r ^= lhs;
    let mut q = r;

    for row in 0..8usize {
        let base = row * 16;
        let indices = [
            base,
            base + 1,
            base + 2,
            base + 3,
            base + 4,
            base + 5,
            base + 6,
            base + 7,
            base + 8,
            base + 9,
            base + 10,
            base + 11,
            base + 12,
            base + 13,
            base + 14,
            base + 15,
        ];
        permute16_indexed(&mut q.0, indices);
    }

    for i in 0..8usize {
        let b = i * 2;
        let indices = [
            b,
            b + 1,
            b + 16,
            b + 17,
            b + 32,
            b + 33,
            b + 48,
            b + 49,
            b + 64,
            b + 65,
            b + 80,
            b + 81,
            b + 96,
            b + 97,
            b + 112,
            b + 113,
        ];
        permute16_indexed(&mut q.0, indices);
    }

    q ^= &r;
    q
}

#[derive(Clone, Copy)]
struct Cost {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

struct Input<'a> {
    password: &'a [u8],
    salt: &'a [u8],
    secret: &'a [u8],
    associated_data: &'a [u8],
}

fn compute_h0(
    input: &Input,
    cost: Cost,
    output_len: usize,
) -> Result<Zeroizing<[u8; 64]>, Argon2Error> {
    let output_len =
        u32::try_from(output_len).map_err(|_| Argon2Error::InvalidParameter("output_len"))?;
    let password_len = u32::try_from(input.password.len())
        .map_err(|_| Argon2Error::InvalidParameter("password"))?;
    let salt_len =
        u32::try_from(input.salt.len()).map_err(|_| Argon2Error::InvalidParameter("salt"))?;
    let secret_len =
        u32::try_from(input.secret.len()).map_err(|_| Argon2Error::InvalidParameter("secret"))?;
    let associated_data_len = u32::try_from(input.associated_data.len())
        .map_err(|_| Argon2Error::InvalidParameter("associated_data"))?;

    let mut header = Zeroizing::new([0u8; 24]);
    for (chunk, value) in header.chunks_exact_mut(4).zip([
        cost.p_cost,
        output_len,
        cost.m_cost,
        cost.t_cost,
        VERSION,
        ARGON2ID_TYPE,
    ]) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    let password_len = password_len.to_le_bytes();
    let salt_len = salt_len.to_le_bytes();
    let secret_len = secret_len.to_le_bytes();
    let associated_data_len = associated_data_len.to_le_bytes();
    let mut h0 = Zeroizing::new([0u8; 64]);
    blake2b_into(
        &[
            &header[..],
            &password_len,
            input.password,
            &salt_len,
            input.salt,
            &secret_len,
            input.secret,
            &associated_data_len,
            input.associated_data,
        ],
        &[],
        &mut h0[..],
    )?;
    Ok(h0)
}

fn validate(input: &Input, cost: Cost, output_len: usize) -> Result<(), Argon2Error> {
    if !(1..=0x00ff_ffff).contains(&cost.p_cost) {
        return Err(Argon2Error::InvalidParameter("p_cost"));
    }
    if cost.t_cost < 1 {
        return Err(Argon2Error::InvalidParameter("t_cost"));
    }
    if u64::from(cost.m_cost) < 8 * u64::from(cost.p_cost) {
        return Err(Argon2Error::InvalidParameter("m_cost"));
    }
    if output_len < 4 {
        return Err(Argon2Error::InvalidParameter("output_len"));
    }
    if output_len > isize::MAX as usize {
        return Err(Argon2Error::CapacityOverflow {
            operation: AllocationOperation::OutputBytes,
            required: output_len,
        });
    }
    if u32::try_from(output_len).is_err() {
        return Err(Argon2Error::InvalidParameter("output_len"));
    }
    if input.salt.len() < 8 || u32::try_from(input.salt.len()).is_err() {
        return Err(Argon2Error::InvalidParameter("salt"));
    }
    for (name, field) in [
        ("password", input.password),
        ("secret", input.secret),
        ("associated_data", input.associated_data),
    ] {
        if u32::try_from(field.len()).is_err() {
            return Err(Argon2Error::InvalidParameter(name));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Layout {
    lanes: usize,
    segment_length: usize,
    lane_length: usize,
    block_count: usize,
}

fn layout(cost: Cost) -> Result<Layout, Argon2Error> {
    let lanes = cost.p_cost as usize;
    let memory = cost.m_cost as usize;
    let capacity_error = || Argon2Error::CapacityOverflow {
        operation: AllocationOperation::MemoryBlocks,
        required: memory,
    };
    let lane_divisor = lanes.checked_mul(4).ok_or_else(capacity_error)?;
    let segment_length = (memory / lane_divisor).max(1);
    let lane_length = segment_length.checked_mul(4).ok_or_else(capacity_error)?;
    let block_count = lanes.checked_mul(lane_length).ok_or_else(capacity_error)?;
    Ok(Layout {
        lanes,
        segment_length,
        lane_length,
        block_count,
    })
}

fn matrix_bytes(block_count: usize) -> Result<usize, Argon2Error> {
    let bytes = block_count
        .checked_mul(BLOCK_BYTES)
        .ok_or(Argon2Error::CapacityOverflow {
            operation: AllocationOperation::MemoryBlocks,
            required: block_count,
        })?;
    if bytes > isize::MAX as usize {
        return Err(Argon2Error::CapacityOverflow {
            operation: AllocationOperation::MemoryBlocks,
            required: block_count,
        });
    }
    Ok(bytes)
}

fn hash_into(input: &Input, cost: Cost, out: &mut [u8]) -> Result<(), Argon2Error> {
    validate(input, cost, out.len())?;
    let block_count = layout(cost)?.block_count;
    matrix_bytes(block_count)?;
    let mut memory = Zeroizing::new(Vec::<Block>::new());
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| Argon2Error::AllocationFailed {
            operation: AllocationOperation::MemoryBlocks,
            required: block_count,
        })?;
    memory.resize(block_count, Block::default());
    derive_with_memory(&mut memory, input, cost, out)
}

fn derive_with_memory(
    memory: &mut [Block],
    input: &Input,
    cost: Cost,
    out: &mut [u8],
) -> Result<(), Argon2Error> {
    let result = compute(memory, input, cost, out);
    memory.zeroize();
    result
}

fn compute(
    memory: &mut [Block],
    input: &Input,
    cost: Cost,
    out: &mut [u8],
) -> Result<(), Argon2Error> {
    validate(input, cost, out.len())?;
    let t_cost = cost.t_cost;

    let Layout {
        lanes,
        segment_length,
        lane_length,
        block_count,
    } = layout(cost)?;
    if memory.len() != block_count {
        return Err(Argon2Error::InvalidParameter("memory"));
    }

    let h0 = compute_h0(input, cost, out.len())?;

    for lane in 0..lanes {
        for i in 0usize..2 {
            let mut initial_input = Zeroizing::new([0u8; 72]);
            initial_input[..64].copy_from_slice(&h0[..]);
            initial_input[64..68].copy_from_slice(&(i as u32).to_le_bytes());
            initial_input[68..72].copy_from_slice(&(lane as u32).to_le_bytes());
            let mut bytes = Zeroizing::new([0u8; BLOCK_BYTES]);
            blake2b_long_into(&initial_input[..], &mut bytes[..])?;
            memory[lane * lane_length + i] = Block::from_bytes(&bytes[..]);
        }
    }
    drop(h0);
    let zero_block = Block::default();

    for pass in 0..t_cost as usize {
        for slice in 0..4usize {
            let data_independent = pass == 0 && slice < 2;

            for lane in 0..lanes {
                let mut address_block = Block::default();
                let mut input_block = Block::default();

                if data_independent {
                    input_block.0[0] = pass as u64;
                    input_block.0[1] = lane as u64;
                    input_block.0[2] = slice as u64;
                    input_block.0[3] = block_count as u64;
                    input_block.0[4] = t_cost as u64;
                    input_block.0[5] = ARGON2ID_TYPE as u64;
                    input_block.0[6] += 1;
                    address_block = compress(&zero_block, &input_block);
                    address_block = compress(&zero_block, &address_block);
                }

                let first_block = if pass == 0 && slice == 0 { 2 } else { 0 };

                let base = lane * lane_length + slice * segment_length;

                let mut prev_index = if first_block == 0 {
                    if slice == 0 {
                        lane * lane_length + lane_length - 1
                    } else {
                        base - 1
                    }
                } else {
                    base + first_block - 1
                };

                for block_in_seg in first_block..segment_length {
                    let cur_index = base + block_in_seg;

                    let rand = if data_independent {
                        let addr_idx = block_in_seg % ADDRESSES_IN_BLOCK;
                        if addr_idx == 0 && block_in_seg > 0 {
                            input_block.0[6] += 1;
                            address_block = compress(&zero_block, &input_block);
                            address_block = compress(&zero_block, &address_block);
                        }
                        address_block.0[addr_idx]
                    } else {
                        memory[prev_index].0[0]
                    };

                    let ref_lane = if pass == 0 && slice == 0 {
                        lane
                    } else {
                        (rand >> 32) as usize % lanes
                    };

                    let reference_area_size = if pass == 0 {
                        if slice == 0 {
                            block_in_seg - 1
                        } else if ref_lane == lane {
                            slice * segment_length + block_in_seg - 1
                        } else {
                            slice * segment_length - if block_in_seg == 0 { 1 } else { 0 }
                        }
                    } else if ref_lane == lane {
                        lane_length - segment_length + block_in_seg - 1
                    } else {
                        lane_length - segment_length - if block_in_seg == 0 { 1 } else { 0 }
                    };

                    if reference_area_size == 0 {
                        let new_block = compress(&memory[prev_index], &memory[prev_index]);
                        if pass == 0 {
                            memory[cur_index] = new_block;
                        } else {
                            memory[cur_index] ^= &new_block;
                        }
                        prev_index = cur_index;
                        continue;
                    }

                    let mut map = rand & 0xffff_ffff;
                    map = (map * map) >> 32;
                    let relative_pos = reference_area_size
                        - 1
                        - ((reference_area_size as u64 * map) >> 32) as usize;

                    let start_pos = if pass != 0 && slice != 3 {
                        (slice + 1) * segment_length
                    } else {
                        0
                    };

                    let lane_index = (start_pos + relative_pos) % lane_length;
                    let ref_index = ref_lane * lane_length + lane_index;

                    let new_block = compress(&memory[prev_index], &memory[ref_index]);
                    if pass == 0 {
                        memory[cur_index] = new_block;
                    } else {
                        memory[cur_index] ^= &new_block;
                    }

                    prev_index = cur_index;
                }
            }
        }
    }

    let last_col = lane_length - 1;
    let mut fin = Zeroizing::new(memory[last_col]);
    for lane in 1..lanes {
        fin.xor_assign(&memory[lane * lane_length + last_col]);
    }

    let mut c_bytes = Zeroizing::new([0u8; BLOCK_BYTES]);
    fin.write_bytes(&mut c_bytes);
    blake2b_long_into(&c_bytes[..], out)
}

/// パスワードとソルトから Argon2id の出力を計算し、呼び出し側のバッファへ書き込みます。
/// 引数の条件は `Argon2Params` の各フィールドと同じで、ソルトは 8 バイト以上、出力と各入力は 4 GiB 未満です。違反した場合は `InvalidParameter` を返します。
/// 出力長または作業メモリのバイト数が扱える範囲を超える場合は `CapacityOverflow` を、作業メモリを確保できない場合は `AllocationFailed` を返します。作業メモリとスタック上の中間値は、返る前に消去します。
pub fn argon2id_hash_into(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    out: &mut [u8],
) -> Result<(), Argon2Error> {
    let input = Input {
        password,
        salt,
        secret: &[],
        associated_data: &[],
    };
    let cost = Cost {
        m_cost,
        t_cost,
        p_cost,
    };
    hash_into(&input, cost, out)
}

/// パスワードとソルトから、指定した長さの Argon2id ハッシュを計算して返します。
/// 引数の条件と失敗は `argon2id_hash_into` と同じです。加えて、出力のバッファを確保できない場合は `AllocationFailed` を返します。
pub fn argon2id_hash(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
) -> Result<Vec<u8>, Argon2Error> {
    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
        output_len,
    };
    argon2id_hash_with_secret(password, salt, params, &[], &[])
}

/// 秘密値と関連データを含めて、`params` で指定した出力長の Argon2id ハッシュを計算して返します。
/// 引数の条件と失敗は `argon2id_hash` と同じです。加えて、秘密値と関連データは 4 GiB 未満である必要があります。
pub fn argon2id_hash_with_secret(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
    secret: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, Argon2Error> {
    let input = Input {
        password,
        salt,
        secret,
        associated_data,
    };
    let cost = Cost {
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
    };
    validate(&input, cost, params.output_len)?;
    let mut out = Vec::new();
    out.try_reserve_exact(params.output_len)
        .map_err(|_| Argon2Error::AllocationFailed {
            operation: AllocationOperation::OutputBytes,
            required: params.output_len,
        })?;
    out.resize(params.output_len, 0);
    hash_into(&input, cost, &mut out)?;
    Ok(out)
}

/// 呼び出し側が渡す 16 バイトのソルトで、PHC 形式の文字列を返します。
#[cfg(feature = "phc")]
pub fn argon2id_hash_encoded_with_salt(
    password: &[u8],
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<String, Argon2Error> {
    encode_with_salt(password, salt, params)
}

/// 呼び出し側の乱数源が書き込む 16 バイトのソルトで、PHC 形式の文字列を返します。
#[cfg(feature = "phc")]
pub fn argon2id_hash_encoded_with_rng<F>(
    password: &[u8],
    params: Argon2Params,
    fill: &mut F,
) -> Result<String, Argon2Error>
where
    F: FnMut(&mut [u8]) -> Result<(), Argon2Error>,
{
    let mut salt = [0u8; 16];
    fill(&mut salt)?;
    encode_with_salt(password, &salt, params)
}

/// OS の乱数源から得た 16 バイトのソルトで、PHC 形式の文字列を返します。
#[cfg(all(feature = "phc", feature = "getrandom"))]
pub fn argon2id_hash_encoded(password: &[u8], params: Argon2Params) -> Result<String, Argon2Error> {
    argon2id_hash_encoded_with_rng(password, params, &mut |salt| {
        getrandom::fill(salt).map_err(|_| Argon2Error::RandomUnavailable)
    })
}

#[cfg(feature = "phc")]
fn decimal_digits(mut value: u32) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

#[cfg(feature = "phc")]
fn phc_required_bytes(params: Argon2Params) -> Result<usize, Argon2Error> {
    if params.output_len > isize::MAX as usize {
        return Err(Argon2Error::CapacityOverflow {
            operation: AllocationOperation::OutputBytes,
            required: params.output_len,
        });
    }
    if u32::try_from(params.output_len).is_err() {
        return Err(Argon2Error::InvalidParameter("output_len"));
    }
    let full = (params.output_len / 3) as u128 * 4;
    let tail = match params.output_len % 3 {
        0 => 0,
        remainder => remainder as u128 + 1,
    };
    let required = "$argon2id$v=19$m=".len() as u128
        + decimal_digits(params.m_cost) as u128
        + ",t=".len() as u128
        + decimal_digits(params.t_cost) as u128
        + ",p=".len() as u128
        + decimal_digits(params.p_cost) as u128
        + 1
        + 22
        + 1
        + full
        + tail;
    let required = required as usize;
    if required > isize::MAX as usize {
        return Err(Argon2Error::CapacityOverflow {
            operation: AllocationOperation::PhcBytes,
            required,
        });
    }
    Ok(required)
}

#[cfg(feature = "phc")]
fn encode_phc_field(input: &[u8]) -> Result<String, Argon2Error> {
    let mut field = encode(input)?;
    field.truncate(field.trim_end_matches('=').len());
    Ok(field)
}

#[cfg(feature = "phc")]
fn encode_with_salt(
    password: &[u8],
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<String, Argon2Error> {
    let required = phc_required_bytes(params)?;
    let hash = Zeroizing::new(argon2id_hash(
        password,
        salt,
        params.m_cost,
        params.t_cost,
        params.p_cost,
        params.output_len,
    )?);
    let encoded_salt = encode_phc_field(salt)?;
    let encoded_hash = encode_phc_field(&hash)?;
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(required)
        .map_err(|_| Argon2Error::AllocationFailed {
            operation: AllocationOperation::PhcBytes,
            required,
        })?;
    write!(
        encoded,
        "$argon2id$v=19$m={},t={},p={}${}${}",
        params.m_cost, params.t_cost, params.p_cost, encoded_salt, encoded_hash
    )
    .map_err(|_| Argon2Error::AllocationFailed {
        operation: AllocationOperation::PhcBytes,
        required,
    })?;
    Ok(encoded)
}

/// PHC 形式の文字列がパスワードに一致するかを返します。
/// 形式が不正な文字列、一致しないパスワード、不正な引数、8 バイト未満のソルトには `Ok(false)` を返します。扱える範囲の超過と確保の失敗は、Base64 の復号で起きたものを含めて `Err` で返します。
#[cfg(feature = "phc")]
pub fn argon2id_verify(encoded: &str, password: &[u8]) -> Result<bool, Argon2Error> {
    let Some(ParsedPhc {
        salt,
        expected,
        params,
    }) = parse_phc(encoded)?
    else {
        return Ok(false);
    };
    let actual = Zeroizing::new(
        match argon2id_hash(
            password,
            &salt,
            params.m_cost,
            params.t_cost,
            params.p_cost,
            params.output_len,
        ) {
            Ok(actual) => actual,
            Err(Argon2Error::InvalidParameter(_)) => return Ok(false),
            Err(error) => return Err(error),
        },
    );
    if actual.len() != expected.len() {
        return Ok(false);
    }
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

#[cfg(feature = "phc")]
fn decode_phc_field(field: &str) -> Result<Option<Vec<u8>>, Argon2Error> {
    match decode(field) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(
            Base64Error::InvalidCharacter
            | Base64Error::InvalidLength
            | Base64Error::NonZeroPaddingBits,
        ) => Ok(None),
        Err(error) => Err(Argon2Error::Base64(error)),
    }
}

#[cfg(feature = "phc")]
struct ParsedPhc {
    salt: Vec<u8>,
    expected: Vec<u8>,
    params: Argon2Params,
}

#[cfg(feature = "phc")]
fn parse_phc(encoded: &str) -> Result<Option<ParsedPhc>, Argon2Error> {
    let mut parts = encoded.splitn(7, '$');
    let (Some(prefix), Some(algorithm), Some(version), Some(parameters), Some(salt), Some(hash)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Ok(None);
    };
    if parts.next().is_some() || !prefix.is_empty() || algorithm != "argon2id" || version != "v=19"
    {
        return Ok(None);
    }
    let mut m_cost = None;
    let mut t_cost = None;
    let mut p_cost = None;
    for parameter in parameters.split(',') {
        let Some((name, value)) = parameter.split_once('=') else {
            return Ok(None);
        };
        let Ok(value) = value.parse() else {
            return Ok(None);
        };
        let slot = match name {
            "m" => &mut m_cost,
            "t" => &mut t_cost,
            "p" => &mut p_cost,
            _ => return Ok(None),
        };
        if slot.replace(value).is_some() {
            return Ok(None);
        }
    }
    let (Some(m_cost), Some(t_cost), Some(p_cost)) = (m_cost, t_cost, p_cost) else {
        return Ok(None);
    };
    let Some(salt) = decode_phc_field(salt)? else {
        return Ok(None);
    };
    let Some(hash) = decode_phc_field(hash)? else {
        return Ok(None);
    };
    let output_len = hash.len();
    Ok(Some(ParsedPhc {
        salt,
        expected: hash,
        params: Argon2Params {
            m_cost,
            t_cost,
            p_cost,
            output_len,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parallelism_uses_the_rfc9106_range() {
        let input = Input {
            password: b"password",
            salt: b"saltsalt",
            secret: &[],
            associated_data: &[],
        };
        for p_cost in [1, 0x00ff_ffff] {
            let cost = Cost {
                m_cost: 8 * p_cost,
                t_cost: 1,
                p_cost,
            };
            assert_eq!(validate(&input, cost, 4), Ok(()));
        }
        for p_cost in [0, 0x0100_0000, u32::MAX] {
            let cost = Cost {
                m_cost: u32::MAX,
                t_cost: 1,
                p_cost,
            };
            assert_eq!(
                validate(&input, cost, 4),
                Err(Argon2Error::InvalidParameter("p_cost"))
            );
        }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn is_zeroed(memory: &[Block]) -> bool {
        memory
            .iter()
            .all(|block| block.0.iter().all(|&word| word == 0))
    }

    #[test]
    fn rfc9106_section_5_3_vector() {
        let password = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];
        let expected = hex_to_bytes(
            "0d640df58d78766c08c037a34a8b53c9\
             d01ef0452d75b65eb52520e96b01e659",
        );
        let params = Argon2Params {
            m_cost: 32,
            t_cost: 3,
            p_cost: 4,
            output_len: 32,
        };
        let result =
            argon2id_hash_with_secret(&password, &salt, params, &secret, &ad).expect("hash");
        assert_eq!(result, expected);
    }

    #[test]
    fn kat_keys_match_independent_reference() {
        let salt = hex_to_bytes("101112131415161718191a1b1c1d1e1f");
        let mut key_a = [0u8; 32];
        argon2id_hash_into(
            b"correct horse battery staple",
            &salt,
            65_536,
            3,
            4,
            &mut key_a,
        )
        .expect("KAT-A key");
        assert_eq!(
            key_a.to_vec(),
            hex_to_bytes("1cd84e588c72f1d0bb3041fdd8a32de5ec738487c23ac9c5d84f119e05858bf8")
        );
        let mut key_c = [0u8; 32];
        argon2id_hash_into(b"kat-c", &salt, 64, 1, 1, &mut key_c).expect("KAT-C key");
        assert_eq!(
            key_c.to_vec(),
            hex_to_bytes("546d78c758163d187ed6f9ca06bf7ef549992cefcdfc718774e1a79e52dc4c34")
        );
    }

    #[test]
    fn invalid_parameters_return_errors() {
        let salt = [0x11u8; 16];
        let mut out = [0u8; 32];
        assert_eq!(
            argon2id_hash_into(b"pw", &salt, 64, 1, 0, &mut out),
            Err(Argon2Error::InvalidParameter("p_cost"))
        );
        assert_eq!(
            argon2id_hash_into(b"pw", &salt, 64, 0, 1, &mut out),
            Err(Argon2Error::InvalidParameter("t_cost"))
        );
        assert_eq!(
            argon2id_hash_into(b"pw", &salt, 7, 1, 1, &mut out),
            Err(Argon2Error::InvalidParameter("m_cost"))
        );
        assert_eq!(
            argon2id_hash_into(b"pw", &salt, 64, 1, 1, &mut [0u8; 3]),
            Err(Argon2Error::InvalidParameter("output_len"))
        );
        assert_eq!(
            argon2id_hash_into(b"pw", &[0x11u8; 7], 64, 1, 1, &mut out),
            Err(Argon2Error::InvalidParameter("salt"))
        );
        assert_eq!(
            argon2id_hash(b"pw", &salt, 64, 1, 0, 32),
            Err(Argon2Error::InvalidParameter("p_cost"))
        );
        let short_output = Argon2Params {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
            output_len: 3,
        };
        assert_eq!(
            argon2id_hash_with_secret(b"pw", &salt, short_output, b"secret", b"ad"),
            Err(Argon2Error::InvalidParameter("output_len"))
        );
    }

    #[test]
    fn out_of_range_lane_counts_return_the_parallelism_error() {
        let salt = [0x11u8; 16];
        let mut out = [0u8; 32];
        for p_cost in [0x2000_0000, 0x2000_0001, u32::MAX] {
            assert_eq!(
                argon2id_hash_into(b"pw", &salt, u32::MAX, 1, p_cost, &mut out),
                Err(Argon2Error::InvalidParameter("p_cost")),
                "p_cost {p_cost}"
            );
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn oversized_output_is_rejected_before_allocation() {
        let salt = [0x11u8; 16];
        assert_eq!(
            argon2id_hash(b"pw", &salt, 64, 1, 1, usize::MAX),
            Err(Argon2Error::CapacityOverflow {
                operation: AllocationOperation::OutputBytes,
                required: usize::MAX,
            })
        );
    }

    #[test]
    fn memory_matrix_is_wiped_after_derivation() {
        let mut memory = vec![Block::default(); 64];
        let mut out = [0u8; 32];
        let input = Input {
            password: b"password",
            salt: b"saltsalt",
            secret: &[],
            associated_data: &[],
        };
        let cost = Cost {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        };
        derive_with_memory(&mut memory, &input, cost, &mut out).expect("derive");
        assert_eq!(
            out.to_vec(),
            argon2id_hash(b"password", b"saltsalt", 64, 1, 1, 32).expect("hash")
        );
        assert!(is_zeroed(&memory));

        for block in memory.iter_mut() {
            block.0 = [u64::MAX; BLOCK_WORDS];
        }
        let invalid = Cost { t_cost: 0, ..cost };
        let error = derive_with_memory(&mut memory, &input, invalid, &mut out)
            .expect_err("t_cost 0 must fail");
        assert_eq!(error, Argon2Error::InvalidParameter("t_cost"));
        assert!(is_zeroed(&memory));
    }

    #[test]
    fn memory_size_arithmetic_is_checked() {
        for blocks in [
            usize::MAX / BLOCK_BYTES + 1,
            isize::MAX as usize / BLOCK_BYTES + 1,
        ] {
            assert_eq!(
                matrix_bytes(blocks),
                Err(Argon2Error::CapacityOverflow {
                    operation: AllocationOperation::MemoryBlocks,
                    required: blocks,
                })
            );
        }
        assert_eq!(matrix_bytes(1024), Ok(1_048_576));
    }

    #[test]
    fn test_deterministic() {
        let password = b"password";
        let salt = b"saltsaltsalt1234";
        let h1 = argon2id_hash(password, salt, 64, 1, 1, 32).expect("hash");
        let h2 = argon2id_hash(password, salt, 64, 1, 1, 32).expect("hash");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_passwords() {
        let salt = b"saltsaltsalt1234";
        let h1 = argon2id_hash(b"password1", salt, 64, 1, 1, 32).expect("hash");
        let h2 = argon2id_hash(b"password2", salt, 64, 1, 1, 32).expect("hash");
        assert_ne!(h1, h2);
    }

    #[cfg(feature = "phc")]
    #[test]
    fn test_phc_roundtrip() {
        let password = b"hunter2";
        let salt = b"saltsaltsalt1234";
        let params = Argon2Params {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        let encoded = encode_with_salt(password, salt, params).expect("encode");
        assert!(encoded.starts_with("$argon2id$v=19$m=64,t=1,p=1$"));
        assert!(argon2id_verify(&encoded, password).expect("verify"));
        assert!(!argon2id_verify(&encoded, b"wrong").expect("verify"));
        let reordered = encoded.replacen("m=64,t=1,p=1", "p=1,m=64,t=1", 1);
        assert!(argon2id_verify(&reordered, password).expect("verify reordered parameters"));
    }

    #[cfg(feature = "phc")]
    #[test]
    fn phc_preserves_standard_base64_symbols_without_padding() {
        let expected = "$argon2id$v=19$m=32,t=1,p=1$+/v7+/v7+/v7+/v7+/v7+w$puUojK6Lw1P8jS9v2YWyq+BtOlWXGPkBwGwk0ujlzA0";
        let password = b"standard PHC interoperability";
        let encoded = encode_with_salt(
            password,
            &[0xfb; 16],
            Argon2Params {
                m_cost: 32,
                t_cost: 1,
                p_cost: 1,
                output_len: 32,
            },
        )
        .expect("encode");
        assert_eq!(encoded, expected);
        assert!(argon2id_verify(expected, password).expect("verify"));
        let url_encoding = encoded.replace('+', "-").replace('/', "_");
        assert!(!argon2id_verify(&url_encoding, password).expect("invalid PHC alphabet"));
    }

    #[cfg(feature = "phc")]
    #[test]
    fn test_phc_invalid() {
        for encoded in [
            "",
            "notphc",
            "$argon2i$v=19$m=32,t=1,p=1$aaa$bbb",
            "$argon2id$v=16$m=32,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
            "$argon2id$v=20$m=32,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
            "$argon2id$v=19$m=32,m=32,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
            "$argon2id$v=19$m=32,t=1,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
            "$argon2id$v=19$m=32,t=1,p=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
        ] {
            assert!(
                !argon2id_verify(encoded, b"pw").expect("invalid PHC"),
                "{encoded}"
            );
        }
    }

    #[cfg(feature = "phc")]
    #[test]
    fn verify_returns_false_for_invalid_parameters() {
        let control = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            output_len: 8,
        };
        let valid = encode_with_salt(b"pw", b"saltsaltsalt1234", control).expect("encode control");
        assert!(argon2id_verify(&valid, b"pw").expect("verify"));

        for encoded in [
            "$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
            "$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
            "$argon2id$v=19$m=8,t=1,p=0$c2FsdHNhbHQ$aGFzaGhhc2g",
            "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaGhhc2g",
        ] {
            assert!(
                !argon2id_verify(encoded, b"pw").expect("invalid parameters"),
                "{encoded}"
            );
        }
    }

    #[cfg(feature = "phc")]
    #[test]
    fn rng_provider_failure_is_propagated_unchanged() {
        let expected = Argon2Error::RandomUnavailable;
        let actual = argon2id_hash_encoded_with_rng(
            b"pw",
            Argon2Params {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
                output_len: 8,
            },
            &mut |_| Err(expected.clone()),
        );
        assert_eq!(actual, Err(expected));
    }

    #[cfg(all(feature = "phc", target_pointer_width = "32"))]
    #[test]
    fn phc_capacity_reports_total_string_bytes() {
        let params = Argon2Params {
            output_len: isize::MAX as usize,
            ..Argon2Params::default()
        };
        let error = phc_required_bytes(params).expect_err("PHC string exceeds isize");
        assert!(matches!(
            error,
            Argon2Error::CapacityOverflow {
                operation: AllocationOperation::PhcBytes,
                required
            } if required > isize::MAX as usize
        ));
    }

    #[test]
    fn test_output_lengths() {
        let salt = b"saltsaltsalt1234";
        for len in [16usize, 32, 64] {
            let h = argon2id_hash(b"pw", salt, 64, 1, 1, len).expect("hash");
            assert_eq!(h.len(), len);
        }
    }
}
