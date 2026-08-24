//! FairPlay's proprietary SAP hash, ported from `fairplay_sap.go`.
//!
//! Not a standard cryptographic hash. All byte arithmetic wraps like Go's
//! `uint8`; where the Go source explicitly promotes to `int` before dividing
//! or indexing, we mirror that with wider intermediates.

use crate::fp_tables_generated::{SAP_INITIAL_HASH, SAP_INITIAL_MATRIX, SAP_SEED};

/// Rotate-left by `count` bits, or zero when `count == 0` (matching the Go
/// helper, which intentionally returns 0 for a zero count).
fn rotate_or_zero(input: u8, count: u8) -> u8 {
    if count == 0 {
        return 0;
    }
    input.rotate_left(count as u32)
}

fn wide_seed(input: u8, count: u8) -> u8 {
    if count == 0 {
        return SAP_SEED[0];
    }
    let idx = ((input as u32) << count | (input as u32) >> (8 - count)) % SAP_SEED.len() as u32;
    SAP_SEED[idx as usize]
}

fn majority(a: u8, b: u8, c: u8) -> u8 {
    a ^ (a ^ b) & (a ^ c)
}

fn select_bits(mask: u8, if_set: u8, if_clear: u8) -> u8 {
    if_clear ^ (if_set ^ if_clear) & mask
}

fn square(value: u8) -> u8 {
    value.wrapping_mul(value)
}

fn cube(value: u8) -> u8 {
    value.wrapping_mul(value).wrapping_mul(value)
}

/// The SAP hash of a 64-byte block, producing a 16-byte digest.
pub fn fairplay_sap_hash(block: &[u8]) -> [u8; 16] {
    debug_assert_eq!(block.len(), 64);

    let mut hash = SAP_INITIAL_HASH;
    let mut matrix = SAP_INITIAL_MATRIX;
    let mut aux = [0u8; 10];
    let mut work = [0u8; 210];

    // Load input in reversed four-byte groups.
    for i in 0..work.len() {
        work[i] = block[(i & 63) ^ 3];
    }

    // uint32 underflow changes the first of four scramble passes: the Go
    // original iterates a uint32 counter, so (i-155) wraps mod 2^32 before the
    // % 210. Must be u32 arithmetic, not usize.
    for i in 0u32..840u32 {
        let x = work[(i.wrapping_sub(155) % 210u32) as usize];
        let y = work[(i.wrapping_sub(57) % 210u32) as usize];
        let z = work[(i.wrapping_sub(13) % 210u32) as usize];
        let w = work[(i % 210u32) as usize];
        work[i as usize % 210] = y
            .rotate_left(5)
            .wrapping_add(z.rotate_left(3) ^ w)
            .wrapping_sub(x.rotate_left(7));
    }

    nonlinear_circuit(&mut hash, &mut matrix, &mut aux, &mut work);

    // Include terminal work XORs directly in their folded output lanes.
    // Go's copy() truncates; aux is 10 bytes so out[4..11] = aux[3..10].
    let mut out = [0u8; 16];
    out[..3].copy_from_slice(&aux[..3]);
    out[4..11].copy_from_slice(&aux[3..]);
    for b in out.iter_mut() {
        *b = b.wrapping_add(0xe1);
    }
    out[3] = 0x3d;
    out[11] = 0x3c;
    out[10] ^= aux[3] ^ 133;

    for (i, value) in work.iter().enumerate() {
        let mut value = *value;
        if i < matrix.len() {
            value ^= matrix[i];
        }
        if i < hash.len() {
            value ^= hash[i];
        }
        out[i & 15] ^= value;
    }

    // Reverse scramble.
    for i in 0u32..256u32 {
        let iu = i as usize;
        out[iu & 15] ^= out[(iu.wrapping_sub(7)) & 15].rotate_left(1)
            ^ out[(iu.wrapping_sub(5)) & 15].rotate_left(6)
            ^ out[(iu.wrapping_sub(1)) & 15].rotate_left(5);
    }
    out
}

/// The nonlinear circuit: ~120 assignments over hash/matrix/aux/work with the
/// same byte/int promotion semantics as the Go original.
#[allow(clippy::too_many_lines)]
fn nonlinear_circuit(hash: &mut [u8; 20], matrix: &mut [u8; 35], aux: &mut [u8; 10], work: &mut [u8; 210]) {
    // h/m/s read hash/matrix/seed through work; ma reads matrix through aux.
    // Local macros (rather than closures) keep the original call-site syntax
    // while avoiding shared-borrow conflicts with the mutation-heavy circuit.
    macro_rules! hi {
        ($i:expr) => {
            hash[$i as usize % 20]
        };
    }
    macro_rules! si {
        ($i:expr) => {
            SAP_SEED[$i as usize % 21]
        };
    }
    macro_rules! h {
        ($i:expr) => {
            hi!(work[$i])
        };
    }
    macro_rules! m {
        ($i:expr) => {
            matrix[work[$i] as usize % 35]
        };
    }
    macro_rules! s {
        ($i:expr) => {
            si!(work[$i])
        };
    }
    macro_rules! ma {
        ($i:expr) => {
            matrix[aux[$i] as usize % 35]
        };
    }

    matrix[12] = 0x14u8.wrapping_add(select_bits(92, work[64], work[99] / 3) & wide_seed(s!(206), 4));
    work[4] = 2u8.wrapping_mul(square(work[99] / 5));
    work[153] ^= square(m!(203)).wrapping_mul(work[190]);
    hash[3] = 0x13 ^ s!(205) >> 1 & 0x10;
    work[33] = work[33].wrapping_sub(s!(36) & !9);
    aux[5] = ((m!(67) & !2 | 1 | h!(181) >> 6 & 2 | hash[3] & 0x10) as u32).wrapping_sub(15) as u8;
    matrix[12] = 0x07;
    work[2] = work[2].wrapping_sub(64);
    hash[19] = s!(58);
    aux[4] = 92u8.wrapping_sub(m!(32));
    aux[9] = m!(15).wrapping_add(0x9e);
    work[34] = work[34].wrapping_add(si!(aux[9]) / 5);
    hash[19] = hash[19].wrapping_add(0xe6 ^ hi!(aux[9]) >> 1 & 0x66);
    work[15] ^= 3u8
        .wrapping_mul(rotate_or_zero(work[72], 0u8.wrapping_sub(s!(190)) & 7))
        .wrapping_sub(9u8.wrapping_mul(s!(126)));
    hash[15] ^= cube(m!(181));
    matrix[4] ^= work[202] / 3;
    matrix[1] = matrix[1].wrapping_add(cube(majority(92u8.wrapping_sub(hi!(aux[4])), !work[105], 0xc6)));
    hash[19] ^= ((224u8 | s!(92) & 27) as u32)
        .wrapping_mul(m!(41) as u32)
        .wrapping_div(3) as u8;
    work[140] = work[140].wrapping_add(rotate_or_zero(92, 0u8.wrapping_sub(work[5]) & 7));
    matrix[12] = matrix[12].wrapping_add(majority(!work[4] ^ m!(12), work[182], 192));
    work[36] = work[36].wrapping_add(125);
    work[124] = majority(
        majority(work[138], hash[15], 74),
        h!(43),
        95,
    )
    .rotate_left(4);
    let aux_hash = hi!(aux[9]);
    aux[1] = 0x4c & !(aux_hash & s!(68) << 1);
    aux[2] = 222u8.wrapping_sub(majority(
        ((work[177] as u32 + s!(79) as u32) >> 1) as u8,
        (3u32 * work[148] as u32 / 5) as u8,
        matrix[1],
    ));
    matrix[16] = matrix[16]
        .wrapping_add((ma!(4) & !0x60 | aux_hash | 8).wrapping_sub(work[33].rotate_left(2) | 128));
    hash[14] ^= ma!(2);
    work[19] = work[19].wrapping_add(majority(
        rotate_or_zero(si!(h!(201)), m!(112) << 1 & 6),
        ((h!(208) & !0x7c) | (h!(164) & 0x7c)) / 5,
        37,
    ));
    matrix[8] = rotate_or_zero(140, 0u8.wrapping_sub(square(s!(45))) & 7) ^ aux[4];
    work[190] = 56;
    work[53] = !((h!(83) | 204) / 5);
    hash[13] = hash[13].wrapping_add(h!(41));
    hash[10] = majority(ma!(4), work[2], aux[2]) / 15;
    aux[3] = 92u8.wrapping_sub(square(0x28 | (ma!(1) & (0x12 | (s!(2) & 4)))));
    let seed_bits = si!(aux[4]);
    matrix[13] ^= seed_bits;
    aux[6] = 92u8.wrapping_add(square(majority(m!(179).wrapping_sub(38), aux[2], 177)));
    let expansion_bits = majority(aux[3].wrapping_add(aux[4] & 74), !seed_bits, 121);
    work[47] ^= m!(89).wrapping_add(majority(expansion_bits ^ 0xa6, aux[4], 4));
    aux[7] = seed_bits
        .wrapping_div(3)
        .wrapping_sub(ma!(9))
        .wrapping_sub(0x14 | work[151] & (aux[4] & 0x88 | 0x62) | aux[4] & 0x22);
    // Go groups <<, >>, &, &^ at the same precedence (left-to-right); Rust
    // ranks shifts above &, so parenthesize to match Go's semantics.
    let expanded_selector = expansion_bits ^ ((aux[4] & 0xca) >> 1) ^ 75;
    aux[9] = aux[9].wrapping_add(
        0x80 | majority(aux[7], work[151], 0x20) & 0x64 | seed_bits & 0x44 | ma!(9) & 0x1b,
    );
    matrix[33] ^= work[26];
    matrix[30] = (aux[9] / 3).wrapping_sub(aux[4] & !8 | 0x13) ^ h!(122);
    work[22] = m!(90) & 0x1b | 0x44;
    let mut wide = select_bits(71, matrix[expanded_selector as usize % 35], si!(aux[5])) as u32;
    matrix[18] = matrix[18].wrapping_add((wide * wide * wide >> 1) as u8);
    matrix[5] = matrix[5].wrapping_sub(s!(92));
    matrix[18] ^= select_bits(aux[3], ma!(3), select_bits(16, m!(183), work[41]))
        .wrapping_mul(select_bits(expanded_selector, h!(59), work[17]));
    matrix[22] = majority(
        select_bits(hash[14] | 28, (work[7] & 28) | 0x82, h!(93)),
        rotate_or_zero(ma!(4), rotate_or_zero(work[11], 0u8.wrapping_sub(m!(28)) & 7) & 7),
        matrix[33],
    )
    .wrapping_add(74);
    hash[15] = hash[15].wrapping_sub(majority(
        majority(aux[3], aux[4], 214),
        si!(h!(39) ^ 217),
        aux[6],
    ));

    let hash9 = hi!(aux[9]);
    let indexed_hash = hi!(
        ((aux[4] / 3).wrapping_sub(aux[9] | work[22]))
            ^ aux[6]
            ^ (((m!(57) | hash9) & (0x52 | (aux[9] & 0x0d))) | ((m!(57) & hash9 | aux[9]) & 0x20))
    );
    aux[6] = square(square(h!(99))) | ma!(9);
    aux[1] = aux[1].wrapping_add(
        rotate_or_zero(h!(151) | s!(202), h!(50) & 7).wrapping_add(majority(
            h!(4),
            ((select_bits(matrix[16], indexed_hash, m!(138)) as u32
                + select_bits(17, work[33], s!(39)) as u32)
                / 5) as u8,
            147,
        )),
    );
    aux[0] = select_bits(
        hash[10] & 7,
        ma!(6) & h!(209),
        select_bits(0x47, rotate_or_zero(s!(127), ma!(6) & 7), si!(ma!(5)) << 1),
    );
    let selected_square = select_bits(198, square(m!(14)), h!(145) ^ aux[0]);
    let seed9 = si!(aux[9]);
    let hash3 = hi!(aux[3]);
    matrix[2] = matrix[2].wrapping_add(
        ((hash3 << 1) & ((work[25] & 0x96) | (seed9 & 8))) | (seed9 & 0x40),
    );
    matrix[14] = matrix[14].wrapping_sub(select_bits(34, work[97], ma!(3) & (aux[0] ^ m!(100))));
    work[23] ^= majority(majority(s!(17), hash3, aux[0]), work[50] / 3, 0x76) << 1;
    hash[17] = 115;
    hash[13] = majority(hi!(aux[7]), work[10], 82) >> 1 & 0x68 | h!(39) & 0x17;
    matrix[33] = matrix[33].wrapping_sub(work[113] & 9);
    matrix[28] = matrix[28].wrapping_sub(aux[3] & !0x20 | work[110] >> 1 & 0x20);
    work[95] = si!(aux[3]);
    hash[15] = majority(work[95].wrapping_sub(48), !work[184], 189)
        & cube(majority(aux[7], si!(aux[1]), 0xaa));
    matrix[22] = matrix[22].wrapping_add(work[183]);
    aux[4] ^= 3u8.wrapping_mul(s!(1));
    aux[5] = aux[5].wrapping_add(
        198u8
            .wrapping_mul(majority(s!(178), ma!(1), 209))
            .wrapping_mul(h!(13))
            .wrapping_mul(s!(26) >> 1),
    );
    aux[8] = select_bits(10, ma!(3), ma!(9));
    matrix[18] = matrix[18].wrapping_sub(select_bits(
        hash[15],
        aux[5] / 15,
        cube(hi!(aux[6]) | 81),
    ));
    aux[1] = aux[1].wrapping_add(si!(hi!(aux[1])) / 3).wrapping_sub(h!(160));
    hash[16] = 147u8.wrapping_sub(majority(
        aux[0],
        majority(s!(69), work[172], aux[2].wrapping_sub(selected_square).wrapping_add(77)),
        0xc2 | aux[0] & 5,
    ));
    hash[3] = hash[3].wrapping_sub(wide_seed(
        majority(s!(155), work[105], 141),
        majority(s!(168), h!(29), 6) & 7,
    ));
    work[5] = rotate_or_zero(0x38, 0u8.wrapping_sub(h!(61) / 5) & 7) ^ !ma!(8) / 5;
    work[198] = work[198].wrapping_add(work[3]);
    wide = 162 | ma!(9) as u32;
    work[164] = work[164].wrapping_add((wide * wide / 5) as u8);
    aux[2] = majority(rotate_or_zero(139, 0u8.wrapping_sub(aux[5]) & 6), hi!(aux[3]), 12)
        | select_bits(95, cube(seed9), hi!(aux[7]));
    matrix[12] = matrix[12].wrapping_add(
        (16 | (work[103] | 60) & (aux[2] | work[103] & 32)) / 3,
    );
    work[143] = work[143].wrapping_sub(
        0x12 | select_bits(aux[9], select_bits(matrix[8], work[35], aux[7]), aux[8] / 3)
            & (0x4d | work[172] >> 1 & 0x20),
    );
    matrix[29] = 162;
    hash[15] = hash[15].wrapping_add(majority(
        m!(149) ^ square(work[43]),
        select_bits(95, h!(125), si!(aux[1])) >> 1,
        115,
    ));
    aux[9] = aux[9].wrapping_sub(hi!(aux[7]));
    hash[7] = hash[7].wrapping_sub(square(rotate_or_zero(
        ma!(5),
        (0u8.wrapping_sub(m!(17))).wrapping_mul(m!(17) & 1),
    )));
    matrix[8] = matrix[8].wrapping_add(cube(s!(202))).wrapping_sub(work[184]);
    hash[16] = m!(102) << 1 & 0x84;
    aux[6] ^= si!(aux[7]) >> 1;
    hash[7] = hash[7].wrapping_sub(h!(191).wrapping_sub(select_bits(177, si!(si!(aux[1])), s!(80) << 1)));
    hash[6] = h!(119);
    hash[12] = (hi!(aux[8]) ^ (m!(71).wrapping_add(m!(15))))
        & majority(work[118] & !0x2c | 2, square(hi!(aux[9])), 27);
    let digest_index = select_bits(0xa9, s!(57).wrapping_mul(231), majority(work[32], ma!(1), 23)) / 5;
    let seed_sample = si!(aux[6]);
    aux[5] = majority(
        seed_sample & 0x1c | h!(82) & 0xa2 | si!(digest_index) & 0x41,
        majority(cube(hi!(aux[7])), work[82], 92),
        192,
    ) ^ digest_index;
    matrix[25] ^= 2u8
        .wrapping_mul(hi!(aux[9]))
        .wrapping_mul(work[5])
        .wrapping_sub(rotate_or_zero(aux[4], seed_sample & 7) & aux[3].wrapping_add(110));
}

