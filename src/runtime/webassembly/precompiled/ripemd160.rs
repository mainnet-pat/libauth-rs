const R1: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const R2: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const S1: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const S2: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

fn f(index: usize, x: u32, y: u32, z: u32) -> u32 {
    match index {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | ((!x) & z),
        32..=47 => (x | (!y)) ^ z,
        48..=63 => (x & z) | (y & (!z)),
        _ => x ^ (y | (!z)),
    }
}

fn k1(index: usize) -> u32 {
    match index {
        0..=15 => 0x0000_0000,
        16..=31 => 0x5a82_7999,
        32..=47 => 0x6ed9_eba1,
        48..=63 => 0x8f1b_bcdc,
        _ => 0xa953_fd4e,
    }
}

fn k2(index: usize) -> u32 {
    match index {
        0..=15 => 0x50a2_8be6,
        16..=31 => 0x5c4d_d124,
        32..=47 => 0x6d70_3ef3,
        48..=63 => 0x7a6d_76e9,
        _ => 0x0000_0000,
    }
}

pub(super) fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut x = [0_u32; 16];
    for (index, chunk) in block.chunks_exact(4).take(16).enumerate() {
        x[index] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let [h0, h1, h2, h3, h4] = *state;
    let mut al = h0;
    let mut bl = h1;
    let mut cl = h2;
    let mut dl = h3;
    let mut el = h4;
    let mut ar = h0;
    let mut br = h1;
    let mut cr = h2;
    let mut dr = h3;
    let mut er = h4;
    for index in 0..80 {
        let t = al
            .wrapping_add(f(index, bl, cl, dl))
            .wrapping_add(x[R1[index]])
            .wrapping_add(k1(index))
            .rotate_left(S1[index])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = t;
        let t = ar
            .wrapping_add(f(79 - index, br, cr, dr))
            .wrapping_add(x[R2[index]])
            .wrapping_add(k2(index))
            .rotate_left(S2[index])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = t;
    }
    let t = h1.wrapping_add(cl).wrapping_add(dr);
    state[1] = h2.wrapping_add(dl).wrapping_add(er);
    state[2] = h3.wrapping_add(el).wrapping_add(ar);
    state[3] = h4.wrapping_add(al).wrapping_add(br);
    state[4] = h0.wrapping_add(bl).wrapping_add(cr);
    state[0] = t;
}
