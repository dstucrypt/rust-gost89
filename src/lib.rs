pub static DSTU_SBOX: [u8; 64] = [
    0xa9, 0xd6, 0xeb, 0x45, 0xf1, 0x3c, 0x70, 0x82,
    0x80, 0xc4, 0x96, 0x7b, 0x23, 0x1f, 0x5e, 0xad,
    0xf6, 0x58, 0xeb, 0xa4, 0xc0, 0x37, 0x29, 0x1d,
    0x38, 0xd9, 0x6b, 0xf0, 0x25, 0xca, 0x4e, 0x17,
    0xf8, 0xe9, 0x72, 0x0d, 0xc6, 0x15, 0xb4, 0x3a,
    0x28, 0x97, 0x5f, 0x0b, 0xc1, 0xde, 0xa3, 0x64,
    0x38, 0xb5, 0x64, 0xea, 0x2c, 0x17, 0x9f, 0xd0,
    0x12, 0x3e, 0x6d, 0xb8, 0xfa, 0xc5, 0x79, 0x04
];

pub struct Sbox {
    pub k8: [u8; 16],
    pub k7: [u8; 16],
    pub k6: [u8; 16],
    pub k5: [u8; 16],
    pub k4: [u8; 16],
    pub k3: [u8; 16],
    pub k2: [u8; 16],
    pub k1: [u8; 16],
}

pub fn unpack_sbox(packed_sbox: [u8; 64])-> Sbox {
    let mut k1: [u8; 16] = [0; 16];
    let mut k2: [u8; 16] = [0; 16];
    let mut k3: [u8; 16] = [0; 16];
    let mut k4: [u8; 16] = [0; 16];
    let mut k5: [u8; 16] = [0; 16];
    let mut k6: [u8; 16] = [0; 16];
    let mut k7: [u8; 16] = [0; 16];
    let mut k8: [u8; 16] = [0; 16];

    let mut i = 0;
    while i < 8 {
        k1[2 * i] = 0x0f & (packed_sbox[i] >> 4);
        k1[(2 * i) + 1] = 0x0f & packed_sbox[i];

        k2[2 * i] = 0x0f & (packed_sbox[i + 8] >> 4);
        k2[(2 * i) + 1] = 0x0f & packed_sbox[i + 8];

        k3[2 * i] = 0x0f & (packed_sbox[i + 16] >> 4);
        k3[(2 * i) + 1] = 0x0f & packed_sbox[i + 16];

        k4[2 * i] = 0x0f & (packed_sbox[i + 24] >> 4);
        k4[(2 * i) + 1] = 0x0f & packed_sbox[i + 24];

        k5[2 * i] = 0x0f & (packed_sbox[i + 32] >> 4);
        k5[(2 * i) + 1] = 0x0f & packed_sbox[i + 32];

        k6[2 * i] = 0x0f & (packed_sbox[i + 40] >> 4);
        k6[(2 * i) + 1] = 0x0f & packed_sbox[i + 40];

        k7[2 * i] = 0x0f & (packed_sbox[i + 48] >> 4);
        k7[(2 * i) + 1] = 0x0f & packed_sbox[i + 48];

        k8[2 * i] = 0x0f & (packed_sbox[i + 56] >> 4);
        k8[(2 * i) + 1] = 0x0f & packed_sbox[i + 56];

        i = i + 1;
    }

    return Sbox {k1: k1, k2: k2, k3: k3, k4: k4,
                 k5: k5, k6: k6, k7: k7, k8: k8};
}

pub struct Gost89 {
    pub k: [u32; 8],
    pub k87: [u32; 256],
    pub k65: [u32; 256],
    pub k43: [u32; 256],
    pub k21: [u32; 256],
}

fn f(c: &Gost89, x: u32) -> u32 {
    let out = c.k87[(x>>24 & 255) as usize] |
            c.k65[(x>>16 & 255) as usize] |
            c.k43[(x>> 8 & 255) as usize] |
            c.k21[(x & 255) as usize];
    /* Rotate left 11 bits */
    return out<<11 | out>>(32-11);

}

pub fn gostinit(sbox: Sbox, key: [u32; 8]) -> Gost89 {
    let mut k87: [u32; 256] = [0; 256];
    let mut k65: [u32; 256] = [0; 256];
    let mut k43: [u32; 256] = [0; 256];
    let mut k21: [u32; 256] = [0; 256];

    let mut i = 0;
    while i < 256 {
        k87[i] = ((sbox.k8[i>>4] as u32) << 4 |
                  (sbox.k7[i & 15] as u32)) << 24;
        k65[i] = ((sbox.k6[i>>4] as u32) << 4 |
                  (sbox.k5[i & 15] as u32)) << 16;
        k43[i] = ((sbox.k4[i>>4] as u32) << 4 |
                  (sbox.k3[i &15] as u32)) << 8;
        k21[i] = (sbox.k2[i>>4] as u32) << 4 |
                  sbox.k1[i &15] as u32;

        i = i + 1;
    }

    return Gost89 {k: key, k87: k87, k65: k65, k43: k43, k21: k21};
}

#[inline]
fn add(a: u32, b: u32)-> u32 {
    return a.wrapping_add(b);
}

pub fn gostcrypt(c: &Gost89, inp: &[u8; 8], out: &mut [u8; 8]) {
    let mut n1: u32 = inp[0] as u32 |
                     (inp[1] as u32) << 8 |
                     (inp[2] as u32) <<16 |
                     (inp[3] as u32) <<24;

    let mut n2: u32 = inp[4] as u32 |
                     (inp[5] as u32) << 8 |
                     (inp[6] as u32) << 16 |
                     (inp[7] as u32) <<24;

    /* Instead of swapping halves, swap names each round */
    n2 ^= f(c, add(n1, c.k[0])); n1 ^= f(c, add(n2, c.k[1]));
    n2 ^= f(c, add(n1, c.k[2])); n1 ^= f(c, add(n2, c.k[3]));
    n2 ^= f(c, add(n1, c.k[4])); n1 ^= f(c, add(n2, c.k[5]));
    n2 ^= f(c, add(n1, c.k[6])); n1 ^= f(c, add(n2, c.k[7]));

    n2 ^= f(c, add(n1, c.k[0])); n1 ^= f(c, add(n2, c.k[1]));
    n2 ^= f(c, add(n1, c.k[2])); n1 ^= f(c, add(n2, c.k[3]));
    n2 ^= f(c, add(n1, c.k[4])); n1 ^= f(c, add(n2, c.k[5]));
    n2 ^= f(c, add(n1, c.k[6])); n1 ^= f(c, add(n2, c.k[7]));

    n2 ^= f(c, add(n1, c.k[0])); n1 ^= f(c, add(n2, c.k[1]));
    n2 ^= f(c, add(n1, c.k[2])); n1 ^= f(c, add(n2, c.k[3]));
    n2 ^= f(c, add(n1, c.k[4])); n1 ^= f(c, add(n2, c.k[5]));
    n2 ^= f(c, add(n1, c.k[6])); n1 ^= f(c, add(n2, c.k[7]));

    n2 ^= f(c, add(n1, c.k[7])); n1 ^= f(c, add(n2, c.k[6]));
    n2 ^= f(c, add(n1, c.k[5])); n1 ^= f(c, add(n2, c.k[4]));
    n2 ^= f(c, add(n1, c.k[3])); n1 ^= f(c, add(n2, c.k[2]));
    n2 ^= f(c, add(n1, c.k[1])); n1 ^= f(c, add(n2, c.k[0]));

    out[0] = (n2 & 0xff) as u8;
    out[1] = ((n2 >> 8) & 0xff) as u8;
    out[2] = ((n2 >>16) & 0xff) as u8;
    out[3] = (n2 >> 24) as u8;
    out[4] = (n1 & 0xff) as u8;
    out[5] = ((n1 >> 8) & 0xff) as u8;
    out[6] = ((n1 >> 16) & 0xff) as u8;
    out[7] = (n1 >> 24) as u8;
}

#[cfg(test)]
mod test {
    use super::unpack_sbox;
    use super::gostinit;
    use super::gostcrypt;
    use super::DSTU_SBOX;

    #[test]
    fn test_gost89_main() {
        let sbox = unpack_sbox(DSTU_SBOX);
        let key: [u32; 8] = [
            0x35_37_39_31, 0x36_38_30_32,
            0x37_39_31_33, 0x38_30_32_34,
            0x39_31_33_35, 0x30_32_34_36,
            0x31_33_35_37, 0x31_34_36_38,
        ];
        let data: [u8; 8] = [0; 8];
        let mut outdata: [u8; 8] = [0; 8];
        let gost89 = gostinit(sbox, key);
        gostcrypt(&gost89, &data, &mut outdata);

        assert_eq!(outdata, [
            0xB1, 0xEE, 0x25, 0x37, 0x35, 0x8B, 0x53, 0x4D
        ]);
    }
}
