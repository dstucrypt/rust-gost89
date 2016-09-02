pub mod sbox;
pub mod gost89;

#[cfg(test)]
mod test {
    use super::sbox;
    use super::gost89;

    #[test]
    fn test_gost89_main() {
        let sbox = sbox::unpack(sbox::DSTU_SBOX);
        let key: [u32; 8] = [
            0x35_37_39_31, 0x36_38_30_32,
            0x37_39_31_33, 0x38_30_32_34,
            0x39_31_33_35, 0x30_32_34_36,
            0x31_33_35_37, 0x31_34_36_38,
        ];
        let data: [u8; 8] = [0; 8];
        let mut outdata: [u8; 8] = [0; 8];
        let gost89 = gost89::init(sbox, key);
        gost89::encrypt(&gost89, &data, &mut outdata);

        assert_eq!(outdata, [
            0xB1, 0xEE, 0x25, 0x37, 0x35, 0x8B, 0x53, 0x4D
        ]);
    }
}
