pub mod sbox;
pub mod gost89;
pub mod gosthash;

#[cfg(test)]
mod test {
    use super::sbox;
    use super::gost89;
    use super::gosthash;

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

    #[test]
    fn test_gosthash() {
        let sbox = sbox::unpack(sbox::DSTU_SBOX);
        let mut hash = gosthash::init(sbox);
        let data = b"12345678901234567890123456789011";
        let mut outdata: [u8; 32] = [0; 32];
        gosthash::update(&mut hash, data);
        gosthash::finish(&hash, &mut outdata);

        let expect = b"v\x86\xf3\xf4\xb1\x13\xaa\xdc\x97\xbc\xa9\xea\x05OA\x82\x1f\x06v\xc5\xc2\x8f\xfb\x98~AyzV\x8e\x1e\xd4";

        assert_eq!(&outdata, expect);
    }
}
