use crate::{stream::sala20::Sala20, stream::StreamCipher, utils::copy};

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex string")
}

struct TestVector {
    key: &'static str,
    iv: &'static str,
    num_bytes: usize,
    xor: &'static str,
}

static TEST_VECTORS: &[TestVector] = &[
    TestVector {
        key: "0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D",
        iv: "0D74DB42A91077DE",
        num_bytes: 131072,
        xor: "C349B6A51A3EC9B712EAED3F90D8BCEE69B7628645F251A996F55260C62EF31FD6C6B0AEA94E136C9D984AD2DF3578F78E457527B03A0450580DD874F63B1AB9",
    },
    TestVector {
        key: "0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12",
        iv: "167DE44BB21980E7",
        num_bytes: 131072,
        xor: "C3EAAF32836BACE32D04E1124231EF47E101367D6305413A0EEB07C60698A2876E4D031870A739D6FFDDD208597AFF0A47AC17EDB0167DD67EBA84F1883D4DFD",
    },
    TestVector {
        key: "0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417",
        iv: "1F86ED54BB2289F0",
        num_bytes: 131072,
        xor: "3CD23C3DC90201ACC0CF49B440B6C417F0DC8D8410A716D5314C059E14B1A8D9A9FB8EA3D9C8DAE12B21402F674AA95C67B1FC514E994C9D3F3A6E41DFF5BBA6",
    },
    TestVector {
        key: "0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C",
        iv: "288FF65DC42B92F9",
        num_bytes: 131072,
        xor: "E00EBCCD70D69152725F9987982178A2E2E139C7BCBE04CA8A0E99E318D9AB76F988C8549F75ADD790BA4F81C176DA653C1A043F11A958E169B6D2319F4EEC1A",
    },
];

struct XSalsa20TestData {
    input: &'static [u8],
    nonce: &'static [u8],
    key: &'static [u8],
    expected: &'static [u8],
}

static XSALSA20_TEST_DATA: &[XSalsa20TestData] = &[
    XSalsa20TestData {
        input: b"Hello world!",
        nonce: b"24-byte nonce for xsalsa",
        key: b"this is 32-byte key for xsalsa20",
        expected: &[
            0x00, 0x2d, 0x45, 0x13, 0x84, 0x3f, 0xc2, 0x40, 0xc4, 0x01, 0xe5, 0x41,
        ],
    },
    XSalsa20TestData {
        input: &[0u8; 64],
        nonce: b"24-byte nonce for xsalsa",
        key: b"this is 32-byte key for xsalsa20",
        expected: &[
            0x48, 0x48, 0x29, 0x7f, 0xeb, 0x1f, 0xb5, 0x2f, 0xb6, 0x6d, 0x81, 0x60, 0x9b, 0xd5,
            0x47, 0xfa, 0xbc, 0xbe, 0x70, 0x26, 0xed, 0xc8, 0xb5, 0xe5, 0xe4, 0x49, 0xd0, 0x88,
            0xbf, 0xa6, 0x9c, 0x08, 0x8f, 0x5d, 0x8d, 0xa1, 0xd7, 0x91, 0x26, 0x7c, 0x2c, 0x19,
            0x5a, 0x7f, 0x8c, 0xae, 0x9c, 0x4b, 0x40, 0x50, 0xd0, 0x8c, 0xe6, 0xd3, 0xa1, 0x51,
            0xec, 0x26, 0x5f, 0x3a, 0x58, 0xe4, 0x76, 0x48,
        ],
    },
];

#[test]
fn test_salsa20() {
    let mut in_buf = Vec::new();
    let mut out_buf = Vec::new();

    for (i, test) in TEST_VECTORS.iter().enumerate() {
        if test.num_bytes % 64 != 0 {
            panic!("#{}: numBytes is not a multiple of 64", i);
        }

        if test.num_bytes > in_buf.len() {
            in_buf = vec![0u8; test.num_bytes];
            out_buf = vec![0u8; test.num_bytes];
        }

        let input = &in_buf[..test.num_bytes];
        let mut output = out_buf[..test.num_bytes].to_vec();

        let key_bytes = from_hex(test.key);
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        let iv = from_hex(test.iv);

        copy(&mut output, input);
        let mut cipher = Sala20::new(&key, &iv).unwrap();
        cipher.xor_key_stream(&mut output).unwrap();

        let mut xor_result = [0u8; 64];
        let mut remaining = &output[..];

        while !remaining.is_empty() {
            for i in 0..64 {
                if i < remaining.len() {
                    xor_result[i] ^= remaining[i];
                }
            }
            if remaining.len() >= 64 {
                remaining = &remaining[64..];
            } else {
                break;
            }
        }

        let expected_xor = from_hex(test.xor);
        assert_eq!(&xor_result[..], &expected_xor[..], "#{}: bad result", i);
    }
}

#[test]
fn test_xsalsa20() {
    for (i, test) in XSALSA20_TEST_DATA.iter().enumerate() {
        let mut output = vec![0u8; test.input.len()];
        let mut key = [0u8; 32];
        key.copy_from_slice(test.key);

        copy(&mut output, test.input);
        let mut cipher = Sala20::new(&key, test.nonce).unwrap();
        cipher.xor_key_stream(&mut output).unwrap();

        assert_eq!(
            output, test.expected,
            "{}: expected {:x?}, got {:x?}",
            i, test.expected, output
        );
    }
}
