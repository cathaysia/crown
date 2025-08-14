use std::cmp::Ordering;

use super::*;

struct Md5Test {
    out: &'static str,
    input: &'static str,
    half_state: &'static [u8],
}

static GOLDEN: &[Md5Test] = &[
        Md5Test {
            out: "d41d8cd98f00b204e9800998ecf8427e",
            input: "",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        },
        Md5Test {
            out: "0cc175b9c0f1b6a831c399e269772661",
            input: "a",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        },
        Md5Test {
            out: "187ef4436122d1cc2f40dc2b92f0eba0",
            input: "ab",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tva\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        },
        Md5Test {
            out: "900150983cd24fb0d6963f7d28e17f72",
            input: "abc",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tva\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        },
        Md5Test {
            out: "e2fc714c4727ee9395f324cd2e7f331f",
            input: "abcd",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
        },
        Md5Test {
            out: "ab56b4d92b40713acc5af89985d4b786",
            input: "abcde",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
        },
        Md5Test {
            out: "e80b5017098950fc58aad83c8c14978e",
            input: "abcdef",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03",
        },
        Md5Test {
            out: "7ac66c0f148de9519b8bd264312c4d64",
            input: "abcdefg",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03",
        },
        Md5Test {
            out: "e8dc4081b13434b45189a720b77b6818",
            input: "abcdefgh",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
        },
        Md5Test {
            out: "8aa99b1f439ff71293e95357bac6fd94",
            input: "abcdefghi",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
        },
        Md5Test {
            out: "a925576942e94b2ef57a066101b48876",
            input: "abcdefghij",
            half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabcde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05",
        },
    ];

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold("".into(), |s, b| s + &format!("{:02x}", b))
}

#[test]
fn test_golden() {
    for test in GOLDEN {
        // Test sum function
        let result = sum(test.input.as_bytes());
        let s = hex_encode(&result);
        assert_eq!(
            s, test.out,
            "Sum function: md5({}) = {} want {}",
            test.input, s, test.out
        );

        // Test digest with various write patterns
        let mut buf = vec![0u8; test.input.len() + 4];
        for j in 0..7 {
            let mut c = Md5::new();

            match j.cmp(&2) {
                Ordering::Less => {
                    c.write_all(test.input.as_bytes()).unwrap();
                }
                Ordering::Equal => {
                    let half = test.input.len() / 2;
                    c.write_all(&test.input.as_bytes()[..half]).unwrap();
                    c.sum();
                    c.write_all(&test.input.as_bytes()[half..]).unwrap();
                }
                _ => {
                    // Test unaligned write
                    buf = buf[1..].to_vec();
                    buf.resize(test.input.len() + 3, 0);
                    buf[..test.input.len()].copy_from_slice(test.input.as_bytes());
                    c.write_all(&buf[..test.input.len()]).unwrap();
                }
            }

            let result = c.sum();
            let s = hex_encode(&result);
            assert_eq!(
                s, test.out,
                "md5[{}]({}) = {} want {}",
                j, test.input, s, test.out
            );
            c.reset();
        }
    }
}

#[test]
fn test_golden_marshal() {
    for test in GOLDEN.iter() {
        let mut h = Md5::new();
        let mut h2 = Md5::new();

        let half = test.input.len() / 2;
        h.write_all(&test.input.as_bytes()[..half]).unwrap();

        let state = h.marshal_binary().unwrap();
        let state_append_vec = h.append_binary(vec![0u8; 4]).unwrap();
        let state_append = &state_append_vec[4..];

        assert_eq!(
            state, test.half_state,
            "md5({:?}) state mismatch",
            test.input
        );
        assert_eq!(
            state_append, test.half_state,
            "md5({:?}) stateAppend mismatch",
            test.input
        );

        h2.unmarshal_binary(&state).unwrap();

        h.write_all(&test.input.as_bytes()[half..]).unwrap();
        h2.write_all(&test.input.as_bytes()[half..]).unwrap();

        let actual = h.sum();
        let actual2 = h2.sum();
        assert_eq!(
            actual, actual2,
            "md5({:?}) = {:?} != marshaled {:?}",
            test.input, actual, actual2
        );
    }
}

#[test]
fn test_large() {
    const N: usize = 10000;
    const OFFSETS: usize = 4;
    let ok = "2bb571599a4180e1d542f76904adc3df";
    let mut block = vec![0u8; N + OFFSETS];

    for offset in 0..OFFSETS {
        for i in 0..N {
            block[offset + i] = b'0' + (i % 10) as u8;
        }

        let mut block_size = 10;
        while block_size <= N {
            let blocks = N / block_size;
            let b = &block[offset..offset + block_size];
            let mut c = Md5::new();

            for _ in 0..blocks {
                c.write_all(b).unwrap();
            }

            let result = c.sum();
            let s = hex_encode(&result);
            assert_eq!(
                s, ok,
                "md5 TestLarge offset={}, blockSize={} = {} want {}",
                offset, block_size, s, ok
            );

            block_size *= 10;
        }
    }
}

#[test]
fn test_extra_large() {
    const N: usize = 100000;
    const OFFSETS: usize = 4;
    let ok = "13572e9e296cff52b79c52148313c3a5";
    let mut block = vec![0u8; N + OFFSETS];

    for offset in 0..OFFSETS {
        for i in 0..N {
            block[offset + i] = b'0' + (i % 10) as u8;
        }

        let mut block_size = 10;
        while block_size <= N {
            let blocks = N / block_size;
            let b = &block[offset..offset + block_size];
            let mut c = Md5::new();

            for _ in 0..blocks {
                c.write_all(b).unwrap();
            }

            let result = c.sum();
            let s = hex_encode(&result);
            assert_eq!(
                s, ok,
                "md5 TestExtraLarge offset={}, blockSize={} = {} want {}",
                offset, block_size, s, ok
            );

            block_size *= 10;
        }
    }
}

#[test]
fn test_block_generic() {
    let mut gen = Md5::new();
    let mut asm = Md5::new();
    let buf = vec![0x42u8; Md5::BLOCK_SIZE * 20];

    block_generic(&mut gen, &buf);
    block(&mut asm, &buf);

    assert_eq!(
        gen.s, asm.s,
        "block and block_generic resulted in different states"
    );
}

struct UnmarshalTest {
    state: [u8; 92],
    sum: &'static str,
}

static LARGE_UNMARSHAL_TESTS: &[UnmarshalTest] = &[
    UnmarshalTest {
        state: [
            109, 100, 53, 1, 165, 247, 240, 61, 214, 83, 133, 217, 77, 10, 125, 195, 216, 129, 137,
            231, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
            84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
            104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 1, 167, 86, 67, 119,
        ],
        sum: "cddefcf74ffec709a0b45a6a987564d5",
    },
    UnmarshalTest {
        state: [
            0x6d, 0x64, 0x35, 0x01, 0x7b, 0xda, 0x1a, 0xc7, 0xc9, 0x27, 0x3f, 0x83, 0x45, 0x58,
            0xe0, 0x88, 0x71, 0xfe, 0x47, 0x18, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
            0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
            0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
            0x72, 0x73, 0x74, 0x75, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x87, 0x56, 0x43, 0x77,
        ],
        sum: "fd9f41874ab240698e7bc9c3ae70c8e4",
    },
];

fn safe_sum(h: &mut Md5) -> Result<[u8; 16], String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.sum()))
        .map_err(|_| "sum panic".to_string())
}

#[test]
// #[ignore] // Skip large hash tests - these require specific state data that may not match our implementation
fn test_large_hashes() {
    for (i, test) in LARGE_UNMARSHAL_TESTS.iter().enumerate() {
        let mut h = Md5::new();
        if let Err(e) = h.unmarshal_binary(&test.state) {
            panic!("test {} could not unmarshal: {:?}", i, e);
        }

        match safe_sum(&mut h) {
            Ok(sum) => {
                let sum_hex = hex_encode(&sum);
                assert_eq!(
                    sum_hex, test.sum,
                    "test {} sum mismatch: expect {} got {}",
                    i, test.sum, sum_hex
                );
            }
            Err(e) => {
                panic!("test {} could not sum: {}", i, e);
            }
        }
    }
}

#[test]
fn rustcrypto_md5_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let this = &crate::md5::sum(&buf);
        let rustcrypto = &md5::compute(&buf).to_vec();

        assert_eq!(this, rustcrypto.as_slice());
    }
}
