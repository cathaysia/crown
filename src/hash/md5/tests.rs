use std::cmp::Ordering;

use super::*;

pub(crate) struct Md5Test {
    pub(crate) out: &'static str,
    pub(crate) input: &'static str,
    pub(crate) _half_state: &'static [u8],
}

pub(crate)static GOLDEN: &[Md5Test] = &[
        Md5Test {
            out: "d41d8cd98f00b204e9800998ecf8427e",
            input: "",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        },
        Md5Test {
            out: "0cc175b9c0f1b6a831c399e269772661",
            input: "a",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        },
        Md5Test {
            out: "187ef4436122d1cc2f40dc2b92f0eba0",
            input: "ab",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tva\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        },
        Md5Test {
            out: "900150983cd24fb0d6963f7d28e17f72",
            input: "abc",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tva\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        },
        Md5Test {
            out: "e2fc714c4727ee9395f324cd2e7f331f",
            input: "abcd",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
        },
        Md5Test {
            out: "ab56b4d92b40713acc5af89985d4b786",
            input: "abcde",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
        },
        Md5Test {
            out: "e80b5017098950fc58aad83c8c14978e",
            input: "abcdef",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03",
        },
        Md5Test {
            out: "7ac66c0f148de9519b8bd264312c4d64",
            input: "abcdefg",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03",
        },
        Md5Test {
            out: "e8dc4081b13434b45189a720b77b6818",
            input: "abcdefgh",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
        },
        Md5Test {
            out: "8aa99b1f439ff71293e95357bac6fd94",
            input: "abcdefghi",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
        },
        Md5Test {
            out: "a925576942e94b2ef57a066101b48876",
            input: "abcdefghij",
            _half_state: b"md5\x01gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tvabcde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05",
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
        let result = sum_md5(test.input.as_bytes());
        let s = hex_encode(&result);
        assert_eq!(
            s, test.out,
            "Sum function: md5({}) = {} want {}",
            test.input, s, test.out
        );

        // Test digest with various write patterns
        let mut buf = vec![0u8; test.input.len() + 4];
        for j in 0..7 {
            let mut c = super::new_md5();

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
            let mut c = super::new_md5();

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
            let mut c = super::new_md5();

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
fn rustcrypto_md5_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let this = &super::sum_md5(&buf);
        let rustcrypto = &md5::compute(&buf).to_vec();

        assert_eq!(this, rustcrypto.as_slice());
    }
}
