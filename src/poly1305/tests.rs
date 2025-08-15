mod data;

use bytes::Buf;
use data::TEST_DATA;

use super::{verify, TAG_SIZE};

struct Test {
    inx: String,
    key: String,
    tag: String,
    state: String,
}

impl Test {
    pub fn input(&self) -> Vec<u8> {
        hex::decode(&self.inx).unwrap()
    }

    pub fn key(&self) -> [u8; 32] {
        hex::decode(&self.key).unwrap().try_into().unwrap()
    }

    pub fn tag(&self) -> [u8; 16] {
        hex::decode(&self.tag).unwrap().try_into().unwrap()
    }

    pub fn initial_state(&self) -> [u64; 3] {
        if self.state.is_empty() {
            return [0; 3];
        }
        let buf = hex::decode(&self.state).unwrap();
        if buf.len() != 3 * 8 {
            panic!("Invalid state length")
        }
        let mut buf = buf.as_slice();

        [buf.get_u64(), buf.get_u64(), buf.get_u64()]
    }
}

fn test_sum_imp(
    unaligned: bool,
    sum_impl: fn(tag: &mut [u8; TAG_SIZE], msg: &[u8], key: &[u8; 32]),
) {
    let mut tag = [0u8; 16];
    for v in TEST_DATA.iter() {
        if v.initial_state() != [0; 3] {
            continue;
        }

        let mut inx = v.input();
        if unaligned {
            inx = unalign_bytes(&inx);
        }

        let mut key = v.key();
        sum_impl(&mut tag, &inx, &key);

        assert_eq!(hex::encode(tag), hex::encode(v.tag()));
        assert!(verify(&tag, &inx, &key));

        if !inx.is_empty() && key != [0u8; 32] {
            inx[0] ^= 0xff;
            assert!(!verify(&tag, &inx, &key));
            inx[0] ^= 0xff;
        }

        if !inx.is_empty() {
            key[0] ^= 0xff;
            assert!(!verify(&tag, &inx, &key));
            key[0] ^= 0xff;
        }
        tag[0] ^= 0xff;
        assert!(!verify(&tag, &inx, &key));
        tag[0] ^= 0xff;
    }
}

#[test]
fn test_sum() {
    test_sum_imp(false, super::sum);
}

#[test]
fn test_sum_generic() {
    test_sum_imp(false, super::sum_generic);
}

fn unalign_bytes(_input: &[u8]) -> Vec<u8> {
    todo!()
}
