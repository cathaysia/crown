#[cfg(test)]
mod tests;

use crate::{
    aead::ocb3::Ocb3Marker,
    block::BlockCipher,
    error::{CryptoError, CryptoResult},
};

const KHAZAD_T0: [u64; 256] = [
    0xbad3d268bbb96a01,
    0x54fc4d19e59a66b1,
    0x2f71bc93e26514cd,
    0x749ccdb925871b51,
    0x53f55102f7a257a4,
    0xd3686bb8d0d6be03,
    0xd26b6fbdd6deb504,
    0x4dd72964b35285fe,
    0x50f05d0dfdba4aad,
    0xace98a26cf09e063,
    0x8d8a0e83091c9684,
    0xbfdcc679a5914d1a,
    0x7090ddad3da7374d,
    0x52f65507f1aa5ca3,
    0x9ab352c87ba417e1,
    0x4cd42d61b55a8ef9,
    0xea238f65460320ac,
    0xd56273a6c4e68411,
    0x97a466f155cc68c2,
    0xd16e63b2dcc6a80d,
    0x3355ccffaa85d099,
    0x51f35908fbb241aa,
    0x5bed712ac7e20f9c,
    0xa6f7a204f359ae55,
    0xde7f5f81febec120,
    0x48d83d75ad7aa2e5,
    0xa8e59a32d729cc7f,
    0x99b65ec771bc0ae8,
    0xdb704b90e096e63b,
    0x3256c8faac8ddb9e,
    0xb7c4e65195d11522,
    0xfc19d72b32b3aace,
    0xe338ab48704b7393,
    0x9ebf42dc63843bfd,
    0x91ae7eef41fc52d0,
    0x9bb056cd7dac1ce6,
    0xe23baf4d76437894,
    0xbbd0d66dbdb16106,
    0x41c319589b32f1da,
    0x6eb2a5cb7957e517,
    0xa5f2ae0bf941b35c,
    0xcb400bc08016564b,
    0x6bbdb1da677fc20c,
    0x95a26efb59dc7ecc,
    0xa1febe1fe1619f40,
    0xf308eb1810cbc3e3,
    0xb1cefe4f81e12f30,
    0x0206080a0c10160e,
    0xcc4917db922e675e,
    0xc45137f3a26e3f66,
    0x1d2774694ee8cf53,
    0x143c504478a09c6c,
    0xc3582be8b0560e73,
    0x63a591f2573f9a34,
    0xda734f95e69eed3c,
    0x5de76934d3d2358e,
    0x5fe1613edfc22380,
    0xdc79578bf2aed72e,
    0x7d87e99413cf486e,
    0xcd4a13de94266c59,
    0x7f81e19e1fdf5e60,
    0x5aee752fc1ea049b,
    0x6cb4adc17547f319,
    0x5ce46d31d5da3e89,
    0xf704fb0c08ebefff,
    0x266a98bed42d47f2,
    0xff1cdb2438abb7c7,
    0xed2a937e543b11b9,
    0xe825876f4a1336a2,
    0x9dba4ed3699c26f4,
    0x6fb1a1ce7f5fee10,
    0x8e8f028c03048b8d,
    0x192b647d56c8e34f,
    0xa0fdba1ae7699447,
    0xf00de7171ad3deea,
    0x89861e97113cba98,
    0x0f113c332278692d,
    0x07091c1b12383115,
    0xafec8629c511fd6a,
    0xfb10cb30208b9bdb,
    0x0818202830405838,
    0x153f54417ea8976b,
    0x0d1734392e687f23,
    0x040c101418202c1c,
    0x0103040506080b07,
    0x64ac8de94507ab21,
    0xdf7c5b84f8b6ca27,
    0x769ac5b329970d5f,
    0x798bf9800bef6472,
    0xdd7a538ef4a6dc29,
    0x3d47f4c98ef5b2b3,
    0x163a584e74b08a62,
    0x3f41fcc382e5a4bd,
    0x3759dcebb2a5fc85,
    0x6db7a9c4734ff81e,
    0x3848e0d890dd95a8,
    0xb9d6de67b1a17708,
    0x7395d1a237bf2a44,
    0xe926836a4c1b3da5,
    0x355fd4e1beb5ea8b,
    0x55ff491ce3926db6,
    0x7193d9a83baf3c4a,
    0x7b8df18a07ff727c,
    0x8c890a860f149d83,
    0x7296d5a731b72143,
    0x88851a921734b19f,
    0xf607ff090ee3e4f8,
    0x2a7ea882fc4d33d6,
    0x3e42f8c684edafba,
    0x5ee2653bd9ca2887,
    0x27699cbbd2254cf5,
    0x46ca0543890ac0cf,
    0x0c14303c28607424,
    0x65af89ec430fa026,
    0x68b8bdd56d67df05,
    0x61a399f85b2f8c3a,
    0x03050c0f0a181d09,
    0xc15e23e2bc46187d,
    0x57f94116ef827bb8,
    0xd6677fa9cefe9918,
    0xd976439aec86f035,
    0x58e87d25cdfa1295,
    0xd875479fea8efb32,
    0x66aa85e34917bd2f,
    0xd7647bacc8f6921f,
    0x3a4ee8d29ccd83a6,
    0xc84507cf8a0e4b42,
    0x3c44f0cc88fdb9b4,
    0xfa13cf35268390dc,
    0x96a762f453c463c5,
    0xa7f4a601f551a552,
    0x98b55ac277b401ef,
    0xec29977b52331abe,
    0xb8d5da62b7a97c0f,
    0xc7543bfca876226f,
    0xaeef822cc319f66d,
    0x69bbb9d06b6fd402,
    0x4bdd317aa762bfec,
    0xabe0963ddd31d176,
    0xa9e69e37d121c778,
    0x67a981e64f1fb628,
    0x0a1e28223c504e36,
    0x47c901468f02cbc8,
    0xf20bef1d16c3c8e4,
    0xb5c2ee5b99c1032c,
    0x226688aacc0d6bee,
    0xe532b356647b4981,
    0xee2f9f715e230cb0,
    0xbedfc27ca399461d,
    0x2b7dac87fa4538d1,
    0x819e3ebf217ce2a0,
    0x1236485a6c90a67e,
    0x839836b52d6cf4ae,
    0x1b2d6c775ad8f541,
    0x0e1238362470622a,
    0x23658cafca0560e9,
    0xf502f30604fbf9f1,
    0x45cf094c8312ddc6,
    0x216384a5c61576e7,
    0xce4f1fd19e3e7150,
    0x49db3970ab72a9e2,
    0x2c74b09ce87d09c4,
    0xf916c33a2c9b8dd5,
    0xe637bf596e635488,
    0xb6c7e25493d91e25,
    0x2878a088f05d25d8,
    0x17395c4b72b88165,
    0x829b32b02b64ffa9,
    0x1a2e68725cd0fe46,
    0x8b80169d1d2cac96,
    0xfe1fdf213ea3bcc0,
    0x8a8312981b24a791,
    0x091b242d3648533f,
    0xc94603ca8c064045,
    0x879426a1354cd8b2,
    0x4ed2256bb94a98f7,
    0xe13ea3427c5b659d,
    0x2e72b896e46d1fca,
    0xe431b75362734286,
    0xe03da7477a536e9a,
    0xeb208b60400b2bab,
    0x90ad7aea47f459d7,
    0xa4f1aa0eff49b85b,
    0x1e22786644f0d25a,
    0x85922eab395ccebc,
    0x60a09dfd5d27873d,
    0x0000000000000000,
    0x256f94b1de355afb,
    0xf401f70302f3f2f6,
    0xf10ee3121cdbd5ed,
    0x94a16afe5fd475cb,
    0x0b1d2c273a584531,
    0xe734bb5c686b5f8f,
    0x759fc9bc238f1056,
    0xef2c9b74582b07b7,
    0x345cd0e4b8bde18c,
    0x3153c4f5a695c697,
    0xd46177a3c2ee8f16,
    0xd06d67b7dacea30a,
    0x869722a43344d3b5,
    0x7e82e59b19d75567,
    0xadea8e23c901eb64,
    0xfd1ad32e34bba1c9,
    0x297ba48df6552edf,
    0x3050c0f0a09dcd90,
    0x3b4decd79ac588a1,
    0x9fbc46d9658c30fa,
    0xf815c73f2a9386d2,
    0xc6573ff9ae7e2968,
    0x13354c5f6a98ad79,
    0x060a181e14303a12,
    0x050f14111e28271b,
    0xc55233f6a4663461,
    0x113344556688bb77,
    0x7799c1b62f9f0658,
    0x7c84ed9115c74369,
    0x7a8ef58f01f7797b,
    0x7888fd850de76f75,
    0x365ad8eeb4adf782,
    0x1c24706c48e0c454,
    0x394be4dd96d59eaf,
    0x59eb7920cbf21992,
    0x1828607850c0e848,
    0x56fa4513e98a70bf,
    0xb3c8f6458df1393e,
    0xb0cdfa4a87e92437,
    0x246c90b4d83d51fc,
    0x206080a0c01d7de0,
    0xb2cbf2408bf93239,
    0x92ab72e04be44fd9,
    0xa3f8b615ed71894e,
    0xc05d27e7ba4e137a,
    0x44cc0d49851ad6c1,
    0x62a695f751379133,
    0x103040506080b070,
    0xb4c1ea5e9fc9082b,
    0x84912aae3f54c5bb,
    0x43c511529722e7d4,
    0x93a876e54dec44de,
    0xc25b2fedb65e0574,
    0x4ade357fa16ab4eb,
    0xbddace73a9815b14,
    0x8f8c0689050c808a,
    0x2d77b499ee7502c3,
    0xbcd9ca76af895013,
    0x9cb94ad66f942df3,
    0x6abeb5df6177c90b,
    0x40c01d5d9d3afadd,
    0xcf4c1bd498367a57,
    0xa2fbb210eb798249,
    0x809d3aba2774e9a7,
    0x4fd1216ebf4293f0,
    0x1f217c6342f8d95d,
    0xca430fc5861e5d4c,
    0xaae39238db39da71,
    0x42c61557912aecd3,
];

const KHAZAD_C: [u64; 9] = [
    0xba542f7453d3d24d,
    0x50ac8dbf70529a4c,
    0xead597d133515ba6,
    0xde48a899db32b7fc,
    0xe39e919be2bb416e,
    0xa5cb6b95a1f3b102,
    0xccc41d14c363da5d,
    0x5fdc7dcd7f5a6c5c,
    0xf726ffede89d6f8e,
];

const KHAZAD_S: [u8; 256] = [
    0xba, 0x54, 0x2f, 0x74, 0x53, 0xd3, 0xd2, 0x4d, 0x50, 0xac, 0x8d, 0xbf, 0x70, 0x52, 0x9a, 0x4c,
    0xea, 0xd5, 0x97, 0xd1, 0x33, 0x51, 0x5b, 0xa6, 0xde, 0x48, 0xa8, 0x99, 0xdb, 0x32, 0xb7, 0xfc,
    0xe3, 0x9e, 0x91, 0x9b, 0xe2, 0xbb, 0x41, 0x6e, 0xa5, 0xcb, 0x6b, 0x95, 0xa1, 0xf3, 0xb1, 0x02,
    0xcc, 0xc4, 0x1d, 0x14, 0xc3, 0x63, 0xda, 0x5d, 0x5f, 0xdc, 0x7d, 0xcd, 0x7f, 0x5a, 0x6c, 0x5c,
    0xf7, 0x26, 0xff, 0xed, 0xe8, 0x9d, 0x6f, 0x8e, 0x19, 0xa0, 0xf0, 0x89, 0x0f, 0x07, 0xaf, 0xfb,
    0x08, 0x15, 0x0d, 0x04, 0x01, 0x64, 0xdf, 0x76, 0x79, 0xdd, 0x3d, 0x16, 0x3f, 0x37, 0x6d, 0x38,
    0xb9, 0x73, 0xe9, 0x35, 0x55, 0x71, 0x7b, 0x8c, 0x72, 0x88, 0xf6, 0x2a, 0x3e, 0x5e, 0x27, 0x46,
    0x0c, 0x65, 0x68, 0x61, 0x03, 0xc1, 0x57, 0xd6, 0xd9, 0x58, 0xd8, 0x66, 0xd7, 0x3a, 0xc8, 0x3c,
    0xfa, 0x96, 0xa7, 0x98, 0xec, 0xb8, 0xc7, 0xae, 0x69, 0x4b, 0xab, 0xa9, 0x67, 0x0a, 0x47, 0xf2,
    0xb5, 0x22, 0xe5, 0xee, 0xbe, 0x2b, 0x81, 0x12, 0x83, 0x1b, 0x0e, 0x23, 0xf5, 0x45, 0x21, 0xce,
    0x49, 0x2c, 0xf9, 0xe6, 0xb6, 0x28, 0x17, 0x82, 0x1a, 0x8b, 0xfe, 0x8a, 0x09, 0xc9, 0x87, 0x4e,
    0xe1, 0x2e, 0xe4, 0xe0, 0xeb, 0x90, 0xa4, 0x1e, 0x85, 0x60, 0x00, 0x25, 0xf4, 0xf1, 0x94, 0x0b,
    0xe7, 0x75, 0xef, 0x34, 0x31, 0xd4, 0xd0, 0x86, 0x7e, 0xad, 0xfd, 0x29, 0x30, 0x3b, 0x9f, 0xf8,
    0xc6, 0x13, 0x06, 0x05, 0xc5, 0x11, 0x77, 0x7c, 0x7a, 0x78, 0x36, 0x1c, 0x39, 0x59, 0x18, 0x56,
    0xb3, 0xb0, 0x24, 0x20, 0xb2, 0x92, 0xa3, 0xc0, 0x44, 0x62, 0x10, 0xb4, 0x84, 0x43, 0x93, 0xc2,
    0x4a, 0xbd, 0x8f, 0x2d, 0xbc, 0x9c, 0x6a, 0x40, 0xcf, 0xa2, 0x80, 0x4f, 0x1f, 0xca, 0xaa, 0x42,
];

pub struct Khazad {
    enc_keys: [u64; 9],
    dec_keys: [u64; 9],
}

impl Khazad {
    pub const BLOCK_SIZE: usize = 8;
    pub const KEY_SIZE: usize = 16;

    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }

        let mut enc_keys = [0u64; 9];
        let mut dec_keys = [0u64; 9];

        let mut k2 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let mut k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());

        for i in 0..=8 {
            let next_k = khazad_sp(k1) ^ KHAZAD_C[i] ^ k2;
            enc_keys[i] = next_k;
            k2 = k1;
            k1 = next_k;
        }

        // Decryption keys
        dec_keys[0] = enc_keys[8];
        for i in 1..8 {
            dec_keys[i] = khazad_theta(enc_keys[8 - i]);
        }
        dec_keys[8] = enc_keys[0];

        Ok(Khazad { enc_keys, dec_keys })
    }

    fn crypt_block(&self, inout: &mut [u8], keys: &[u64; 9]) {
        let mut state = u64::from_be_bytes(inout[0..8].try_into().unwrap()) ^ keys[0];

        for i in 1..8 {
            state = khazad_sp(state) ^ keys[i];
        }

        // Last round is different: no MDS (theta)
        state = khazad_gamma(state) ^ keys[8];

        let bytes = state.to_be_bytes();
        inout[0..8].copy_from_slice(&bytes);
    }
}

impl BlockCipher for Khazad {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        self.crypt_block(inout, &self.enc_keys);
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        self.crypt_block(inout, &self.dec_keys);
    }
}

impl super::BlockCipherMarker for Khazad {}
impl Ocb3Marker for Khazad {}

#[inline(always)]
fn khazad_sp(l: u64) -> u64 {
    let mut res = 0u64;
    let bytes = l.to_be_bytes();
    for i in 0..8 {
        let t = KHAZAD_T0[bytes[i] as usize];
        res ^= khazad_permute_mds(t, i);
    }
    res
}

#[inline(always)]
fn khazad_permute_mds(t: u64, col: usize) -> u64 {
    let bytes = t.to_be_bytes();
    let mut res_bytes = [0u8; 8];
    for i in 0..8 {
        res_bytes[i] = bytes[i ^ col];
    }
    u64::from_be_bytes(res_bytes)
}

#[inline(always)]
fn khazad_gamma(l: u64) -> u64 {
    let b = l.to_be_bytes();
    let res_bytes = [
        KHAZAD_S[b[0] as usize],
        KHAZAD_S[b[1] as usize],
        KHAZAD_S[b[2] as usize],
        KHAZAD_S[b[3] as usize],
        KHAZAD_S[b[4] as usize],
        KHAZAD_S[b[5] as usize],
        KHAZAD_S[b[6] as usize],
        KHAZAD_S[b[7] as usize],
    ];
    u64::from_be_bytes(res_bytes)
}

#[inline(always)]
fn khazad_theta(l: u64) -> u64 {
    let mut res = 0u64;
    let b = l.to_be_bytes();
    for i in 0..8 {
        let t = KHAZAD_T0[KHAZAD_S[b[i] as usize] as usize];
        res ^= khazad_permute_mds(t, i);
    }
    res
}
