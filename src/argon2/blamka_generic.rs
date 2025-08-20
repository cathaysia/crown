use std::num::Wrapping;

use super::{Block, BLOCK_LENGTH};

pub fn process_block_generic(out: &mut Block, in1: &Block, in2: &Block, xor: bool) {
    let mut t = [0u64; BLOCK_LENGTH];

    for i in 0..BLOCK_LENGTH {
        t[i] = in1[i] ^ in2[i];
    }

    for i in (0..BLOCK_LENGTH).step_by(16) {
        let t = t.as_mut_ptr();
        unsafe {
            blamka_generic(
                &mut *t.wrapping_add(i),
                &mut *t.wrapping_add(i + 1),
                &mut *t.wrapping_add(i + 2),
                &mut *t.wrapping_add(i + 3),
                &mut *t.wrapping_add(i + 4),
                &mut *t.wrapping_add(i + 5),
                &mut *t.wrapping_add(i + 6),
                &mut *t.wrapping_add(i + 7),
                &mut *t.wrapping_add(i + 8),
                &mut *t.wrapping_add(i + 9),
                &mut *t.wrapping_add(i + 10),
                &mut *t.wrapping_add(i + 11),
                &mut *t.wrapping_add(i + 12),
                &mut *t.wrapping_add(i + 13),
                &mut *t.wrapping_add(i + 14),
                &mut *t.wrapping_add(i + 15),
            );
        }
    }

    for i in (0..BLOCK_LENGTH / 8).step_by(2) {
        let t = t.as_mut_ptr();
        unsafe {
            blamka_generic(
                &mut *t.wrapping_add(i),
                &mut *t.wrapping_add(i + 1),
                &mut *t.wrapping_add(16 + i),
                &mut *t.wrapping_add(16 + i + 1),
                &mut *t.wrapping_add(32 + i),
                &mut *t.wrapping_add(32 + i + 1),
                &mut *t.wrapping_add(48 + i),
                &mut *t.wrapping_add(48 + i + 1),
                &mut *t.wrapping_add(64 + i),
                &mut *t.wrapping_add(64 + i + 1),
                &mut *t.wrapping_add(80 + i),
                &mut *t.wrapping_add(80 + i + 1),
                &mut *t.wrapping_add(96 + i),
                &mut *t.wrapping_add(96 + i + 1),
                &mut *t.wrapping_add(112 + i),
                &mut *t.wrapping_add(112 + i + 1),
            );
        }
    }

    if xor {
        for i in 0..BLOCK_LENGTH {
            out[i] ^= in1[i] ^ in2[i] ^ t[i];
        }
    } else {
        for i in 0..BLOCK_LENGTH {
            out[i] = in1[i] ^ in2[i] ^ t[i];
        }
    }
}

#[allow(clippy::manual_rotate)]
#[allow(clippy::too_many_arguments)]
pub fn blamka_generic(
    t00: &mut u64,
    t01: &mut u64,
    t02: &mut u64,
    t03: &mut u64,
    t04: &mut u64,
    t05: &mut u64,
    t06: &mut u64,
    t07: &mut u64,
    t08: &mut u64,
    t09: &mut u64,
    t10: &mut u64,
    t11: &mut u64,
    t12: &mut u64,
    t13: &mut u64,
    t14: &mut u64,
    t15: &mut u64,
) {
    macro_rules! op1 {
        ($v00:ident, $v04:ident) => {
            *$v00 = (Wrapping(*$v00)
                + Wrapping(*$v04)
                + Wrapping(2) * Wrapping(*$v00 as u32 as u64) * Wrapping(*$v04 as u32 as u64))
            .0;
        };
        (#internal $v00:ident, $v04:ident, $v12:ident, $l1:literal, $l2: literal, $v08:ident, $l3: literal, $l4:literal) => {
            op1!($v00, $v04);
            *$v12 ^= *$v00;
            *$v12 = *$v12 >> $l1 | *$v12 << $l2;
            op1!($v08, $v12);
            *$v04 ^= *$v08;
            *$v04 = *$v04 >> $l3 | *$v04 << $l4;
        };
        ($v00:ident, $v04:ident, $v12:ident, $v08:ident) => {
            op1!(#internal $v00, $v04, $v12, 32, 32, $v08, 24, 40);

            op1!(#internal $v00, $v04, $v12, 16, 48, $v08, 63, 1);
        };
    }

    op1!(t00, t04, t12, t08);
    op1!(t01, t05, t13, t09);
    op1!(t02, t06, t14, t10);
    op1!(t03, t07, t15, t11);

    op1!(t00, t05, t15, t10);
    op1!(t01, t06, t12, t11);
    op1!(t02, t07, t13, t08);
    op1!(t03, t04, t14, t09);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ge() {
        struct Test {
            input: &'static str,
            output: &'static str,
        }

        let cases = [
            Test{input:"88b4ceb81b14bee7a92bd4fdd591fcbe05176035901b7da3559ebd9e447ae3bd75be5f10ca159d891e0493230d7baa30944d2308dbdd06041238e0cb95dc365be1053d5bd19436b8256a2cdf708f5c259459cb3736404cada00a628f2fc46770e4973224ad97d76a5147384dd3e16251cce841ae28cfd60e8ce343b7d5f21ca2",output:"f91d99738e272665e26f130f4d3a018443f93655196f85d9cbad408f8a88ff01d0e8ab7b6660ba94b1cc985bd11b959472ff275004347f7f218421e88fbfd438612a29359a901eb1dfee4b4d6b5993f0ecea9ebd8913e9bf985105b23053e42d1f4048e7aefd8c7f451ace88ef079908f5f5baac560911723fbbd0d2894d89e1"},
            Test{input:"0beb5b0e748d6f7072c9ab8e37d64b60e8d2ed2975a6afa5d8cb70e9e0b5cc1899f7156f3301c5556836ee93a0fceef50c48bd62530987a52d85be871fa2fc834e9aa4989e692a0f0c8a5683b8a3ea05d859420a73611dd62db7d68670bef4271629e41f666b2d5a31c7c0d1736a31e278db0dd967b3afbc403868456d5e0c06",output:"47c9a78990e79438a304123f4a28115d49d91946873057149071c8321386b55b6b3420e2107fdf90e624c26479421105e9093230355c0c9aa2287245fb6299a937d0fef14e925cd7eea6aec673e3587215f35256921a55b4d3c7012675900cefc63f2a6fd669d0a6f9bad17a7ad751a9c6fcab6ecc0e2240e14f0139b2b88e2c"},
            Test{input:"5064249a043334c538528b92e3ce547be2e9d6ccabfc991f5ffd6d898357bbb3914ec9fff8921eddde91f79bcfe89266ea920063a53ea35a3b6d9e81c8f10cc05620364d55ef73bb509e89610d0100464b82c09d69263d91b2a1e5c0001554eea42c9ea9fb681483dfdfddb0964ee1a4caf8ee5d03668381db1bdc683dbf47d6",output:"318b60f0bfce40f7ba6fa74bdaae99592ed091f5c46eac895cae1df1fa8703f2fe9280d48c6debfea398a18dfefe50ad26a013a24b9fb75e0688e91d8fab00d0c3b4fa94eed0cf2d9fc4cc3d86fea54bbb12826aaf42e4c01cbca1d664c00697f685debd72bbbed74e7b38c614db604e4b4c29a40307d348a999f80dda4f3180"},
            Test{input:"1e009b8d903c7e212b2472a1bf00fe7ee76721b50040e0669e1864cb3ad5994d4590ccdd1f95ec0c0734795ac3313155a2669c4d44d6e14869c453d1467dea720c51e0d7beed6a9ab5d40c089edc1df0b7fea3e8ed98b300c7281b1595b323d378dc09b09fdeefaed3418439ce54ab696f05a3e550b82d0591230143e8c52508",output:"e8252a8dae689af1ad9835a3eafdeacf0c71468897520459373e1ba3a78653899afebb371ccc004043888bc359e85d62771d1715d083cea8967222b23ba84c2e4b79a5e771369f7902ff91bbac00f715a45f9aaac8d90e09e4a567c4a9549cbbdfc31ee65a5ba070688fd3f443d7d936c12dab1fd98a95adc39599f3c927ac37"},
            Test{input:"55e4209d0d2bad7a02d9212f5eeabafc0890b28287ba5c8d030c906effafa6d7cede44e9ac0719d6916d982d277f6a0a674b778e96fd7898f9047c24e7907f8b572a86b9c91ccd7c45b0d49be36d657bd3b76347f3b9ad0722bf7a66136d6109917426d5f8760c319ad5b79e42a3046435a85a3dfe90aac009cb308588b786bf",output:"4c3c5620efd9ed6bc334df2d363e83cc2fb3481847cde40b6592fbf7031220d23fc5e6e8a36d6208cf586ee90acb2bdd5cf2936ceddbbe2b81b9f93bcdc244d2204c01584328c65e6c19dfbc0df8bcc9a22629b835a69c1a4a29492040c7ade2e86010a4624b425d39dc52f7d4889cd57b4ae6049f52d2c7d945e17c9c22573e"},
        ];

        for case in cases {
            let Test { input, output } = case;
            let input = hex::decode(input).unwrap();
            let mut input = {
                let mut out = [0u64; 16];
                for i in 0..16 {
                    out[i] = u64::from_le_bytes(input[i * 8..(i + 1) * 8].try_into().unwrap());
                }
                out
            };
            let [t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15] =
                &mut input;

            blamka_generic(
                t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15,
            );
            let input = {
                let mut out = [0u8; 128];
                for i in 0..16 {
                    out[i * 8..(i + 1) * 8].copy_from_slice(&input[i].to_le_bytes());
                }
                out
            };
            assert_eq!(hex::encode(input), output);
        }
    }
}
