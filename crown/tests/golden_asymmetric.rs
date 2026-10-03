//! Golden-vector gate for asymmetric algorithms: X448, Ed448/Ed448ph,
//! ECDH (RFC 5903), ECDSA (RFC 6979), DSA (RFC 6979 A.2.2), SM2 (GM/T),
//! and finite-field DH (MODP-2048).
//!
//! Vectors are lifted from the in-module KATs (cross-checked against the RFCs).

use crown::bn::Bn;
use crown::dh;
use crown::dsa;
use crown::ec::{coord32, coord_padded, curve, mul_base, CurveId};
use crown::ecdh;
use crown::ecdsa::{self, DigestId};
use crown::ed448;
use crown::rsa::Rng;
use crown::sm2;
use crown::x448;

fn h(s: &str) -> Vec<u8> {
    // Match the in-module `bn_hex` helper: drop non-hex chars and left-pad
    // odd-length digit strings with '0' (P-521 RFC 6979 vectors are 131 digits).
    let mut d: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if d.len() % 2 == 1 {
        d.insert(0, '0');
    }
    hex::decode(&d).unwrap()
}

fn bn(s: &str) -> Bn {
    Bn::from_be_bytes(&h(s))
}

fn to56(s: &str) -> [u8; 56] {
    let v = h(s);
    let mut out = [0u8; 56];
    out.copy_from_slice(&v);
    out
}

fn to57(s: &str) -> [u8; 57] {
    let v = h(s);
    let mut out = [0u8; 57];
    out.copy_from_slice(&v);
    out
}

fn to114(s: &str) -> [u8; 114] {
    let v = h(s);
    let mut out = [0u8; 114];
    out.copy_from_slice(&v);
    out
}

/// Deterministic nonce source: feeds a fixed `k` on the first call, then
/// zeros (the in-module tests use the same shape).
struct FixedK {
    k: Vec<u8>,
    used: bool,
}

impl Rng for FixedK {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        if !self.used {
            let n = out.len().min(self.k.len());
            out[..n].copy_from_slice(&self.k[..n]);
            self.used = true;
        } else {
            for b in out.iter_mut() {
                *b = 0;
            }
        }
    }
}

fn fixed_k(k: &Bn, order_bytes: usize) -> FixedK {
    FixedK {
        k: k.to_be_bytes_padded(order_bytes).unwrap(),
        used: false,
    }
}

// X448 — RFC 7748 §5.2 scalar_mult vectors 1-2, §6.2 Diffie-Hellman,
// plus the §5.2 iterative one-iteration vector.

#[test]
fn test_golden_x448() {
    let mut checked = 0usize;

    // RFC 7748 §5.2 vector 1.
    {
        let scalar = to56(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
             700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let u = to56(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
             814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        let expected = h("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
             e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
        // x448(private, peer) == scalar_mult; output is non-zero so Some.
        let out = x448::x448(&scalar, &u).unwrap();
        assert_eq!(&out[..], &expected[..], "RFC 7748 §5.2 vector 1");
        checked += 1;
    }

    // RFC 7748 §5.2 vector 2.
    {
        let scalar = to56(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
             38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        );
        let u = to56(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
             165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        );
        let expected = h("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
             ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d");
        let out = x448::x448(&scalar, &u).unwrap();
        assert_eq!(&out[..], &expected[..], "RFC 7748 §5.2 vector 2");
        checked += 1;
    }

    // RFC 7748 §6.2 Diffie-Hellman.
    {
        let alice_priv = to56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let bob_priv = to56(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
             6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        );
        let alice_pub_expected = h("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
             22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        let bob_pub_expected = h("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
             27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        let shared_expected = h("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
             b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

        let alice_pub = x448::public_from_private(&alice_priv);
        let bob_pub = x448::public_from_private(&bob_priv);
        assert_eq!(&alice_pub[..], &alice_pub_expected[..], "X448 Alice pub");
        assert_eq!(&bob_pub[..], &bob_pub_expected[..], "X448 Bob pub");

        let s1 = x448::x448(&alice_priv, &bob_pub).unwrap();
        let s2 = x448::x448(&bob_priv, &alice_pub).unwrap();
        assert_eq!(&s1[..], &shared_expected[..], "X448 shared secret");
        assert_eq!(s1, s2, "X448 both sides agree");
        checked += 1;
    }

    // RFC 7748 §5.2 iterative: one iteration starting from k = u = 5.
    {
        let mut k = [0u8; 56];
        k[0] = 5;
        let expected = h("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
             4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");
        let out = x448::x448(&k, &k).unwrap();
        assert_eq!(&out[..], &expected[..], "RFC 7748 §5.2 iterative one");
        checked += 1;
    }

    assert!(checked >= 3, "only {checked} X448 vectors verified");
}

// Ed448 — RFC 8032 §7.4 (pure) + §7.5 (Ed448ph)

#[test]
fn test_golden_ed448() {
    let mut checked = 0usize;

    // RFC 8032 §7.4 blank message.
    {
        let secret = to57(concat!(
            "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3",
            "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
        ));
        let public = to57(concat!(
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778",
            "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
        ));
        let msg: Vec<u8> = Vec::new();
        let context = b"";
        let expected = to114(concat!(
            "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f",
            "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a",
            "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db",
            "b61149f05a7363268c71d95808ff2e652600"
        ));

        assert_eq!(ed448::public_from_secret(&secret), public);
        let sig = ed448::sign(&secret, &msg, context);
        assert_eq!(sig[..], expected[..], "RFC 8032 §7.4 blank");
        assert!(ed448::verify(&public, &sig, &msg, context));
        checked += 1;
    }

    // RFC 8032 §7.4 1 octet.
    {
        let secret = to57(concat!(
            "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a",
            "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
        ));
        let public = to57(concat!(
            "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086",
            "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
        ));
        let msg = h("03");
        let context = b"";
        let expected = to114(concat!(
            "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435",
            "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb",
            "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f",
            "f3348ab21aa4adafd1d234441cf807c03a00"
        ));

        assert_eq!(ed448::public_from_secret(&secret), public);
        let sig = ed448::sign(&secret, &msg, context);
        assert_eq!(sig[..], expected[..], "RFC 8032 §7.4 1-octet");
        assert!(ed448::verify(&public, &sig, &msg, context));
        checked += 1;
    }

    // RFC 8032 §7.4 1 octet with context "foo".
    {
        let secret = to57(concat!(
            "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a",
            "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
        ));
        let public = to57(concat!(
            "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086",
            "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
        ));
        let msg = h("03");
        let context = h("666f6f");
        let expected = to114(concat!(
            "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2",
            "151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da",
            "1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d",
            "5428407e85dcbc98a49155c13764e66c3c00"
        ));

        assert_eq!(ed448::public_from_secret(&secret), public);
        let sig = ed448::sign(&secret, &msg, &context);
        assert_eq!(sig[..], expected[..], "RFC 8032 §7.4 1-octet ctx");
        assert!(ed448::verify(&public, &sig, &msg, &context));
        checked += 1;
    }

    // RFC 8032 §7.4 11 octets.
    {
        let secret = to57(concat!(
            "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffd",
            "f60500553abc0e05cd02184bdb89c4ccd67e187951267eb328"
        ));
        let public = to57(concat!(
            "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e3",
            "65fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400"
        ));
        let msg = h("0c3e544074ec63b0265e0c");
        let context = b"";
        let expected = to114(concat!(
            "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d3",
            "89dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b05",
            "1068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5",
            "028961c9bf8ffd973fe5d5c206492b140e00"
        ));

        assert_eq!(ed448::public_from_secret(&secret), public);
        let sig = ed448::sign(&secret, &msg, context);
        assert_eq!(sig[..], expected[..], "RFC 8032 §7.4 11-octet");
        assert!(ed448::verify(&public, &sig, &msg, context));
        checked += 1;
    }

    // RFC 8032 §7.5 Ed448ph — TEST abc, empty context.
    {
        let secret = to57(concat!(
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49"
        ));
        let public = to57(concat!(
            "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743",
            "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880"
        ));
        let msg = b"abc";
        let context = b"";
        let expected = to114(concat!(
            "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae38",
            "1f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd",
            "433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3",
            "ad203df7dc7ce360c3cd3696d9d9fab90f00"
        ));

        assert_eq!(ed448::public_from_secret(&secret), public);
        let ph = ed448::prehash(msg);
        let sig = ed448::sign_ph(&secret, &ph, context);
        assert_eq!(sig[..], expected[..], "RFC 8032 §7.5 blank ctx");
        assert!(ed448::verify_ph(&public, &sig, &ph, context));
        checked += 1;
    }

    // RFC 8032 §7.5 Ed448ph — TEST abc, context "foo".
    {
        let secret = to57(concat!(
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49"
        ));
        let public = to57(concat!(
            "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743",
            "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880"
        ));
        let msg = b"abc";
        let context = b"foo";
        let expected = to114(concat!(
            "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa48",
            "1065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3",
            "653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab7128",
            "4f8d0704a608c54a6b62d97beb511d132100"
        ));

        assert_eq!(ed448::public_from_secret(&secret), public);
        let ph = ed448::prehash(msg);
        let sig = ed448::sign_ph(&secret, &ph, context);
        assert_eq!(sig[..], expected[..], "RFC 8032 §7.5 foo ctx");
        assert!(ed448::verify_ph(&public, &sig, &ph, context));
        // Context must match.
        assert!(!ed448::verify_ph(&public, &sig, &ph, b""));
        assert!(!ed448::verify_ph(&public, &sig, &ph, b"bar"));
        checked += 1;
    }

    assert!(checked >= 6, "only {checked} Ed448 vectors verified");
}

// ECDH — RFC 5903 §8.1/8.2/8.3 (P-256 / P-384 / P-521)

#[test]
fn test_golden_ecdh() {
    let mut checked = 0usize;

    // RFC 5903 §8.1 — P-256.
    {
        let i = bn("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        let r = bn("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
        let gix = bn("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180");
        let giy = bn("5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3");
        let grx = bn("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63");
        let gry = bn("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");
        let shared = bn("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

        let c = curve(CurveId::P256);
        let pub_i = mul_base(&c, &i);
        let pub_r = mul_base(&c, &r);
        assert_eq!(coord32(&pub_i.x), coord32(&gix), "P-256 gix");
        assert_eq!(coord32(&pub_i.y), coord32(&giy), "P-256 giy");
        assert_eq!(coord32(&pub_r.x), coord32(&grx), "P-256 grx");
        assert_eq!(coord32(&pub_r.y), coord32(&gry), "P-256 gry");

        let s1 = ecdh::agree(CurveId::P256, &i, &pub_r).unwrap();
        let s2 = ecdh::agree(CurveId::P256, &r, &pub_i).unwrap();
        assert_eq!(s1, s2, "P-256 both sides agree");
        assert_eq!(s1.len(), 32);
        assert_eq!(s1, coord32(&shared).to_vec(), "RFC 5903 P-256 girx");
        checked += 1;
    }

    // RFC 5903 §8.2 — P-384.
    {
        let i = bn(
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655\
             E35B538041E649EE3FAEF896783AB194",
        );
        let r = bn(
            "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942\
             E0308312916B8ED2960E4BD55A7448FC",
        );
        let shared = bn(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4\
             D603135569B9E9D09CF5D4A270F59746",
        );

        let c = curve(CurveId::P384);
        let pub_i = mul_base(&c, &i);
        let pub_r = mul_base(&c, &r);
        assert!(!pub_i.is_infinity() && !pub_r.is_infinity());

        let s1 = ecdh::agree(CurveId::P384, &i, &pub_r).unwrap();
        let s2 = ecdh::agree(CurveId::P384, &r, &pub_i).unwrap();
        assert_eq!(s1, s2, "P-384 both sides agree");
        assert_eq!(s1.len(), 48);
        assert_eq!(s1, coord_padded(&shared, 48), "RFC 5903 P-384 girx");
        checked += 1;
    }

    // RFC 5903 §8.3 — P-521.
    {
        let i = bn(
            "0037ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A0\
             95AA85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D\
             4A52",
        );
        let r = bn(
            "0145BA99A847AF43793FDD0E872E7CDFA16BE30FDC780F97BCCC3F078380201E\
             9C677D600B343757A3BDBF2A3163E4C2F869CCA7458AA4A4EFFC311F5CB15168\
             5EB9",
        );
        let shared = bn(
            "01144C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04\
             D1427E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3\
             DDEA",
        );

        let c = curve(CurveId::P521);
        let pub_i = mul_base(&c, &i);
        let pub_r = mul_base(&c, &r);
        assert!(!pub_i.is_infinity() && !pub_r.is_infinity());

        let s1 = ecdh::agree(CurveId::P521, &i, &pub_r).unwrap();
        let s2 = ecdh::agree(CurveId::P521, &r, &pub_i).unwrap();
        assert_eq!(s1, s2, "P-521 both sides agree");
        assert_eq!(s1.len(), 66);
        assert_eq!(s1, coord_padded(&shared, 66), "RFC 5903 P-521 girx");
        checked += 1;
    }

    assert!(checked >= 3, "only {checked} ECDH vectors verified");
}

// ECDSA — RFC 6979 A.2.5 (P-256), A.2.6 (P-384), A.2.7 (P-521)

#[test]
fn test_golden_ecdsa() {
    let mut checked = 0usize;

    // A.2.5 P-256 SHA-256, message "sample".
    {
        let d = bn("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let k = bn("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
        let expect_r = bn("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let expect_s = bn("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

        let msg = b"sample";
        let mut rng = fixed_k(&k, 32);
        let (r, s) = ecdsa::sign_sha256(&d, msg, &mut rng).unwrap();
        assert_eq!(coord32(&r), coord32(&expect_r), "P-256 sample r");
        assert_eq!(coord32(&s), coord32(&expect_s), "P-256 sample s");

        let c = curve(CurveId::P256);
        let pub_key = mul_base(&c, &d);
        assert!(ecdsa::verify_sha256(&pub_key, msg, &r, &s).unwrap());
        assert!(!ecdsa::verify_sha256(&pub_key, b"taste", &r, &s).unwrap());
        checked += 1;
    }

    // A.2.5 P-256 SHA-256, message "test".
    {
        let d = bn("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let k = bn("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0");
        let expect_r = bn("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367");
        let expect_s = bn("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");

        let msg = b"test";
        let mut rng = fixed_k(&k, 32);
        let (r, s) = ecdsa::sign_sha256(&d, msg, &mut rng).unwrap();
        assert_eq!(coord32(&r), coord32(&expect_r), "P-256 test r");
        assert_eq!(coord32(&s), coord32(&expect_s), "P-256 test s");

        let c = curve(CurveId::P256);
        let pub_key = mul_base(&c, &d);
        assert!(ecdsa::verify_sha256(&pub_key, msg, &r, &s).unwrap());
        checked += 1;
    }

    // A.2.6 P-384 SHA-384, message "sample".
    {
        let d = bn(
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8\
             96D5724E4C70A825F872C9EA60D2EDF5",
        );
        let k = bn(
            "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA\
             2907E3E83BA95368623B8C4686915CF9",
        );
        let expect_r = bn(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\
             81A648152E44ACF96E36DD1E80FABE46",
        );
        let expect_s = bn(
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F\
             A329C145786E679E7B82C71A38628AC8",
        );

        let msg = b"sample";
        let mut rng = fixed_k(&k, 48);
        let (r, s) = ecdsa::sign(CurveId::P384, DigestId::Sha384, &d, msg, &mut rng).unwrap();
        let padded_r = r.to_be_bytes_padded(48).unwrap();
        let padded_s = s.to_be_bytes_padded(48).unwrap();
        assert_eq!(
            padded_r,
            expect_r.to_be_bytes_padded(48).unwrap(),
            "P-384 sample r"
        );
        assert_eq!(
            padded_s,
            expect_s.to_be_bytes_padded(48).unwrap(),
            "P-384 sample s"
        );

        let c = curve(CurveId::P384);
        let pub_key = mul_base(&c, &d);
        assert!(ecdsa::verify(CurveId::P384, DigestId::Sha384, &pub_key, msg, &r, &s).unwrap());
        assert!(
            !ecdsa::verify(CurveId::P384, DigestId::Sha384, &pub_key, b"taste", &r, &s).unwrap()
        );
        checked += 1;
    }

    // A.2.7 P-521 SHA-512, message "sample".
    {
        let d = bn(
            "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C\
             AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83\
             538",
        );
        let k = bn(
            "1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F1019\
             8B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBF\
             FD3",
        );
        let expect_r = bn(
            "0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1\
             74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37\
             7FA",
        );
        let expect_s = bn(
            "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2\
             82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A\
             67A",
        );

        let msg = b"sample";
        let mut rng = fixed_k(&k, 66);
        let (r, s) = ecdsa::sign(CurveId::P521, DigestId::Sha512, &d, msg, &mut rng).unwrap();
        let padded_r = r.to_be_bytes_padded(66).unwrap();
        let padded_s = s.to_be_bytes_padded(66).unwrap();
        assert_eq!(
            padded_r,
            expect_r.to_be_bytes_padded(66).unwrap(),
            "P-521 sample r"
        );
        assert_eq!(
            padded_s,
            expect_s.to_be_bytes_padded(66).unwrap(),
            "P-521 sample s"
        );

        let c = curve(CurveId::P521);
        let pub_key = mul_base(&c, &d);
        assert!(ecdsa::verify(CurveId::P521, DigestId::Sha512, &pub_key, msg, &r, &s).unwrap());
        assert!(
            !ecdsa::verify(CurveId::P521, DigestId::Sha512, &pub_key, b"taste", &r, &s).unwrap()
        );
        checked += 1;
    }

    assert!(checked >= 4, "only {checked} ECDSA vectors verified");
}

// DSA — RFC 6979 A.2.2 (DSA 2048-bit, SHA-256)

#[test]
fn test_golden_dsa() {
    let mut checked = 0usize;

    // A.2.2 — message "sample".
    {
        let params = dsa::dsa_2048_256();
        let x = bn("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC");
        let expect_y = bn(
            "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94\
             9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61\
             1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE\
             CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB\
             5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254\
             687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1\
             23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA\
             74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF",
        );
        let y = params.g.mod_pow_odd_consttime(&x, &params.p).unwrap();
        assert!(!y.is_zero());
        assert_eq!(
            y.to_be_bytes_padded(256).unwrap(),
            expect_y.to_be_bytes_padded(256).unwrap(),
            "published y"
        );

        let k = bn("8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52");
        let expect_r = bn("EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809");
        let expect_s = bn("7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53");

        let key = dsa::DsaKeyPair {
            params: params.clone(),
            x: x.clone(),
            y,
        };
        let msg = b"sample";
        let mut rng = fixed_k(&k, 32);
        let (r, s) = dsa::sign_sha256(&key, msg, &mut rng).unwrap();
        assert_eq!(
            r.to_be_bytes_padded(32).unwrap(),
            expect_r.to_be_bytes_padded(32).unwrap(),
            "DSA sample r"
        );
        assert_eq!(
            s.to_be_bytes_padded(32).unwrap(),
            expect_s.to_be_bytes_padded(32).unwrap(),
            "DSA sample s"
        );
        assert!(dsa::verify_sha256(&params, &key.y, msg, &r, &s).unwrap());
        assert!(!dsa::verify_sha256(&params, &key.y, b"taste", &r, &s).unwrap());
        checked += 1;
    }

    // A.2.2 — message "test".
    {
        let params = dsa::dsa_2048_256();
        let x = bn("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC");
        let y = params.g.mod_pow_odd_consttime(&x, &params.p).unwrap();
        let k = bn("1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7");
        let expect_r = bn("8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0");
        let expect_s = bn("7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E");

        let key = dsa::DsaKeyPair {
            params: params.clone(),
            x,
            y,
        };
        let msg = b"test";
        let mut rng = fixed_k(&k, 32);
        let (r, s) = dsa::sign_sha256(&key, msg, &mut rng).unwrap();
        assert_eq!(
            r.to_be_bytes_padded(32).unwrap(),
            expect_r.to_be_bytes_padded(32).unwrap(),
            "DSA test r"
        );
        assert_eq!(
            s.to_be_bytes_padded(32).unwrap(),
            expect_s.to_be_bytes_padded(32).unwrap(),
            "DSA test s"
        );
        assert!(dsa::verify_sha256(&params, &key.y, msg, &r, &s).unwrap());
        checked += 1;
    }

    assert!(checked >= 2, "only {checked} DSA vectors verified");
}

// SM2 — GM/T 0003.5 sample + sign/verify roundtrip

#[test]
fn test_golden_sm2() {
    let mut checked = 0usize;

    // GM/T 0003.5 sample: d, M = "message digest", ID = "1234567812345678".
    {
        let d = bn("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let k = bn("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
        let msg = b"message digest";

        let c = sm2::sm2_curve();
        let pub_key = mul_base(&c, &d);
        let expect_x = bn("09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020");
        let expect_y = bn("CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13");
        assert_eq!(coord32(&pub_key.x), coord32(&expect_x), "SM2 Px");
        assert_eq!(coord32(&pub_key.y), coord32(&expect_y), "SM2 Py");

        let mut rng = FixedK {
            k: k.to_be_bytes_padded(32).unwrap(),
            used: false,
        };
        let (r, s) = sm2::sign_default_id(&d, msg, &mut rng).unwrap();

        let expect_r = bn("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3");
        let expect_s = bn("B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA");
        assert_eq!(coord32(&r), coord32(&expect_r), "SM2 r");
        assert_eq!(coord32(&s), coord32(&expect_s), "SM2 s");

        assert!(sm2::verify_default_id(&pub_key, msg, &r, &s).unwrap());
        assert!(!sm2::verify_default_id(&pub_key, b"other", &r, &s).unwrap());
        checked += 1;
    }

    // Sign/verify roundtrip with a deterministic nonce.
    // (In-module test is roundtrip-only; no published vector.)
    {
        struct CounterRng(u64);
        impl Rng for CounterRng {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (self.0 >> 33) as u8;
                }
            }
        }
        let mut rng = CounterRng(0x0bad_c0de_0bad_c0de);
        let c = sm2::sm2_curve();
        let d = bn("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
        let pub_key = mul_base(&c, &d);
        let msg = b"sm2 roundtrip message";
        let (r, s) = sm2::sign_default_id(&d, msg, &mut rng).unwrap();
        assert!(sm2::verify_default_id(&pub_key, msg, &r, &s).unwrap());
        assert!(!sm2::verify_default_id(&pub_key, b"tampered", &r, &s).unwrap());
        checked += 1;
    }

    assert!(checked >= 1, "only {checked} SM2 vectors verified");
}

// DH MODP-2048 — roundtrip + range rejects.
// In-module tests are roundtrip-only (no published shared-secret vector).

#[test]
fn test_golden_dh_modp2048() {
    struct CounterRng(u64);
    impl Rng for CounterRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    let mut checked = 0usize;

    // MODP-2048 parameter sanity (RFC 3526).
    {
        let (p, g) = dh::modp2048();
        assert_eq!(p.bit_len(), 2048);
        assert!(p.is_odd());
        assert!(g.is_one() || g == Bn::from_u64(2));
        let pmod8 = p.modulus(&Bn::from_u64(8));
        assert_eq!(pmod8, Bn::from_u64(7), "RFC 3526 p ≡ 7 (mod 8)");
        checked += 1;
    }

    // Generate + agree roundtrip.
    {
        let (p, g) = dh::modp2048();
        let mut rng = CounterRng(0x0123_4567_89ab_cdef);
        let (x1, y1) = dh::generate(&p, &g, &mut rng).unwrap();
        let (x2, y2) = dh::generate(&p, &g, &mut rng).unwrap();
        let s1 = dh::agree(&p, &x1, &y2).unwrap();
        let s2 = dh::agree(&p, &x2, &y1).unwrap();
        assert_eq!(s1, s2, "DH both sides agree");
        checked += 1;
    }

    // Trivial public values must be rejected.
    {
        let (p, g) = dh::modp2048();
        let mut rng = CounterRng(1);
        let (x, _y) = dh::generate(&p, &g, &mut rng).unwrap();
        assert!(dh::agree(&p, &x, &Bn::zero()).is_err(), "reject y=0");
        assert!(dh::agree(&p, &x, &Bn::one()).is_err(), "reject y=1");
        let pm1 = p.sub(&Bn::one()).unwrap();
        assert!(dh::agree(&p, &x, &pm1).is_err(), "reject y=p-1");
        checked += 1;
    }

    assert!(checked >= 2, "only {checked} DH cases verified");
}

// RSA PKCS#1 v1.5 signatures over the newly supported digest set,
// generated with the OpenSSL CLI (system 3.0.13 for the SHA-2/SHA-3/
// RIPEMD-160/MD5-SHA1 cases, a locally built 3.5.8 for SM3). PKCS#1 v1.5
// is deterministic, so the same bytes assert both verify and sign parity.
// Note: OpenSSL's RSA-SM3 DigestInfo uses the sm3WithRSAEncryption OID
// (see the digestinfo_prefix comment in crown/src/rsa/mod.rs).

#[test]
fn test_golden_rsa_new_digests() {
    use crown::kdf::HashFactory;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    let key_der = include_bytes!("data/rsa2048_new_digests_pkcs8.der");
    let (n, e, d, p, q, dp, dq, qinv) =
        crown::rsa::der::parse_pkcs8_rsa_private_key(key_der).unwrap();
    let key = crown::rsa::RsaPrivateKey::from_components(
        &n,
        &e,
        &d,
        Some(&p),
        Some(&q),
        Some(&dp),
        Some(&dq),
        Some(&qinv),
    )
    .unwrap();
    let public =
        crown::rsa::RsaPublicKey::from_components(&key.public().n(), &key.public().e()).unwrap();

    const MSG: &[u8] = b"crown parity vectors";

    let cases: &[(&str, HashFactory, &str)] = &[
        (
            "sha512-224",
            crown::envelope::EvpHash::new_sha512_224,
            "434ba96f7092c7fda4440caef90abea34208670951b3df3440289f44cb28ca1500379679e566e1f37dda1d7348ea3738c6553871201ea4198dd7d3232c3117ff2bece58ba2b2546992c976349c9ae53251630d4e47443fbf4a98525c362180c58f5eac8f84162bcc3e8c2d4e748d5a0365f317f5255917957a36d23a047ac09a0a747aaad312874543253176ae4b6ba827eebbefa3e1906dd6f3d4e045e0b5da8e70600a965ab5087c96d95d0982f84b95e71ee47409001b14e0644cf98ded514c89044b94fa0a6e013721411095320989d4d0050764ea122d7dde0893d6b26142a2bd95f04b13f0859b683e6f100b93d14afe1bf844aba27e0322f23a6654ca",
        ),
        (
            "sha512-256",
            crown::envelope::EvpHash::new_sha512_256,
            "7e28c4f10a934678b162ae7a4dd134bf93bb317497bab3d221833e6977b9e077bf9f01ba362235fd85448a53bbee83ffbe148829a0fcd655b688599c56c10be961863bc2ed09b16dc453f146dfcc6ed3095a0ec108605e46d28ff84370b023b6a05810383a0b5085fa08f20d8709782460bce652fc815d9508b932c87a0fc2411fbaed1e809fb9e8c3abb2f7bef58a83516a0ce32dfca0c9377291bae687dd75cdd0ae758923ba8e4102d787318b1908d7745708be7403e49df6a888be4f0878fad5a4839ce082c77e9b951f9e99886362b87b0901fd8317c10901b27d5cc379b079b5efc1da56dabe0210a674633b32aa33346be38c59552203987519acefe3",
        ),
        (
            "sha3-224",
            crown::envelope::EvpHash::new_sha3_224,
            "05626628f10c424cde7c9630d245142aaf99596cea35432bb19308fc273c728f23e6720fdd2075a227b21110e348ffdd90f2a57d1d7f8e1ed9374b90ef8200b31c1317bcddd65bab4f1e684b4b09a2b787da48ed853f24179c06f46705875220c4b2d80a416372d400584439345ce4b16f7199de7b1a378d07936e058520bace9a66b5864f9955cd80ad4640cce9294383b4b0f1b60fb8aa8a89c41084820d42317a284c901cf0653456aa8f1864a2c0a53076fd172f6d013aad387f0aa482f6dcfebb1420321876fc4fbc2616aefbb961b2c241e4aac38449ae1a994926685d45c811d4f17a5a66b1be5e60c186e667fdd71d66bf807ca0b0b5d4cd9000315f",
        ),
        (
            "sha3-256",
            crown::envelope::EvpHash::new_sha3_256,
            "536af67d89e40431167ad38109b8aa012fed453b5cb5e5680b80ee5dee8e7ca7f58e98899aafcc8cd6ebec3452bccf6fbda07beb7dc248cf149e15a19c8f62c14e7013da4b33d57469f2d4303d7842c0221055e620b3ae20aa37ffdb356259d1002162e9e6af915e20ab74c8ec0962d30d4bd66bd432348ba55bc08d5eb8eaf2db97e61905c06aa1444c7cbdb990927c07710e296c1658d8ff583e55e2e2291d8a785c2405e5d3395e9b6662c69538d659ed7e035a881928afddbb0ffeef8eb718076d7515e0980eca8c5ae5f6da76fd1d341ac388616edd03e25960ba7b01532652d7b5315d0d4b5248a954da5a6b1d083532e94dc63e1fa8c2eeae2c8e0f40",
        ),
        (
            "sha3-384",
            crown::envelope::EvpHash::new_sha3_384,
            "6844bf91ce570587696cd6330000a75cfe27a3ae4302a2bf911ab7c65ef261536b949ee782490eb4a675556f95b3c991db8f7c29bc950ad1b15a4a6c6c25c6a2c2b204044bb2e5664138b0576a1048db034b559bfcd0b7bd49fd1cf50a46c91b66e0936681af728382575e579089824e1c9c43472fe0b38345aa352649021b8d535b797eabd8f6c21b168de54964d812ac16bda49a61b1f58aed11964067fa1e0251d926b53ec288920c7fcf48726aebb5ba508b16c4b64532c3724fef88001d267f503aa08011b8573a477c7fb340533c6ff3701cc9b4b0c78e0be8a7f255176b45120cc868aec60e9b954541bfce603e9f726a597cbb83a92cc3f6f59486c3",
        ),
        (
            "sha3-512",
            crown::envelope::EvpHash::new_sha3_512,
            "197d32a971e5778f56d5a662764dfc0dd6d37f8b4be30b6af73a0e399e94cf6b87b3093bd63afb90b8a7d0e07b669556236dfd299d513ba7cc16bd216d14e15ed9549bb74888b7fac14f54b91d4543eef0785bfc6fb0379ab15b6440efe527ea3d361a84490dd775a2da91848a65fa9925eff85622fdcfd99944486dfe07ad6e8d93eda594d3c464d8eb22ebfc528866c57849c15017d4c91022ca3a716bddcf7e28edd0829729feb710f9f485284a13258d229c9d953889df6df277bc96e3bc89dec5b18ee35a57cea583d3febf920663bdea011baa89b7ff17b247c54e57274c58e1bb2771013a8173f0f35819b62bb2e18989d6c610bd0508d1180b636b39",
        ),
        (
            "sm3",
            crown::envelope::EvpHash::new_sm3,
            "55cf66e688f6eaf6ab81f6493bb0b17d6eb45632a80372a88c27c944c9bae242b38bf393fab6016e351fa2c03a0c4a34638b953db76416dc5f216dfec8a21e5b78bf14a12eba083c9f4ecc44e700e191604717ebb7cf769e56a440606c2b3fa074df84573c49258a0f5d0558a0491b7b14c4643d3071d50b32002574a75b6e587596b121221cf505c2a5d1f6dbe37e2c592687b6bdbdc268fee3a011cb5a18ae1487f14d2483b4bf49273414876d358f6d7edacd9cb7a8615a2b6d920f13fc8961ea1e36a38b193061477e999743a19af7e4fbca407e5bd0de09939b3e530a5818564c4c97b8169b495107cafe9fc863493077e32cba04e8487c5d4af65d2400",
        ),
        (
            "ripemd160",
            crown::envelope::EvpHash::new_ripemd160,
            "00fd6cb42f96976e0e85fa8939cd14a76ceec051f3c8d1f4811f7839338bb94967c80c95e089d30d8887facd02d3b146bb2676f21d391c991e5b1b961aa7c1990df4076df52da2920951b5086ebf2005bd9d89d0c4682bad0d07be16945a4f546e8a99d3516b6bcbf85b4ed2028d45f3d6199ee1e4f79fea5620e82a976a2c60db7c950700f09908e4afff6827fc1688d76326ca6fd4c316cfe41dddb2327295a5739ca28c8f3a3176734bf1729dc0b33e54a548376a7711b945384785d5dd103c26b01addb3246e46228a806cd57386aa17553e6a3b7974a9846d9983e997ffc473e30f1bdb3e025b64880e6c406ff3407e3ae1f9d74c5310813e30712a349d",
        ),
        (
            "md5-sha1",
            crown::envelope::EvpHash::new_md5_sha1,
            "5e0ffddc2effa7ebd138f2dc988c980b92faa06e01ac3d200d3bef92a5b46899ee2221412da5e523efe66d2271069afb2bfbade1019e1d0ed42e630b038fab98d22fd7c9fccca2b26b4fb05876f6ea6c49380ca06da4bbdbb0673b9d6238762f2b1d41583c7597331d02a4bf1db60dd241ad030c30d26318e2295f616f28fd16d1cb4b8a8b85bd6d1afd4a8b2660dbbfd2edce435d56e68dd44df848705b6f62be736e954806cf9c8539c9893a9ed90c330b44ab2c463bdf4f1d19b32dee3959bea6d30643be94e811b1328e5c75bab0bffa9a119386ea2d3bbb177b737851548a2e7aca67678eccda0468f785f8a5786bb1bcaffeda295484dbdee45967eb9b",
        ),
    ];

    let mut checked = 0usize;
    for (name, hash, sig_hex) in cases {
        let sig = hex(sig_hex);
        assert!(
            public.verify_pkcs1v15(*hash, MSG, &sig).unwrap(),
            "{name} verify"
        );
        // Deterministic: crown's signing must reproduce OpenSSL's bytes.
        let ours = key.sign_pkcs1v15(*hash, MSG).unwrap();
        assert_eq!(ours, sig, "{name} sign parity");
        checked += 1;
    }
    assert!(checked >= 9, "only {checked} RSA digest vectors verified");
}

// ECDSA/DSA signatures with the extended digest set (SHA-1, SHA-224,
// SHA-3, SM3, RIPEMD-160), generated with the OpenSSL CLI. ECDSA/DSA are
// randomized, so these pin the verify direction; the sign direction is
// pinned by crown-sign → openssl-verify cross-checks run while generating
// these vectors (all Verified OK).

#[test]
fn test_golden_ecdsa_dsa_new_digests() {
    use crown::ec::CurveId;
    use crown::ecdsa::{self, DigestId};

    fn bn(s: &str) -> Bn {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Bn::from_be_bytes(&bytes)
    }
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    /// Decode a DER ECDSA/DSA signature SEQUENCE{r,s}.
    fn parse_sig(der: &[u8]) -> (Bn, Bn) {
        let mut top = crown::rsa::der::Parser::new(der);
        let mut seq = top.read_sequence().unwrap();
        let r = seq.read_integer().unwrap();
        let s = seq.read_integer().unwrap();
        (Bn::from_be_bytes(&r), Bn::from_be_bytes(&s))
    }

    let msg = b"crown parity vectors";
    let mut checked = 0usize;

    // ECDSA P-256 with a fixed OpenSSL-generated key.
    let d = bn("4d6f13b188950e94da8aae3f02fdab9636a07246fe3e9832115bc777c08a9e13");
    let c = curve(CurveId::P256);
    let pub_key = mul_base(&c, &d);
    let ec_cases: Vec<(&str, DigestId, &str)> = vec![
        ("sha224", DigestId::Sha224, "30440220391242bd524a98129e949a66d0412148589817ae64e049148acd58f115e28e7102204628cec0fea8da352d0bc483ba6a410460aad0adb20a2f1a38255984a0cdaaa1"),
        ("sha3-256", DigestId::Sha3_256, "3046022100805c483a894f9c821c22afbb75ed8a42b8d252bb0536d7dde306a4bfdaa1ad66022100ef8c8c65bff9eea3f87afa5e934c6b5b9d9ba9ee948f8da3dd89441f06f64aed"),
        ("sm3", DigestId::Sm3, "304402204aa6ae019e40f8d1e0f31cf7076ecabbc651e60123b69aa0de9055bb99dfd75b02203750ee49807e8e193d54c02a814a24715d75fedc34db5a845d14bdb3042810f4"),
        ("ripemd160", DigestId::Ripemd160, "3044022001a3a10d0e786e301744ec437d57da4972903d4e589d8bb9f6b42d43bcc8754202203daab8b11302dcc97f9462500736e4d4204b92803e64c60370b82b02be8465d5"),
        ("sha1", DigestId::Sha1, "3046022100fa5877ea40017e971c5e88ecaa7d26ba087333ca5426d47e82f4a692399a77040221008e833073c7ea4ac7ac6867714bdc8bb8b3a8f7d80fda6b04ac780b89a47da204"),
    ];
    for (name, hash, sig_hex) in &ec_cases {
        let (r, s) = parse_sig(&hex(sig_hex));
        assert!(
            ecdsa::verify(CurveId::P256, *hash, &pub_key, msg, &r, &s).unwrap(),
            "ecdsa {name}"
        );
        checked += 1;
    }

    // DSA 2048/256 with a fixed OpenSSL-generated key.
    let params = dsa::DsaParams {
        p: bn("00db9fe1845242d3e1adfc314b62cde5d29b2f0a461a8f25bf66692fd62c8855e1d07909c8b450e601d59ce5da67a1440e7de57264e62b999e9417ce33a25aaa0b0b196f4db3a76809950897e7c3d0a6eda46ab24cf25d997534471874a592db457a7c7465dd6c93bb158238071441414edcb0725a22ad0eb3e106655f304285bc08c3c69b0623c2b927c5711d51c7039b343c51ab6add401039db8a7977f15291d451045e4ca54494754b909fcfb043a5f1f34328384840af3c1629b1dcd53fc8eedd9e5923c3369434f52eddbbb7da87b2e110c8f9aad50d678e5f00a14e194d76d19ba2b2489b7ce0f337c7270866c64d08a45450d066ebd17aeca7c0050bb7"),
        q: bn("00df3c19f2c10e82fcd2a3376e163d5a397dc91d5bd633ccd046d8688f"),
        g: bn("00b70beb3df15d4b0b322bace46b8d57a32f482a81058b03c495fd0db972fdabd9175208588966453d07c8a6b77e0f167eb9f5f8bcc41476cc2f728fce5be6f29fbe16d30d498afea1a28697e190dc6782515252927ac04f72fcbbe9d1bc31f554dc9acab32d672e424e7e668238f9b4a4afc8cee1f8c0609cc7416f5cc3959fd0c30222db4246298281f8b75c6186f92191cc17a25c5b70d79d4dc55dbd0fcf93cb26447c876746f49308b611e16578fc005c25a2a2b7a1cd5d310b3a95414e7ec4fec38d841f4034b81d95fa44864cb6b6738c98f84ddeae3f9a5be6d313ad419c8cba4b2b17b9a1eb4d64dd544bc768b335ae00424c8bb33edddf98672846cf"),
    };
    let y = bn("46b8e820974605a7f2717a393ecf938c3dd3fc07019178406dab291aea304ecc373f95226fee8135453fb1d60d2fc7f2624507de68343ff6f28e764fe90f1e61a1b733ba5f9183570e8578e246446305033648c344ba31033df8b4b53cb5b19a72750524a0d262acc51c1903ac8291e9e726360c6f1de7b057dbbc15c96c6ea6b17b5d0ac3e05bd9ac092b494e88f24a3d8c5fabee0cb7727615b48731e631472854a2f4989c42063b6a12bcb1cd37a141fb2d3420ddee15e2ae6549e21d20083b0e35a5773b63f768596c09946b7b16ec4388f87108e499ff6ed9790a317ff143792f432955b0b1795ebdb864ffe7e38b8d134aaf435748c90a7c963afd07ae");
    let dsa_cases: Vec<(&str, DigestId, &str)> = vec![
        ("sha224", DigestId::Sha224, "303c021c5dd99d4ace017585c086a8400cce40f9c64a9978d15fefc72a41ddd8021c59aed4a36c50c3298623027ad842b0087f6858ce3ea6983745c0f0f1"),
        ("sha3-256", DigestId::Sha3_256, "303e021d00cc3b11adc7a7825bf2ead642def0caf03e4a219ae2fc3c6f3fc7eba2021d00859b8ba0d5de8bc221d412926d6e900e873c7243d0cdcdad5017c019"),
    ];
    for (name, hash, sig_hex) in &dsa_cases {
        let (r, s) = parse_sig(&hex(sig_hex));
        assert!(
            dsa::verify(&params, &y, *hash, msg, &r, &s).unwrap(),
            "dsa {name}"
        );
        checked += 1;
    }
    assert!(
        checked >= 7,
        "only {checked} ECDSA/DSA digest vectors verified"
    );
}
