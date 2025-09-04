use hmac::Mac;

use crate::{core::CoreWrite, hash::Hash};

#[test]
fn rustcrypto_hmac_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let this = {
            let mut hmac = crate::hmac::new(crate::sha256::new256, &buf);
            hmac.write_all(buf.as_slice())
                .expect("HMAC write should not fail");
            hmac.sum()
        };

        let rustcrypto = {
            let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&buf).unwrap();
            hmac.update(&buf);
            hmac.finalize().into_bytes().to_vec()
        };

        assert_eq!(this, rustcrypto.as_slice());
    }
}
