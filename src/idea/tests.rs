use crate::cipher::BlockCipher;

#[test]
fn test_idea() {
    let mut key = [0u8; 16];
    rand::fill(&mut key);
    let enc = super::Idea::new(&key).unwrap();
    for _ in 0..1000 {
        let mut inout = [0u8; 8];
        rand::fill(&mut inout);
        let mut out = inout;
        enc.encrypt(&mut out);
        enc.decrypt(&mut out);
        assert_eq!(inout, out);
    }
}
