pub fn keccak_f1600(da: &mut [u8; 200]) {
    super::keccakf::keccak_f1600_generic(da);
}
