# ml_dsa_ntt-x86_64.pl — porting notes

## Source

- Perl: `crypto/ml_dsa/asm/ml_dsa_ntt-x86_64.pl` from OpenSSL **master**
  (the vendored 3.5.8 reference tree predates the script).
- C consumers: `crypto/ml_dsa/ml_dsa_ntt.c` (`ml_dsa_poly_ntt`,
  `ml_dsa_poly_ntt_inverse`, `ml_dsa_poly_ntt_mult`).
- Exports: `ml_dsa_ntt_avx2_capable`, `ml_dsa_poly_ntt_avx2`,
  `ml_dsa_poly_ntt_inverse_avx2`, `ml_dsa_poly_ntt_mult_avx2`.

## Build (frozen perl output)

Unlike the other asm modules, this port embeds the post-xlate AT&T output
verbatim in `crown/src/ml_dsa/ntt_x86_64.ts` instead of re-running the
perl translation, because the upstream script is not part of the vendored
reference tree. Regenerate with:

```bash
cp ml_dsa_ntt-x86_64.pl /home/loongtao/crown-ref/openssl/crypto/ml_dsa/asm/
cd /home/loongtao/crown-ref/openssl/crypto/ml_dsa/asm
CC=gcc perl ml_dsa_ntt-x86_64.pl elf > /tmp/ml_dsa_ntt.s
# then replace the body of crown/src/ml_dsa/ntt_x86_64.ts
```

The generation machine must pass the perl's AVX2 assembler probe
(`CC=gcc perl ...`): without it the script emits `ud2` stubs. The
generated file has no `ud2` instructions when the probe succeeds, and the
`.note.gnu.property` directive is already in the GNU-as quoted form that
LLVM's `global_asm!` accepts.

## Compatibility

- The routines take the same FIPS 204 Montgomery-domain coefficient arrays
  and the same `ZETAS_MONTGOMERY` table as `crown/src/ml_dsa/ntt.rs`
  (constants match the C/asm).
- `ml_dsa_ntt_avx2_capable` performs the runtime AVX2+BMI2 check;
  `ntt.rs` falls back to its portable implementation when it returns 0.

## Tests

`cargo test -p crown --lib --features asm`:

- `ml_dsa::ntt::asm_tests::avx2_matches_portable` cross-checks
  `ntt`/`ntt_inverse`/`ntt_mult` against the portable implementations over
  pseudo-random polynomials;
- the ML-DSA keygen/sign/verify and wycheproof suites run through the asm
  path on AVX2 hosts.
