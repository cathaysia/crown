#ifndef crown_H
#define crown_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct AeadCipher AeadCipher;

/**
 * An opaque parsed X.509 attribute certificate (RFC 5755).
 */
typedef struct AttributeCertificate AttributeCertificate;

typedef struct BlockCipher BlockCipher;

/**
 * Opaque big number handle.
 */
typedef struct BnHandle BnHandle;

/**
 * CBC chaining state, in the requested direction.
 */
typedef struct CbcHandle CbcHandle;

/**
 * An opaque parsed X.509 certificate.
 */
typedef struct Certificate Certificate;

/**
 * An opaque trust store for RFC 5280 path validation.
 */
typedef struct CertificateStore CertificateStore;

/**
 * An opaque parsed CMP message (RFC 4210).
 */
typedef struct CmpMessage CmpMessage;

/**
 * An opaque parsed X.509 CRL.
 */
typedef struct Crl Crl;

/**
 * An opaque parsed PKCS#10 certification request.
 */
typedef struct Csr Csr;

/**
 * Opaque EC key handle: always carries the public point, optionally the
 * private scalar.
 */
typedef struct EcKeyHandle EcKeyHandle;

typedef struct Hash Hash;

typedef struct Mac Mac;

/**
 * An opaque parsed PKCS#12 PFX with its bags decrypted.
 */
typedef struct Pkcs12 Pkcs12;

/**
 * An opaque parsed PKCS#7 / CMS object.
 */
typedef struct Pkcs7 Pkcs7;

/**
 * Opaque RSA key handle: the public part is always present, the private
 * part only for keys loaded with `crown_rsa_new_private`.
 */
typedef struct RsaKeyHandle RsaKeyHandle;

typedef struct StreamCipher StreamCipher;

typedef struct Xts Xts;

/**
 * Create an AES-CBC transform. `key` selects the variant (16/24/32 bytes)
 * and `iv` must be 16 bytes. `encrypt` is non-zero for the encryption
 * direction.
 *
 * Returns NULL on failure.
 */
struct CbcHandle *crown_cbc_new_aes(const uint8_t *key,
                                    uintptr_t key_len,
                                    const uint8_t *iv,
                                    uintptr_t iv_len,
                                    int32_t encrypt);

/**
 * Release a CBC transform. NULL is ignored.
 */
void crown_cbc_free(struct CbcHandle *c);

/**
 * Block size of the transform in bytes (16 for AES).
 */
uintptr_t crown_cbc_block_size(const struct CbcHandle *c);

/**
 * Transform `len` bytes in place. `len` must be a non-zero multiple of the
 * block size; the chaining state carries over to the next call.
 *
 * Returns 0 on success, -1 on failure.
 */
int32_t crown_cbc_crypt(struct CbcHandle *c, uint8_t *data, uintptr_t len);

struct AeadCipher *aead_cipher_new_aes_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_aes_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_aes_ccm(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_aes_eax(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_aria_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_aria_ocb3(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_aria_ccm(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_aria_eax(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_blowfish_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_blowfish_ocb3(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 uintptr_t tag_size,
                                                 uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_blowfish_ccm(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_blowfish_eax(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_cast5_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_cast5_ocb3(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_cast5_ccm(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_cast5_eax(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_des_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_des_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_des_ccm(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_des_eax(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tripledes_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_tripledes_ocb3(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  uintptr_t tag_size,
                                                  uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tripledes_ccm(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 uintptr_t tag_size,
                                                 uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tripledes_eax(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 uintptr_t tag_size,
                                                 uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tea_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_tea_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tea_ccm(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tea_eax(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_twofish_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_twofish_ocb3(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_twofish_ccm(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_twofish_eax(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_xtea_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_xtea_ocb3(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_xtea_ccm(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_xtea_eax(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_rc6_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_rc6_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_rc6_ccm(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_rc6_eax(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_sm4_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_sm4_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_sm4_ccm(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_sm4_eax(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_skipjack_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_skipjack_ocb3(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 uintptr_t tag_size,
                                                 uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_skipjack_ccm(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_skipjack_eax(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_kasumi_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_kasumi_ocb3(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_kasumi_ccm(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_kasumi_eax(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_kseed_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_kseed_ocb3(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_kseed_ccm(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_kseed_eax(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_anubis_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_anubis_ocb3(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_anubis_ccm(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_anubis_eax(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_noekeon_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_noekeon_ocb3(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_noekeon_ccm(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_noekeon_eax(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_khazad_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_khazad_ocb3(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_khazad_ccm(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_khazad_eax(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_serpent_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_serpent_ocb3(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_serpent_ccm(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_serpent_eax(const uint8_t *key,
                                               uintptr_t key_len,
                                               uintptr_t tag_size,
                                               uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_idea_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_idea_ocb3(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_idea_ccm(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_idea_eax(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_rc2_gcm(const uint8_t *key,
                                           uintptr_t key_len,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_rc2_ccm(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_rc2_eax(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_rc5_gcm(const uint8_t *key,
                                           uintptr_t key_len,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_rc5_ccm(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_rc5_eax(const uint8_t *key,
                                           uintptr_t key_len,
                                           uintptr_t tag_size,
                                           uintptr_t nonce_size,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_camellia_gcm(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_camellia_ccm(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size,
                                                const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_camellia_eax(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size,
                                                const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_multi2_gcm(const uint8_t *key,
                                              uintptr_t key_len,
                                              const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_multi2_ccm(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size,
                                              const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_multi2_eax(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size,
                                              const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_chacha20_poly1305(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_xchacha20_poly1305(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_aes_gcm_siv(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_ascon_aead128(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_aes_siv(const uint8_t *key, uintptr_t key_len);

uintptr_t aead_cipher_nonce_size(const struct AeadCipher *self);

uintptr_t aead_cipher_tag_size(const struct AeadCipher *self);

int32_t aead_cipher_seal_in_place_separate_tag(const struct AeadCipher *self,
                                               uint8_t *inout,
                                               uintptr_t inout_len,
                                               const uint8_t *nonce,
                                               uintptr_t nonce_len,
                                               const uint8_t *aad,
                                               uintptr_t aad_len,
                                               uint8_t *tag,
                                               uintptr_t tag_len);

int32_t aead_cipher_open_in_place_separate_tag(const struct AeadCipher *self,
                                               uint8_t *inout,
                                               uintptr_t inout_len,
                                               const uint8_t *tag,
                                               uintptr_t tag_len,
                                               const uint8_t *nonce,
                                               uintptr_t nonce_len,
                                               const uint8_t *aad,
                                               uintptr_t aad_len);

void aead_cipher_free(struct AeadCipher *cipher);

struct BlockCipher *block_cipher_new_aes_cbc(const uint8_t *key,
                                             uintptr_t key_len,
                                             const uint8_t *iv,
                                             uintptr_t iv_len);

struct BlockCipher *block_cipher_new_aria_cbc(const uint8_t *key,
                                              uintptr_t key_len,
                                              const uint8_t *iv,
                                              uintptr_t iv_len);

struct BlockCipher *block_cipher_new_blowfish_cbc(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct BlockCipher *block_cipher_new_cast5_cbc(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct BlockCipher *block_cipher_new_des_cbc(const uint8_t *key,
                                             uintptr_t key_len,
                                             const uint8_t *iv,
                                             uintptr_t iv_len);

struct BlockCipher *block_cipher_new_tripledes_cbc(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct BlockCipher *block_cipher_new_tea_cbc(const uint8_t *key,
                                             uintptr_t key_len,
                                             const uint8_t *iv,
                                             uintptr_t iv_len);

struct BlockCipher *block_cipher_new_twofish_cbc(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct BlockCipher *block_cipher_new_xtea_cbc(const uint8_t *key,
                                              uintptr_t key_len,
                                              const uint8_t *iv,
                                              uintptr_t iv_len);

struct BlockCipher *block_cipher_new_idea_cbc(const uint8_t *key,
                                              uintptr_t key_len,
                                              const uint8_t *iv,
                                              uintptr_t iv_len);

struct BlockCipher *block_cipher_new_rc6_cbc(const uint8_t *key,
                                             uintptr_t key_len,
                                             const uint8_t *iv,
                                             uintptr_t iv_len);

struct BlockCipher *block_cipher_new_sm4_cbc(const uint8_t *key,
                                             uintptr_t key_len,
                                             const uint8_t *iv,
                                             uintptr_t iv_len);

struct BlockCipher *block_cipher_new_skipjack_cbc(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct BlockCipher *block_cipher_new_kasumi_cbc(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct BlockCipher *block_cipher_new_kseed_cbc(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct BlockCipher *block_cipher_new_anubis_cbc(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct BlockCipher *block_cipher_new_noekeon_cbc(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct BlockCipher *block_cipher_new_khazad_cbc(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct BlockCipher *block_cipher_new_serpent_cbc(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct BlockCipher *block_cipher_new_desx_cbc(const uint8_t *key,
                                              uintptr_t key_len,
                                              const uint8_t *iv,
                                              uintptr_t iv_len);

struct BlockCipher *block_cipher_new_rc2_cbc(const uint8_t *key,
                                             uintptr_t key_len,
                                             const uint8_t *iv,
                                             uintptr_t iv_len,
                                             const uintptr_t *rounds);

struct BlockCipher *block_cipher_new_rc5_cbc(const uint8_t *key,
                                             uintptr_t key_len,
                                             const uint8_t *iv,
                                             uintptr_t iv_len,
                                             const uintptr_t *rounds);

struct BlockCipher *block_cipher_new_camellia_cbc(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len,
                                                  const uintptr_t *rounds);

struct BlockCipher *block_cipher_new_multi2_cbc(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len,
                                                const uintptr_t *rounds);

int32_t block_cipher_encrypt(struct BlockCipher *self,
                             uint8_t *inout,
                             uintptr_t inout_len,
                             uintptr_t pos,
                             uintptr_t *output_len);

int32_t block_cipher_decrypt(struct BlockCipher *self,
                             uint8_t *inout,
                             uintptr_t inout_len,
                             uintptr_t *output_len);

void block_cipher_free(struct BlockCipher *cipher);

struct Hash *hash_new_md2(void);

struct Hash *hash_new_md2_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_md4(void);

struct Hash *hash_new_md4_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_md5(void);

struct Hash *hash_new_md5_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha1(void);

struct Hash *hash_new_sha1_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha224(void);

struct Hash *hash_new_sha224_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha256(void);

struct Hash *hash_new_sha256_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha384(void);

struct Hash *hash_new_sha384_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha512(void);

struct Hash *hash_new_sha512_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha512_224(void);

struct Hash *hash_new_sha512_224_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha512_256(void);

struct Hash *hash_new_sha512_256_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha3_224(void);

struct Hash *hash_new_sha3_224_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha3_256(void);

struct Hash *hash_new_sha3_256_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha3_384(void);

struct Hash *hash_new_sha3_384_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sha3_512(void);

struct Hash *hash_new_sha3_512_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_shake128(void);

struct Hash *hash_new_shake128_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_shake256(void);

struct Hash *hash_new_shake256_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_sm3(void);

struct Hash *hash_new_sm3_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_md5_sha1(void);

struct Hash *hash_new_md5_sha1_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_ripemd160(void);

struct Hash *hash_new_ripemd160_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_mdc2(void);

struct Hash *hash_new_mdc2_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_whirlpool(void);

struct Hash *hash_new_whirlpool_hmac(const uint8_t *key, uintptr_t key_len);

struct Hash *hash_new_blake2s(const uint8_t *key, uintptr_t key_len, uintptr_t output_len);

struct Hash *hash_new_blake2b(const uint8_t *key, uintptr_t key_len, uintptr_t output_len);

int32_t hash_write(struct Hash *self, const uint8_t *data, uintptr_t len);

int32_t hash_flush(struct Hash *self);

int32_t hash_read(struct Hash *self, uint8_t *buf, uintptr_t len);

int32_t hash_sum(struct Hash *self, uint8_t *output, uintptr_t output_len);

void hash_reset(struct Hash *self);

uintptr_t hash_size(const struct Hash *self);

uintptr_t hash_block_size(const struct Hash *self);

void hash_free(struct Hash *hash);

/**
 * Keygen from 64-byte seed. `variant` is 512/768/1024.
 * `public` and `private` buffers must be large enough (see ml_kem lengths).
 */
int32_t ml_kem_keygen(uint32_t variant,
                      const uint8_t *seed,
                      uintptr_t seed_len,
                      uint8_t *public_,
                      uintptr_t *public_len,
                      uint8_t *private_,
                      uintptr_t *private_len);

int32_t ml_kem_encapsulate(uint32_t variant,
                           const uint8_t *public_,
                           uintptr_t public_len,
                           const uint8_t *message,
                           uintptr_t message_len,
                           uint8_t *ciphertext,
                           uintptr_t *ciphertext_len,
                           uint8_t *shared);

int32_t ml_kem_decapsulate(uint32_t variant,
                           const uint8_t *private_,
                           uintptr_t private_len,
                           const uint8_t *ciphertext,
                           uintptr_t ciphertext_len,
                           uint8_t *shared);

struct Mac *mac_new_siphash(const uint8_t *key, uintptr_t key_len, uintptr_t output_len);

struct Mac *mac_new_kmac128(const uint8_t *key,
                            uintptr_t key_len,
                            const uint8_t *custom,
                            uintptr_t custom_len,
                            uintptr_t output_len);

struct Mac *mac_new_kmac256(const uint8_t *key,
                            uintptr_t key_len,
                            const uint8_t *custom,
                            uintptr_t custom_len,
                            uintptr_t output_len);

struct Mac *mac_new_cmac_aes(const uint8_t *key, uintptr_t key_len);

struct Mac *mac_new_gmac_aes(const uint8_t *key,
                             uintptr_t key_len,
                             const uint8_t *iv,
                             uintptr_t iv_len);

void mac_write(struct Mac *self, const uint8_t *data, uintptr_t len);

int32_t mac_sum(struct Mac *self, uint8_t *out, uintptr_t out_len);

void mac_free(struct Mac *this_);

uint8_t *aes_key_wrap(const uint8_t *key,
                      uintptr_t key_len,
                      const uint8_t *pt,
                      uintptr_t pt_len,
                      uintptr_t *out_len);

uint8_t *aes_key_unwrap(const uint8_t *key,
                        uintptr_t key_len,
                        const uint8_t *ct,
                        uintptr_t ct_len,
                        uintptr_t *out_len);

uint8_t *aes_key_wrap_padded(const uint8_t *key,
                             uintptr_t key_len,
                             const uint8_t *pt,
                             uintptr_t pt_len,
                             uintptr_t *out_len);

uint8_t *aes_key_unwrap_padded(const uint8_t *key,
                               uintptr_t key_len,
                               const uint8_t *ct,
                               uintptr_t ct_len,
                               uintptr_t *out_len);

/**
 * FF1 decimal encrypt. Returns a newly allocated ASCII string.
 */
uint8_t *ff1_encrypt_decimal(const uint8_t *key,
                             uintptr_t key_len,
                             const uint8_t *tweak,
                             uintptr_t tweak_len,
                             const uint8_t *input,
                             uintptr_t input_len,
                             uintptr_t *out_len);

uint8_t *ff1_decrypt_decimal(const uint8_t *key,
                             uintptr_t key_len,
                             const uint8_t *tweak,
                             uintptr_t tweak_len,
                             const uint8_t *input,
                             uintptr_t input_len,
                             uintptr_t *out_len);

void crown_free_buf(uint8_t *p, uintptr_t len);

/**
 * Parse a certificate from PEM or DER. Returns an opaque handle, or null.
 */
struct Certificate *certificate_parse(const uint8_t *data, uintptr_t len);

/**
 * Free a certificate handle.
 */
void certificate_free(struct Certificate *certificate);

/**
 * The DER encoding of the certificate.
 */
int32_t certificate_encode(const struct Certificate *certificate, uint8_t *out, uintptr_t *out_len);

/**
 * The PEM encoding of the certificate (with a trailing newline).
 */
int32_t certificate_to_pem(const struct Certificate *certificate, uint8_t *out, uintptr_t *out_len);

/**
 * The subject name in RFC 4514 form.
 */
int32_t certificate_subject(const struct Certificate *certificate,
                            uint8_t *out,
                            uintptr_t *out_len);

/**
 * The issuer name in RFC 4514 form.
 */
int32_t certificate_issuer(const struct Certificate *certificate, uint8_t *out, uintptr_t *out_len);

/**
 * The serial number magnitude (big-endian, without the sign octet).
 */
int32_t certificate_serial(const struct Certificate *certificate, uint8_t *out, uintptr_t *out_len);

/**
 * The validity window as Unix timestamps.
 */
int32_t certificate_validity(const struct Certificate *certificate,
                             int64_t *not_before,
                             int64_t *not_after);

/**
 * Fingerprint with `hash`: 0=SHA-256, 1=SHA-1, 2=SHA-384, 3=SHA-512,
 * 4=SHA3-256, 5=SM3, 6=RIPEMD-160, 7=MD5.
 */
int32_t certificate_fingerprint(const struct Certificate *certificate,
                                uint32_t hash,
                                uint8_t *out,
                                uintptr_t *out_len);

/**
 * The DER `SubjectPublicKeyInfo` of the certificate.
 */
int32_t certificate_subject_public_key_info(const struct Certificate *certificate,
                                            uint8_t *out,
                                            uintptr_t *out_len);

/**
 * 1 when the subject equals the issuer, 0 otherwise.
 */
int32_t certificate_is_self_signed(const struct Certificate *certificate);

/**
 * 1 when the certificate has the CA basic constraint, 0 otherwise.
 */
int32_t certificate_is_ca(const struct Certificate *certificate);

/**
 * Verify the certificate signature with the issuer's public key.
 */
int32_t certificate_verify_signature(const struct Certificate *certificate,
                                     const struct Certificate *issuer);

/**
 * Verify a certificate against its issuer: name chaining, CA constraints,
 * the signature and, when `check_time` is non-zero, the validity window at
 * `now` (Unix seconds; 0 means the current time is unavailable, which is
 * treated as expired).
 *
 * `sm2_id` selects the SM2 identity; pass null for the GM/T default.
 */
int32_t certificate_verify(const struct Certificate *certificate,
                           const struct Certificate *issuer,
                           int64_t now,
                           int32_t check_time,
                           const uint8_t *sm2_id,
                           uintptr_t sm2_id_len);

/**
 * Parse a CSR from PEM or DER.
 */
struct Csr *csr_parse(const uint8_t *data, uintptr_t len);

/**
 * Free a CSR handle.
 */
void csr_free(struct Csr *csr);

/**
 * The DER encoding of the CSR.
 */
int32_t csr_encode(const struct Csr *csr, uint8_t *out, uintptr_t *out_len);

/**
 * The subject name in RFC 4514 form.
 */
int32_t csr_subject(const struct Csr *csr, uint8_t *out, uintptr_t *out_len);

/**
 * The DER `SubjectPublicKeyInfo` of the CSR.
 */
int32_t csr_public_key_info(const struct Csr *csr, uint8_t *out, uintptr_t *out_len);

/**
 * Verify the CSR self-signature. `sm2_id` may be null for the GM/T default.
 */
int32_t csr_verify_signature(const struct Csr *csr, const uint8_t *sm2_id, uintptr_t sm2_id_len);

/**
 * Parse a CRL from PEM or DER.
 */
struct Crl *crl_parse(const uint8_t *data, uintptr_t len);

/**
 * Free a CRL handle.
 */
void crl_free(struct Crl *crl);

/**
 * The DER encoding of the CRL.
 */
int32_t crl_encode(const struct Crl *crl, uint8_t *out, uintptr_t *out_len);

/**
 * The issuer name in RFC 4514 form.
 */
int32_t crl_issuer(const struct Crl *crl, uint8_t *out, uintptr_t *out_len);

/**
 * Verify the CRL signature with the issuer certificate. `sm2_id` may be
 * null for the GM/T default.
 */
int32_t crl_verify_signature(const struct Crl *crl,
                             const struct Certificate *issuer,
                             const uint8_t *sm2_id,
                             uintptr_t sm2_id_len);

/**
 * 1 when `serial` (big-endian magnitude) is listed in the CRL, 0 when not.
 */
int32_t crl_is_revoked(const struct Crl *crl, const uint8_t *serial, uintptr_t serial_len);

/**
 * Parse a PKCS#7 / CMS object from PEM or DER.
 */
struct Pkcs7 *pkcs7_parse(const uint8_t *data, uintptr_t len);

/**
 * Free a PKCS#7 handle.
 */
void pkcs7_free(struct Pkcs7 *pkcs7);

/**
 * 1 when the object is CMS SignedData, 0 otherwise.
 */
int32_t pkcs7_is_signed_data(const struct Pkcs7 *pkcs7);

/**
 * Number of signers, or -1 when the object is not SignedData.
 */
int64_t pkcs7_signer_count(const struct Pkcs7 *pkcs7);

/**
 * Number of embedded certificates, or -1 when not SignedData.
 */
int64_t pkcs7_certificate_count(const struct Pkcs7 *pkcs7);

/**
 * Clone the embedded certificate at `index` into a new handle, or null.
 */
struct Certificate *pkcs7_certificate(const struct Pkcs7 *pkcs7, uintptr_t index);

/**
 * The encapsulated content (fails for detached signatures).
 */
int32_t pkcs7_content(const struct Pkcs7 *pkcs7, uint8_t *out, uintptr_t *out_len);

/**
 * Verify every signer. For detached signatures pass the content in
 * `detached`; pass null for attached content. `sm2_id` may be null for the
 * GM/T default. Returns 1 verified, 0 not, -1 on error.
 */
int32_t pkcs7_verify(const struct Pkcs7 *pkcs7,
                     const uint8_t *detached,
                     uintptr_t detached_len,
                     const uint8_t *sm2_id,
                     uintptr_t sm2_id_len);

/**
 * Parse a PKCS#12 PFX (DER or PEM) with its password. Shrouded key bags are
 * decrypted with the password; the MAC is verified when present and its
 * result is exposed through `pkcs12_mac_verified`.
 */
struct Pkcs12 *pkcs12_parse(const uint8_t *data,
                            uintptr_t len,
                            const uint8_t *password,
                            uintptr_t password_len);

/**
 * Free a PKCS#12 handle.
 */
void pkcs12_free(struct Pkcs12 *pkcs12);

/**
 * 1 when the PFX MAC verified, 0 when there is no MAC, -1 when it did not
 * verify.
 */
int32_t pkcs12_mac_verified(const struct Pkcs12 *pkcs12);

/**
 * Number of bags in the PFX.
 */
int64_t pkcs12_bag_count(const struct Pkcs12 *pkcs12);

/**
 * Kind of the bag at `index`: 0 certificate, 1 private key, 2 CRL,
 * 3 secret, 4 safeContents, 5 other; -1 on error.
 */
int32_t pkcs12_bag_kind(const struct Pkcs12 *pkcs12, uintptr_t index);

/**
 * The `friendlyName` of the bag at `index`: 1 present, 0 absent, -1 error.
 */
int32_t pkcs12_bag_friendly_name(const struct Pkcs12 *pkcs12,
                                 uintptr_t index,
                                 uint8_t *out,
                                 uintptr_t *out_len);

/**
 * Clone the certificate bag at `index` into a new handle, or null.
 */
struct Certificate *pkcs12_bag_certificate(const struct Pkcs12 *pkcs12, uintptr_t index);

/**
 * Clone the CRL bag at `index` into a new handle, or null.
 */
struct Crl *pkcs12_bag_crl(const struct Pkcs12 *pkcs12, uintptr_t index);

/**
 * The PKCS#8 DER of the key bag at `index`.
 */
int32_t pkcs12_bag_private_key(const struct Pkcs12 *pkcs12,
                               uintptr_t index,
                               uint8_t *out,
                               uintptr_t *out_len);

/**
 * Decrypt a PKCS#8 `EncryptedPrivateKeyInfo` DER, writing plain PKCS#8 DER.
 */
int32_t pkcs8_decrypt(const uint8_t *data,
                      uintptr_t len,
                      const uint8_t *password,
                      uintptr_t password_len,
                      uint8_t *out,
                      uintptr_t *out_len);

/**
 * Encrypt PKCS#8 DER with PBES2. `cipher`: 0=AES-128-CBC, 1=AES-192-CBC,
 * 2=AES-256-CBC, 3=3DES.
 */
int32_t pkcs8_encrypt(const uint8_t *data,
                      uintptr_t len,
                      const uint8_t *password,
                      uintptr_t password_len,
                      uint32_t cipher,
                      uint32_t iterations,
                      uint8_t *out,
                      uintptr_t *out_len);

/**
 * The DER `SubjectPublicKeyInfo` of a PKCS#8 key.
 */
int32_t pkcs8_public_key_info(const uint8_t *data, uintptr_t len, uint8_t *out, uintptr_t *out_len);

/**
 * The algorithm OID (dotted string) of a public key, e.g.
 * `"1.2.840.113549.1.1.1"` for RSA.
 */
int32_t public_key_algorithm(const uint8_t *data, uintptr_t len, uint8_t *out, uintptr_t *out_len);

/**
 * Number of bits of a public key, or -1 when not meaningful.
 */
int64_t public_key_bits(const uint8_t *data, uintptr_t len);

/**
 * The signature algorithm OID of a certificate as a dotted string.
 */
int32_t certificate_signature_algorithm(const struct Certificate *certificate,
                                        uint8_t *out,
                                        uintptr_t *out_len);

/**
 * Whether the certificate signature algorithm is one crown can verify.
 */
int32_t certificate_signature_supported(const struct Certificate *certificate);

/**
 * Create an empty certificate store.
 */
struct CertificateStore *certificate_store_new(void);

/**
 * Free a certificate store.
 */
void certificate_store_free(struct CertificateStore *store);

/**
 * Add a trust anchor.
 */
int32_t certificate_store_add_trusted(struct CertificateStore *store,
                                      const struct Certificate *certificate);

/**
 * Add an untrusted intermediate certificate.
 */
int32_t certificate_store_add_untrusted(struct CertificateStore *store,
                                        const struct Certificate *certificate);

/**
 * Add a CRL (DER) to the store.
 */
int32_t certificate_store_add_crl(struct CertificateStore *store,
                                  const uint8_t *crl,
                                  uintptr_t crl_len);

/**
 * Verify `certificate` against the store.
 *
 * `purpose`: 0 any, 1 sslServer, 2 sslClient, 3 smimeSign, 4 smimeEncrypt,
 * 5 codeSigning, 6 ocspHelper, 7 timeStamping, 8 crlSign.
 * `flags` bitmask: 1 CRL check, 2 CRL check all, 4 policy check,
 * 8 explicit policy, 16 inhibit anyPolicy, 32 x509 strict, 64 partial chain.
 * Returns 1 verified, 0 not, -1 on error.
 */
int32_t certificate_store_verify(const struct CertificateStore *store,
                                 const struct Certificate *certificate,
                                 int64_t now,
                                 int32_t check_time,
                                 uint32_t purpose,
                                 uint32_t flags);

/**
 * Encrypt `content` to one RSA recipient certificate (AES-256-CBC).
 * Output is a DER `ContentInfo`; use the query pattern for `out`.
 */
int32_t cms_encrypt(const uint8_t *content,
                    uintptr_t content_len,
                    const struct Certificate *recipient,
                    uint8_t *out,
                    uintptr_t *out_len);

/**
 * Decrypt a CMS EnvelopedData (DER) with an RSA key (PKCS#8 DER) and its
 * certificate. Returns the plaintext with the query pattern.
 */
int32_t cms_decrypt(const uint8_t *data,
                    uintptr_t data_len,
                    const uint8_t *key,
                    uintptr_t key_len,
                    const struct Certificate *certificate,
                    uint8_t *out,
                    uintptr_t *out_len);

/**
 * Decrypt a CMS EnvelopedData (DER) with a password recipient.
 */
int32_t cms_decrypt_password(const uint8_t *data,
                             uintptr_t data_len,
                             const uint8_t *password,
                             uintptr_t password_len,
                             uint8_t *out,
                             uintptr_t *out_len);

/**
 * Verify an OCSP response (DER or PEM) against its issuer certificate.
 * Returns 1 verified, 0 not, -1 on error.
 */
int32_t ocsp_response_verify(const uint8_t *response,
                             uintptr_t response_len,
                             const struct Certificate *issuer);

/**
 * Parse an attribute certificate from PEM or DER.
 */
struct AttributeCertificate *attribute_certificate_parse(const uint8_t *data, uintptr_t len);

/**
 * Free an attribute certificate handle.
 */
void attribute_certificate_free(struct AttributeCertificate *certificate);

/**
 * The DER encoding of the attribute certificate.
 */
int32_t attribute_certificate_encode(const struct AttributeCertificate *certificate,
                                     uint8_t *out,
                                     uintptr_t *out_len);

/**
 * The PEM encoding of the attribute certificate.
 */
int32_t attribute_certificate_to_pem(const struct AttributeCertificate *certificate,
                                     uint8_t *out,
                                     uintptr_t *out_len);

/**
 * The serial number magnitude.
 */
int32_t attribute_certificate_serial(const struct AttributeCertificate *certificate,
                                     uint8_t *out,
                                     uintptr_t *out_len);

/**
 * Verify the attribute certificate against its issuer certificate,
 * optionally checking the validity window at `now`.
 */
int32_t attribute_certificate_verify(const struct AttributeCertificate *certificate,
                                     const struct Certificate *issuer,
                                     int64_t now,
                                     int32_t check_time);

/**
 * Whether the attribute certificate holder is the given certificate.
 */
int32_t attribute_certificate_holder_matches(const struct AttributeCertificate *certificate,
                                             const struct Certificate *holder);

/**
 * Verify a CMS AuthenticatedData object with an RSA/ECDH recipient key
 * (PKCS#8 DER) and certificate; returns the content with the query pattern.
 */
int32_t cms_authdata_verify(const uint8_t *data,
                            uintptr_t data_len,
                            const uint8_t *key,
                            uintptr_t key_len,
                            const struct Certificate *certificate,
                            uint8_t *out,
                            uintptr_t *out_len);

/**
 * Verify a CMS AuthenticatedData object with a password recipient.
 */
int32_t cms_authdata_verify_password(const uint8_t *data,
                                     uintptr_t data_len,
                                     const uint8_t *password,
                                     uintptr_t password_len,
                                     uint8_t *out,
                                     uintptr_t *out_len);

/**
 * Verify an RFC 3161 timestamp response (DER or PEM). When `request` is
 * given, its message imprint and nonce must match. Returns 1 verified,
 * 0 not, -1 on error.
 */
int32_t ts_verify(const uint8_t *response,
                  uintptr_t response_len,
                  const struct Certificate *tsa,
                  const uint8_t *request,
                  uintptr_t request_len);

/**
 * Parse a CMP message from DER or PEM.
 */
struct CmpMessage *cmp_message_parse(const uint8_t *data, uintptr_t len);

/**
 * Free a CMP message handle.
 */
void cmp_message_free(struct CmpMessage *message);

/**
 * The protocol version (1..=3).
 */
int32_t cmp_message_pvno(const struct CmpMessage *message);

/**
 * The body kind: 0 ir, 1 cr, 2 p10cr, 3 kur, 4 rr, 5 ccr, 6 pkiconf,
 * 7 genm, 8 genp, 9 error, 10 certConf, 11 pollReq, 12 pollRep, 13 other.
 */
int32_t cmp_message_body_kind(const struct CmpMessage *message);

/**
 * The sender name.
 */
int32_t cmp_message_sender(const struct CmpMessage *message, uint8_t *out, uintptr_t *out_len);

/**
 * The recipient name.
 */
int32_t cmp_message_recipient(const struct CmpMessage *message, uint8_t *out, uintptr_t *out_len);

/**
 * Number of embedded extra certificates.
 */
int64_t cmp_message_certificate_count(const struct CmpMessage *message);

/**
 * Verify the password-based protection (PBM).
 */
int32_t cmp_message_verify_password(const struct CmpMessage *message,
                                    const uint8_t *password,
                                    uintptr_t password_len);

/**
 * Verify the signature-based protection against the signer in `extraCerts`.
 */
int32_t cmp_message_verify_signature(const struct CmpMessage *message);

/**
 * ML-DSA keygen from 32-byte seed. variant = 44/65/87.
 * On success writes pk/sk; call with null buffers first to get lengths.
 */
int32_t ml_dsa_keygen(uint32_t variant,
                      const uint8_t *seed,
                      uintptr_t seed_len,
                      uint8_t *public_,
                      uintptr_t *public_len,
                      uint8_t *private_,
                      uintptr_t *private_len);

int32_t ml_dsa_sign(uint32_t variant,
                    const uint8_t *private_,
                    uintptr_t private_len,
                    const uint8_t *msg,
                    uintptr_t msg_len,
                    const uint8_t *ctx,
                    uintptr_t ctx_len,
                    uint8_t *sig,
                    uintptr_t *sig_len);

int32_t ml_dsa_verify(uint32_t variant,
                      const uint8_t *public_,
                      uintptr_t public_len,
                      const uint8_t *msg,
                      uintptr_t msg_len,
                      const uint8_t *ctx,
                      uintptr_t ctx_len,
                      const uint8_t *sig,
                      uintptr_t sig_len);

/**
 * SLH-DSA keygen. `name` is e.g. "SLH-DSA-SHA2-128s". seed is 3n bytes.
 */
int32_t slh_dsa_keygen(const uint8_t *name,
                       uintptr_t name_len,
                       const uint8_t *seed,
                       uintptr_t seed_len,
                       uint8_t *public_,
                       uintptr_t *public_len,
                       uint8_t *private_,
                       uintptr_t *private_len);

int32_t slh_dsa_sign(const uint8_t *name,
                     uintptr_t name_len,
                     const uint8_t *private_,
                     uintptr_t private_len,
                     const uint8_t *msg,
                     uintptr_t msg_len,
                     const uint8_t *ctx,
                     uintptr_t ctx_len,
                     uint8_t *sig,
                     uintptr_t *sig_len);

int32_t slh_dsa_verify(const uint8_t *name,
                       uintptr_t name_len,
                       const uint8_t *public_,
                       uintptr_t public_len,
                       const uint8_t *msg,
                       uintptr_t msg_len,
                       const uint8_t *ctx,
                       uintptr_t ctx_len,
                       const uint8_t *sig,
                       uintptr_t sig_len);

/**
 * Ed25519 keygen. Writes 32-byte seed to `seed`, 32-byte public to `public`.
 */
int32_t ed25519_keygen(uint8_t *seed, uint8_t *public_);

int32_t ed25519_sign(const uint8_t *secret,
                     uintptr_t secret_len,
                     const uint8_t *msg,
                     uintptr_t msg_len,
                     uint8_t *sig);

int32_t ed25519_verify(const uint8_t *public_,
                       uintptr_t public_len,
                       const uint8_t *msg,
                       uintptr_t msg_len,
                       const uint8_t *sig,
                       uintptr_t sig_len);

struct StreamCipher *stream_cipher_new_aes_cfb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_aes_ctr(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_aes_ofb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_aria_cfb(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_aria_ctr(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_aria_ofb(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_blowfish_cfb(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_blowfish_ctr(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_blowfish_ofb(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_cast5_cfb(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_cast5_ctr(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_cast5_ofb(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_des_cfb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_des_ctr(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_des_ofb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_tripledes_cfb(const uint8_t *key,
                                                     uintptr_t key_len,
                                                     const uint8_t *iv,
                                                     uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_tripledes_ctr(const uint8_t *key,
                                                     uintptr_t key_len,
                                                     const uint8_t *iv,
                                                     uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_tripledes_ofb(const uint8_t *key,
                                                     uintptr_t key_len,
                                                     const uint8_t *iv,
                                                     uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_tea_cfb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_tea_ctr(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_tea_ofb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_twofish_cfb(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_twofish_ctr(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_twofish_ofb(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_xtea_cfb(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_xtea_ctr(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_xtea_ofb(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_idea_cfb(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_idea_ctr(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_idea_ofb(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_rc6_cfb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_rc6_ctr(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_rc6_ofb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_sm4_cfb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_sm4_ctr(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_sm4_ofb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_skipjack_cfb(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_skipjack_ctr(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_skipjack_ofb(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_kasumi_cfb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_kasumi_ctr(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_kasumi_ofb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_kseed_cfb(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_kseed_ctr(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_kseed_ofb(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_anubis_cfb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_anubis_ctr(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_anubis_ofb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_noekeon_cfb(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_noekeon_ctr(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_noekeon_ofb(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_khazad_cfb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_khazad_ctr(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_khazad_ofb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_serpent_cfb(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_serpent_ctr(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_serpent_ofb(const uint8_t *key,
                                                   uintptr_t key_len,
                                                   const uint8_t *iv,
                                                   uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_rc2_cfb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len,
                                               const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_rc2_ctr(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len,
                                               const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_rc2_ofb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len,
                                               const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_rc5_cfb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len,
                                               const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_rc5_ctr(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len,
                                               const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_rc5_ofb(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len,
                                               const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_camellia_cfb(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len,
                                                    const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_camellia_ctr(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len,
                                                    const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_camellia_ofb(const uint8_t *key,
                                                    uintptr_t key_len,
                                                    const uint8_t *iv,
                                                    uintptr_t iv_len,
                                                    const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_multi2_cfb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len,
                                                  const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_multi2_ctr(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len,
                                                  const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_multi2_ofb(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  const uint8_t *iv,
                                                  uintptr_t iv_len,
                                                  const uintptr_t *rounds);

struct StreamCipher *stream_cipher_new_rc4(const uint8_t *key, uintptr_t key_len);

struct StreamCipher *stream_cipher_new_salsa20(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_chacha20(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_rabbit(const uint8_t *key,
                                              uintptr_t key_len,
                                              const uint8_t *iv,
                                              uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_sosemanuk(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 const uint8_t *iv,
                                                 uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_sober128(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

int32_t stream_cipher_encrypt(struct StreamCipher *self, uint8_t *inout, uintptr_t len);

int32_t stream_cipher_decrypt(struct StreamCipher *self, uint8_t *inout, uintptr_t len);

void stream_cipher_free(struct StreamCipher *cipher);

struct Xts *xts_new_aes(const uint8_t *key, uintptr_t key_len);

struct Xts *xts_new_sm4_gb(const uint8_t *key, uintptr_t key_len);

struct Xts *xts_new_sm4(const uint8_t *key, uintptr_t key_len);

int32_t xts_encrypt(const struct Xts *self,
                    const uint8_t *tweak,
                    uintptr_t tweak_len,
                    uint8_t *data,
                    uintptr_t data_len);

int32_t xts_decrypt(const struct Xts *self,
                    const uint8_t *tweak,
                    uintptr_t tweak_len,
                    uint8_t *data,
                    uintptr_t data_len);

void xts_free(struct Xts *this_);

/**
 * Fill `len` bytes with cryptographically secure random data.
 *
 * Returns 0 on success, -1 on failure.
 */
int32_t crown_random(uint8_t *buf, uintptr_t len);

/**
 * Allocate a big number with the value zero.
 */
struct BnHandle *crown_bn_new(void);

/**
 * Release a big number. NULL is ignored.
 */
void crown_bn_free(struct BnHandle *bn);

/**
 * Allocate a big number from a big-endian byte string (leading zeros are
 * accepted). Returns NULL on a NULL input.
 */
struct BnHandle *crown_bn_from_bin(const uint8_t *bin, uintptr_t len);

/**
 * Replace the value of `bn` with the big-endian integer in `bin`.
 *
 * Returns 0 on success, -1 on a NULL argument.
 */
int32_t crown_bn_set_from_bin(struct BnHandle *bn, const uint8_t *bin, uintptr_t len);

/**
 * Write the minimal big-endian encoding (no leading zeros, nothing at all
 * for zero) into `out`, which must hold at least `crown_bn_bytes` bytes.
 *
 * Returns the number of bytes written, or 0 if the value does not fit (or
 * `out` is NULL) — matching `BN_bn2bin`.
 */
uintptr_t crown_bn_to_bin(const struct BnHandle *bn, uint8_t *out, uintptr_t out_len);

/**
 * Number of significant bits (0 for zero).
 */
uintptr_t crown_bn_bits(const struct BnHandle *bn);

/**
 * Number of bytes needed for the minimal big-endian encoding (0 for zero).
 */
uintptr_t crown_bn_bytes(const struct BnHandle *bn);

/**
 * Set the value to a 32-bit word. Returns 0 on success.
 */
int32_t crown_bn_set_word(struct BnHandle *bn, uint32_t word);

/**
 * `a - b`. Returns NULL when the result would be negative or an argument is
 * NULL.
 */
struct BnHandle *crown_bn_sub(const struct BnHandle *a, const struct BnHandle *b);

/**
 * Copy the value of `src` into `dst`. Returns 0 on success, -1 on a NULL
 * argument.
 */
int32_t crown_bn_copy(struct BnHandle *dst, const struct BnHandle *src);

/**
 * Compare two big numbers: -1 if `a < b`, 0 if equal, 1 if `a > b`.
 * Returns -2 on a NULL argument.
 */
int32_t crown_bn_cmp(const struct BnHandle *a, const struct BnHandle *b);

/**
 * Generate a Diffie-Hellman key pair for the group `(p, g)`: writes the
 * private exponent to `*out_private` and `g^x mod p` to `*out_public`.
 *
 * Both outputs are freshly allocated and owned by the caller. Returns 0 on
 * success, -1 on failure.
 */
int32_t crown_dh_key_pair(const struct BnHandle *p,
                          const struct BnHandle *g,
                          struct BnHandle **out_private,
                          struct BnHandle **out_public);

/**
 * Compute the shared secret `peer^private mod p` and store it in
 * `*out_secret`. Returns 0 on success, -1 on failure.
 */
int32_t crown_dh_secret(const struct BnHandle *private_,
                        const struct BnHandle *peer,
                        const struct BnHandle *p,
                        struct BnHandle **out_secret);

/**
 * Validate a peer's DH public value: 1 when `1 < f < p - 1`, else 0.
 */
int32_t crown_dh_validate(const struct BnHandle *f, const struct BnHandle *p);

/**
 * Curve identifiers shared with the C side: 0 = P-256, 1 = P-384,
 * 2 = P-521.
 */
uintptr_t crown_ec_curve_field_bytes(uint32_t curve);

/**
 * Derive the public value for a 32-byte X25519 private key.
 *
 * Returns 0 on success, -1 on failure.
 */
int32_t crown_x25519_public(const uint8_t *private_, uint8_t *public_);

/**
 * X25519 key agreement. Returns 0 on success, -1 when the shared secret is
 * the all-zero value (low-order peer point) or an argument is NULL.
 */
int32_t crown_x25519(const uint8_t *private_, const uint8_t *peer_public, uint8_t *shared);

/**
 * Generate a fresh X25519 key pair into `private`/`public` (32 bytes each).
 * Returns 0 on success, -1 on failure.
 */
int32_t crown_x25519_keypair(uint8_t *private_, uint8_t *public_);

/**
 * Generate a fresh key pair on `curve` (0 = P-256, 1 = P-384, 2 = P-521).
 * Returns NULL on failure.
 */
struct EcKeyHandle *crown_ec_key_generate(uint32_t curve);

/**
 * Build a key from its components. `public_point` is the SEC1 encoding
 * (`0x04 || X || Y`); when it is NULL/empty the point is derived from the
 * private scalar. `private_scalar` may be NULL for a public-only key.
 *
 * Returns NULL on failure.
 */
struct EcKeyHandle *crown_ec_key_new(uint32_t curve,
                                     const uint8_t *private_scalar,
                                     uintptr_t scalar_len,
                                     const uint8_t *public_point,
                                     uintptr_t point_len);

/**
 * Curve id of a key handle (0 = P-256, 1 = P-384, 2 = P-521), or
 * `UINT32_MAX` on a NULL argument.
 */
uint32_t crown_ec_key_curve(const struct EcKeyHandle *key);

/**
 * Release a key handle. NULL is ignored.
 */
void crown_ec_key_free(struct EcKeyHandle *key);

/**
 * Write the SEC1 uncompressed public point into `out`.
 *
 * Returns the number of bytes written, or 0 on failure (including `out` too
 * small — the required size is `2 * field_bytes + 1`).
 */
uintptr_t crown_ec_key_public(const struct EcKeyHandle *key, uint8_t *out, uintptr_t out_len);

/**
 * ECDH: compute the shared secret (the X coordinate, left-padded to the
 * field size) between `key` (which must hold a private scalar) and the SEC1
 * `peer_point`.
 *
 * Returns the number of bytes written, or 0 on failure.
 */
uintptr_t crown_ecdh_compute(const struct EcKeyHandle *key,
                             const uint8_t *peer_point,
                             uintptr_t peer_len,
                             uint8_t *out,
                             uintptr_t out_len);

/**
 * ECDSA signature over an already-computed digest. The signature is
 * `r || s`, each left-padded to the field size (RFC 5656 / RFC 4253 wire
 * form).
 *
 * Returns the number of bytes written, or 0 on failure.
 */
uintptr_t crown_ecdsa_sign_digest(const struct EcKeyHandle *key,
                                  const uint8_t *digest,
                                  uintptr_t digest_len,
                                  uint8_t *out,
                                  uintptr_t out_len);

/**
 * ECDSA verification over an already-computed digest. `sig` is `r || s`,
 * each left-padded to the field size.
 *
 * Returns 1 when the signature is valid, 0 otherwise.
 */
int32_t crown_ecdsa_verify_digest(uint32_t curve,
                                  const uint8_t *public_point,
                                  uintptr_t point_len,
                                  const uint8_t *digest,
                                  uintptr_t digest_len,
                                  const uint8_t *sig,
                                  uintptr_t sig_len);

/**
 * Build a public-only RSA key from `n` and `e`. Returns NULL on failure.
 */
struct RsaKeyHandle *crown_rsa_new_public(const uint8_t *n,
                                          uintptr_t n_len,
                                          const uint8_t *e,
                                          uintptr_t e_len);

/**
 * Build an RSA key from its components. `d` and the CRT parameters
 * (`p`, `q`, `dp`, `dq`, `qinv`) may be NULL/empty for a public-only key;
 * the CRT parameters are optional even when `d` is present.
 *
 * Returns NULL on failure.
 */
struct RsaKeyHandle *crown_rsa_new_private(const uint8_t *n,
                                           uintptr_t n_len,
                                           const uint8_t *e,
                                           uintptr_t e_len,
                                           const uint8_t *d,
                                           uintptr_t d_len,
                                           const uint8_t *p,
                                           uintptr_t p_len,
                                           const uint8_t *q,
                                           uintptr_t q_len,
                                           const uint8_t *dp,
                                           uintptr_t dp_len,
                                           const uint8_t *dq,
                                           uintptr_t dq_len,
                                           const uint8_t *qinv,
                                           uintptr_t qinv_len);

/**
 * Release an RSA key handle. NULL is ignored.
 */
void crown_rsa_free(struct RsaKeyHandle *key);

/**
 * Write the RSA modulus (minimal big-endian) into `out`.
 *
 * Returns the number of bytes written, or 0 on failure.
 */
uintptr_t crown_rsa_n(const struct RsaKeyHandle *key, uint8_t *out, uintptr_t out_len);

/**
 * Write the RSA public exponent (minimal big-endian) into `out`.
 *
 * Returns the number of bytes written, or 0 on failure.
 */
uintptr_t crown_rsa_e(const struct RsaKeyHandle *key, uint8_t *out, uintptr_t out_len);

/**
 * Modulus size in bytes.
 */
uintptr_t crown_rsa_size(const struct RsaKeyHandle *key);

/**
 * PKCS#1 v1.5 signature over an already-computed digest.
 *
 * Returns the number of signature bytes written, or 0 on failure (wrong key
 * type, unknown digest length, or `out` too small).
 */
uintptr_t crown_rsa_sign_digest(const struct RsaKeyHandle *key,
                                const uint8_t *digest,
                                uintptr_t digest_len,
                                uint8_t *out,
                                uintptr_t out_len);

/**
 * PKCS#1 v1.5 verification of a signature over an already-computed digest.
 *
 * Returns 1 when the signature is valid, 0 otherwise.
 */
int32_t crown_rsa_verify_digest(const struct RsaKeyHandle *key,
                                const uint8_t *digest,
                                uintptr_t digest_len,
                                const uint8_t *sig,
                                uintptr_t sig_len);

#endif  /* crown_H */
