#ifndef crown_H
#define crown_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct AeadCipher AeadCipher;

typedef struct BlockCipher BlockCipher;

typedef struct Hash Hash;

typedef struct StreamCipher StreamCipher;

struct AeadCipher *aead_cipher_new_aes_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_aes_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_blowfish_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_blowfish_ocb3(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 uintptr_t tag_size,
                                                 uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_cast5_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_cast5_ocb3(const uint8_t *key,
                                              uintptr_t key_len,
                                              uintptr_t tag_size,
                                              uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_des_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_des_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tripledes_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_tripledes_ocb3(const uint8_t *key,
                                                  uintptr_t key_len,
                                                  uintptr_t tag_size,
                                                  uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_tea_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_tea_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_twofish_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_twofish_ocb3(const uint8_t *key,
                                                uintptr_t key_len,
                                                uintptr_t tag_size,
                                                uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_xtea_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_xtea_ocb3(const uint8_t *key,
                                             uintptr_t key_len,
                                             uintptr_t tag_size,
                                             uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_rc6_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_rc6_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_sm4_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_sm4_ocb3(const uint8_t *key,
                                            uintptr_t key_len,
                                            uintptr_t tag_size,
                                            uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_skipjack_gcm(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_skipjack_ocb3(const uint8_t *key,
                                                 uintptr_t key_len,
                                                 uintptr_t tag_size,
                                                 uintptr_t nonce_size);

struct AeadCipher *aead_cipher_new_rc2_gcm(const uint8_t *key,
                                           uintptr_t key_len,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_rc5_gcm(const uint8_t *key,
                                           uintptr_t key_len,
                                           const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_camellia_gcm(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uintptr_t *rounds);

struct AeadCipher *aead_cipher_new_chacha20_poly1305(const uint8_t *key, uintptr_t key_len);

struct AeadCipher *aead_cipher_new_xchacha20_poly1305(const uint8_t *key, uintptr_t key_len);

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

struct StreamCipher *stream_cipher_new_rc4(const uint8_t *key, uintptr_t key_len);

struct StreamCipher *stream_cipher_new_salsa20(const uint8_t *key,
                                               uintptr_t key_len,
                                               const uint8_t *iv,
                                               uintptr_t iv_len);

struct StreamCipher *stream_cipher_new_chacha20(const uint8_t *key,
                                                uintptr_t key_len,
                                                const uint8_t *iv,
                                                uintptr_t iv_len);

int32_t stream_cipher_encrypt(struct StreamCipher *self, uint8_t *inout, uintptr_t len);

int32_t stream_cipher_decrypt(struct StreamCipher *self, uint8_t *inout, uintptr_t len);

void stream_cipher_free(struct StreamCipher *cipher);

#endif  /* crown_H */
