#ifndef LIBSSH2_CROWN_H
#define LIBSSH2_CROWN_H
/* Copyright (C) crown contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * libssh2 crypto backend for the crown library (https://github.com/cathaysia/crown),
 * using the C ABI exported by crown-cabi.
 *
 * This header is pulled in by src/crypto.h when LIBSSH2_CROWN is defined. It
 * maps the backend-neutral types and macros declared there onto crown-cabi
 * handles; the implementations live in libssh2_crown.c.
 */

#define LIBSSH2_CRYPTO_ENGINE libssh2_crown

#include <stddef.h>
#include <stdint.h>

/* crown-cabi C API (shipped as crown-cabi/include/crown.h) */
#include "crown.h"

/* Feature set.
 *
 * Overridable from the build system: LIBSSH2_NO_<FEATURE> forces a feature
 * off (applied below, mirroring src/crypto_config.h). MD5, hmac-ripemd160,
 * DSA, RSA-SHA1, Blowfish, RC4, CAST and 3DES stay disabled via those
 * defaults. */
#define LIBSSH2_MD5 0
#define LIBSSH2_HMAC_RIPEMD 0
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_AES_CBC 1
/* AES-GCM is not wired to this backend yet; chacha20-poly1305@openssh.com is
 * implemented by libssh2 itself and AES-CTR remains available. */
#define LIBSSH2_AES_GCM 0
#define LIBSSH2_3DES 0
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 0
#define LIBSSH2_CAST 0
#define LIBSSH2_RSA 1
/* libssh2 1.11.1 gates the "ssh-rsa" host-key blob type behind
 * LIBSSH2_RSA_SHA1 (hostkey_method_ssh_rsa_init in src/hostkey.c), and
 * RFC 8332 key blobs keep that type even for rsa-sha2-* signatures. Without
 * it RSA host keys cannot be parsed at all. The method table lists
 * rsa-sha2-512/rsa-sha2-256 before ssh-rsa, so SHA-1 signatures are only
 * negotiated with servers that offer nothing else. */
#define LIBSSH2_RSA_SHA1_ENABLE 1
#define LIBSSH2_RSA_SHA1 1
#define LIBSSH2_RSA_SHA2 1
#define LIBSSH2_ECDSA 1
#define LIBSSH2_ED25519 1

/* Feature overrides.
 *
 * Upstream backends include "crypto_config.h" from libssh2's src/ directory.
 * This header lives outside that tree, so a quoted include cannot resolve
 * there; apply the same overrides inline instead. Keep in sync with
 * src/crypto_config.h. */
#define LIBSSH2_MD5_PEM LIBSSH2_MD5

#ifdef LIBSSH2_NO_MD5
#undef LIBSSH2_MD5
#define LIBSSH2_MD5 0
#endif

#ifdef LIBSSH2_NO_MD5_PEM
#undef LIBSSH2_MD5_PEM
#define LIBSSH2_MD5_PEM 0
#endif

#ifdef LIBSSH2_NO_HMAC_RIPEMD
#undef LIBSSH2_HMAC_RIPEMD
#define LIBSSH2_HMAC_RIPEMD 0
#endif

/* DSA is opt-in. */
#if !defined(LIBSSH2_DSA_ENABLE)
#undef LIBSSH2_DSA
#define LIBSSH2_DSA 0
#endif

#ifdef LIBSSH2_NO_RSA
#undef LIBSSH2_RSA
#define LIBSSH2_RSA 0
#endif

#ifdef LIBSSH2_NO_RSA_SHA1
#undef LIBSSH2_RSA_SHA1
#define LIBSSH2_RSA_SHA1 0
#endif

#ifdef LIBSSH2_NO_ECDSA
#undef LIBSSH2_ECDSA
#define LIBSSH2_ECDSA 0
#endif

#ifdef LIBSSH2_NO_ED25519
#undef LIBSSH2_ED25519
#define LIBSSH2_ED25519 0
#endif

#ifdef LIBSSH2_NO_AES_CTR
#undef LIBSSH2_AES_CTR
#define LIBSSH2_AES_CTR 0
#endif

#ifdef LIBSSH2_NO_AES_CBC
#undef LIBSSH2_AES_CBC
#define LIBSSH2_AES_CBC 0
#endif

#ifdef LIBSSH2_NO_BLOWFISH
#undef LIBSSH2_BLOWFISH
#define LIBSSH2_BLOWFISH 0
#endif

#ifdef LIBSSH2_NO_RC4
#undef LIBSSH2_RC4
#define LIBSSH2_RC4 0
#endif

#ifdef LIBSSH2_NO_CAST
#undef LIBSSH2_CAST
#define LIBSSH2_CAST 0
#endif

#ifdef LIBSSH2_NO_3DES
#undef LIBSSH2_3DES
#define LIBSSH2_3DES 0
#endif

/* Digest lengths. crypto.h only defines LIBSSH2_ED25519_* after including this
 * header, so the core-facing length macros live here like in the other
 * backends. */
#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

#define EC_MAX_POINT_LEN ((528 * 2 / 8) + 1)

#define LIBSSH2_ED25519_KEY_LEN 32

/*******************************************************************/
/*
 * crown backend: generic functions
 */

void _libssh2_crown_crypto_init(void);
void _libssh2_crown_crypto_exit(void);

int _libssh2_crown_random(unsigned char *buf, size_t len);

#define libssh2_crypto_init() \
    _libssh2_crown_crypto_init()
#define libssh2_crypto_exit() \
    _libssh2_crown_crypto_exit()

#define _libssh2_random(buf, len) \
    _libssh2_crown_random((buf), (len))

#define libssh2_prepare_iovec(vec, len) /* Empty. */

/*******************************************************************/
/*
 * crown backend: hash and HMAC
 */

struct ssh2_crown_hash_ctx {
    struct Hash *h;
};

#define libssh2_sha1_ctx struct ssh2_crown_hash_ctx
#define libssh2_sha256_ctx struct ssh2_crown_hash_ctx
#define libssh2_sha384_ctx struct ssh2_crown_hash_ctx
#define libssh2_sha512_ctx struct ssh2_crown_hash_ctx
#define libssh2_hmac_ctx struct ssh2_crown_hash_ctx

enum {
    SSH2_CROWN_SHA1 = 1,
    SSH2_CROWN_SHA256,
    SSH2_CROWN_SHA384,
    SSH2_CROWN_SHA512
};

/* Helpers backing the per-algorithm macros below; the init/update/final
 * triplet returns 1 on success and 0 on failure, the one-shot form returns 0
 * on success and non-zero on failure. */
int _crown_hash_init(struct ssh2_crown_hash_ctx *ctx, int alg);
int _crown_hash_update(struct ssh2_crown_hash_ctx *ctx, const void *data, size_t datalen);
int _crown_hash_final(struct ssh2_crown_hash_ctx *ctx, void *digest, size_t digest_len);
int _crown_hash_one_shot(int alg, const void *data, size_t datalen, void *digest);

#define libssh2_sha1_init(pctx) \
    _crown_hash_init(pctx, SSH2_CROWN_SHA1)
#define libssh2_sha1_update(ctx, data, datalen) \
    _crown_hash_update(&(ctx), (data), (datalen))
#define libssh2_sha1_final(ctx, hash) \
    _crown_hash_final(&(ctx), (hash), SHA_DIGEST_LENGTH)
#define libssh2_sha1(data, datalen, hash) \
    _crown_hash_one_shot(SSH2_CROWN_SHA1, (data), (datalen), (hash))

#define libssh2_sha256_init(pctx) \
    _crown_hash_init(pctx, SSH2_CROWN_SHA256)
#define libssh2_sha256_update(ctx, data, datalen) \
    _crown_hash_update(&(ctx), (data), (datalen))
#define libssh2_sha256_final(ctx, hash) \
    _crown_hash_final(&(ctx), (hash), SHA256_DIGEST_LENGTH)
#define libssh2_sha256(data, datalen, hash) \
    _crown_hash_one_shot(SSH2_CROWN_SHA256, (data), (datalen), (hash))

#define libssh2_sha384_init(pctx) \
    _crown_hash_init(pctx, SSH2_CROWN_SHA384)
#define libssh2_sha384_update(ctx, data, datalen) \
    _crown_hash_update(&(ctx), (data), (datalen))
#define libssh2_sha384_final(ctx, hash) \
    _crown_hash_final(&(ctx), (hash), SHA384_DIGEST_LENGTH)
#define libssh2_sha384(data, datalen, hash) \
    _crown_hash_one_shot(SSH2_CROWN_SHA384, (data), (datalen), (hash))

#define libssh2_sha512_init(pctx) \
    _crown_hash_init(pctx, SSH2_CROWN_SHA512)
#define libssh2_sha512_update(ctx, data, datalen) \
    _crown_hash_update(&(ctx), (data), (datalen))
#define libssh2_sha512_final(ctx, hash) \
    _crown_hash_final(&(ctx), (hash), SHA512_DIGEST_LENGTH)
#define libssh2_sha512(data, datalen, hash) \
    _crown_hash_one_shot(SSH2_CROWN_SHA512, (data), (datalen), (hash))

/*******************************************************************/
/*
 * crown backend: RSA
 */

#define libssh2_rsa_ctx struct RsaKeyHandle

void _libssh2_rsa_free(libssh2_rsa_ctx *rsa);

/*******************************************************************/
/*
 * crown backend: NIST curves (ECDH + ECDSA)
 */

typedef enum {
    LIBSSH2_EC_CURVE_NISTP256 = 0,
    LIBSSH2_EC_CURVE_NISTP384 = 1,
    LIBSSH2_EC_CURVE_NISTP521 = 2
} libssh2_curve_type;

#define libssh2_ecdsa_ctx struct EcKeyHandle
#define _libssh2_ec_key struct EcKeyHandle

void _libssh2_ecdsa_free(libssh2_ecdsa_ctx *ec_ctx);

/*******************************************************************/
/*
 * crown backend: Ed25519
 */

struct ssh2_crown_ed25519_ctx {
    LIBSSH2_SESSION *session;
    uint8_t public_key[LIBSSH2_ED25519_KEY_LEN];
    uint8_t private_key[LIBSSH2_ED25519_KEY_LEN];
    int has_private;
};

#define libssh2_ed25519_ctx struct ssh2_crown_ed25519_ctx

void _libssh2_ed25519_free(libssh2_ed25519_ctx *ed_ctx);

/*******************************************************************/
/*
 * crown backend: ciphers
 */

struct ssh2_crown_cipher_ctx {
    int algo;
    int encrypt;
    /* struct StreamCipher * for CTR, struct CbcHandle * for CBC */
    void *cipher;
};

#define _libssh2_cipher_ctx struct ssh2_crown_cipher_ctx
#define _libssh2_cipher_type(algo) int algo

enum {
    SSH2_CROWN_CIPHER_AES128CTR = 1,
    SSH2_CROWN_CIPHER_AES192CTR,
    SSH2_CROWN_CIPHER_AES256CTR,
    SSH2_CROWN_CIPHER_AES128CBC,
    SSH2_CROWN_CIPHER_AES192CBC,
    SSH2_CROWN_CIPHER_AES256CBC,
    SSH2_CROWN_CIPHER_AES128GCM,
    SSH2_CROWN_CIPHER_AES256GCM,
    /* The SSH chacha20-poly1305 construction is implemented by libssh2
     * itself; this id exists only because the core method table refers to
     * it. */
    SSH2_CROWN_CIPHER_CHACHA20,
    /* Remaining ids exist for method-table references from features that
     * this backend leaves disabled. */
    SSH2_CROWN_CIPHER_3DES,
    SSH2_CROWN_CIPHER_BLOWFISH,
    SSH2_CROWN_CIPHER_ARCFOUR,
    SSH2_CROWN_CIPHER_CAST5
};

#define _libssh2_cipher_aes128ctr SSH2_CROWN_CIPHER_AES128CTR
#define _libssh2_cipher_aes192ctr SSH2_CROWN_CIPHER_AES192CTR
#define _libssh2_cipher_aes256ctr SSH2_CROWN_CIPHER_AES256CTR
#define _libssh2_cipher_aes128 SSH2_CROWN_CIPHER_AES128CBC
#define _libssh2_cipher_aes192 SSH2_CROWN_CIPHER_AES192CBC
#define _libssh2_cipher_aes256 SSH2_CROWN_CIPHER_AES256CBC
#define _libssh2_cipher_aes128gcm SSH2_CROWN_CIPHER_AES128GCM
#define _libssh2_cipher_aes256gcm SSH2_CROWN_CIPHER_AES256GCM
#define _libssh2_cipher_chacha20 SSH2_CROWN_CIPHER_CHACHA20
#define _libssh2_cipher_3des SSH2_CROWN_CIPHER_3DES
#define _libssh2_cipher_blowfish SSH2_CROWN_CIPHER_BLOWFISH
#define _libssh2_cipher_arcfour SSH2_CROWN_CIPHER_ARCFOUR
#define _libssh2_cipher_cast5 SSH2_CROWN_CIPHER_CAST5

void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx);

/*******************************************************************/
/*
 * crown backend: big numbers
 */

#define _libssh2_bn struct BnHandle
#define _libssh2_bn_ctx int
#define _libssh2_bn_ctx_new() 0
#define _libssh2_bn_ctx_free(bnctx) ((void)0)

/* _libssh2_bn_to_bin follows the libssh2 convention: zero means success, so
 * an empty write (zero value or a buffer that is too small) is a failure. */
#define _libssh2_bn_init() crown_bn_new()
#define _libssh2_bn_init_from_bin() crown_bn_new()
#define _libssh2_bn_free(bn) crown_bn_free(bn)
#define _libssh2_bn_set_word(bn, word) \
    (crown_bn_set_word((bn), (word)) != 0)
#define _libssh2_bn_bits(bn) ((size_t)crown_bn_bits(bn))
#define _libssh2_bn_bytes(bn) ((size_t)crown_bn_bytes(bn))
#define _libssh2_bn_to_bin(bn, bin) \
    ((int)(crown_bn_to_bin((bn), (bin), crown_bn_bytes(bn)) == 0))

int _libssh2_bn_from_bin(_libssh2_bn *bn, size_t len, const unsigned char *v);

/*******************************************************************/
/*
 * crown backend: Diffie-Hellman
 */

/* Default sizes for diffie-hellman-group-exchange. */
#define LIBSSH2_DH_GEX_MINGROUP 2048
#define LIBSSH2_DH_GEX_OPTGROUP 4096
#define LIBSSH2_DH_GEX_MAXGROUP 8192

#define LIBSSH2_DH_MAX_MODULUS_BITS 16384

#define _libssh2_dh_ctx struct BnHandle *

void _libssh2_dh_init(_libssh2_dh_ctx *dhctx);
int _libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *public, _libssh2_bn *g, _libssh2_bn *p, int group_order, _libssh2_bn_ctx *bnctx);
int _libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret, _libssh2_bn *f, _libssh2_bn *p, _libssh2_bn_ctx *bnctx);
void _libssh2_dh_dtor(_libssh2_dh_ctx *dhctx);

#define libssh2_dh_init(dhctx) _libssh2_dh_init(dhctx)
#define libssh2_dh_key_pair(dhctx, public, g, p, group_order, bnctx) \
    _libssh2_dh_key_pair(dhctx, public, g, p, group_order, bnctx)
#define libssh2_dh_secret(dhctx, secret, f, p, bnctx) \
    _libssh2_dh_secret(dhctx, secret, f, p, bnctx)
#define libssh2_dh_dtor(dhctx) _libssh2_dh_dtor(dhctx)

#endif /* LIBSSH2_CROWN_H */
