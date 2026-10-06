/* Copyright (C) crown contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * libssh2 crypto backend implemented on top of the crown library
 * (https://github.com/cathaysia/crown) through its crown-cabi C API.
 *
 * The contract implemented here is the one documented in
 * src/HACKING-CRYPTO.md: the functions declared in src/crypto.h plus the
 * type/macro mapping in libssh2_crown.h.
 */

/* The crown backend is built as its own object library outside the libssh2
 * CMake directory scope, so the -DHAVE_CONFIG_H that libssh2 adds for its own
 * sources does not reach this file. Define it before the private headers so
 * libssh2_setup.h picks up the generated libssh2_config.h. */
#define HAVE_CONFIG_H 1

#include "libssh2_priv.h"
#include "misc.h"

#include <stdlib.h>
#include <string.h>

/*******************************************************************/
/*
 * Global init/exit and randomness
 */

void _libssh2_crown_crypto_init(void) {
    /* crown has no global state to initialise. */
}

void _libssh2_crown_crypto_exit(void) {
}

int _libssh2_crown_random(unsigned char *buf, size_t len) {
    if(len == 0)
        return 0;
    return crown_random(buf, len);
}

/*******************************************************************/
/*
 * Hash and HMAC
 */

static struct Hash *crown_hash_new(int alg, const unsigned char *key, size_t key_len) {
    switch(alg) {
        case SSH2_CROWN_SHA1:
            return key ? hash_new_sha1_hmac(key, key_len) : hash_new_sha1();
        case SSH2_CROWN_SHA256:
            return key ? hash_new_sha256_hmac(key, key_len) : hash_new_sha256();
        case SSH2_CROWN_SHA384:
            return key ? hash_new_sha384_hmac(key, key_len) : hash_new_sha384();
        case SSH2_CROWN_SHA512:
            return key ? hash_new_sha512_hmac(key, key_len) : hash_new_sha512();
        default:
            return NULL;
    }
}

static size_t crown_hash_size_of(int alg) {
    switch(alg) {
        case SSH2_CROWN_SHA1:
            return SHA_DIGEST_LENGTH;
        case SSH2_CROWN_SHA256:
            return SHA256_DIGEST_LENGTH;
        case SSH2_CROWN_SHA384:
            return SHA384_DIGEST_LENGTH;
        case SSH2_CROWN_SHA512:
            return SHA512_DIGEST_LENGTH;
        default:
            return 0;
    }
}

int _crown_hash_init(struct ssh2_crown_hash_ctx *ctx, int alg) {
    if(!ctx)
        return 0;
    /* The context is not initialized yet; do not inspect it. */
    ctx->h = crown_hash_new(alg, NULL, 0);
    return ctx->h ? 1 : 0;
}

int _crown_hash_update(struct ssh2_crown_hash_ctx *ctx, const void *data, size_t datalen) {
    if(!ctx || !ctx->h)
        return 0;
    if(datalen && !data)
        return 0;

    /* hash_write() returns the number of bytes consumed. */
    return hash_write(ctx->h, (const uint8_t *)data, datalen) ==
                   (int)datalen
               ? 1
               : 0;
}

int _crown_hash_final(struct ssh2_crown_hash_ctx *ctx, void *digest, size_t digest_len) {
    size_t size;
    int ret;

    if(!ctx || !ctx->h || !digest)
        return 0;

    size = hash_size(ctx->h);
    if(!size || (digest_len && digest_len < size))
        return 0;

    ret = hash_sum(ctx->h, (uint8_t *)digest, size) > 0 ? 1 : 0;
    hash_free(ctx->h);
    ctx->h = NULL;
    return ret;
}

int _crown_hash_one_shot(int alg, const void *data, size_t datalen, void *digest) {
    struct ssh2_crown_hash_ctx ctx;
    size_t size = crown_hash_size_of(alg);

    if(!size || !digest)
        return 1;
    if(datalen && !data)
        return 1;

    ctx.h = crown_hash_new(alg, NULL, 0);
    if(!ctx.h)
        return 1;

    if(!_crown_hash_update(&ctx, data, datalen)) {
        hash_free(ctx.h);
        return 1;
    }
    return _crown_hash_final(&ctx, digest, size) ? 0 : 1;
}

static int crown_hmac_init(struct ssh2_crown_hash_ctx *ctx, int alg, void *key, size_t key_len) {
    if(!ctx || !key)
        return 0;
    /* _libssh2_hmac_ctx_init() has already cleared the context. */
    ctx->h = crown_hash_new(alg, (const unsigned char *)key, key_len);
    return ctx->h ? 1 : 0;
}

int _libssh2_hmac_ctx_init(libssh2_hmac_ctx *ctx) {
    if(!ctx)
        return 0;
    ctx->h = NULL;
    return 1;
}

int _libssh2_hmac_sha1_init(libssh2_hmac_ctx *ctx, void *key, size_t keylen) {
    return crown_hmac_init(ctx, SSH2_CROWN_SHA1, key, keylen);
}

int _libssh2_hmac_sha256_init(libssh2_hmac_ctx *ctx, void *key, size_t keylen) {
    return crown_hmac_init(ctx, SSH2_CROWN_SHA256, key, keylen);
}

int _libssh2_hmac_sha512_init(libssh2_hmac_ctx *ctx, void *key, size_t keylen) {
    return crown_hmac_init(ctx, SSH2_CROWN_SHA512, key, keylen);
}

int _libssh2_hmac_update(libssh2_hmac_ctx *ctx, const void *data, size_t datalen) {
    return _crown_hash_update(ctx, data, datalen);
}

int _libssh2_hmac_final(libssh2_hmac_ctx *ctx, void *data) {
    /* The HMAC size is the size of the underlying hash. */
    return _crown_hash_final(ctx, data, 0);
}

void _libssh2_hmac_cleanup(libssh2_hmac_ctx *ctx) {
    if(ctx && ctx->h) {
        hash_free(ctx->h);
        ctx->h = NULL;
    }
}

/*******************************************************************/
/*
 * Ciphers
 */

static size_t crown_cipher_key_len(int algo) {
    switch(algo) {
        case SSH2_CROWN_CIPHER_AES128CTR:
        case SSH2_CROWN_CIPHER_AES128CBC:
            return 16;
        case SSH2_CROWN_CIPHER_AES192CTR:
        case SSH2_CROWN_CIPHER_AES192CBC:
            return 24;
        case SSH2_CROWN_CIPHER_AES256CTR:
        case SSH2_CROWN_CIPHER_AES256CBC:
            return 32;
        default:
            return 0;
    }
}

int _libssh2_cipher_init(_libssh2_cipher_ctx *ctx, _libssh2_cipher_type(algo), unsigned char *iv, unsigned char *secret, int encrypt) {
    size_t key_len;

    if(!ctx || !iv || !secret)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    ctx->algo = algo;
    ctx->encrypt = encrypt;
    ctx->cipher = NULL;

    key_len = crown_cipher_key_len(algo);
    if(!key_len)
        return -1;

    switch(algo) {
        case SSH2_CROWN_CIPHER_AES128CTR:
        case SSH2_CROWN_CIPHER_AES192CTR:
        case SSH2_CROWN_CIPHER_AES256CTR:
            /* CTR is its own inverse: a single transform covers both
             * directions and keeps the counter state across calls. */
            ctx->cipher = stream_cipher_new_aes_ctr(secret, key_len, iv, 16);
            break;
        case SSH2_CROWN_CIPHER_AES128CBC:
        case SSH2_CROWN_CIPHER_AES192CBC:
        case SSH2_CROWN_CIPHER_AES256CBC:
            ctx->cipher = crown_cbc_new_aes(secret, key_len, iv, 16, encrypt);
            break;
        default:
            return -1;
    }

    return ctx->cipher ? 0 : -1;
}

int _libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx, _libssh2_cipher_type(algo), int encrypt, unsigned char *block, size_t blocksize, int firstlast) {
    (void)algo;
    (void)encrypt;
    (void)firstlast;

    if(!ctx || !ctx->cipher || (!block && blocksize))
        return -1;

    switch(ctx->algo) {
        case SSH2_CROWN_CIPHER_AES128CTR:
        case SSH2_CROWN_CIPHER_AES192CTR:
        case SSH2_CROWN_CIPHER_AES256CTR:
            if(stream_cipher_encrypt(ctx->cipher, block, blocksize))
                return -1;
            return 0;
        case SSH2_CROWN_CIPHER_AES128CBC:
        case SSH2_CROWN_CIPHER_AES192CBC:
        case SSH2_CROWN_CIPHER_AES256CBC:
            return crown_cbc_crypt(ctx->cipher, block, blocksize);
        default:
            return -1;
    }
}

void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx) {
    if(!ctx || !ctx->cipher)
        return;

    switch(ctx->algo) {
        case SSH2_CROWN_CIPHER_AES128CTR:
        case SSH2_CROWN_CIPHER_AES192CTR:
        case SSH2_CROWN_CIPHER_AES256CTR:
            stream_cipher_free(ctx->cipher);
            break;
        case SSH2_CROWN_CIPHER_AES128CBC:
        case SSH2_CROWN_CIPHER_AES192CBC:
        case SSH2_CROWN_CIPHER_AES256CBC:
            crown_cbc_free(ctx->cipher);
            break;
        default:
            break;
    }
    ctx->cipher = NULL;
}

/*******************************************************************/
/*
 * Big numbers
 */

int _libssh2_bn_from_bin(_libssh2_bn *bn, size_t len, const unsigned char *v) {
    if(!bn || (!v && len))
        return -1;

    if(len == 0)
        return crown_bn_set_word(bn, 0) ? -1 : 0;

    return crown_bn_set_from_bin(bn, v, len) ? -1 : 0;
}

/*******************************************************************/
/*
 * Diffie-Hellman
 */

void _libssh2_dh_init(_libssh2_dh_ctx *dhctx) {
    if(dhctx)
        *dhctx = NULL;
}

int _libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *pub, _libssh2_bn *g, _libssh2_bn *p, int group_order, _libssh2_bn_ctx *bnctx) {
    struct BnHandle *x = NULL;
    struct BnHandle *y = NULL;

    (void)bnctx;

    if(!dhctx || !pub || !g || !p || group_order <= 0)
        return -1;

    if(crown_dh_key_pair(p, g, &x, &y))
        return -1;

    /* The caller owns both big numbers; replace their values in place. */
    if(crown_bn_copy(pub, y)) {
        crown_bn_free(x);
        crown_bn_free(y);
        return -1;
    }
    crown_bn_free(y);

    if(*dhctx)
        crown_bn_free(*dhctx);
    *dhctx = x;
    return 0;
}

int _libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret, _libssh2_bn *f, _libssh2_bn *p, _libssh2_bn_ctx *bnctx) {
    struct BnHandle *shared = NULL;
    int ret;

    (void)bnctx;

    if(!dhctx || !*dhctx || !secret || !f || !p)
        return -1;

    if(crown_dh_secret(*dhctx, f, p, &shared))
        return -1;

    ret = crown_bn_copy(secret, shared);
    crown_bn_free(shared);
    return ret ? -1 : 0;
}

void _libssh2_dh_dtor(_libssh2_dh_ctx *dhctx) {
    if(dhctx && *dhctx) {
        crown_bn_free(*dhctx);
        *dhctx = NULL;
    }
}

/*******************************************************************/
/*
 * X25519
 */

int _libssh2_curve25519_gen_k(
    _libssh2_bn **k,
    uint8_t private_key[LIBSSH2_ED25519_KEY_LEN],
    uint8_t server_public_key[LIBSSH2_ED25519_KEY_LEN]
) {
    uint8_t shared[LIBSSH2_ED25519_KEY_LEN];

    if(!k || !private_key || !server_public_key)
        return -1;

    if(crown_x25519(private_key, server_public_key, shared))
        return -1;

    if(*k)
        return crown_bn_set_from_bin(*k, shared, sizeof(shared)) ? -1 : 0;
    *k = crown_bn_from_bin(shared, sizeof(shared));
    return *k ? 0 : -1;
}

int _libssh2_curve25519_new(LIBSSH2_SESSION *session, uint8_t **out_public_key, uint8_t **out_private_key) {
    uint8_t *pub;
    uint8_t *priv;

    if(!out_public_key || !out_private_key)
        return -1;

    pub = LIBSSH2_ALLOC(session, LIBSSH2_ED25519_KEY_LEN);
    priv = LIBSSH2_ALLOC(session, LIBSSH2_ED25519_KEY_LEN);
    if(!pub || !priv) {
        LIBSSH2_FREE(session, pub);
        LIBSSH2_FREE(session, priv);
        return -1;
    }

    if(crown_x25519_keypair(priv, pub)) {
        LIBSSH2_FREE(session, pub);
        LIBSSH2_FREE(session, priv);
        return -1;
    }

    *out_public_key = pub;
    *out_private_key = priv;
    return 0;
}

/*******************************************************************/
/*
 * Ed25519
 */

int _libssh2_ed25519_new_public(libssh2_ed25519_ctx **ed_ctx, LIBSSH2_SESSION *session, const unsigned char *raw_pub_key, const size_t key_len) {
    libssh2_ed25519_ctx *ctx;

    if(!ed_ctx || !raw_pub_key || key_len != LIBSSH2_ED25519_KEY_LEN)
        return -1;

    ctx = LIBSSH2_CALLOC(session, sizeof(*ctx));
    if(!ctx)
        return -1;

    ctx->session = session;
    memcpy(ctx->public_key, raw_pub_key, LIBSSH2_ED25519_KEY_LEN);
    ctx->has_private = 0;
    *ed_ctx = ctx;
    return 0;
}

int _libssh2_ed25519_sign(libssh2_ed25519_ctx *ctx, LIBSSH2_SESSION *session, uint8_t **out_sig, size_t *out_sig_len, const uint8_t *message, size_t message_len) {
    uint8_t *sig;

    if(!ctx || !ctx->has_private || !out_sig || !out_sig_len)
        return -1;

    sig = LIBSSH2_ALLOC(session, LIBSSH2_ED25519_SIG_LEN);
    if(!sig)
        return -1;

    if(ed25519_sign(ctx->private_key, LIBSSH2_ED25519_KEY_LEN, message, message_len, sig)) {
        LIBSSH2_FREE(session, sig);
        return -1;
    }

    *out_sig = sig;
    *out_sig_len = LIBSSH2_ED25519_SIG_LEN;
    return 0;
}

int _libssh2_ed25519_verify(libssh2_ed25519_ctx *ctx, const uint8_t *s, size_t s_len, const uint8_t *m, size_t m_len) {
    if(!ctx || !s || s_len != LIBSSH2_ED25519_SIG_LEN)
        return -1;

    return ed25519_verify(ctx->public_key, LIBSSH2_ED25519_KEY_LEN, m, m_len, s, s_len) == 1 ? 0 : -1;
}

void _libssh2_ed25519_free(libssh2_ed25519_ctx *ctx) {
    if(ctx)
        LIBSSH2_FREE(ctx->session, ctx);
}

/*******************************************************************/
/*
 * NIST curves: ECDH and ECDSA
 */

static const char *crown_curve_name(libssh2_curve_type curve) {
    switch(curve) {
        case LIBSSH2_EC_CURVE_NISTP256:
            return "nistp256";
        case LIBSSH2_EC_CURVE_NISTP384:
            return "nistp384";
        case LIBSSH2_EC_CURVE_NISTP521:
            return "nistp521";
        default:
            return NULL;
    }
}

static const char *crown_ecdsa_method_name(libssh2_curve_type curve) {
    switch(curve) {
        case LIBSSH2_EC_CURVE_NISTP256:
            return "ecdsa-sha2-nistp256";
        case LIBSSH2_EC_CURVE_NISTP384:
            return "ecdsa-sha2-nistp384";
        case LIBSSH2_EC_CURVE_NISTP521:
            return "ecdsa-sha2-nistp521";
        default:
            return NULL;
    }
}

libssh2_curve_type _libssh2_ecdsa_get_curve_type(libssh2_ecdsa_ctx *ec_ctx) {
    uint32_t curve = crown_ec_key_curve(ec_ctx);

    switch(curve) {
        case 0:
            return LIBSSH2_EC_CURVE_NISTP256;
        case 1:
            return LIBSSH2_EC_CURVE_NISTP384;
        case 2:
            return LIBSSH2_EC_CURVE_NISTP521;
        default:
            return (libssh2_curve_type)-1;
    }
}

int _libssh2_ecdsa_curve_type_from_name(const char *name, libssh2_curve_type *out_type) {
    libssh2_curve_type type;

    if(!name || strlen(name) != 19)
        return -1;

    if(strcmp(name, "ecdsa-sha2-nistp256") == 0)
        type = LIBSSH2_EC_CURVE_NISTP256;
    else if(strcmp(name, "ecdsa-sha2-nistp384") == 0)
        type = LIBSSH2_EC_CURVE_NISTP384;
    else if(strcmp(name, "ecdsa-sha2-nistp521") == 0)
        type = LIBSSH2_EC_CURVE_NISTP521;
    else
        return -1;

    if(out_type)
        *out_type = type;
    return 0;
}

int _libssh2_ecdsa_create_key(LIBSSH2_SESSION *session, _libssh2_ec_key **out_private_key, unsigned char **out_public_key_octal, size_t *out_public_key_octal_len, libssh2_curve_type curve) {
    struct EcKeyHandle *key;
    unsigned char *octal;
    size_t field = crown_ec_curve_field_bytes((uint32_t)curve);
    size_t written;

    if(!out_private_key || !out_public_key_octal ||
       !out_public_key_octal_len || !field)
        return -1;

    key = crown_ec_key_generate((uint32_t)curve);
    if(!key)
        return -1;

    octal = LIBSSH2_ALLOC(session, 2 * field + 1);
    if(!octal) {
        crown_ec_key_free(key);
        return -1;
    }

    written = crown_ec_key_public(key, octal, 2 * field + 1);
    if(!written) {
        LIBSSH2_FREE(session, octal);
        crown_ec_key_free(key);
        return -1;
    }

    *out_private_key = key;
    *out_public_key_octal = octal;
    *out_public_key_octal_len = written;
    return 0;
}

int _libssh2_ecdsa_curve_name_with_octal_new(
    libssh2_ecdsa_ctx **ec_ctx,
    const unsigned char *publickey_encoded, size_t publickey_encoded_len,
    libssh2_curve_type curve
) {
    struct EcKeyHandle *key;

    if(!ec_ctx)
        return -1;

    key = crown_ec_key_new((uint32_t)curve, NULL, 0, publickey_encoded, publickey_encoded_len);
    if(!key)
        return -1;

    *ec_ctx = key;
    return 0;
}

/*
 * Append an SSH mpint (RFC 4251): minimal big-endian bytes prefixed with a
 * 32-bit length, padded with one zero byte when the high bit is set. Writes
 * at most 4 + val_len + 1 bytes and returns the new write position.
 */
static unsigned char *crown_store_mpint(unsigned char *p, const unsigned char *val, size_t val_len) {
    while(val_len > 1 && val[0] == 0) {
        val++;
        val_len--;
    }

    if(val_len == 1 && val[0] == 0)
        val_len = 0;

    if(val_len && (val[0] & 0x80)) {
        _libssh2_htonu32(p, (uint32_t)(val_len + 1));
        p += 4;
        *p++ = 0;
        memcpy(p, val, val_len);
        return p + val_len;
    }

    _libssh2_htonu32(p, (uint32_t)val_len);
    p += 4;
    if(val_len) {
        memcpy(p, val, val_len);
        p += val_len;
    }
    return p;
}

/*
 * libssh2 hands ECDSA backends the data to be signed or verified, not a
 * digest (the core does not pre-hash, unlike the RSA-SHA2 paths). RFC 5656
 * pairs the curve with the hash: P-256 -> SHA-256, P-384 -> SHA-384,
 * P-521 -> SHA-512.
 */
static int crown_ecdsa_digest(uint32_t curve, const unsigned char *data, size_t data_len, unsigned char *out, size_t *out_len) {
    struct Hash *hash;

    switch(curve) {
        case 0:
            hash = hash_new_sha256();
            *out_len = 32;
            break;
        case 1:
            hash = hash_new_sha384();
            *out_len = 48;
            break;
        case 2:
            hash = hash_new_sha512();
            *out_len = 64;
            break;
        default:
            return -1;
    }
    if(!hash)
        return -1;
    if(data_len && hash_write(hash, data, data_len) != (int)data_len) {
        hash_free(hash);
        return -1;
    }
    if(hash_sum(hash, out, *out_len) <= 0) {
        hash_free(hash);
        return -1;
    }
    hash_free(hash);
    return 0;
}

int _libssh2_ecdsa_sign(LIBSSH2_SESSION *session, libssh2_ecdsa_ctx *ec_ctx, const unsigned char *hash, size_t hash_len, unsigned char **signature, size_t *signature_len) {
    unsigned char raw[2 * EC_MAX_POINT_LEN];
    unsigned char digest[64];
    unsigned char *sig;
    unsigned char *p;
    size_t field;
    size_t digest_len = 0;
    size_t written;

    if(!ec_ctx || !hash || !signature || !signature_len)
        return -1;

    field = crown_ec_curve_field_bytes(crown_ec_key_curve(ec_ctx));
    if(!field || 2 * field > sizeof(raw))
        return -1;

    if(crown_ecdsa_digest(crown_ec_key_curve(ec_ctx), hash, hash_len, digest, &digest_len))
        return -1;

    written = crown_ecdsa_sign_digest(ec_ctx, digest, digest_len, raw, 2 * field);
    if(written != 2 * field)
        return -1;

    /* The core expects the ecdsa_signature_blob form: string(r) string(s). */
    sig = LIBSSH2_ALLOC(session, 2 * field + 16);
    if(!sig)
        return -1;

    p = sig;
    p = crown_store_mpint(p, raw, field);
    p = crown_store_mpint(p, raw + field, field);

    *signature = sig;
    *signature_len = (size_t)(p - sig);
    return 0;
}

int _libssh2_ecdsa_verify(libssh2_ecdsa_ctx *ec_ctx, const unsigned char *r, size_t r_len, const unsigned char *s, size_t s_len, const unsigned char *m, size_t m_len) {
    unsigned char point[EC_MAX_POINT_LEN];
    unsigned char sig[2 * EC_MAX_POINT_LEN];
    unsigned char digest[64];
    uint32_t curve;
    size_t field;
    size_t point_len;
    size_t digest_len = 0;

    if(!ec_ctx || !r || !s || !m)
        return -1;

    /* SSH mpints may carry a leading zero byte (high bit set), while crown
     * wants r and s left-padded to the field size. */
    while(r_len > 0 && *r == 0) {
        r++;
        r_len--;
    }
    while(s_len > 0 && *s == 0) {
        s++;
        s_len--;
    }

    curve = crown_ec_key_curve(ec_ctx);
    field = crown_ec_curve_field_bytes(curve);
    point_len = crown_ec_key_public(ec_ctx, point, sizeof(point));
    if(!field || !point_len || r_len > field || s_len > field)
        return -1;

    memset(sig, 0, 2 * field);
    memcpy(sig + (field - r_len), r, r_len);
    memcpy(sig + field + (field - s_len), s, s_len);

    if(crown_ecdsa_digest(curve, m, m_len, digest, &digest_len))
        return -1;

    return crown_ecdsa_verify_digest(curve, point, point_len, digest, digest_len, sig, 2 * field) ? 0 : -1;
}

void _libssh2_ecdsa_free(libssh2_ecdsa_ctx *ec_ctx) {
    if(ec_ctx)
        crown_ec_key_free(ec_ctx);
}

int _libssh2_ecdh_gen_k(_libssh2_bn **k, _libssh2_ec_key *private_key, const unsigned char *server_public_key, size_t server_public_key_len) {
    unsigned char shared[EC_MAX_POINT_LEN];
    size_t written;

    if(!k || !private_key || !server_public_key)
        return -1;

    written = crown_ecdh_compute(private_key, server_public_key, server_public_key_len, shared, sizeof(shared));
    if(!written)
        return -1;

    if(*k)
        return crown_bn_set_from_bin(*k, shared, written) ? -1 : 0;
    *k = crown_bn_from_bin(shared, written);
    return *k ? 0 : -1;
}

/*******************************************************************/
/*
 * RSA
 */

int _libssh2_rsa_new(libssh2_rsa_ctx **rsa, const unsigned char *edata, unsigned long elen, const unsigned char *ndata, unsigned long nlen, const unsigned char *ddata, unsigned long dlen, const unsigned char *pdata, unsigned long plen, const unsigned char *qdata, unsigned long qlen, const unsigned char *e1data, unsigned long e1len, const unsigned char *e2data, unsigned long e2len, const unsigned char *coeffdata, unsigned long coefflen) {
    struct RsaKeyHandle *key;

    if(!rsa || !edata || !ndata)
        return -1;

    key = crown_rsa_new_private(ndata, nlen, edata, elen, ddata, dlen, pdata, plen, qdata, qlen, e1data, e1len, e2data, e2len, coeffdata, coefflen);
    if(!key)
        return -1;

    *rsa = key;
    return 0;
}

static int crown_hash_by_digest_len(size_t digest_len, const unsigned char *data, size_t data_len, unsigned char *out) {
    struct Hash *hash;

    switch(digest_len) {
        case 20:
            hash = hash_new_sha1();
            break;
        case 32:
            hash = hash_new_sha256();
            break;
        case 48:
            hash = hash_new_sha384();
            break;
        case 64:
            hash = hash_new_sha512();
            break;
        default:
            return -1;
    }
    if(!hash)
        return -1;
    if(data_len && hash_write(hash, data, data_len) != (int)data_len) {
        hash_free(hash);
        return -1;
    }
    if(hash_sum(hash, out, digest_len) <= 0) {
        hash_free(hash);
        return -1;
    }
    hash_free(hash);
    return 0;
}

#if LIBSSH2_RSA_SHA1
int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session, libssh2_rsa_ctx *rsactx, const unsigned char *hash, size_t hash_len, unsigned char **signature, size_t *signature_len) {
    unsigned char *sig;
    size_t size;
    size_t written;

    if(!rsactx || !signature || !signature_len)
        return -1;

    /* Like the SHA2 path, the core pre-hashes and passes the digest. */
    size = crown_rsa_size(rsactx);
    if(!size || hash_len != 20)
        return -1;

    sig = LIBSSH2_ALLOC(session, size);
    if(!sig)
        return -1;

    written = crown_rsa_sign_digest(rsactx, hash, hash_len, sig, size);
    if(!written) {
        LIBSSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = written;
    return 0;
}

int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa, const unsigned char *sig, size_t sig_len, const unsigned char *m, size_t m_len) {
    unsigned char digest[20];

    if(!rsa || !sig || !m)
        return -1;

    if(crown_hash_by_digest_len(20, m, m_len, digest))
        return -1;

    return crown_rsa_verify_digest(rsa, digest, sizeof(digest), sig, sig_len) == 1
               ? 0
               : -1;
}
#endif /* LIBSSH2_RSA_SHA1 */

int _libssh2_rsa_sha2_sign(LIBSSH2_SESSION *session, libssh2_rsa_ctx *rsa, const unsigned char *hash, size_t hash_len, unsigned char **signature, size_t *signature_len) {
    unsigned char *sig;
    size_t size;
    size_t written;

    if(!rsa || !signature || !signature_len)
        return -1;

    size = crown_rsa_size(rsa);
    if(!size)
        return -1;

    sig = LIBSSH2_ALLOC(session, size);
    if(!sig)
        return -1;

    written = crown_rsa_sign_digest(rsa, hash, hash_len, sig, size);
    if(!written) {
        LIBSSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = written;
    return 0;
}

int _libssh2_rsa_sha2_verify(libssh2_rsa_ctx *rsa, size_t hash_len, const unsigned char *sig, size_t sig_len, const unsigned char *m, size_t m_len) {
    unsigned char digest[64];

    if(!rsa || !sig || !m || hash_len > sizeof(digest))
        return -1;

    /* Unlike the signing side (which the core pre-hashes), verification
     * data arrives unhashed; `hash_len` names the hash. */
    if(crown_hash_by_digest_len(hash_len, m, m_len, digest))
        return -1;

    return crown_rsa_verify_digest(rsa, digest, hash_len, sig, sig_len) == 1
               ? 0
               : -1;
}

void _libssh2_rsa_free(libssh2_rsa_ctx *rsa) {
    if(rsa)
        crown_rsa_free(rsa);
}

/*******************************************************************/
/*
 * Private key files
 */

enum crown_key_kind {
    CROWN_KEY_UNKNOWN = 0,
    CROWN_KEY_RSA,
    CROWN_KEY_ECDSA,
    CROWN_KEY_ED25519
};

/*
 * Decode an already-parsed OpenSSH private key (the container libssh2 decodes
 * in src/pem.c, including bcrypt-pbkdf for encrypted keys) and build the
 * matching crown key handle.
 *
 * `want` selects the key type the caller needs (CROWN_KEY_UNKNOWN accepts
 * any). On success `*kind` and `*handle` describe the loaded key; the
 * handle must be released with the matching _libssh2_*_free() call.
 */
static int crown_key_from_decoded(LIBSSH2_SESSION *session, struct string_buf *decrypted, enum crown_key_kind want, enum crown_key_kind *kind, void **handle) {
    unsigned char *name = NULL;
    size_t name_len = 0;

    if(_libssh2_get_string(decrypted, &name, &name_len))
        return -1;

    if(name_len == 11 && !memcmp(name, "ssh-ed25519", 11)) {
        unsigned char *pub = NULL;
        unsigned char *priv = NULL;
        size_t pub_len = 0;
        size_t priv_len = 0;
        libssh2_ed25519_ctx *ctx;

        if(want != CROWN_KEY_UNKNOWN && want != CROWN_KEY_ED25519)
            return -1;

        /* public 32 bytes, then the 64-byte seed||public blob */
        if(_libssh2_get_string(decrypted, &pub, &pub_len) ||
           _libssh2_get_string(decrypted, &priv, &priv_len))
            return -1;
        if(pub_len != LIBSSH2_ED25519_KEY_LEN ||
           priv_len < LIBSSH2_ED25519_KEY_LEN)
            return -1;

        ctx = LIBSSH2_CALLOC(session, sizeof(*ctx));
        if(!ctx)
            return -1;
        ctx->session = session;
        memcpy(ctx->public_key, pub, LIBSSH2_ED25519_KEY_LEN);
        memcpy(ctx->private_key, priv, LIBSSH2_ED25519_KEY_LEN);
        ctx->has_private = 1;

        *kind = CROWN_KEY_ED25519;
        *handle = ctx;
        return 0;
    } else if(name_len == 7 && !memcmp(name, "ssh-rsa", 7)) {
        unsigned char *n = NULL, *e = NULL, *d = NULL, *iqmp = NULL;
        unsigned char *p = NULL, *q = NULL;
        size_t n_len, e_len, d_len, iqmp_len, p_len, q_len;
        struct RsaKeyHandle *key;

        if(want != CROWN_KEY_UNKNOWN && want != CROWN_KEY_RSA)
            return -1;

        /* OpenSSH order: n, e, d, iqmp, p, q */
        if(_libssh2_get_bignum_bytes(decrypted, &n, &n_len) ||
           _libssh2_get_bignum_bytes(decrypted, &e, &e_len) ||
           _libssh2_get_bignum_bytes(decrypted, &d, &d_len) ||
           _libssh2_get_bignum_bytes(decrypted, &iqmp, &iqmp_len) ||
           _libssh2_get_bignum_bytes(decrypted, &p, &p_len) ||
           _libssh2_get_bignum_bytes(decrypted, &q, &q_len))
            return -1;

        key = crown_rsa_new_private(n, n_len, e, e_len, d, d_len, p, p_len, q, q_len, NULL, 0, NULL, 0, iqmp, iqmp_len);
        if(!key)
            return -1;
        *kind = CROWN_KEY_RSA;
        *handle = key;
        return 0;
    } else if(name_len > 12 && name_len < 32 &&
              !memcmp(name, "ecdsa-sha2-", 11)) {
        char namestr[32];
        unsigned char *curvebuf = NULL;
        unsigned char *point = NULL;
        unsigned char *exponent = NULL;
        size_t curvebuf_len, point_len, exponent_len;
        libssh2_curve_type curve;
        struct EcKeyHandle *key;

        if(want != CROWN_KEY_UNKNOWN && want != CROWN_KEY_ECDSA)
            return -1;

        memcpy(namestr, name, name_len);
        namestr[name_len] = '\0';
        if(_libssh2_ecdsa_curve_type_from_name(namestr, &curve))
            return -1;

        if(_libssh2_get_string(decrypted, &curvebuf, &curvebuf_len) ||
           _libssh2_get_string(decrypted, &point, &point_len) ||
           _libssh2_get_bignum_bytes(decrypted, &exponent, &exponent_len))
            return -1;

        key = crown_ec_key_new((uint32_t)curve, exponent, exponent_len, point, point_len);
        if(!key)
            return -1;
        *kind = CROWN_KEY_ECDSA;
        *handle = key;
        return 0;
    }

    return -1;
}

static int crown_load_key_file(LIBSSH2_SESSION *session, const char *filename, const char *passphrase, enum crown_key_kind want, enum crown_key_kind *kind, void **handle) {
    struct string_buf *decrypted = NULL;
    FILE *fp;
    int ret;

    fp = fopen(filename, "r");
    if(!fp) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE, "Unable to open private key file");
        return -1;
    }

    ret = _libssh2_openssh_pem_parse(session, (const unsigned char *)passphrase, fp, &decrypted);
    fclose(fp);
    if(ret) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to parse private key (only OpenSSH format is "
                       "supported by the crown backend)");
        return -1;
    }

    ret = crown_key_from_decoded(session, decrypted, want, kind, handle);
    if(ret)
        _libssh2_error_flags(session, LIBSSH2_ERROR_FILE, "Unable to decode private key", LIBSSH2_ERR_FLAG_DUP);

    _libssh2_string_buf_free(session, decrypted);
    return ret;
}

static int crown_load_key_memory(LIBSSH2_SESSION *session, const char *privkeyblob, size_t privkeyblob_len, const char *passphrase, enum crown_key_kind want, enum crown_key_kind *kind, void **handle) {
    struct string_buf *decrypted = NULL;
    int ret;

    if(_libssh2_openssh_pem_parse_memory(session, (const unsigned char *)passphrase, privkeyblob, privkeyblob_len, &decrypted)) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to parse private key (only OpenSSH format is "
                       "supported by the crown backend)");
        return -1;
    }

    ret = crown_key_from_decoded(session, decrypted, want, kind, handle);
    if(ret)
        _libssh2_error_flags(session, LIBSSH2_ERROR_FILE, "Unable to decode private key", LIBSSH2_ERR_FLAG_DUP);

    _libssh2_string_buf_free(session, decrypted);
    return ret;
}

/*
 * Build the SSH public key blob (RFC 4253 wire format) and the matching
 * algorithm name for a loaded key. `*method` is a session allocation and is
 * not NUL-terminated; its length is returned through `*method_len`.
 */
static int crown_pubkey_blob(LIBSSH2_SESSION *session, enum crown_key_kind kind, void *handle, unsigned char **method, size_t *method_len, unsigned char **pubkeydata, size_t *pubkeydata_len) {
    unsigned char *p = NULL;
    unsigned char *blob = NULL;
    unsigned char *method_buf = NULL;
    size_t blob_len = 0;
    const char *method_name = NULL;
    size_t method_name_len = 0;

    if(kind == CROWN_KEY_ED25519) {
        libssh2_ed25519_ctx *ctx = (libssh2_ed25519_ctx *)handle;
        method_name = "ssh-ed25519";
        method_name_len = 11;
        blob_len = 4 + method_name_len + 4 + LIBSSH2_ED25519_KEY_LEN;
        blob = LIBSSH2_ALLOC(session, blob_len);
        if(!blob)
            return -1;
        p = blob;
        _libssh2_store_str(&p, method_name, method_name_len);
        _libssh2_store_str(&p, (const char *)ctx->public_key, LIBSSH2_ED25519_KEY_LEN);
    } else if(kind == CROWN_KEY_ECDSA) {
        libssh2_curve_type curve =
            _libssh2_ecdsa_get_curve_type((libssh2_ecdsa_ctx *)handle);
        const char *curve_name = crown_curve_name(curve);
        unsigned char point[EC_MAX_POINT_LEN];
        size_t point_len;

        method_name = crown_ecdsa_method_name(curve);
        if(!method_name || !curve_name)
            return -1;
        method_name_len = strlen(method_name);

        point_len = crown_ec_key_public(handle, point, sizeof(point));
        if(!point_len)
            return -1;

        blob_len = 4 + method_name_len + 4 + strlen(curve_name) + 4 +
                   point_len;
        blob = LIBSSH2_ALLOC(session, blob_len);
        if(!blob)
            return -1;
        p = blob;
        _libssh2_store_str(&p, method_name, method_name_len);
        _libssh2_store_str(&p, curve_name, strlen(curve_name));
        _libssh2_store_str(&p, (const char *)point, point_len);
    } else if(kind == CROWN_KEY_RSA) {
        unsigned char *n;
        unsigned char *e;
        size_t n_cap;
        size_t n_len;
        size_t e_len;

        method_name = "ssh-rsa";
        method_name_len = 7;

        n_cap = crown_rsa_size(handle);
        if(!n_cap)
            return -1;
        n = LIBSSH2_ALLOC(session, n_cap);
        e = LIBSSH2_ALLOC(session, 16);
        if(!n || !e) {
            LIBSSH2_FREE(session, n);
            LIBSSH2_FREE(session, e);
            return -1;
        }

        n_len = crown_rsa_n(handle, n, n_cap);
        e_len = crown_rsa_e(handle, e, 16);
        if(!n_len || !e_len) {
            LIBSSH2_FREE(session, n);
            LIBSSH2_FREE(session, e);
            return -1;
        }

        /* 4 + method + 4 + mpint(e) + 4 + mpint(n); each mpint may need
         * one extra leading zero byte. */
        blob_len = 4 + method_name_len + 4 + e_len + 1 + 4 + n_len + 1;
        blob = LIBSSH2_ALLOC(session, blob_len);
        if(!blob) {
            LIBSSH2_FREE(session, n);
            LIBSSH2_FREE(session, e);
            return -1;
        }
        p = blob;
        _libssh2_store_str(&p, method_name, method_name_len);
        /* The store helpers return 1 on success. */
        if(!_libssh2_store_bignum2_bytes(&p, e, e_len) ||
           !_libssh2_store_bignum2_bytes(&p, n, n_len)) {
            LIBSSH2_FREE(session, n);
            LIBSSH2_FREE(session, e);
            LIBSSH2_FREE(session, blob);
            return -1;
        }
        LIBSSH2_FREE(session, n);
        LIBSSH2_FREE(session, e);
        blob_len = (size_t)(p - blob);
    } else {
        return -1;
    }

    method_buf = LIBSSH2_ALLOC(session, method_name_len + 1);
    if(!method_buf) {
        LIBSSH2_FREE(session, blob);
        return -1;
    }
    memcpy(method_buf, method_name, method_name_len);
    method_buf[method_name_len] = '\0';

    *method = method_buf;
    *method_len = method_name_len;
    *pubkeydata = blob;
    *pubkeydata_len = blob_len;
    return 0;
}

static void crown_free_loaded_key(LIBSSH2_SESSION *session, enum crown_key_kind kind, void *handle) {
    (void)session;

    switch(kind) {
        case CROWN_KEY_RSA:
            _libssh2_rsa_free((libssh2_rsa_ctx *)handle);
            break;
        case CROWN_KEY_ECDSA:
            _libssh2_ecdsa_free((libssh2_ecdsa_ctx *)handle);
            break;
        case CROWN_KEY_ED25519:
            _libssh2_ed25519_free((libssh2_ed25519_ctx *)handle);
            break;
        default:
            break;
    }
}

int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session, unsigned char **method, size_t *method_len, unsigned char **pubkeydata, size_t *pubkeydata_len, const char *privatekey, const char *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;
    int ret;

    if(!method || !method_len || !pubkeydata || !pubkeydata_len)
        return -1;

    if(crown_load_key_file(session, privatekey, passphrase, CROWN_KEY_UNKNOWN, &kind, &handle))
        return -1;

    ret = crown_pubkey_blob(session, kind, handle, method, method_len, pubkeydata, pubkeydata_len);

    crown_free_loaded_key(session, kind, handle);
    return ret;
}

int _libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session, unsigned char **method, size_t *method_len, unsigned char **pubkeydata, size_t *pubkeydata_len, const char *privatekeydata, size_t privatekeydata_len, const char *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;
    int ret;

    if(!method || !method_len || !pubkeydata || !pubkeydata_len ||
       !privatekeydata)
        return -1;

    if(crown_load_key_memory(session, privatekeydata, privatekeydata_len, passphrase, CROWN_KEY_UNKNOWN, &kind, &handle))
        return -1;

    ret = crown_pubkey_blob(session, kind, handle, method, method_len, pubkeydata, pubkeydata_len);

    crown_free_loaded_key(session, kind, handle);
    return ret;
}

int _libssh2_rsa_new_private(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session, const char *filename, unsigned const char *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;

    if(!rsa)
        return -1;

    if(crown_load_key_file(session, filename, (const char *)passphrase, CROWN_KEY_RSA, &kind, &handle))
        return -1;

    *rsa = handle;
    return 0;
}

int _libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session, const char *filedata, size_t filedata_len, unsigned const char *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;

    if(!rsa || !filedata)
        return -1;

    if(crown_load_key_memory(session, filedata, filedata_len, (const char *)passphrase, CROWN_KEY_RSA, &kind, &handle))
        return -1;

    *rsa = handle;
    return 0;
}

int _libssh2_ecdsa_new_private(libssh2_ecdsa_ctx **ec_ctx, LIBSSH2_SESSION *session, const char *filename, unsigned const char *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;

    if(!ec_ctx)
        return -1;

    if(crown_load_key_file(session, filename, (const char *)passphrase, CROWN_KEY_ECDSA, &kind, &handle))
        return -1;

    *ec_ctx = handle;
    return 0;
}

int _libssh2_ecdsa_new_private_frommemory(libssh2_ecdsa_ctx **ec_ctx, LIBSSH2_SESSION *session, const char *filedata, size_t filedata_len, unsigned const char *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;

    if(!ec_ctx || !filedata)
        return -1;

    if(crown_load_key_memory(session, filedata, filedata_len, (const char *)passphrase, CROWN_KEY_ECDSA, &kind, &handle))
        return -1;

    *ec_ctx = handle;
    return 0;
}

int _libssh2_ed25519_new_private(libssh2_ed25519_ctx **ed_ctx, LIBSSH2_SESSION *session, const char *filename, const uint8_t *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;

    if(!ed_ctx)
        return -1;

    if(crown_load_key_file(session, filename, (const char *)passphrase, CROWN_KEY_ED25519, &kind, &handle))
        return -1;

    *ed_ctx = handle;
    return 0;
}

int _libssh2_ed25519_new_private_frommemory(libssh2_ed25519_ctx **ed_ctx, LIBSSH2_SESSION *session, const char *filedata, size_t filedata_len, unsigned const char *passphrase) {
    enum crown_key_kind kind = CROWN_KEY_UNKNOWN;
    void *handle = NULL;

    if(!ed_ctx || !filedata)
        return -1;

    if(crown_load_key_memory(session, filedata, filedata_len, (const char *)passphrase, CROWN_KEY_ED25519, &kind, &handle))
        return -1;

    *ed_ctx = handle;
    return 0;
}

int _libssh2_sk_pub_keyfilememory(LIBSSH2_SESSION *session, unsigned char **method, size_t *method_len, unsigned char **pubkeydata, size_t *pubkeydata_len, int *algorithm, unsigned char *flags, const char **application, const unsigned char **key_handle, size_t *handle_len, const char *privatekeydata, size_t privatekeydata_len, const char *passphrase) {
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)privatekeydata;
    (void)privatekeydata_len;
    (void)passphrase;

    return _libssh2_error_flags(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                                "FIDO security-key algorithms are not "
                                "supported by the crown backend",
                                LIBSSH2_ERR_FLAG_DUP);
}

/*******************************************************************/
/*
 * Public key signature algorithm upgrades
 */

const char *_libssh2_supported_key_sign_algorithms(
    LIBSSH2_SESSION *session,
    unsigned char *key_method,
    size_t key_method_len
) {
    (void)session;

#if LIBSSH2_RSA_SHA2
    if(key_method && key_method_len == 7 &&
       memcmp(key_method, "ssh-rsa", key_method_len) == 0) {
        return "rsa-sha2-512,rsa-sha2-256"
#if LIBSSH2_RSA_SHA1
               ",ssh-rsa"
#endif
            ;
    }
#else
    (void)key_method;
    (void)key_method_len;
#endif

    return NULL;
}
