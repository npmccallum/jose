/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "misc.h"
#include <jose/hooks.h>
#include <jose/openssl.h>

#include <string.h>

#define NAMES "ES256", "ES384", "ES512"

struct jose_jws_sctx_hook {
    EVP_MD_CTX *ctx;
    EC_KEY *key;
};

struct jose_jws_vctx_hook {
    jose_jws_sctx_hook_t sctx;
    ECDSA_SIG *sig;
};

declare_cleanup(ECDSA_SIG)

static bool
handles(jose_ctx_t *ctx, json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack(jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) < 3;
}

static bool
resolve(jose_ctx_t *ctx, json_t *jwk)
{
    json_auto_t *upd = NULL;
    const char *alg = NULL;
    const char *crv = NULL;
    const char *kty = NULL;
    const char *grp = NULL;

    if (json_unpack(jwk, "{s?s,s?s,s?s}",
                    "kty", &kty, "alg", &alg, "crv", &crv) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: grp = "P-256"; break;
    case 1: grp = "P-384"; break;
    case 2: grp = "P-521"; break;
    default: return true;
    }

    if (!kty && json_object_set_new(jwk, "kty", json_string("EC")) == -1)
        return false;
    if (kty && strcmp(kty, "EC") != 0)
        return false;

    if (!crv && json_object_set_new(jwk, "crv", json_string(grp)) == -1)
        return false;
    if (crv && strcmp(crv, grp) != 0)
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "sig", "key_ops",
                    "sign", "verify");
    if (!upd)
        return false;

    return json_object_update_missing(jwk, upd) == 0;
}

static const char *
suggest(jose_ctx_t *ctx, const json_t *jwk)
{
    const char *kty = NULL;
    const char *crv = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}",
                    "kty", &kty, "crv", &crv) == -1)
        return NULL;

    if (strcmp(kty, "EC") != 0)
        return NULL;

    switch (str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: return "ES256";
    case 1: return "ES384";
    case 2: return "ES512";
    default: return NULL;
    }
}

static bool
setup(jose_ctx_t *ctx, const json_t *jwk, const char *alg,
      jose_jws_sctx_hook_t *sctx)
{
    const EVP_MD *md = NULL;
    const char *req = NULL;

    sctx->key = jose_openssl_jwk_to_EC_KEY(jwk);
    if (!sctx->key)
        return false;

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(sctx->key))) {
    case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
    case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
    case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
    default: return false;
    }

    if (strcmp(alg, req) != 0)
        return false;

    sctx->ctx = EVP_MD_CTX_new();
    if (!sctx->ctx)
        return false;

    return EVP_DigestInit(sctx->ctx, md) > 0;
}

static void
sig_free(jose_jws_sctx_hook_t *sctx)
{
    if (!sctx)
        return;

    EVP_MD_CTX_free(sctx->ctx);
    EC_KEY_free(sctx->key);
    free(sctx);
}

static jose_jws_sctx_hook_t *
sig_init(jose_ctx_t *ctx, const json_t *jwk, const char *alg)
{
    jose_jws_sctx_hook_t *sctx = NULL;

    sctx = calloc(1, sizeof(*sctx));
    if (!sctx)
        return NULL;

    if (setup(ctx, jwk, alg, sctx))
        return sctx;

    sig_free(sctx);
    return NULL;
}

static bool
sig_push(jose_jws_sctx_hook_t *sctx, const char *data)
{
    return EVP_DigestUpdate(sctx->ctx,
                            (const uint8_t *) data,
                            strlen(data)) > 0;
}

static jose_buf_t *
sig_done(jose_jws_sctx_hook_t *sctx)
{
    uint8_t hash[EVP_MD_size(EVP_MD_CTX_md(sctx->ctx))];
    openssl_auto(ECDSA_SIG) *ecdsa = NULL;
    jose_buf_auto_t *sig = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    unsigned int hlen = 0;
    int degree = 0;

    if (EVP_DigestFinal(sctx->ctx, hash, &hlen) <= 0)
        goto error;

    degree = EC_GROUP_get_degree(EC_KEY_get0_group(sctx->key));
    sig = jose_buf((degree + 7) / 8 * 2, JOSE_BUF_FLAG_WIPE);
    if (!sig)
        goto error;

    ecdsa = ECDSA_do_sign(hash, hlen, sctx->key);
    if (!ecdsa)
        goto error;

    ECDSA_SIG_get0(ecdsa, &r, &s);

    if (!bn_encode(r, sig->data, sig->size / 2))
        goto error;

    if (!bn_encode(s, &sig->data[sig->size / 2], sig->size / 2))
        goto error;

    sig_free(sctx);
    return jose_buf_incref(sig);

error:
    sig_free(sctx);
    return NULL;
}

static void
ver_free(jose_jws_vctx_hook_t *vctx)
{
    if (!vctx)
        return;

    EVP_MD_CTX_free(vctx->sctx.ctx);
    EC_KEY_free(vctx->sctx.key);
    ECDSA_SIG_free(vctx->sig);
    free(vctx);
}

static jose_jws_vctx_hook_t *
ver_init(jose_ctx_t *ctx, const json_t *jwk, const char *alg, jose_buf_t *sig)
{
    jose_jws_vctx_hook_t *vctx = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;

    vctx = calloc(1, sizeof(*vctx));
    if (!vctx)
        return NULL;

    vctx->sig = ECDSA_SIG_new();
    if (!vctx->sig)
        goto error;

    r = bn_decode(sig->data, sig->size / 2);
    s = bn_decode(&sig->data[sig->size / 2], sig->size / 2);
    if (ECDSA_SIG_set0(vctx->sig, r, s) <= 0) {
        BN_free(r);
        BN_free(s);
        goto error;
    }

    if (setup(ctx, jwk, alg, &vctx->sctx))
        return vctx;

error:
    ver_free(vctx);
    return NULL;
}

static bool
ver_push(jose_jws_vctx_hook_t *vctx, const char *data)
{
    return EVP_DigestUpdate(vctx->sctx.ctx,
                            (const uint8_t *) data,
                            strlen(data)) > 0;
}

static bool
ver_done(jose_jws_vctx_hook_t *vctx)
{
    uint8_t hash[EVP_MD_size(EVP_MD_CTX_md(vctx->sctx.ctx))];
    unsigned int hlen = 0;
    bool ret = false;

    if (EVP_DigestFinal(vctx->sctx.ctx, hash, &hlen) > 0)
        ret = ECDSA_do_verify(hash, hlen, vctx->sig, vctx->sctx.key) == 1;

    ver_free(vctx);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .handles = handles,
        .resolve = resolve
    };

    static jose_jws_signer_t signers[] = {
        { NULL, "ES256", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        { NULL, "ES384", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        { NULL, "ES512", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; signers[i].alg; i++)
        jose_jws_register_signer(&signers[i]);
}
