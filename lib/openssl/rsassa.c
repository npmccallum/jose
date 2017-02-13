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

#include <openssl/sha.h>

#include <string.h>

#define NAMES "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"

typedef typeof(EVP_DigestSignInit) initfnc_t;

struct jose_jws_vctx_hook {
    EVP_MD_CTX *ctx;
    jose_buf_t *sig;
};

declare_cleanup(EVP_PKEY)

static bool
handles(jose_ctx_t *ctx, json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack(jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) < 7;
}

static bool
resolve(jose_ctx_t *ctx, json_t *jwk)
{
    json_auto_t *upd = NULL;
    const char *alg = NULL;
    const char *kty = NULL;

    if (json_unpack(jwk, "{s?s,s?s}", "kty", &kty, "alg", &alg) == -1)
        return false;

    if (str2enum(alg, NAMES, NULL) >= 6)
        return true;

    if (!kty && json_object_set_new(jwk, "kty", json_string("RSA")) == -1)
        return false;
    if (kty && strcmp(kty, "RSA") != 0)
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
    const char *n = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "n", &n) == -1)
        return NULL;

    if (strcmp(kty, "RSA") != 0)
        return NULL;

    len = jose_b64_dlen(strlen(n)) * 8;

    switch ((len < 4096 ? len : 4096) & (4096 | 3072 | 2048)) {
    case 4096: return "RS512";
    case 3072: return "RS384";
    case 2048: return "RS256";
    default: return NULL;
    }
}

static EVP_MD_CTX *
setup(const json_t *jwk, const char *alg, initfnc_t *func)
{
    openssl_auto(EVP_PKEY) *key = NULL;
    EVP_PKEY_CTX *epc = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *emc = NULL;
    const RSA *rsa = NULL;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
    default: return NULL;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    /* Don't use small keys. RFC 7518 3.3 */
    rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
        return NULL;
    if (RSA_size(rsa) < 2048 / 8)
        return NULL;

    emc = EVP_MD_CTX_new();
    if (!emc)
        return NULL;

    if (func(emc, &epc, md, NULL, key) <= 0) {
        EVP_MD_CTX_free(emc);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(epc, pad) <= 0) {
        EVP_MD_CTX_free(emc);
        return NULL;
    }

    return emc;
}

static void
sig_free(jose_jws_sctx_hook_t *sctx)
{
    EVP_MD_CTX_free((EVP_MD_CTX *) sctx);
}

static jose_jws_sctx_hook_t *
sig_init(jose_ctx_t *ctx, const json_t *jwk, const char *alg)
{
    return (jose_jws_sctx_hook_t *) setup(jwk, alg, EVP_DigestSignInit);
}

static bool
sig_push(jose_jws_sctx_hook_t *sctx, const char *data)
{
    return EVP_DigestSignUpdate((EVP_MD_CTX *) sctx, data, strlen(data)) > 0;
}

static jose_buf_t *
sig_done(jose_jws_sctx_hook_t *sctx)
{
    jose_buf_auto_t *sig = NULL;
    size_t len = 0;

    if (EVP_DigestSignFinal((EVP_MD_CTX *) sctx, NULL, &len) <= 0)
        goto error;

    sig = jose_buf(len, JOSE_BUF_FLAG_WIPE);
    if (!sig)
        goto error;

    if (EVP_DigestSignFinal((EVP_MD_CTX *) sctx, sig->data, &len) <= 0)
        goto error;

    if (sig->size != len)
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

    EVP_MD_CTX_free(vctx->ctx);
    jose_buf_decref(vctx->sig);
    free(vctx);
}

static jose_jws_vctx_hook_t *
ver_init(jose_ctx_t *ctx, const json_t *jwk, const char *alg, jose_buf_t *sig)
{
    jose_jws_vctx_hook_t *vctx = NULL;

    vctx = calloc(1, sizeof(*vctx));
    if (!vctx)
        return NULL;

    vctx->ctx = setup(jwk, alg, EVP_DigestVerifyInit);
    if (!vctx->ctx) {
        free(vctx);
        return NULL;
    }

    vctx->sig = jose_buf_incref(sig);
    return vctx;
}

static bool
ver_push(jose_jws_vctx_hook_t *vctx, const char *data)
{
    return EVP_DigestVerifyUpdate(vctx->ctx, data, strlen(data)) > 0;
}

static bool
ver_done(jose_jws_vctx_hook_t *vctx)
{
    int i = 0;

    i = EVP_DigestVerifyFinal(vctx->ctx, vctx->sig->data, vctx->sig->size);
    ver_free(vctx);
    return i == 1;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .handles = handles,
        .resolve = resolve
    };

    static jose_jws_signer_t signers[] = {
        { NULL, "RS256", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        { NULL, "RS384", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        { NULL, "RS512", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        { NULL, "PS256", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        { NULL, "PS384", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        { NULL, "PS512", suggest,
            sig_init, sig_push, sig_done, sig_free,
            ver_init, ver_push, ver_done, ver_free },
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; signers[i].alg; i++)
        jose_jws_register_signer(&signers[i]);
}
