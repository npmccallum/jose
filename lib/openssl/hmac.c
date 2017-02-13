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

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <string.h>

#define NAMES "HS256", "HS384", "HS512"

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
    const char *kty = NULL;
    const char *alg = NULL;
    json_t *bytes = NULL;
    json_int_t len = 0;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bytes", &bytes) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: len = 32; break;
    case 1: len = 48; break;
    case 2: len = 64; break;
    default: return true;
    }

    if (!kty && json_object_set_new(jwk, "kty", json_string("oct")) == -1)
        return false;
    if (kty && strcmp(kty, "oct") != 0)
        return false;

    if (!bytes && json_object_set_new(jwk, "bytes", json_integer(len)) == -1)
        return false;
    if (bytes && (!json_is_integer(bytes) || json_integer_value(bytes) < len))
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
    const char *k = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    len = jose_b64_dlen(strlen(k));

    /* Round down to the nearest hash length. */
    len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;
    len &= SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH;

    switch (len) {
    case SHA512_DIGEST_LENGTH: return "HS512";
    case SHA384_DIGEST_LENGTH: return "HS384";
    case SHA256_DIGEST_LENGTH: return "HS256";
    default: return NULL;
    }
}

static void
sig_free(jose_jws_sctx_hook_t *sctx)
{
    HMAC_CTX_free((HMAC_CTX *) sctx);
}

static jose_jws_sctx_hook_t *
sig_init(jose_ctx_t *ctx, const json_t *jwk, const char *alg)
{
    jose_buf_auto_t *key = NULL;
    const EVP_MD *md = NULL;
    HMAC_CTX *hctx = NULL;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return NULL;
    }

    key = jose_b64_decode_json(json_object_get(jwk, "k"));
    if (!key) {
        jose_ctx_err(ctx, "Error decoding JWK");
        return NULL;
    }

    if (key->size < (size_t) EVP_MD_size(md)) {
        jose_ctx_err(ctx, "Key is too small");
        return NULL;
    }

    hctx = HMAC_CTX_new();
    if (!hctx)
        return NULL;

    if (HMAC_Init_ex(hctx, key->data, key->size, md, NULL) <= 0) {
        jose_ctx_err(ctx, "Error initializing HMAC_CTX");
        HMAC_CTX_free(hctx);
        return NULL;
    }

    return (jose_jws_sctx_hook_t *) hctx;
}

static bool
sig_push(jose_jws_sctx_hook_t *sctx, const char *data)
{
    HMAC_CTX *hctx = (HMAC_CTX *) sctx;
    return HMAC_Update(hctx, (uint8_t *) data, strlen(data)) > 0;
}

static jose_buf_t *
sig_done(jose_jws_sctx_hook_t *sctx)
{
    HMAC_CTX *hctx = (HMAC_CTX *) sctx;
    jose_buf_auto_t *s = NULL;
    unsigned int i = 0;

    s = jose_buf(EVP_MD_size(HMAC_CTX_get_md(hctx)), JOSE_BUF_FLAG_WIPE);
    if (!s)
        return NULL;

    if (HMAC_Final(hctx, s->data, &i) <= 0)
        return NULL;

    return jose_buf_incref(s);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .handles = handles,
        .resolve = resolve
    };

    static jose_jws_signer_t signers[] = {
        { NULL, "HS256", suggest, sig_init, sig_push, sig_done, sig_free },
        { NULL, "HS384", suggest, sig_init, sig_push, sig_done, sig_free },
        { NULL, "HS512", suggest, sig_init, sig_push, sig_done, sig_free },
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; signers[i].alg; i++)
        jose_jws_register_signer(&signers[i]);
}
