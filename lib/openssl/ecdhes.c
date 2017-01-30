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

#include <openssl/rand.h>

#include <string.h>

#define NAMES "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"

declare_cleanup(EVP_MD_CTX)
declare_cleanup(EC_POINT)
declare_cleanup(EC_KEY)
declare_cleanup(BN_CTX)

static json_t *
exchange(jose_ctx_t *ctx, const json_t *prv, const json_t *pub)
{
    openssl_auto(EC_KEY) *lcl = NULL;
    openssl_auto(EC_KEY) *rem = NULL;
    openssl_auto(BN_CTX) *bnc = NULL;
    openssl_auto(EC_POINT) *p = NULL;
    const EC_GROUP *grp = NULL;

    bnc = BN_CTX_new();
    if (!bnc)
        return NULL;

    lcl = jose_openssl_jwk_to_EC_KEY(prv);
    if (!lcl)
        return NULL;

    rem = jose_openssl_jwk_to_EC_KEY(pub);
    if (!rem)
        return NULL;

    grp = EC_KEY_get0_group(lcl);
    if (EC_GROUP_cmp(grp, EC_KEY_get0_group(rem), bnc) != 0)
        return NULL;

    p = EC_POINT_new(grp);
    if (!p)
        return NULL;

    if (EC_POINT_mul(grp, p, NULL, EC_KEY_get0_public_key(rem),
                     EC_KEY_get0_private_key(lcl), bnc) <= 0)
        return NULL;

    return jose_openssl_jwk_from_EC_POINT(EC_KEY_get0_group(rem), p, NULL);
}

static bool
concatkdf(const EVP_MD *md, uint8_t dk[], size_t dkl,
          const uint8_t z[], size_t zl, ...)
{
    openssl_auto(EVP_MD_CTX) *ctx = NULL;
    jose_buf_auto_t *hsh = NULL;
    size_t reps = 0;
    size_t left = 0;
    va_list ap;

    hsh = jose_buf(EVP_MD_size(md), JOSE_BUF_FLAG_WIPE);
    if (!hsh)
        return false;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    reps = dkl / hsh->size;
    left = dkl % hsh->size;

    for (uint32_t c = 0; c <= reps; c++) {
        uint32_t cnt = htobe32(c + 1);

        if (EVP_DigestInit_ex(ctx, md, NULL) <= 0)
            return false;

        if (EVP_DigestUpdate(ctx, &cnt, sizeof(cnt)) <= 0)
            return false;

        if (EVP_DigestUpdate(ctx, z, zl) <= 0)
            return false;

        va_start(ap, zl);
        for (void *b = va_arg(ap, void *); b; b = va_arg(ap, void *)) {
            size_t l = va_arg(ap, size_t);
            uint32_t e = htobe32(l);

            if (EVP_DigestUpdate(ctx, &e, sizeof(e)) <= 0) {
                va_end(ap);
                return false;
            }

            if (EVP_DigestUpdate(ctx, b, l) <= 0) {
                va_end(ap);
                return false;
            }
        }
        va_end(ap);

        if (EVP_DigestUpdate(ctx, &(uint32_t) { htobe32(dkl * 8) }, 4) <= 0) {
            va_end(ap);
            return false;
        }

        if (EVP_DigestFinal_ex(ctx, hsh->data, NULL) <= 0)
            return false;

        memcpy(&dk[c * hsh->size], hsh->data, c == reps ? left : hsh->size);
    }

    return true;
}

static bool
handles(jose_ctx_t *ctx, json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack(jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) < 4;
}

static bool
resolve(jose_ctx_t *ctx, json_t *jwk)
{
    const char *alg = NULL;
    const char *crv = NULL;
    const char *kty = NULL;
    const char *grp = NULL;
    json_auto_t *upd = NULL;

    if (json_unpack(jwk, "{s?s,s?s,s?s}",
                    "kty", &kty, "alg", &alg, "crv", &crv) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: grp = "P-256"; break;
    case 1: grp = "P-256"; break;
    case 2: grp = "P-384"; break;
    case 3: grp = "P-521"; break;
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

    upd = json_pack("{s:s,s:[s,s]}", "use", "enc", "key_ops",
                    "wrapKey", "unwrapKey");
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
    case 0: return "ECDH-ES+A128KW";
    case 1: return "ECDH-ES+A192KW";
    case 2: return "ECDH-ES+A256KW";
    default: return NULL;
    }
}

static bool
wrap(jose_ctx_t *ctx, json_t *jwe, json_t *cek, const json_t *jwk,
     json_t *rcp, const char *alg)
{
    jose_buf_auto_t *ky = NULL;
    jose_buf_auto_t *pu = NULL;
    jose_buf_auto_t *pv = NULL;
    jose_buf_auto_t *dk = NULL;
    json_auto_t *tmp = NULL;
    json_auto_t *hdr = NULL;
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    const char *enc = NULL;
    json_t *epk = NULL;
    json_t *h = NULL;

    if (json_object_get(cek, "k")) {
        if (strcmp(alg, "ECDH-ES") == 0)
            return false;
    } else if (!jose_jwk_generate(ctx, cek)) {
        return false;
    }

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: dk = jose_b64_decode_json(json_object_get(cek, "k"));  break;
    case 1: dk = jose_buf(16, JOSE_BUF_FLAG_WIPE); aes = "A128KW"; break;
    case 2: dk = jose_buf(24, JOSE_BUF_FLAG_WIPE); aes = "A192KW"; break;
    case 3: dk = jose_buf(32, JOSE_BUF_FLAG_WIPE); aes = "A256KW"; break;
    default: return false;
    }
    if (!dk)
        return false;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return false;

    if (json_unpack(hdr, "{s?s,s?s,s?s}", "apu", &apu,
                    "apv", &apv, "enc", &enc) == -1)
        return false;

    if (!aes && !enc)
        return false;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        return false;

    epk = json_pack("{s:s,s:O}", "kty", "EC", "crv",
                    json_object_get(jwk, "crv"));
    if (!epk)
        return false;

    if (json_object_set_new(h, "epk", epk) == -1)
        return false;

    if (!jose_jwk_generate(ctx, epk))
        return false;

    tmp = exchange(ctx, epk, jwk);
    if (!tmp)
        return false;

    if (!jose_jwk_clean(ctx, epk))
        return false;

    ky = jose_b64_decode_json(json_object_get(tmp, "x"));
    if (!ky)
        return false;

    pu = jose_b64_decode(apu);
    pv = jose_b64_decode(apv);
    if ((apu && !pu) || (apv && !pv))
        return false;

    if (!concatkdf(EVP_sha256(), dk->data, dk->size, ky->data, ky->size,
                   aes ? alg : enc, strlen(aes ? alg : enc),
                   pu ? pu->data : (uint8_t *) "",
                   pu ? pu->size : 0,
                   pv ? pv->data : (uint8_t *) "",
                   pv ? pv->size : 0, NULL))
        return false;

    json_decref(tmp);
    tmp = json_pack("{s:s,s:o}", "kty", "oct", "k",
                    jose_b64_encode_json(dk->data, dk->size));
    if (!tmp)
        return false;

    if (aes) {
        for (jose_jwe_wrapper_t *w = jose_jwe_wrappers(); w; w = w->next) {
            if (strcmp(aes, w->alg) == 0)
                return w->wrap(ctx, jwe, cek, tmp, rcp, aes);
        }

        return false;
    }

    return json_object_update(cek, tmp) == 0;
}

static jose_buf_t *
get_dk(jose_ctx_t *ctx, const json_t *jwe, const json_t *rcp)
{
    json_auto_t *head = NULL;
    json_auto_t *jwk = NULL;
    const char *enc = NULL;

    head = jose_jwe_merge_header(jwe, rcp);
    if (!head)
        return NULL;

    if (json_unpack(head, "{s:s}", "enc", &enc) == -1)
        return NULL;

    jwk = json_pack("{s:s}", "alg", enc);
    if (!jwk)
        return NULL;

    if (!jose_jwk_generate(ctx, jwk))
        return NULL;

    if (!json_is_string(json_object_get(jwk, "k")))
        return NULL;

    return jose_b64_decode_json(json_object_get(jwk, "k"));
}

static bool
unwrap(jose_ctx_t *ctx, const json_t *jwe, const json_t *jwk,
       const json_t *rcp, const char *alg, json_t *cek)
{
    jose_buf_auto_t *ky = NULL;
    jose_buf_auto_t *pu = NULL;
    jose_buf_auto_t *pv = NULL;
    jose_buf_auto_t *dk = NULL;
    json_auto_t *tmp = NULL;
    json_auto_t *hdr = NULL;
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    const char *enc = NULL;
    json_t *epk = NULL;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: dk = get_dk(ctx, jwe, rcp);  break;
    case 1: dk = jose_buf(16, JOSE_BUF_FLAG_WIPE); aes = "A128KW"; break;
    case 2: dk = jose_buf(24, JOSE_BUF_FLAG_WIPE); aes = "A192KW"; break;
    case 3: dk = jose_buf(32, JOSE_BUF_FLAG_WIPE); aes = "A256KW"; break;
    default: return false;
    }
    if (!dk)
        return false;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (json_unpack(hdr, "{s:o,s?s,s?s,s:s}", "epk", &epk, "apu", &apu,
                    "apv", &apv, "enc", &enc) == -1)
        return false;

    if (!aes && !enc)
        return false;

    pu = jose_b64_decode(apu);
    pv = jose_b64_decode(apv);
    if ((apu && !pu) || (apv && !pv))
        return false;

    /* If the JWK has a private key, perform the normal exchange. */
    if (json_object_get(jwk, "d"))
        tmp = exchange(ctx, jwk, epk);

    /* Otherwise, allow external exchanges. */
    else if (json_equal(json_object_get(jwk, "crv"),
                        json_object_get(epk, "crv")))
        tmp = json_deep_copy(jwk);

    ky = jose_b64_decode_json(json_object_get(tmp, "x"));
    if (!ky)
        return false;

    if (!concatkdf(EVP_sha256(), dk->data, dk->size, ky->data, ky->size,
                   aes ? alg : enc, strlen(aes ? alg : enc),
                   pu ? pu->data : (uint8_t *) "",
                   pu ? pu->size : 0,
                   pv ? pv->data : (uint8_t *) "",
                   pv ? pv->size : 0, NULL))
        return false;

    json_decref(tmp);
    tmp = json_pack("{s:s,s:o}", "kty", "oct", "k",
                    jose_b64_encode_json(dk->data, dk->size));
    if (!tmp)
        return false;

    if (aes) {
        for (jose_jwe_wrapper_t *w = jose_jwe_wrappers(); w; w = w->next) {
            if (strcmp(aes, w->alg) == 0)
                return w->unwrap(ctx, jwe, tmp, rcp, aes, cek);
        }

        return false;
    }

    return json_object_update_missing(cek, tmp) == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_exchanger_t exchanger = {
        .exchange = exchange
    };

    static jose_jwk_resolver_t resolver = {
        .handles = handles,
        .resolve = resolve
    };

    static jose_jwe_wrapper_t wrappers[] = {
        { NULL, "ECDH-ES", suggest, wrap, unwrap },
        { NULL, "ECDH-ES+A128KW", suggest, wrap, unwrap },
        { NULL, "ECDH-ES+A192KW", suggest, wrap, unwrap },
        { NULL, "ECDH-ES+A256KW", suggest, wrap, unwrap },
        {}
    };

    jose_jwk_register_exchanger(&exchanger);
    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; wrappers[i].alg; i++)
        jose_jwe_register_wrapper(&wrappers[i]);
}
