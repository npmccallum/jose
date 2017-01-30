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

#include <string.h>

#define NAMES "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"

static const char *
suggest(jose_ctx_t *ctx, const json_t *jwk)
{
    if (!json_is_string(jwk))
        return NULL;

    return "PBES2-HS256+A128KW";
}

static json_t *
pbkdf2(jose_ctx_t *ctx, const json_t *jwk, const char *alg, int iter,
       uint8_t st[], size_t stl)
{
    jose_buf_auto_t *slt = NULL;
    jose_buf_auto_t *dk = NULL;
    const EVP_MD *md = NULL;

    if (!json_is_string(jwk))
        return NULL;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); dk = jose_buf(16, JOSE_BUF_FLAG_WIPE); break;
    case 1: md = EVP_sha384(); dk = jose_buf(24, JOSE_BUF_FLAG_WIPE); break;
    case 2: md = EVP_sha512(); dk = jose_buf(32, JOSE_BUF_FLAG_WIPE); break;
    default: return NULL;
    }

    if (!dk)
        return NULL;

    slt = jose_buf(strlen(alg) + 1 + stl, JOSE_BUF_FLAG_WIPE);
    if (!slt)
        return NULL;

    memcpy(slt->data, alg, slt->size - stl);
    memcpy(&slt->data[slt->size - stl], st, stl);

    if (PKCS5_PBKDF2_HMAC(json_string_value(jwk), json_string_length(jwk),
                          slt->data, slt->size, iter,
                          md, dk->size, dk->data) > 0)
        return json_pack("{s:s,s:o}", "kty", "oct", "k",
                         jose_b64_encode_json(dk->data, dk->size));

    return NULL;
}

static bool
wrap(jose_ctx_t *ctx, json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp,
     const char *alg)
{
    json_auto_t *key = NULL;
    json_auto_t *hdr = NULL;
    const char *aes = NULL;
    json_t *p2c = NULL;
    json_t *h = NULL;
    size_t stl = 0;
    int iter;

    if (!json_object_get(cek, "k") && !jose_jwk_generate(ctx, cek))
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: aes = "A128KW"; stl = 16; break;
    case 1: aes = "A192KW"; stl = 24; break;
    case 2: aes = "A256KW"; stl = 32; break;
    default: return false;
    }

    uint8_t st[stl];

    if (RAND_bytes(st, stl) <= 0)
        return false;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        return false;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return false;

    p2c = json_object_get(hdr, "p2c");
    if (p2c) {
        if (!json_is_integer(p2c))
            return false;

        iter = json_integer_value(p2c);
        if (iter < 1000)
            return false;
    } else {
        iter = 10000;
        if (json_object_set_new(h, "p2c", json_integer(iter)) == -1)
            return false;
    }

    if (json_object_set_new(h, "p2s", jose_b64_encode_json(st, stl)) == -1)
        return false;

    key = pbkdf2(ctx, jwk, alg, iter, st, stl);
    if (!key)
        return false;

    for (jose_jwe_wrapper_t *w = jose_jwe_wrappers(); w; w = w->next) {
        if (strcmp(aes, w->alg) == 0)
            return w->wrap(ctx, jwe, cek, key, rcp, aes);
    }

    return false;
}

static bool
unwrap(jose_ctx_t *ctx, const json_t *jwe, const json_t *jwk,
       const json_t *rcp, const char *alg, json_t *cek)
{
    jose_buf_auto_t *st = NULL;
    json_auto_t *key = NULL;
    json_auto_t *hdr = NULL;
    const char *aes = NULL;
    const char *p2s = NULL;
    json_int_t p2c = -1;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: aes = "A128KW"; break;
    case 1: aes = "A192KW"; break;
    case 2: aes = "A256KW"; break;
    default: return false;
    }

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return false;

    if (json_unpack(hdr, "{s:s,s:I}", "p2s", &p2s, "p2c", &p2c) == -1)
        return false;

    st = jose_b64_decode(p2s);
    if (!st || st->size < 8)
        return false;

    key = pbkdf2(ctx, jwk, alg, p2c, st->data, st->size);
    if (!key)
        return false;

    for (jose_jwe_wrapper_t *w = jose_jwe_wrappers(); w; w = w->next) {
        if (strcmp(aes, w->alg) == 0)
            return w->unwrap(ctx, jwe, key, rcp, aes, cek);
    }

    return false;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwe_wrapper_t wrappers[] = {
        { NULL, "PBES2-HS256+A128KW", suggest, wrap, unwrap },
        { NULL, "PBES2-HS384+A192KW", suggest, wrap, unwrap },
        { NULL, "PBES2-HS512+A256KW", suggest, wrap, unwrap },
        {}
    };

    for (size_t i = 0; wrappers[i].alg; i++)
        jose_jwe_register_wrapper(&wrappers[i]);
}
