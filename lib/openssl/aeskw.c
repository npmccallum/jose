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

#define NAMES "A128KW", "A192KW", "A256KW"

declare_cleanup(EVP_CIPHER_CTX)

static bool
handles(json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack(jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) < 3;
}

static bool
resolve(json_t *jwk)
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
    case 0: len = 16; break;
    case 1: len = 24; break;
    case 2: len = 32; break;
    default: return true;
    }

    if (!kty && json_object_set_new(jwk, "kty", json_string("oct")) == -1)
        return false;
    if (kty && strcmp(kty, "oct") != 0)
        return false;

    if (!bytes && json_object_set_new(jwk, "bytes", json_integer(len)) == -1)
        return false;
    if (bytes && (!json_is_integer(bytes) || json_integer_value(bytes) != len))
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "enc", "key_ops",
                    "wrapKey", "unwrapKey");
    if (!upd)
        return false;

    return json_object_update_missing(jwk, upd) == 0;
}

static const char *
suggest(const json_t *jwk)
{
    const char *kty = NULL;
    const char *k = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    switch (jose_b64_dlen(strlen(k))) {
    case 16: return "A128KW";
    case 24: return "A192KW";
    case 32: return "A256KW";
    default: return NULL;
    }
}

static bool
wrap(json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp,
     const char *alg)
{
    openssl_auto(EVP_CIPHER_CTX) *ctx = NULL;
    const EVP_CIPHER *cph = NULL;
    jose_buf_auto_t *ky = NULL;
    jose_buf_auto_t *pt = NULL;
    jose_buf_auto_t *ct = NULL;
    int tmp;

    if (!json_object_get(cek, "k") && !jose_jwk_generate(cek))
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return false;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

    ky = jose_b64_decode_json(json_object_get(jwk, "k"));
    if (!ky)
        return false;

    if ((int) ky->size != EVP_CIPHER_key_length(cph))
        return false;

    pt = jose_b64_decode_json(json_object_get(cek, "k"));
    if (!pt)
        return false;

    ct = jose_buf(pt->size + EVP_CIPHER_block_size(cph) * 2 - 1,
                  JOSE_BUF_FLAG_NONE);
    if (!ct)
        return false;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(ctx, cph, NULL, ky->data, iv) <= 0)
        return false;

    if (EVP_EncryptUpdate(ctx, ct->data, &tmp, pt->data, pt->size) <= 0)
        return false;
    ct->size = tmp;

    if (EVP_EncryptFinal(ctx, &ct->data[tmp], &tmp) <= 0)
        return false;
    ct->size += tmp;

    return json_object_set_new(rcp, "encrypted_key",
                               jose_b64_encode_json(ct->data, ct->size)) == 0;
}

static bool
unwrap(const json_t *jwe, const json_t *jwk, const json_t *rcp,
       const char *alg, json_t *cek)
{
    openssl_auto(EVP_CIPHER_CTX) *ctx = NULL;
    const EVP_CIPHER *cph = NULL;
    jose_buf_auto_t *ky = NULL;
    jose_buf_auto_t *pt = NULL;
    jose_buf_auto_t *ct = NULL;
    int tmp = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return NULL;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

    ky = jose_b64_decode_json(json_object_get(jwk, "k"));
    if (!ky)
        return false;

    if ((int) ky->size != EVP_CIPHER_key_length(cph))
        return false;

    ct = jose_b64_decode_json(json_object_get(rcp, "encrypted_key"));
    if (!ct)
        return false;

    pt = jose_buf(ct->size, JOSE_BUF_FLAG_WIPE);
    if (!pt)
        return false;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_DecryptInit_ex(ctx, cph, NULL, ky->data, iv) <= 0)
        return false;

    if (EVP_DecryptUpdate(ctx, pt->data, &tmp, ct->data, ct->size) <= 0)
        return false;
    pt->size = tmp;

    if (EVP_DecryptFinal(ctx, &pt->data[tmp], &tmp) <= 0)
        return false;
    pt->size += tmp;

    return json_object_set_new(cek, "k",
                               jose_b64_encode_json(pt->data, pt->size)) == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .handles = handles,
        .resolve = resolve
    };

    static jose_jwe_wrapper_t wrappers[] = {
        { NULL, "A128KW", suggest, wrap, unwrap },
        { NULL, "A192KW", suggest, wrap, unwrap },
        { NULL, "A256KW", suggest, wrap, unwrap },
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; wrappers[i].alg; i++)
        jose_jwe_register_wrapper(&wrappers[i]);
}
