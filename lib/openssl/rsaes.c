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

#ifdef EVP_PKEY_CTX_set_rsa_oaep_md
#define NAMES "RSA1_5", "RSA-OAEP", "RSA-OAEP-256"
#define HAVE_OAEP
#else
#define NAMES "RSA1_5"
#define EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) (-1)
#endif

static const char *algs[] = { NAMES, NULL };

declare_cleanup(EVP_PKEY_CTX)
declare_cleanup(EVP_PKEY)

static bool
handles(jose_ctx_t *ctx, json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack(jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return algs[str2enum(alg, NAMES, NULL)] != NULL;
}

static bool
resolve(jose_ctx_t *ctx, json_t *jwk)
{
    json_auto_t *upd = NULL;
    const char *kty = NULL;
    const char *alg = NULL;

    if (json_unpack(jwk, "{s?s,s?s}", "kty", &kty, "alg", &alg) == -1)
        return false;

    if (!algs[str2enum(alg, NAMES, NULL)])
        return true;

    if (!kty && json_object_set_new(jwk, "kty", json_string("RSA")) == -1)
        return false;
    if (kty && strcmp(kty, "RSA") != 0)
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

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    if (strcmp(kty, "RSA") != 0)
        return NULL;

    return "RSA1_5";
}

static bool
wrap(jose_ctx_t *ctx, json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp,
     const char *alg)
{
    openssl_auto(EVP_PKEY_CTX) *epc = NULL;
    openssl_auto(EVP_PKEY) *key = NULL;
    jose_buf_auto_t *pt = NULL;
    jose_buf_auto_t *ct = NULL;
    const EVP_MD *md = NULL;
    const RSA *rsa = NULL;
    size_t len = 0;
    int tmp = 0;
    int pad = 0;

    if (!json_object_get(cek, "k") && !jose_jwk_generate(ctx, cek))
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: pad = RSA_PKCS1_PADDING;      tmp = 11; md = EVP_sha1(); break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha1(); break;
    case 2: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha256(); break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return false;

    pt = jose_b64_decode_json(json_object_get(cek, "k"));
    if (!pt)
        return false;

    rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
        return false;

    if ((int) pt->size >= RSA_size(rsa) - tmp)
        return false;

    epc = EVP_PKEY_CTX_new(key, NULL);
    if (!epc)
        return false;

    if (EVP_PKEY_encrypt_init(epc) <= 0)
        return false;

    if (EVP_PKEY_CTX_set_rsa_padding(epc, pad) <= 0)
        return false;

    if (pad == RSA_PKCS1_OAEP_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(epc, md) <= 0)
            return false;

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(epc, md) <= 0)
            return false;
    }

    if (EVP_PKEY_encrypt(epc, NULL, &len, pt->data, pt->size) <= 0)
        return false;

    ct = jose_buf(len, JOSE_BUF_FLAG_NONE);
    if (!ct)
        return false;

    if (EVP_PKEY_encrypt(epc, ct->data, &ct->size, pt->data, pt->size) <= 0)
        return false;

    return json_object_set_new(rcp, "encrypted_key",
                               jose_b64_encode_json(ct->data, ct->size)) == 0;
}

static bool
unwrap(jose_ctx_t *ctx, const json_t *jwe, const json_t *jwk,
       const json_t *rcp, const char *alg, json_t *cek)
{
    openssl_auto(EVP_PKEY_CTX) *epc = NULL;
    openssl_auto(EVP_PKEY) *key = NULL;
    jose_buf_auto_t *pt = NULL;
    jose_buf_auto_t *ct = NULL;
    jose_buf_auto_t *rt = NULL;
    jose_buf_t *tt = NULL;
    const EVP_MD *md = NULL;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: pad = RSA_PKCS1_PADDING;      md = EVP_sha1(); break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; md = EVP_sha1(); break;
    case 2: pad = RSA_PKCS1_OAEP_PADDING; md = EVP_sha256(); break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return false;

    ct = jose_b64_decode_json(json_object_get(rcp, "encrypted_key"));
    if (!ct)
        return false;

    pt = jose_buf(ct->size, JOSE_BUF_FLAG_WIPE);
    if (!pt)
        return false;

    epc = EVP_PKEY_CTX_new(key, NULL);
    if (!epc)
        return false;

    if (EVP_PKEY_decrypt_init(epc) <= 0)
        return false;

    if (EVP_PKEY_CTX_set_rsa_padding(epc, pad) <= 0)
        return false;

    if (pad == RSA_PKCS1_OAEP_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(epc, md) <= 0)
            return false;

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(epc, md) <= 0)
            return false;
    }

    /* Handle MMA Attack as prescribed by RFC 3218, always generate a
     * random buffer of appropriate length so that the same operations
     * are performed whether decrypt succeeds or not, in an attempt to
     * foil timing attacks */
    if (pad == RSA_PKCS1_PADDING) {
        rt = jose_buf(ct->size, JOSE_BUF_FLAG_WIPE);
        if (!rt)
            return false;
        if (RAND_bytes(rt->data, rt->size) <= 0)
            return false;
    }

    tt = pt;
    if (EVP_PKEY_decrypt(epc, pt->data, &pt->size, ct->data, ct->size) <= 0) {
        if (pad == RSA_PKCS1_PADDING) {
            tt = rt;
        } else
            return false;
    }

    return json_object_set_new(cek, "k",
                               jose_b64_encode_json(tt->data, tt->size)) == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .handles = handles,
        .resolve = resolve
    };

    static jose_jwe_wrapper_t wrappers[] = {
        { NULL, "RSA1_5", suggest, wrap, unwrap },
#ifdef HAVE_OAEP
        { NULL, "RSA-OAEP", suggest, wrap, unwrap },
        { NULL, "RSA-OAEP-256", suggest, wrap, unwrap },
#endif
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; wrappers[i].alg; i++)
        jose_jwe_register_wrapper(&wrappers[i]);
}
