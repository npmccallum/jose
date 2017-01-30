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

#define NAMES "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"

declare_cleanup(EVP_CIPHER_CTX)
declare_cleanup(HMAC_CTX)

static bool
mktag(const EVP_MD *md, const char *prot, const char *aad,
      const uint8_t ky[], size_t kyl,
      const uint8_t iv[], size_t ivl,
      const uint8_t ct[], size_t ctl,
      uint8_t tg[])
{
    openssl_auto(HMAC_CTX) *hctx = NULL;
    uint8_t hsh[EVP_MD_size(md)];
    bool ret = false;
    uint64_t al = 0;

    hctx = HMAC_CTX_new();
    if (!hctx)
        return false;

    if (HMAC_Init_ex(hctx, ky, kyl, md, NULL) <= 0)
        return false;

    al += strlen(prot);
    if (HMAC_Update(hctx, (uint8_t *) prot, strlen(prot)) <= 0)
        return false;

    if (aad) {
        al++;
        if (HMAC_Update(hctx, (uint8_t *) ".", 1) <= 0)
            return false;

        al += strlen(aad);
        if (HMAC_Update(hctx, (uint8_t *) aad, strlen(aad)) <= 0)
            return false;
    }

    if (HMAC_Update(hctx, iv, ivl) <= 0)
        return false;

    if (HMAC_Update(hctx, ct, ctl) <= 0)
        return false;

    al = htobe64(al * 8);
    if (HMAC_Update(hctx, (uint8_t *) &al, sizeof(al)) <= 0)
        return false;

    ret = HMAC_Final(hctx, hsh, NULL) > 0;
    memcpy(tg, hsh, sizeof(hsh) / 2);
    return ret;
}

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
    if (bytes && (!json_is_integer(bytes) || json_integer_value(bytes) != len))
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "enc", "key_ops",
                    "encrypt", "decrypt");
    if (!upd)
        return false;

    return json_object_update_missing(jwk, upd) == 0;
}

static const char *
suggest(const json_t *jwk)
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
    case SHA512_DIGEST_LENGTH: return "A256CBC-HS512";
    case SHA384_DIGEST_LENGTH: return "A192CBC-HS384";
    case SHA256_DIGEST_LENGTH: return "A128CBC-HS256";
    default: return NULL;
    }
}

static bool
encrypt(json_t *jwe, const json_t *cek, const uint8_t pt[], size_t ptl,
        const char *enc, const char *prot, const char *aad)
{
    openssl_auto(EVP_CIPHER_CTX) *ctx = NULL;
    const EVP_CIPHER *cph = NULL;
    jose_buf_auto_t *ct = NULL;
    jose_buf_auto_t *ky = NULL;
    const EVP_MD *md = NULL;
    int len;

    switch (str2enum(enc, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    uint8_t tg[EVP_MD_size(md) / 2];

    ky = jose_b64_decode_json(json_object_get(cek, "k"));
    if (!ky)
        return false;

    if ((int) ky->size != EVP_CIPHER_key_length(cph) * 2)
        return false;

    ct = jose_buf(ptl + EVP_CIPHER_block_size(cph) - 1, JOSE_BUF_FLAG_NONE);
    if (!ct)
        return false;

    if (RAND_bytes(iv, sizeof(iv)) <= 0)
        return false;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    if (EVP_EncryptInit(ctx, cph, &ky->data[ky->size / 2], iv) <= 0)
        return false;

    if (EVP_EncryptUpdate(ctx, ct->data, &len, pt, ptl) <= 0)
        return false;
    ct->size = len;

    if (EVP_EncryptFinal(ctx, &ct->data[ct->size], &len) <= 0)
        return false;
    ct->size += len;

    if (!mktag(md, prot, aad, ky->data, ky->size / 2,
               iv, sizeof(iv), ct->data, ct->size, tg))
        return false;

    if (json_object_set_new(jwe, "iv",
                            jose_b64_encode_json(iv, sizeof(iv))) == -1)
        return false;

    if (json_object_set_new(jwe, "ciphertext",
                            jose_b64_encode_json(ct->data, ct->size)) == -1)
        return false;

    if (json_object_set_new(jwe, "tag",
                            jose_b64_encode_json(tg, sizeof(tg))) == -1)
        return false;

    return true;
}

static jose_buf_t *
decrypt(const json_t *jwe, const json_t *cek, const char *enc,
        const char *prot, const char *aad)
{
    openssl_auto(EVP_CIPHER_CTX) *ctx = NULL;
    const EVP_CIPHER *cph = NULL;
    jose_buf_auto_t *ky = NULL;
    jose_buf_auto_t *iv = NULL;
    jose_buf_auto_t *ct = NULL;
    jose_buf_auto_t *tg = NULL;
    jose_buf_auto_t *pt = NULL;
    const EVP_MD *md = NULL;
    bool vfy = false;
    int len = 0;

    switch (str2enum(enc, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return NULL;
    }

    uint8_t tag[EVP_MD_size(md) / 2];

    ky = jose_b64_decode_json(json_object_get(cek, "k"));
    iv = jose_b64_decode_json(json_object_get(jwe, "iv"));
    ct = jose_b64_decode_json(json_object_get(jwe, "ciphertext"));
    tg = jose_b64_decode_json(json_object_get(jwe, "tag"));
    if (!ky || !iv || !ct || !tg)
        return NULL;

    if (ky->size != (size_t) EVP_CIPHER_key_length(cph) * 2)
        return NULL;

    if (iv->size != (size_t) EVP_CIPHER_iv_length(cph))
        return NULL;

    if (tg->size != sizeof(tag))
        return NULL;

    if (!mktag(md, prot, aad, ky->data, ky->size / 2,
               iv->data, iv->size, ct->data, ct->size, tag))
        return NULL;

    if (CRYPTO_memcmp(tag, tg->data, tg->size) != 0)
        return NULL;

    pt = jose_buf(ct->size, JOSE_BUF_FLAG_WIPE);
    if (!pt)
        return NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return NULL;

    if (EVP_DecryptInit(ctx, cph, &ky->data[ky->size / 2], iv->data) <= 0)
        return NULL;

    if (EVP_DecryptUpdate(ctx, pt->data, &len, ct->data, ct->size) <= 0)
        return NULL;
    pt->size = len;

    vfy = EVP_DecryptFinal(ctx, &pt->data[len], &len) > 0;
    pt->size += len;
    return vfy ? jose_buf_incref(pt) : NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .handles = handles,
        .resolve = resolve
    };

    static jose_jwe_crypter_t crypters[] = {
        { NULL, "A128CBC-HS256", suggest, encrypt, decrypt },
        { NULL, "A192CBC-HS384", suggest, encrypt, decrypt },
        { NULL, "A256CBC-HS512", suggest, encrypt, decrypt },
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; crypters[i].enc; i++)
        jose_jwe_register_crypter(&crypters[i]);
}
