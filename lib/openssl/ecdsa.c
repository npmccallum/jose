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

declare_cleanup(EVP_MD_CTX)
declare_cleanup(ECDSA_SIG)
declare_cleanup(EC_KEY)

static EC_KEY *
setup(const json_t *jwk, const char *alg, const char *prot, const char *payl,
      uint8_t hsh[], size_t *hl)
{
    openssl_auto(EVP_MD_CTX) *ctx = NULL;
    openssl_auto(EC_KEY) *key = NULL;
    const EVP_MD *md = NULL;
    const char *req = NULL;
    unsigned int ign = 0;

    *hl = 0;

    key = jose_openssl_jwk_to_EC_KEY(jwk);
    if (!key)
        return NULL;

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key))) {
    case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
    case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
    case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
    default: return NULL;
    }

    if (strcmp(alg, req) != 0)
        return NULL;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return NULL;

    if (EVP_DigestInit(ctx, md) <= 0)
        return NULL;

    if (EVP_DigestUpdate(ctx, (const uint8_t *) prot, strlen(prot)) <= 0)
        return NULL;

    if (EVP_DigestUpdate(ctx, (const uint8_t *) ".", 1) <= 0)
        return NULL;

    if (EVP_DigestUpdate(ctx, (const uint8_t *) payl, strlen(payl)) <= 0)
        return NULL;

    if (EVP_DigestFinal(ctx, hsh, &ign) <= 0)
        return NULL;

    *hl = EVP_MD_size(md);
    return EC_KEY_up_ref(key) > 0 ? key : NULL;
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
suggest(const json_t *jwk)
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
sign(json_t *sig, const json_t *jwk,
     const char *alg, const char *prot, const char *payl)
{
    openssl_auto(ECDSA_SIG) *ecdsa = NULL;
    openssl_auto(EC_KEY) *key = NULL;
    uint8_t hsh[EVP_MAX_MD_SIZE];
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    size_t hl = 0;

    key = setup(jwk, alg, prot, payl, hsh, &hl);
    if (!key)
        return false;

    uint8_t out[(EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8 * 2];

    ecdsa = ECDSA_do_sign(hsh, hl, key);
    if (!ecdsa)
        return false;

    ECDSA_SIG_get0(ecdsa, &r, &s);

    if (!bn_encode(r, out, sizeof(out) / 2))
        return false;

    if (!bn_encode(s, &out[sizeof(out) / 2], sizeof(out) / 2))
        return false;

    return json_object_set_new(sig, "signature",
                               jose_b64_encode_json(out, sizeof(out))) == 0;
}

static bool
verify(const json_t *sig, const json_t *jwk,
       const char *alg, const char *prot, const char *payl)
{
    openssl_auto(ECDSA_SIG) *ecdsa = NULL;
    uint8_t hsh[EVP_MAX_MD_SIZE];
    jose_buf_auto_t *sgn = NULL;
    EC_KEY *key = NULL;
    bool ret = false;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    size_t hshl = 0;

    key = setup(jwk, alg, prot, payl, hsh, &hshl);
    if (!key)
        return false;

    sgn = jose_b64_decode_json(json_object_get(sig, "signature"));
    if (sig) {
        r = bn_decode(sgn->data, sgn->size / 2);
        s = bn_decode(&sgn->data[sgn->size / 2], sgn->size / 2);
        ecdsa = ECDSA_SIG_new();
        if (ecdsa && ECDSA_SIG_set0(ecdsa, r, s) > 0) {
            r = NULL;
            s = NULL;
            ret = ECDSA_do_verify(hsh, hshl, ecdsa, key) == 1;
        }
    }

    EC_KEY_free(key);
    BN_free(r);
    BN_free(s);
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
        { NULL, "ES256", suggest, sign, verify },
        { NULL, "ES384", suggest, sign, verify },
        { NULL, "ES512", suggest, sign, verify },
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; signers[i].alg; i++)
        jose_jws_register_signer(&signers[i]);
}
