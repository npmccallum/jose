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

static RSA *
mkrsa(const json_t *jwk)
{
    openssl_auto(BIGNUM) *bn = NULL;
    json_auto_t *exp = NULL;
    RSA *key = NULL;
    int bits = 2048;

    if (json_unpack((json_t *) jwk, "{s?i,s?O}",
                    "bits", &bits, "e", &exp) == -1)
        return NULL;

    if (bits < 2048)
        return NULL;

    if (!exp)
        exp = json_integer(65537);

    switch (exp ? exp->type : JSON_NULL) {
    case JSON_STRING:
        bn = bn_decode_json(exp);
        if (!bn)
            return NULL;
        break;

    case JSON_INTEGER:
        bn = BN_new();
        if (!bn)
            return NULL;

        if (BN_set_word(bn, json_integer_value(exp)) <= 0)
            return NULL;
        break;

    default:
        break;
    }

    key = RSA_new();
    if (!key)
        return NULL;

    bits = RSA_generate_key_ex(key, bits, bn, NULL);
    if (bits <= 0) {
        RSA_free(key);
        key = NULL;
    }

    return key;
}

static bool
handles(json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    return strcmp(kty, "RSA") == 0;
}

static bool
generate(json_t *jwk)
{
    json_auto_t *tmp = NULL;
    RSA *rsa = NULL;

    rsa = mkrsa(jwk);
    if (!rsa)
        return false;

    tmp = jose_openssl_jwk_from_RSA(rsa);
    RSA_free(rsa);
    if (!tmp)
        return false;

    if (json_object_get(jwk, "bits") && json_object_del(jwk, "bits") == -1)
        return false;

    if (json_object_get(jwk, "e") && json_object_del(jwk, "e") == -1)
        return false;

    return json_object_update_missing(jwk, tmp) == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .handles = handles,
        .kty = "RSA",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
