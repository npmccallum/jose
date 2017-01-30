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

static bool
handles(json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    return strcmp(kty, "EC") == 0;
}

static bool
generate(json_t *jwk)
{
    json_auto_t *tmp = NULL;
    const char *crv = NULL;
    int nid = NID_undef;
    EC_KEY *key = NULL;

    if (json_unpack(jwk, "{s:s}", "crv", &crv) == -1)
        return false;

    switch (str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: nid = NID_X9_62_prime256v1; break;
    case 1: nid = NID_secp384r1; break;
    case 2: nid = NID_secp521r1; break;
    default: return false;
    }

    key = EC_KEY_new_by_curve_name(nid);
    if (!key)
        return false;

    if (EC_KEY_generate_key(key) <= 0) {
        EC_KEY_free(key);
        return false;
    }

    tmp = jose_openssl_jwk_from_EC_KEY(key);
    EC_KEY_free(key);

    return json_object_update(jwk, tmp) == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .handles = handles,
        .kty = "EC",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
