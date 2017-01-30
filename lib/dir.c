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
#include <jose/jose.h>
#include <jose/hooks.h>

#include <string.h>

static const char *
suggest(jose_ctx_t *ctx, const json_t *jwk)
{
    static const char *encs[] = {
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
        NULL
    };

    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return NULL;

    for (size_t i = 0; encs[i]; i++) {
        if (strcmp(encs[i], alg) == 0)
            return "dir";
    }

    return NULL;
}

static bool
copy(json_t *to, const json_t *from)
{
    json_auto_t *cpy = NULL;
    cpy = json_deep_copy(from);
    return json_object_update(to, cpy) == 0;
}

static bool
wrap(jose_ctx_t *ctx, json_t *jwe, json_t *cek, const json_t *jwk,
     json_t *rcp, const char *alg)
{
    if (!json_object_get(cek, "k") && !copy(cek, jwk))
        return false;

    return json_object_set_new(rcp, "encrypted_key", json_string("")) == 0;
}

static bool
unwrap(jose_ctx_t *ctx, const json_t *jwe, const json_t *jwk,
       const json_t *rcp, const char *alg, json_t *cek)
{
    return copy(cek, jwk);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwe_wrapper_t dir_wrapper = {
        .alg = "dir",
        .suggest = suggest,
        .wrap = wrap,
        .unwrap = unwrap,
    };

    jose_jwe_register_wrapper(&dir_wrapper);
}
