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

#include <string.h>
#include <openssl/rand.h>

static bool
handles(jose_ctx_t *ctx, json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    return strcmp(kty, "oct") == 0;
}

static bool
generate(jose_ctx_t *ctx, json_t *jwk)
{
    jose_buf_auto_t *buf = NULL;
    json_int_t len = 0;

    if (json_unpack(jwk, "{s:I}", "bytes", &len) == -1)
        return false;

    buf = jose_buf(len, JOSE_BUF_FLAG_WIPE);
    if (!buf)
        return false;

    if (RAND_bytes(buf->data, len) <= 0)
        return false;

    if (json_object_set_new(jwk, "k",
                            jose_b64_encode_json(buf->data, buf->size)) == -1)
        return false;

    return json_object_del(jwk, "bytes") == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .handles = handles,
        .kty = "oct",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
