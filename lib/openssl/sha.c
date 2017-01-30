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

#include <jose/hooks.h>

#include <openssl/sha.h>

static bool
sha1(jose_ctx_t *ctx, const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA1(in, inl, out) != NULL;
}

static bool
sha224(jose_ctx_t *ctx, const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA224(in, inl, out) != NULL;
}

static bool
sha256(jose_ctx_t *ctx, const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA256(in, inl, out) != NULL;
}

static bool
sha384(jose_ctx_t *ctx, const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA384(in, inl, out) != NULL;
}

static bool
sha512(jose_ctx_t *ctx, const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA512(in, inl, out) != NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_hasher_t hashes[] = {
        { NULL, "sha512", SHA512_DIGEST_LENGTH, sha512 },
        { NULL, "sha384", SHA384_DIGEST_LENGTH, sha384 },
        { NULL, "sha256", SHA256_DIGEST_LENGTH, sha256 },
        { NULL, "sha224", SHA224_DIGEST_LENGTH, sha224 },
        { NULL, "sha1",   SHA_DIGEST_LENGTH,    sha1   },
        {}
    };

    for (size_t i = 0; hashes[i].name; i++)
        jose_jwk_register_hasher(&hashes[i]);
}
