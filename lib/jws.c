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


#define _GNU_SOURCE
#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/hooks.h>

#include <string.h>

static const jose_jws_signer_t *
find(const char *alg)
{
    for (const jose_jws_signer_t *s = jose_jws_signers(); s; s = s->next) {
        if (strcmp(alg, s->alg) == 0)
            return s;
    }

    return NULL;
}

bool
jose_jws_sign(jose_ctx_t *ctx, json_t *jws, const json_t *jwk,
              const json_t *sig)
{
    const jose_jws_signer_t *signer = NULL;
    const char *payl = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *alg = NULL;
    json_auto_t *s = NULL;
    json_auto_t *p = NULL;

    if (!sig)
        s = json_object();
    else if (!json_is_object(sig))
        return false;
    else
        s = json_deep_copy(sig);

    if (!jose_jwk_allowed(jwk, false, "sign"))
        return false;

    if (json_unpack(s, "{s?o}", "protected", &p) == -1)
        return false;

    if (json_is_object(p))
        p = json_incref(p);
    else if (json_is_string(p))
        p = jose_b64_decode_json_load(p);
    else if (p)
        return false;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        return false;

    if (json_unpack(p, "{s:s}", "alg", &alg) == -1 &&
        json_unpack(s, "{s:{s:s}}", "header", "alg", &alg) == -1) {
        alg = kalg;
        for (signer = jose_jws_signers(); signer && !alg; signer = signer->next)
            alg = signer->suggest(ctx, jwk);

        if (!set_protected_new(s, "alg", json_string(alg)))
            return false;
    }

    if (kalg && strcmp(alg, kalg) != 0)
        return false;

    if (json_unpack(jws, "{s:s}", "payload", &payl) == -1)
        return false;

    prot = encode_protected(s);
    if (!prot)
        return false;

    signer = find(alg);
    if (!signer)
        return false;

    if (signer->sign(ctx, s, jwk, alg, prot, payl))
        return add_entity(jws, s, "signatures", "signature", "protected",
                         "header", NULL);

    return false;
}

bool
jose_jws_verify(jose_ctx_t *ctx, const json_t *jws, const json_t *jwk,
                const json_t *sig)
{
    const jose_jws_signer_t *signer = NULL;
    const char *prot = NULL;
    const char *payl = NULL;
    const char *kalg = NULL;
    const char *halg = NULL;
    json_auto_t *hdr = NULL;

    if (!sig) {
        const json_t *array = NULL;

        array = json_object_get(jws, "signatures");
        if (!json_is_array(array))
            return jose_jws_verify(ctx, jws, jwk, jws);

        for (size_t i = 0; i < json_array_size(array); i++) {
            if (jose_jws_verify(ctx, jws, jwk, json_array_get(array, i)))
                return true;
        }

        return false;
    }

    if (!jose_jwk_allowed(jwk, false, "verify"))
        return false;

    if (json_unpack((json_t *) jws, "{s: s}", "payload", &payl) == -1)
        return false;

    if (json_unpack((json_t *) sig, "{s?s}", "protected", &prot) != 0)
        return false;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) != 0)
        return false;

    hdr = jose_jws_merge_header(sig);
    if (!hdr)
        return false;

    if (json_unpack(hdr, "{s:s}", "alg", &halg) != 0)
        return false;

    if (!halg) {
        if (!kalg)
            return false;
        halg = kalg;
    } else if (kalg && strcmp(halg, kalg) != 0)
        return false;

    signer = find(halg);
    if (!signer)
        return false;

    return signer->verify(ctx, sig, jwk, halg, prot ? prot : "", payl);
}

json_t *
jose_jws_merge_header(const json_t *sig)
{
    json_auto_t *p = NULL;
    json_t *h = NULL;

    p = json_object_get(sig, "protected");
    if (!p)
        p = json_object();
    else if (json_is_object(p))
        p = json_deep_copy(p);
    else if (json_is_string(p))
        p = jose_b64_decode_json_load(p);

    if (!json_is_object(p))
        return NULL;

    h = json_object_get(sig, "header");
    if (h) {
        if (json_object_update_missing(p, h) == -1)
            return NULL;
    }

    return json_incref(p);
}
