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
#include <jose/jwe.h>
#include <jose/hooks.h>

#include <string.h>

static const jose_jwe_crypter_t *
find_crypter(const char *enc)
{
    for (const jose_jwe_crypter_t *c = jose_jwe_crypters(); c && enc; c = c->next) {
        if (strcmp(enc, c->enc) == 0)
            return c;
    }

    return NULL;
}

static const jose_jwe_wrapper_t *
find_wrapper(const char *alg)
{
    for (const jose_jwe_wrapper_t *s = jose_jwe_wrappers(); s && alg; s = s->next) {
        if (strcmp(alg, s->alg) == 0)
            return s;
    }

    return NULL;
}

static const jose_jwe_zipper_t *
find_zipper(const char *zip)
{
    for (const jose_jwe_zipper_t *z = jose_jwe_zippers(); z && zip; z = z->next) {
        if (strcmp(zip, z->zip) == 0)
            return z;
    }

    return NULL;
}

bool
jose_jwe_encrypt(jose_ctx_t *ctx, json_t *jwe, const json_t *cek,
                 const uint8_t pt[], size_t ptl)
{
    const jose_jwe_crypter_t *crypter = NULL;
    const jose_jwe_zipper_t *zipper = NULL;
    jose_buf_auto_t *zpt = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *penc = NULL;
    const char *senc = NULL;
    const char *zip = NULL;
    const char *aad = NULL;
    json_auto_t *p = NULL;

    if (!jose_jwk_allowed(cek, false, "encrypt"))
        return false;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) == -1)
        return false;

    if (json_unpack(jwe, "{s?s,s?{s?s,s?s},s?O,s?{s?s}}", "aad", &aad,
                    "protected", "enc", &penc, "zip", &zip, "protected", &p,
                    "unprotected", "enc", &senc) == -1)
        return false;

    if (!penc && !zip && json_is_string(p)) {
        json_decref(p);
        p = jose_b64_decode_json_load(p);
        if (!p)
            return false;

        if (json_unpack(p, "{s?s,s?s}", "enc", &penc, "zip", &zip) == -1)
            return false;
    }

    if (penc && senc && strcmp(penc, senc) != 0)
        return false;

    if (!penc && !senc) {
        senc = kalg;

        for (crypter = jose_jwe_crypters(); crypter && !senc; crypter = crypter->next)
            senc = crypter->suggest(ctx, cek);

        if (!senc || !set_protected_new(jwe, "enc", json_string(senc)))
            return false;
    }

    if (kalg && strcmp(penc ? penc : senc, kalg) != 0)
        return false;

    if (zip) {
        zipper = find_zipper(zip);
        if (!zipper)
            return false;

        zpt = zipper->deflate(ctx, pt, ptl);
        if (!zpt)
            return false;
    }

    crypter = find_crypter(penc ? penc : senc);
    if (!crypter)
        return false;

    prot = encode_protected(jwe);
    if (!prot)
        return false;

    return crypter->encrypt(ctx, jwe, cek,
                            zpt ? zpt->data : pt,
                            zpt ? zpt->size : ptl,
                            penc ? penc : senc,
                            prot, aad);
}

bool
jose_jwe_encrypt_json(jose_ctx_t *ctx, json_t *jwe, const json_t *cek,
                      json_t *pt)
{
    char *ept = NULL;
    bool ret = false;

    ept = json_dumps(pt, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
    if (!ept)
        return NULL;

    ret = jose_jwe_encrypt(ctx, jwe, cek, (uint8_t *) ept, strlen(ept));
    memset(ept, 0, strlen(ept));
    free(ept);
    return ret;
}

bool
jose_jwe_wrap(jose_ctx_t *ctx, json_t *jwe, json_t *cek, const json_t *jwk,
              json_t *rcp)
{
    const jose_jwe_wrapper_t *wrapper = NULL;
    const char *kalg = NULL;
    const char *halg = NULL;
    const char *henc = NULL;
    json_auto_t *hdr = NULL;
    json_auto_t *r = NULL;

    if (!cek)
        return false;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return false;

    if (json_unpack(hdr, "{s?s,s?s}", "alg", &halg, "enc", &henc) == -1)
        return false;

    if (!json_object_get(cek, "k")) {
        const char *kenc = NULL;

        if (json_unpack(cek, "{s?s}", "alg", &kenc) == -1)
            return false;

        if (!kenc) {
            kenc = henc ? henc : "A128CBC-HS256";
            if (json_object_set_new(cek, "alg", json_string(kenc)) == -1)
                return false;
        }
    }

    if (!jose_jwk_allowed(cek, false, "encrypt"))
        return false;

    if (!jose_jwk_allowed(jwk, false, "wrapKey"))
        return false;

    kalg = json_string_value(json_object_get(jwk, "alg"));

    if (!rcp)
        r = json_object();
    else if (!json_is_object(rcp))
        return false;
    else
        r = json_deep_copy(rcp);

    if (!halg) {
        json_t *h = NULL;

        halg = kalg;
        for (const jose_jwe_wrapper_t *s = jose_jwe_wrappers(); s && !halg; s = s->next)
            halg = s->suggest(ctx, jwk);

        if (!halg)
            return false;

        h = json_object_get(r, "header");
        if (!h && json_object_set_new(r, "header", h = json_object()) == -1)
            return false;

        if (json_object_set_new(h, "alg", json_string(halg)) == -1)
            return false;
    }

    if (halg && kalg && strcmp(halg, kalg) != 0)
        return false;

    wrapper = find_wrapper(halg);
    if (!wrapper)
        return false;

    if (!wrapper->wrap(ctx, jwe, cek, jwk, r, halg))
        return false;

    return add_entity(jwe, r, "recipients", "header", "encrypted_key", NULL);
}

json_t *
jose_jwe_unwrap(jose_ctx_t *ctx, const json_t *jwe, const json_t *jwk,
                const json_t *rcp)
{
    const jose_jwe_wrapper_t *wrapper = NULL;
    const char *halg = NULL;
    const char *henc = NULL;
    const char *kalg = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *hdr = NULL;

    if (!rcp) {
        const json_t *rcps = NULL;

        rcps = json_object_get(jwe, "recipients");
        if (json_is_array(rcps)) {
            for (size_t i = 0; i < json_array_size(rcps) && !cek; i++)
                cek = jose_jwe_unwrap(ctx, jwe, jwk, json_array_get(rcps, i));
        } else if (!rcps) {
            cek = jose_jwe_unwrap(ctx, jwe, jwk, jwe);
        }

        return json_incref(cek);
    }

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s?s,s?s}", "alg", &halg, "enc", &henc) == -1)
        return NULL;

    if (!jose_jwk_allowed(jwk, false, "unwrapKey"))
        return NULL;

    kalg = json_string_value(json_object_get(jwk, "alg"));
    if (!halg)
        halg = kalg;
    else if (kalg && strcmp(halg, kalg) != 0 &&
             (!henc || strcmp(henc, kalg) != 0))
        return NULL;

    wrapper = find_wrapper(halg);
    if (!wrapper)
        return NULL;

    cek = json_pack("{s:s,s:s,s:O,s:[ss]}",
                    "kty", "oct", "use", "enc",
                    "enc", json_object_get(hdr, "enc"),
                    "key_ops", "encrypt", "decrypt");
    if (!cek)
        return NULL;

    if (!wrapper->unwrap(ctx, jwe, jwk, rcp, halg, cek))
        return NULL;

    return json_incref(cek);
}

jose_buf_t *
jose_jwe_decrypt(jose_ctx_t *ctx, const json_t *jwe, const json_t *cek)
{
    const jose_jwe_crypter_t *crypter = NULL;
    const jose_jwe_zipper_t *zipper = NULL;
    jose_buf_auto_t *pt = NULL;
    json_auto_t *hdr = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *szip = NULL;
    const char *enc = NULL;
    const char *aad = NULL;
    const char *zip = NULL;

    if (!jose_jwk_allowed(cek, false, "decrypt"))
        return NULL;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) == -1)
        return NULL;

    if (json_unpack((json_t *) jwe, "{s?s,s?s,s?{s?s}}",
                    "aad", &aad, "protected", &prot,
                    "unprotected", "zip", &szip) == -1)
        return NULL;

    hdr = jose_jwe_merge_header(jwe, NULL);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s?s,s?s}", "enc", &enc, "zip", &zip) == -1)
        return NULL;

    if (!enc)
        enc = kalg;

    if (kalg) {
        if (strcmp(enc, kalg) != 0)
            return NULL;
    }

    zipper = find_zipper(zip);
    if (zip && (!zipper || szip))
        return NULL;

    crypter = find_crypter(enc);
    if (!crypter)
        return NULL;

    pt = crypter->decrypt(ctx, jwe, cek, enc, prot ? prot : "", aad);

    if (pt && zipper) {
        jose_buf_auto_t *tmp = NULL;
        tmp = zipper->inflate(ctx, pt->data, pt->size);
        jose_buf_decref(pt);
        pt = jose_buf_incref(tmp);
    }

    return jose_buf_incref(pt);
}

json_t *
jose_jwe_decrypt_json(jose_ctx_t *ctx, const json_t *jwe, const json_t *cek)
{
    jose_buf_auto_t *pt = NULL;
    json_t *ct = NULL;

    ct = json_object_get(jwe, "ciphertext");
    if (!json_is_string(ct))
        return NULL;

    pt = jose_jwe_decrypt(ctx, jwe, cek);
    if (!pt)
        return NULL;

    return json_loadb((char *) pt->data, pt->size, JSON_DECODE_ANY, NULL);
}

json_t *
jose_jwe_merge_header(const json_t *jwe, const json_t *rcp)
{
    json_auto_t *p = NULL;
    json_t *s = NULL;
    json_t *h = NULL;

    p = json_object_get(jwe, "protected");
    if (!p)
        p = json_object();
    else if (json_is_object(p))
        p = json_deep_copy(p);
    else if (json_is_string(p))
        p = jose_b64_decode_json_load(p);

    if (!json_is_object(p))
        return NULL;

    s = json_object_get(jwe, "unprotected");
    if (s) {
        if (json_object_update_missing(p, s) == -1)
            return NULL;
    }

    h = json_object_get(rcp, "header");
    if (h) {
        if (json_object_update_missing(p, h) == -1)
            return NULL;
    }

    return json_incref(p);
}
