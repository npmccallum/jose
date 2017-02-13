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

struct jose_jws_sctx {
    const jose_jws_signer_t *signer;
    jose_jws_sctx_hook_t *hook;
    json_t *sig;
};

struct jose_jws_vctx {
    const jose_jws_signer_t *signer;
    union {
        jose_jws_sctx_hook_t *sctx;
        jose_jws_vctx_hook_t *vctx;
    } hook;
    jose_buf_t *sig;
};

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
jose_jws_sign(jose_ctx_t *ctx, json_t *jws, const json_t *sig,
              const json_t *jwk)
{
    jose_jws_sctx_t *sctx = NULL;
    const char *payl = NULL;

    if (json_unpack(jws, "{s:s}", "payload", &payl) == -1)
        return false;

    sctx = jose_jws_sign_init(ctx, sig, jwk);
    if (!sctx)
        return false;

    if (!jose_jws_sign_push(sctx, payl)) {
        jose_jws_sign_free(sctx);
        return false;
    }

    return jose_jws_sign_done(sctx, jws);
}

jose_jws_sctx_t *
jose_jws_sign_init(jose_ctx_t *ctx, const json_t *sig, const json_t *jwk)
{
    const jose_jws_signer_t *signer = NULL;
    jose_jws_sctx_t *sctx = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *alg = NULL;
    json_auto_t *s = NULL;
    json_auto_t *p = NULL;

    if (!sig) {
        s = json_object();
    } else if (!json_is_object(sig)) {
        jose_ctx_err(ctx, "Parameter sig MUST be an object or NULL");
        return NULL;
    } else {
        s = json_deep_copy(sig);
    }

    if (!jose_jwk_allowed(jwk, false, "sign")) {
        jose_ctx_err(ctx, "JWK cannot be used to sign");
        return NULL;
    }

    if (json_unpack(s, "{s?o}", "protected", &p) == -1)
        return NULL;

    if (json_is_object(p))
        p = json_incref(p);
    else if (json_is_string(p))
        p = jose_b64_decode_json_load(p);
    else if (p) {
        jose_ctx_err(ctx, "Protected header must be an object or base64");
        return NULL;
    }

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        return NULL;

    if (json_unpack(p, "{s:s}", "alg", &alg) == -1 &&
        json_unpack(s, "{s:{s:s}}", "header", "alg", &alg) == -1) {
        alg = kalg;
        for (signer = jose_jws_signers(); signer && !alg; signer = signer->next)
            alg = signer->suggest(ctx, jwk);

        if (!set_protected_new(s, "alg", json_string(alg))) {
            jose_ctx_err(ctx, "Error setting algorithm in protected header");
            return NULL;
        }
    }

    if (kalg && strcmp(alg, kalg) != 0) {
        jose_ctx_err(ctx, "JWK cannot be used with specified algorithm");
        return NULL;
    }

    prot = encode_protected(s);
    if (!prot) {
        jose_ctx_err(ctx, "Error encoding protected header");
        return NULL;
    }

    signer = find(alg);
    if (!signer) {
        jose_ctx_err(ctx, "Algorithm is not a supported signing algorithm");
        return NULL;
    }

    sctx = calloc(1, sizeof(*sctx));
    if (!sctx)
        return NULL;

    sctx->signer = signer;
    sctx->sig = json_incref(s);

    sctx->hook = signer->sig_init(ctx, jwk, alg);
    if (!sctx->hook) {
        free(sctx);
        return NULL;
    }

    if (!signer->sig_push(sctx->hook, prot ? prot : ""))
        goto error;

    if (!signer->sig_push(sctx->hook, "."))
        goto error;

    return sctx;

error:
    jose_jws_sign_free(sctx);
    return NULL;
}

bool
jose_jws_sign_push(jose_jws_sctx_t *sctx, const char *payl)
{
    if (!sctx || !sctx->signer)
        return false;

    return sctx->signer->sig_push(sctx->hook, payl);
}

bool
jose_jws_sign_done(jose_jws_sctx_t *sctx, json_t *jws)
{
    jose_buf_auto_t *buf = NULL;
    json_auto_t *sig = sctx->sig;
    json_auto_t *enc = NULL;

    buf = sctx->signer->sig_done(sctx->hook);
    if (!buf)
        return false;

    enc = jose_b64_encode_json(buf->data, buf->size);
    if (!enc)
        return false;

    if (json_object_set(sig, "signature", enc) == -1)
        return false;

    return add_entity(jws, sig, "signatures",
                      "signature", "protected", "header", NULL);
}

void
jose_jws_sign_free(jose_jws_sctx_t *sctx)
{
    if (!sctx)
        return;

    if (sctx->hook)
        sctx->signer->sig_free(sctx->hook);

    json_decref(sctx->sig);
    free(sctx);
}

bool
jose_jws_verify(jose_ctx_t *ctx, const json_t *jws, const json_t *sig,
                const json_t *jwk)
{
    jose_jws_vctx_t *vctx = NULL;
    const char *payl = NULL;

    if (!sig) {
        const json_t *array = NULL;

        array = json_object_get(jws, "signatures");
        if (!json_is_array(array))
            return jose_jws_verify(ctx, jws, jws, jwk);

        for (size_t i = 0; i < json_array_size(array); i++) {
            if (jose_jws_verify(ctx, jws, json_array_get(array, i), jwk))
                return true;
        }

        return false;
    }

    if (json_unpack((json_t *) jws, "{s:s}", "payload", &payl) == -1) {
        jose_ctx_err(ctx, "JWS is missing the payload attribute");
        return false;
    }

    vctx = jose_jws_verify_init(ctx, sig, jwk);
    if (!vctx)
        return false;

    if (!jose_jws_verify_push(vctx, payl)) {
        jose_jws_verify_free(vctx);
        return false;
    }

    return jose_jws_verify_done(vctx);
}

jose_jws_vctx_t *
jose_jws_verify_init(jose_ctx_t *ctx, const json_t *sig, const json_t *jwk)
{
    const jose_jws_signer_t *signer = NULL;
    jose_jws_vctx_t *vctx = NULL;
    jose_buf_auto_t *buf = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *halg = NULL;
    const char *sign = NULL;
    json_auto_t *hdr = NULL;

    if (!jose_jwk_allowed(jwk, false, "verify")) {
        jose_ctx_err(ctx, "JWK cannot be used to verify");
        return NULL;
    }

    if (json_unpack((json_t *) sig, "{s?s,s:s}",
                    "protected", &prot, "signature", &sign) != 0)
        return NULL;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) != 0)
        return NULL;

    hdr = jose_jws_merge_header(sig);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s?s}", "alg", &halg) != 0)
        return NULL;

    if (!halg) {
        if (!kalg) {
            jose_ctx_err(ctx, "Signature algorithm cannot be inferred");
            return NULL;
        }

        halg = kalg;
    } else if (kalg && strcmp(halg, kalg) != 0) {
        jose_ctx_err(ctx, "JWK cannot be used with specified algorithm");
        return NULL;
    }

    signer = find(halg);
    if (!signer) {
        jose_ctx_err(ctx, "Algorithm is not a supported signing algorithm");
        return NULL;
    }

    buf = jose_b64_decode_json(json_object_get(sig, "signature"));
    if (!buf)
        return NULL;

    vctx = calloc(1, sizeof(*vctx));
    if (!vctx)
        return NULL;

    vctx->signer = signer;

    if (signer->ver_init) {
        vctx->hook.vctx = signer->ver_init(ctx, jwk, halg, buf);
        if (!vctx->hook.vctx)
            goto error;

        if (!signer->ver_push(vctx->hook.vctx, prot ? prot : ""))
            goto error;

        if (!signer->ver_push(vctx->hook.vctx, "."))
            goto error;
    } else {
        vctx->hook.sctx = signer->sig_init(ctx, jwk, halg);
        if (!vctx->hook.sctx)
            goto error;

        if (!signer->sig_push(vctx->hook.sctx, prot ? prot : ""))
            goto error;

        if (!signer->sig_push(vctx->hook.sctx, "."))
            goto error;

        vctx->sig = jose_buf_incref(buf);
    }

    return vctx;

error:
    jose_jws_verify_free(vctx);
    return NULL;
}

bool
jose_jws_verify_push(jose_jws_vctx_t *vctx, const char *payl)
{
    if (!vctx || !payl)
        return false;

    if (vctx->signer->ver_push)
        return vctx->signer->ver_push(vctx->hook.vctx, payl);
    else
        return vctx->signer->sig_push(vctx->hook.sctx, payl);
}

bool
jose_jws_verify_done(jose_jws_vctx_t *vctx)
{
    jose_buf_auto_t *buf = NULL;
    jose_buf_auto_t *sig = NULL;
    const jose_jws_signer_t *s;
    typeof(vctx->hook) h;
    bool mismatch = false;

    if (!vctx)
        return false;

    s = vctx->signer;
    sig = vctx->sig;
    h = vctx->hook;
    free(vctx);

    if (s->ver_done)
        return s->ver_done(h.vctx);

    buf = s->sig_done(h.sctx);
    if (!buf || !sig)
        return false;

    /* Constant time signature comparison. */
    mismatch = buf->size == sig->size;
    for (size_t i = 0; i < buf->size && i < sig->size; i++)
        mismatch |= buf->data[i] != sig->data[i];

    return mismatch;
}

void
jose_jws_verify_free(jose_jws_vctx_t *vctx)
{
    const jose_jws_signer_t *s;
    typeof(vctx->hook) h;

    if (!vctx)
        return;

    s = vctx->signer;
    h = vctx->hook;
    free(vctx);

    if (s->ver_free && h.vctx)
        s->ver_free(h.vctx);
    else if (s->sig_free && h.sctx)
        s->sig_free(h.sctx);
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
