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

#include "compat.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
const unsigned char *
EVP_PKEY_get0_hmac(EVP_PKEY *pkey, size_t *len)
{
    ASN1_OCTET_STRING *os = NULL;

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_HMAC)
        return NULL;

    os = EVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}

void
RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n)
        *n = r->n;

    if (e)
        *e = r->e;

    if (d)
        *d = r->d;
}

void
RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p)
        *p = r->p;

    if (q)
        *q = r->q;
}

void
RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1,
                    const BIGNUM **iqmp)
{
    if (dmp1)
        *dmp1 = r->dmp1;

    if (dmq1)
        *dmq1 = r->dmq1;

    if (iqmp)
        *iqmp = r->iqmp;
}

RSA *
EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_RSA)
        return NULL;

    return pkey->pkey.rsa;
}

EC_KEY *
EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_EC)
        return NULL;

    return pkey->pkey.ec;
}

int
RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if (!r->n && !n)
        return 0;

    if (!r->e && !e)
        return 0;

    if (n) {
        BN_free(r->n);
        r->n = n;
    }

    if (e) {
        BN_free(r->e);
        r->e = e;
    }

    if (d) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

int
RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    if (!r->p && !p)
        return 0;

    if (!r->q && !q)
        return 0;

    if (p) {
        BN_free(r->p);
        r->p = p;
    }

    if (q) {
        BN_free(r->q);
        r->q = q;
    }

    return 1;
}

int
RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    if (!r->dmp1 && !dmp1)
        return 0;

    if (!r->dmq1 && !dmq1)
        return 0;

    if (!r->iqmp && !iqmp)
        return 0;

    if (dmp1) {
        BN_free(r->dmp1);
        r->dmp1 = dmp1;
    }

    if (dmq1) {
        BN_free(r->dmq1);
        r->dmq1 = dmq1;
    }

    if (iqmp) {
        BN_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
    EVP_MD_CTX *ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX));
    if (!ctx)
        return NULL;

    EVP_MD_CTX_init(ctx);
    return ctx;
}

void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    if (!ctx)
        return;

    EVP_MD_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr)
        *pr = sig->r;

    if (ps)
        *ps = sig->s;
}

int
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (!r || !s)
        return 0;

    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

HMAC_CTX *
HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = OPENSSL_malloc(sizeof(HMAC_CTX));

    if (!ctx)
        return NULL;

    HMAC_CTX_init(ctx);
    return ctx;
}

const EVP_MD *
HMAC_CTX_get_md(const HMAC_CTX *ctx)
{
    return ctx->md;
}

void
HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (!ctx)
        return;

    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
#endif
