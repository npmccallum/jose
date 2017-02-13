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

#pragma once

#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
const unsigned char *
EVP_PKEY_get0_hmac(EVP_PKEY *pkey, size_t *len);

void
RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

void
RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);

void
RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1,
                    const BIGNUM **iqmp);

RSA *
EVP_PKEY_get0_RSA(EVP_PKEY *pkey);

EC_KEY *
EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

int
RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);

int
RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);

int
RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);

EVP_MD_CTX *
EVP_MD_CTX_new(void);

void
EVP_MD_CTX_free(EVP_MD_CTX *ctx);

void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);

int
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

HMAC_CTX *
HMAC_CTX_new(void);

const EVP_MD *
HMAC_CTX_get_md(const HMAC_CTX *ctx);

void
HMAC_CTX_free(HMAC_CTX *ctx);
#endif
