/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <jansson.h>
#include <stdbool.h>

typedef enum {
    JOSE_JWK_X5T_NONE   = 0,
    JOSE_JWK_X5T_SHA1   = 1 << 0,
    JOSE_JWK_X5T_SHA224 = 1 << 1,
    JOSE_JWK_X5T_SHA256 = 1 << 2,
    JOSE_JWK_X5T_SHA384 = 1 << 3,
    JOSE_JWK_X5T_SHA512 = 1 << 4,
} jose_jwk_x5t_t;

/**
 * Generate a new (random) JWK.
 */
bool __attribute__((warn_unused_result))
jose_jwk_generate(json_t *jwk);

bool
jose_jwk_publicize(json_t *jwk);

/**
 * Create a JWK from an EVP_PKEY.
 */
json_t * __attribute__((warn_unused_result))
jose_jwk_from_key(EVP_PKEY *key, bool prv);

json_t * __attribute__((warn_unused_result))
jose_jwk_from_x5t(const X509 *x509, jose_jwk_x5t_t hashes);

json_t * __attribute__((warn_unused_result))
jose_jwk_from_x5c(const STACK_OF(X509) *chain, jose_jwk_x5t_t hashes);

/**
 * Create a copy of the JWK.
 *
 * Private key material will be included if and only if prv is true.
 */
json_t * __attribute__((warn_unused_result))
jose_jwk_dup(const json_t *jwk, bool prv);

/**
 * Convert a JWK to an EVP_PKEY.
 *
 * NOTE WELL: RSA is vulnerable to a timing attack. OpenSSL provides
 *            countermeasures to protect against this. However, this
 *            requires that the OpenSSL PRNG is properly seeded before
 *            this function is called. You have been warned.
 */
EVP_PKEY * __attribute__((warn_unused_result))
jose_jwk_to_key(const json_t *jwk);

bool
jose_jwk_use_allowed(const json_t *jwk, const char *use);

bool
jose_jwk_op_allowed(const json_t *jwk, const char *op);
