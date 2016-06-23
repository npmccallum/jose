/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwk.h"
#include "b64.h"
#include "conv.h"
#include "hash.h"

#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static const char *jwkprv[] = {
    "k", "d", "p", "q", "dp", "dq", "qi", "oth", NULL
};

static bool
getxyd(const EC_KEY *key, BIGNUM **x, BIGNUM **y, const BIGNUM **d)
{
    const EC_GROUP *grp = NULL;
    const EC_POINT *pub = NULL;
    EC_POINT *p = NULL;
    BN_CTX *ctx = NULL;

    grp = EC_KEY_get0_group(key);
    if (!grp)
        return false;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    pub = EC_KEY_get0_public_key(key);
    *d = EC_KEY_get0_private_key(key);
    if (!pub) {
        if (!*d)
            goto error;

        pub = p = EC_POINT_new(grp);
        if (!pub)
            goto error;

        if (EC_POINT_mul(grp, p, *d, NULL, NULL, ctx) < 0)
            goto error;
    }

    *x = BN_new();
    *y = BN_new();
    if (!*x || !*y)
        goto error;

    if (EC_POINT_get_affine_coordinates_GFp(grp, pub, *x, *y, ctx) < 0)
        goto error;

    EC_POINT_free(p);
    BN_CTX_free(ctx);
    return true;

error:
    BN_free(*x); *x = NULL;
    BN_free(*y); *y = NULL;
    EC_POINT_free(p);
    BN_CTX_free(ctx);
    return false;
}

static json_t *
from_ec(EC_KEY *key, bool prv)
{
    const BIGNUM *d = NULL;
    const char *crv = NULL;
    json_t *jwk = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int len = 0;

    if (!key)
        return NULL;

    len = (EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8;

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key))) {
    case NID_X9_62_prime256v1: crv = "P-256"; break;
    case NID_secp384r1: crv = "P-384"; break;
    case NID_secp521r1: crv = "P-521"; break;
    default: goto egress;
    }

    if (!getxyd(key, &x, &y, &d))
        goto egress;

    jwk = json_pack("{s:s,s:s,s:o,s:o}", "kty", "EC", "crv", crv,
                    "x", bn_encode_json(x, len), "y", bn_encode_json(y, len));
    if (d && prv && json_object_set_new(jwk, "d",
                                        bn_encode_json(d, len)) == -1) {
        json_decref(jwk);
        jwk = NULL;
    }

egress:
    BN_free(x);
    BN_free(y);
    return jwk;
}

static json_t *
from_rsa(RSA *key, bool prv)
{
    json_t *jwk = NULL;

    if (!key)
        return NULL;

    if (!key->n || !key->e)
        return NULL;

    if (prv && key->d && key->p && key->q &&
        key->dmp1 && key->dmq1 && key->iqmp) {
        jwk = json_pack(
            "{s:s,s:o,s:o,s:o,s:o,s:o,s:o,s:o,s:o}",
            "kty", "RSA",
            "n", bn_encode_json(key->n, 0),
            "e", bn_encode_json(key->e, 0),
            "d", bn_encode_json(key->d, 0),
            "p", bn_encode_json(key->p, 0),
            "q", bn_encode_json(key->q, 0),
            "dp", bn_encode_json(key->dmp1, 0),
            "dq", bn_encode_json(key->dmq1, 0),
            "qi", bn_encode_json(key->iqmp, 0)
        );
    } else {
        jwk = json_pack(
            "{s:s,s:o,s:o}",
            "kty", "RSA",
            "n", bn_encode_json(key->n, 0),
            "e", bn_encode_json(key->e, 0)
        );
    }

    return jwk;
}

static json_t *
from_hmac(EVP_PKEY *key, bool prv)
{
    const uint8_t *buf = NULL;
    json_t *jwk = NULL;
    size_t len = 0;

    buf = EVP_PKEY_get0_hmac(key, &len);
    if (!buf)
        return NULL;

    jwk = json_pack("{s:s}", "kty", "oct");
    if (jwk && prv) {
        json_t *k = jose_b64_encode_json(buf, len);
        if (json_object_set_new(jwk, "k", k) == -1) {
            json_decref(jwk);
            return NULL;
        }
    }

    return jwk;
}

static EC_POINT *
mkpub(const EC_GROUP *grp, const json_t *x, const json_t *y, const BIGNUM *D)
{
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *X = NULL;
    BIGNUM *Y = NULL;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    pub = EC_POINT_new(grp);
    if (!pub)
        goto error;

    if (x && y) {
        X = bn_decode_json(x);
        Y = bn_decode_json(y);
        if (!X || !Y)
            goto error;

        if (EC_POINT_set_affine_coordinates_GFp(grp, pub, X, Y, ctx) < 0)
            goto error;
    } else if (D) {
        if (EC_POINT_mul(grp, pub, D, NULL, NULL, ctx) < 0)
            goto error;
    } else {
        goto error;
    }

    BN_CTX_free(ctx);
    BN_free(X);
    BN_free(Y);
    return pub;

error:
    EC_POINT_free(pub);
    BN_CTX_free(ctx);
    BN_free(X);
    BN_free(Y);
    return NULL;
}

static EVP_PKEY *
to_ec(const json_t *jwk)
{
    const char *kty = NULL;
    const char *crv = NULL;
    const json_t *x = NULL;
    const json_t *y = NULL;
    const json_t *d = NULL;
    EVP_PKEY *pkey = NULL;
    EC_POINT *pub = NULL;
    int nid = NID_undef;
    EC_KEY *key = NULL;
    BIGNUM *D = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s,s:o,s:o,s?o}", "kty", &kty,
                    "crv", &crv, "x", &x, "y", &y, "d", &d) == -1)
        return NULL;

    if (strcmp(kty, "EC") != 0)
        return NULL;

    switch (str_to_enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: nid = NID_X9_62_prime256v1; break;
    case 1: nid = NID_secp384r1; break;
    case 2: nid = NID_secp521r1; break;
    default: return NULL;
    }

    key = EC_KEY_new_by_curve_name(nid);
    if (!key)
        return NULL;

    if (d) {
        D = bn_decode_json(d);
        if (!D)
            goto egress;

        if (EC_KEY_set_private_key(key, D) < 0)
            goto egress;
    }

    pub = mkpub(EC_KEY_get0_group(key), x, y, D);
    if (!pub)
        goto egress;

    if (EC_KEY_set_public_key(key, pub) < 0)
        goto egress;

    if (EC_KEY_check_key(key) == 0)
        goto egress;

    pkey = EVP_PKEY_new();
    if(!pkey)
        goto egress;

    if (EVP_PKEY_set1_EC_KEY(pkey, key) < 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

egress:
    EC_POINT_free(pub);
    EC_KEY_free(key);
    BN_free(D);
    return pkey;
}

static EVP_PKEY *
to_rsa(const json_t *jwk)
{
    const json_t *dp = NULL;
    const json_t *dq = NULL;
    const json_t *qi = NULL;
    const json_t *n = NULL;
    const json_t *e = NULL;
    const json_t *d = NULL;
    const json_t *p = NULL;
    const json_t *q = NULL;
    const char *kty = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    if (json_unpack(
            (json_t *) jwk, "{s:s,s:o,s:o,s?o,s?o,s?o,s?o,s?o,s?o}",
            "kty", &kty, "n", &n, "e", &e, "d", &d, "p", &p,
            "q", &q, "dp", &dp, "dq", &dq, "qi", &qi
        ) != 0)
        return NULL;

    rsa = RSA_new();
    if (!rsa)
        return NULL;

    rsa->n = bn_decode_json(n);
    rsa->e = bn_decode_json(e);
    if (!rsa->n || !rsa->e)
        goto egress;

    if (d && p && q && dp && dq && qi) {
        rsa->d = bn_decode_json(d);
        rsa->p = bn_decode_json(p);
        rsa->q = bn_decode_json(q);
        rsa->dmp1 = bn_decode_json(dp);
        rsa->dmq1 = bn_decode_json(dq);
        rsa->iqmp = bn_decode_json(qi);

        if (!rsa->d || !rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 ||
            !rsa->iqmp || RSA_blinding_on(rsa, NULL) <= 0)
            goto egress;
    }

    pkey = EVP_PKEY_new();
    if (!pkey)
        goto egress;

    if (EVP_PKEY_set1_RSA(pkey, rsa) < 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

egress:
    RSA_free(rsa);
    return pkey;
}

static EVP_PKEY *
to_hmac(const json_t *jwk)
{
    EVP_PKEY *key = NULL;
    uint8_t *buf = NULL;
    size_t len = 0;

    jwk = json_object_get(jwk, "k");
    if (!json_is_string(jwk))
        return NULL;

    len = jose_b64_dlen(json_string_length(jwk));
    buf = malloc(len);

    if (jose_b64_decode_json(jwk, buf))
        key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buf, len);

    memset(buf, 0, len);
    free(buf);
    return key;
}

static bool
gen_hmac(json_t *jwk)
{
    EVP_PKEY *key = NULL;
    json_t *bytes = NULL;
    uint8_t *buf = NULL;
    json_t *tmp = NULL;
    size_t len = 0;

    if (json_unpack(jwk, "{s?O}", "bytes", &bytes) == -1)
        return false;

    if (!bytes)
        bytes = json_integer(256 / 8);

    if (!json_is_integer(bytes)) {
        json_decref(bytes);
        return false;
    }

    len = json_integer_value(bytes);
    buf = malloc(len);
    json_decref(bytes);
    if (!buf)
        return false;

    if (RAND_bytes(buf, len) <= 0) {
        free(buf);
        return false;
    }

    key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buf, len);
    free(buf);
    if (!key)
        return false;

    tmp = jose_jwk_from_key(key, true);
    EVP_PKEY_free(key);

    if (json_object_update(jwk, tmp) == -1) {
        json_decref(tmp);
        return false;
    }

    if (json_object_get(jwk, "bytes") && json_object_del(jwk, "bytes") == -1) {
        json_decref(tmp);
        return false;
    }

    json_decref(tmp);
    return true;
}

static bool
gen_rsa(json_t *jwk)
{
    json_t *tmp = NULL;
    json_t *exp = NULL;
    BIGNUM *bn = NULL;
    RSA *key = NULL;
    int bits = 2048;

    if (json_unpack(jwk, "{s?i,s?O}", "bits", &bits, "e", &exp) == -1)
        return false;

    if (bits < 2048) {
        json_decref(exp);
        return false;
    }

    if (!exp)
        exp = json_integer(65537);

    switch (exp ? exp->type : JSON_NULL) {
    case JSON_STRING:
        bn = bn_decode_json(exp);
        json_decref(exp);
        if (!bn)
            return false;

        key = RSA_new();
        if (!key) {
            BN_free(bn);
            return false;
        }

        bits = RSA_generate_key_ex(key, bits, bn, NULL);
        BN_free(bn);
        if (bits <= 0) {
            RSA_free(key);
            return false;
        }
        break;

    case JSON_INTEGER:
        key = RSA_generate_key(bits, json_integer_value(exp), NULL, NULL);
        json_decref(exp);
        break;

    default:
        json_decref(exp);
        return false;
    }

    tmp = from_rsa(key, true);
    RSA_free(key);

    if (json_object_update(jwk, tmp) == -1) {
        json_decref(tmp);
        return false;
    }

    if (json_object_get(jwk, "bits") && json_object_del(jwk, "bits") == -1) {
        json_decref(tmp);
        return false;
    }

    json_decref(tmp);
    return true;
}

static bool
gen_ec(json_t *jwk)
{
    const char *crv = NULL;
    int nid = NID_undef;
    json_t *tmp = NULL;
    EC_KEY *key = NULL;

    if (json_unpack(jwk, "{s:s}", "crv", &crv) == -1)
        return false;

    switch (str_to_enum(crv, "P-256", "P-384", "P-521", NULL)) {
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

    tmp = from_ec(key, true);
    EC_KEY_free(key);

    if (json_object_update(jwk, tmp) == -1) {
        json_decref(tmp);
        return false;
    }

    json_decref(tmp);
    return true;
}

bool
jose_jwk_generate(json_t *jwk)
{
    const char *kty = NULL;
    bool ret = false;

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    switch (str_to_enum(kty, "oct", "RSA", "EC", NULL)) {
    case 0: ret = gen_hmac(jwk); break;
    case 1: ret = gen_rsa(jwk); break;
    case 2: ret = gen_ec(jwk); break;
    default: break;
    }

    return ret;
}

bool
jose_jwk_publicize(json_t *jwk)
{
    for (size_t i = 0; jwkprv[i]; i++) {
        if (!json_object_get(jwk, jwkprv[i]))
            continue;

        if (json_object_del(jwk, jwkprv[i]) == -1)
            return false;
    }

    return true;
}

json_t *
jose_jwk_from_key(EVP_PKEY *key, bool prv)
{
    if (!key)
        return NULL;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC: return from_hmac(key, prv);
    case EVP_PKEY_RSA: return from_rsa(key->pkey.rsa, prv);
    case EVP_PKEY_EC: return from_ec(key->pkey.ec, prv);
    default: return NULL;
    }
}

json_t *
jose_jwk_from_x5t(const X509 *x509, jose_jwk_x5t_t hashes)
{
    static const jose_jwk_x5t_t all[] = {
        JOSE_JWK_X5T_SHA1,
        JOSE_JWK_X5T_SHA224,
        JOSE_JWK_X5T_SHA256,
        JOSE_JWK_X5T_SHA384,
        JOSE_JWK_X5T_SHA512,
        JOSE_JWK_X5T_NONE
    };

    uint8_t *der = NULL;
    json_t *jwk = NULL;
    int len = 0;

    jwk = jose_jwk_from_key(x509->cert_info->key->pkey, false);
    if (!jwk)
        return NULL;

    len = i2d_X509((X509 *) x509, &der);
    if (len < 0)
        goto error;

    for (size_t i = 0; all[i] != JOSE_JWK_X5T_NONE; i++) {
        const EVP_MD *md = NULL;
        const char *key = NULL;
        json_t *val = NULL;

        switch (hashes & all[i]) {
        case JOSE_JWK_X5T_SHA1:   md = EVP_sha1();   key = "x5t";      break;
        case JOSE_JWK_X5T_SHA224: md = EVP_sha224(); key = "x5t#S224"; break;
        case JOSE_JWK_X5T_SHA256: md = EVP_sha256(); key = "x5t#S256"; break;
        case JOSE_JWK_X5T_SHA384: md = EVP_sha384(); key = "x5t#S384"; break;
        case JOSE_JWK_X5T_SHA512: md = EVP_sha512(); key = "x5t#S512"; break;
        default: continue;
        }

        uint8_t hsh[EVP_MD_size(md)];
        unsigned int ign = 0;

        if (EVP_Digest(der, len, hsh, &ign, md, NULL) <= 0)
            goto error;

        val = jose_b64_encode_json(hsh, sizeof(hsh));
        if (json_object_set_new(jwk, key, val) == -1)
            goto error;
    }

    OPENSSL_free(der);
    return jwk;

error:
    OPENSSL_free(der);
    json_decref(jwk);
    return NULL;
}

json_t *
jose_jwk_from_x5c(const STACK_OF(X509) *chain, jose_jwk_x5t_t hashes)
{
    json_t *jwk = NULL;
    json_t *x5c = NULL;
    uint8_t *der = NULL;
    int len = 0;

    for (int i = 0; i < sk_X509_num(chain); i++) {
        X509 *x509 = sk_X509_value(chain, i);

        if (!jwk) {
            jwk = jose_jwk_from_x5t(x509, hashes);
            if (!jwk)
                goto error;

            x5c = json_array();
            if (json_object_set_new(jwk, "x5c", x5c) == -1)
                goto error;
        }

        len = i2d_X509(x509, &der);
        if (len < 0)
            goto error;

        if (json_array_append_new(x5c, jose_b64_encode_json(der, len)) == -1)
            goto error;

        OPENSSL_free(der);
    }

    return jwk;

error:
    OPENSSL_free(der);
    json_decref(jwk);
    return NULL;
}

json_t *
jose_jwk_dup(const json_t *jwk, bool prv)
{
    json_t *out = NULL;

    if (!json_is_object(jwk))
        return NULL;

    out = json_deep_copy(jwk);
    if (!out)
        return NULL;

    if (!prv && !jose_jwk_publicize(out)) {
        json_decref(out);
        return NULL;
    }

    return out;
}

EVP_PKEY *
jose_jwk_to_key(const json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    switch (str_to_enum(kty, "oct", "RSA", "EC", NULL)) {
    case 0: return to_hmac(jwk);
    case 1: return to_rsa(jwk);
    case 2: return to_ec(jwk);
    default: return NULL;
    }
}

bool
jose_jwk_use_allowed(const json_t *jwk, const char *use)
{
    json_t *u = NULL;

    if (!use)
        return false;

    u = json_object_get(jwk, "use");
    if (!json_is_string(u))
        return true;

    return strcmp(json_string_value(u), use) == 0;
}

bool
jose_jwk_op_allowed(const json_t *jwk, const char *op)
{
    json_t *ko = NULL;

    ko = json_object_get(jwk, "key_ops");
    if (!json_is_array(ko))
        return true;

    for (size_t i = 0; i < json_array_size(ko); i++) {
        json_t *o = NULL;

        o = json_array_get(ko, i);
        if (!json_is_string(o))
            continue;

        if (strcmp(json_string_value(o), op) == 0)
            return true;
    }

    return false;
}
