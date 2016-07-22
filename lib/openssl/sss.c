/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/jwk.h>
#include <jose/openssl.h>

static bool
generate(json_t *jwk)
{
    json_t *sss = NULL;
    json_int_t b = 0;
    json_int_t t = 1;
    BIGNUM *p = NULL;
    BIGNUM *e = NULL;
    bool ret = false;

    if (json_unpack(jwk, "{s:I,s?I}", "bytes", &b, "t", &t) == -1)
        return false;

    if (b < 16 || t < 1)
        return false;

    p = BN_new();
    e = BN_new();
    if (!p || !e)
        goto egress;

    if (!BN_generate_prime(p, b * 8, 1, NULL, NULL, NULL, NULL))
        goto egress;

    sss = json_pack("{s:o,s:[]}", "p", bn_encode_json(p, b), "e");
    if (!sss)
        goto egress;

    for (json_int_t i = 0; i < t; i++) {
        if (BN_rand_range(e, p) <= 0)
            goto egress;

        if (json_array_append_new(json_object_get(sss, "e"),
                                  bn_encode_json(e, b)))
            goto egress;
    }

    if (json_object_update(jwk, sss) == -1)
        goto egress;

    ret = true;

egress:
    json_decref(sss);
    BN_free(p);
    BN_free(e);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .kty = "SSS",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
