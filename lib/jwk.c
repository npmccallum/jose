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

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/hooks.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>


bool
jose_jwk_generate(json_t *jwk)
{
    jose_jwk_type_t *type = NULL;
    const char *kty = NULL;

    for (jose_jwk_resolver_t *r = jose_jwk_resolvers(); r; r = r->next) {
        if (!r->handles(jwk))
            continue;
        if (!r->resolve(jwk))
            return false;
    }

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    for (type = jose_jwk_types(); type && strcmp(kty, type->kty) != 0; type = type->next)
        continue;

    if (!type)
        return false;

    for (jose_jwk_generator_t *g = jose_jwk_generators(); g; g = g->next) {
        if (strcmp(g->kty, kty) != 0)
            continue;

        if (!g->generate(jwk))
            return false;

        for (size_t i = 0; type->req[i]; i++) {
            if (!json_object_get(jwk, type->req[i]))
                return false;
        }

        return true;
    }

    return false;
}

static bool
jwk_clean(json_t *jwk)
{
    jose_jwk_type_t *type = NULL;
    const char *kty = NULL;

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    for (type = jose_jwk_types(); type; type = type->next) {
        if (strcasecmp(kty, type->kty) == 0)
            break;
    }

    if (!type)
        return false;

    for (size_t i = 0; type->prv[i]; i++) {
        if (!json_object_get(jwk, type->prv[i]))
            continue;

        if (json_object_del(jwk, type->prv[i]) == -1)
            return false;
    }

    for (jose_jwk_op_t *o = jose_jwk_ops(); o; o = o->next) {
        json_t *arr = NULL;

        if (!o->prv && (!type->sym || !o->pub))
            continue;

        arr = json_object_get(jwk, "key_ops");
        for (size_t i = 0; i < json_array_size(arr); i++) {
            const char *ko = NULL;

            ko = json_string_value(json_array_get(arr, i));
            if (!ko)
                continue;

            if ((!o->prv || strcmp(o->prv, ko) != 0) &&
                (!type->sym || !o->pub || strcmp(o->pub, ko) != 0))
                continue;

            if (json_array_remove(arr, i--) == -1)
                return false;
        }
    }

    return true;
}

bool
jose_jwk_clean(json_t *jwk)
{
    json_t *keys = NULL;

    if (json_is_array(jwk))
        keys = jwk;
    else if (json_is_array(json_object_get(jwk, "keys")))
        keys = json_object_get(jwk, "keys");

    if (!keys)
        return jwk_clean(jwk);

    for (size_t i = 0; i < json_array_size(keys); i++) {
        if (!jwk_clean(json_array_get(keys, i)))
            return false;
    }

    return true;
}

bool
jose_jwk_allowed(const json_t *jwk, bool req, const char *op)
{
    const char *use = NULL;
    json_t *ko = NULL;

    if (!json_is_object(jwk))
        return true;

    if (!op)
        return false;

    if (json_unpack((json_t *) jwk, "{s?s,s?o}",
                    "use", &use, "key_ops", &ko) != 0)
        return false;

    if (!use && !ko)
        return !req;

    for (size_t i = 0; i < json_array_size(ko); i++) {
        json_t *v = json_array_get(ko, i);

        if (json_is_string(v) && strcmp(op, json_string_value(v)) == 0)
            return true;
    }

    for (jose_jwk_op_t *o = jose_jwk_ops(); use && o; o = o->next) {
        if (!o->use || strcmp(use, o->use) != 0)
            continue;

        if (o->pub && strcmp(op, o->pub) == 0)
            return true;

        if (o->prv && strcmp(op, o->prv) == 0)
            return true;
    }

    return false;
}

char *
jose_jwk_thumbprint(const json_t *jwk, const char *hash)
{
    char *out = NULL;
    size_t len = 0;

    len = jose_jwk_thumbprint_len(hash);
    if (!len)
        return NULL;

    out = malloc(len + 1);
    if (!out)
        return NULL;

    if (!jose_jwk_thumbprint_buf(jwk, hash, out)) {
        free(out);
        return NULL;
    }

    return out;
}

size_t
jose_jwk_thumbprint_len(const char *hash)
{
    jose_jwk_hasher_t *hasher = NULL;

    for (hasher = jose_jwk_hashers(); hash && hasher; hasher = hasher->next) {
        if (strcasecmp(hash, hasher->name) == 0)
            break;
    }

    if (!hasher)
        return 0;

    return jose_b64_elen(hasher->size);
}

bool
jose_jwk_thumbprint_buf(const json_t *jwk, const char *hash, char enc[])
{
    jose_jwk_hasher_t *hasher = NULL;
    jose_jwk_type_t *type = NULL;
    json_auto_t *key = NULL;
    const char *kty = NULL;
    char *str = NULL;
    bool ret = false;

    for (hasher = jose_jwk_hashers(); hash && hasher; hasher = hasher->next) {
        if (strcasecmp(hash, hasher->name) == 0)
            break;
    }

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    for (type = jose_jwk_types(); type; type = type->next) {
        if (strcasecmp(kty, type->kty) == 0)
            break;
    }

    if (!hasher || !type)
        return false;

    uint8_t buf[hasher->size];

    key = json_pack("{s:s}", "kty", kty);

    for (size_t i = 0; type->req[i]; i++) {
        json_t *tmp = NULL;

        tmp = json_object_get(jwk, type->req[i]);
        if (!tmp)
            goto egress;

        tmp = json_deep_copy(tmp);
        if (!tmp)
            goto egress;

        if (json_object_set_new(key, type->req[i], tmp) == -1)
            goto egress;
    }

    str = json_dumps(key, JSON_SORT_KEYS | JSON_COMPACT);
    if (!str)
        goto egress;

    ret = hasher->hash((uint8_t *) str, strlen(str), buf);
    if (ret)
        jose_b64_encode_buf(buf, sizeof(buf), enc);

egress:
    memset(buf, 0, sizeof(buf));
    free(str);
    return ret;
}

json_t *
jose_jwk_thumbprint_json(const json_t *jwk, const char *hash)
{
    json_t *ret = NULL;
    char *thp = NULL;

    thp = jose_jwk_thumbprint(jwk, hash);
    if (thp)
        ret = json_string(thp);

    free(thp);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static const char *oct_req[] = { "k", NULL };
    static const char *oct_prv[] = { "k", NULL };

    static const char *rsa_req[] = { "e", "n", NULL };
    static const char *rsa_prv[] = { "p", "d", "q", "dp", "dq", "qi", "oth", NULL };

    static const char *ec_req[] = { "crv", "x", "y", NULL };
    static const char *ec_prv[] = { "d", NULL };

    static jose_jwk_type_t builtin_types[] = {
        { .kty = "oct", .req = oct_req, .prv = oct_prv, .sym = true },
        { .kty = "RSA", .req = rsa_req, .prv = rsa_prv },
        { .kty = "EC", .req = ec_req, .prv = ec_prv },
        {}
    };

    static jose_jwk_op_t builtin_ops[] = {
        { .pub = "verify",  .prv = "sign",      .use = "sig" },
        { .pub = "encrypt", .prv = "decrypt",   .use = "enc" },
        { .pub = "wrapKey", .prv = "unwrapKey", .use = "enc" },

        { .pub = "deriveKey" },
        { .pub = "deriveBits" },
        {}
    };

    for (size_t i = 0; builtin_types[i].kty; i++)
        jose_jwk_register_type(&builtin_types[i]);

    for (size_t i = 0; builtin_ops[i].use; i++)
        jose_jwk_register_op(&builtin_ops[i]);
}

json_t *
jose_jwk_exchange(const json_t *prv, const json_t *pub)
{
    if (!jose_jwk_allowed(prv, false, "deriveKey") &&
        !jose_jwk_allowed(prv, false, "deriveBits"))
        return NULL;

    if (!jose_jwk_allowed(pub, false, "deriveKey") &&
        !jose_jwk_allowed(pub, false, "deriveBits"))
        return NULL;

    for (jose_jwk_exchanger_t *e = jose_jwk_exchangers(); e; e = e->next) {
        json_t *key = NULL;

        key = e->exchange(prv, pub);
        if (key)
            return key;
    }

    return NULL;
}
