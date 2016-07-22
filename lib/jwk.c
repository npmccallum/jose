/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <jose/b64.h>
#include <jose/jwk.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static jose_jwk_type_t *types;
static jose_jwk_op_t *ops;
static jose_jwk_resolver_t *resolvers;
static jose_jwk_generator_t *generators;
static jose_jwk_hasher_t *hashers;

void
jose_jwk_register_type(jose_jwk_type_t *type)
{
    type->next = types;
    types = type;
}

void
jose_jwk_register_op(jose_jwk_op_t *op)
{
    op->next = ops;
    ops = op;
}

void
jose_jwk_register_resolver(jose_jwk_resolver_t *resolver)
{
    resolver->next = resolvers;
    resolvers = resolver;
}

void
jose_jwk_register_generator(jose_jwk_generator_t *generator)
{
    generator->next = generators;
    generators = generator;
}

void
jose_jwk_register_hasher(jose_jwk_hasher_t *hasher)
{
    hasher->next = hashers;
    hashers = hasher;
}

bool
jose_jwk_generate(json_t *jwk)
{
    jose_jwk_type_t *type = NULL;
    const char *kty = NULL;

    for (jose_jwk_resolver_t *r = resolvers; r; r = r->next) {
        if (!r->resolve(jwk))
            return false;
    }

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    for (type = types; type && strcmp(kty, type->kty) != 0; type = type->next)
        continue;

    if (!type)
        return false;

    for (jose_jwk_generator_t *g = generators; g; g = g->next) {
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

    for (type = types; type; type = type->next) {
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

    for (jose_jwk_op_t *o = ops; o; o = o->next) {
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
jose_jwk_allowed(const json_t *jwk, bool req, const char *use, const char *op)
{
    bool found = true;
    json_t *ko = NULL;
    json_t *u = NULL;

    for (jose_jwk_op_t *o = ops; o && !use && op; o = o->next) {
        if (o->pub && strcmp(o->pub, op) == 0)
            use = o->use;

        if (o->prv && strcmp(o->prv, op) == 0)
            use = o->use;
    }

    u = json_object_get(jwk, "use");
    if (use && json_is_string(u)) {
        if (strcmp(json_string_value(u), use) != 0)
            return false;
    } else if (req)
        found = false;

    ko = json_object_get(jwk, "key_ops");
    if (op && json_is_array(ko)) {
        found = false;
        for (size_t i = 0; i < json_array_size(ko) && !found; i++) {
            json_t *o = NULL;

            o = json_array_get(ko, i);
            if (!json_is_string(o))
                continue;

            found = strcmp(json_string_value(o), op) == 0;
        }
    }

    return found;
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

    for (hasher = hashers; hasher; hasher = hasher->next) {
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
    const char *kty = NULL;
    json_t *key = NULL;
    char *str = NULL;
    bool ret = false;

    for (hasher = hashers; hasher; hasher = hasher->next) {
        if (strcasecmp(hash, hasher->name) == 0)
            break;
    }

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    for (type = types; type; type = type->next) {
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
    json_decref(key);
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

    static const char *sss_req[] = { "p", "e", NULL };
    static const char *sss_prv[] = { "e", NULL };

    static jose_jwk_type_t builtin_types[] = {
        { .kty = "oct", .req = oct_req, .prv = oct_prv, .sym = true },
        { .kty = "SSS", .req = sss_req, .prv = sss_prv, .sym = true },
        { .kty = "RSA", .req = rsa_req, .prv = rsa_prv },
        { .kty = "EC",  .req = ec_req,  .prv = ec_prv  },
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
