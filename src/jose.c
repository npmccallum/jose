/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "b64.h"
#include "jwk.h"
#include "jws.h"
#include "jwe.h"

#include <openssl/pem.h>
#include <openssl/rand.h>

#include <argp.h>
#include <string.h>

static uint8_t *
load_all(FILE *file, size_t *len)
{
    static const size_t blocksize = 512;
    uint8_t *buf = NULL;

    for (size_t r = blocksize; r == blocksize; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(buf, *len + blocksize);
        if (!tmp) {
            free(buf);
            return NULL;
        }

        buf = tmp;
        r = fread(&buf[*len], 1, blocksize, stdin);
        *len += r;
    }

    return buf;
}

static json_t *
load_jose(FILE *file, json_t *(*conv)(const char *))
{
    uint8_t *buf = NULL;
    json_t *out = NULL;
    char *str = NULL;
    size_t len = 0;

    buf = load_all(file, &len);
    if (!buf)
        return NULL;

    str = calloc(1, len + 1);
    if (!str) {
        free(buf);
        return NULL;
    }

    memcpy(str, buf, len);
    free(buf);

    out = conv(str);
    if (!out)
        out = json_loads(str, 0, NULL);

    free(str);
    return out;
}

static size_t
str_to_enum(const char *str, ...)
{
    size_t i = 0;
    va_list ap;

    va_start(ap, str);

    for (const char *v = NULL; (v = va_arg(ap, const char *)); i++) {
        if (str && strcmp(str, v) == 0)
            break;
    }

    va_end(ap);
    return i;
}

static EVP_PKEY *
import_ec(FILE *file)
{
    EVP_PKEY *pkey = NULL;
    EC_GROUP *grp = NULL;
    EC_KEY *eckey = NULL;

    grp = PEM_read_ECPKParameters(file, NULL, NULL, NULL);
    if (!grp)
        goto error;

    eckey = PEM_read_ECPrivateKey(file, NULL, NULL, NULL);
    if (!eckey)
        goto error;

    if (EC_KEY_set_group(eckey, grp) <= 0)
        goto error;

    pkey = EVP_PKEY_new();
    if (!pkey)
        goto error;

    if (EVP_PKEY_set_type(pkey, EVP_PKEY_EC) <= 0)
        goto error;

    if (EVP_PKEY_set1_EC_KEY(pkey, eckey) <= 0)
        goto error;

    EC_GROUP_free(grp);
    EC_KEY_free(eckey);
    return pkey;

error:
    EVP_PKEY_free(pkey);
    EC_GROUP_free(grp);
    EC_KEY_free(eckey);
    return NULL;
}

static int
jose_import(int argc, char *argv[])
{
    STACK_OF(X509) *certs = NULL;
    json_t *jwk = NULL;
    FILE *file = NULL;

    if (argc < 3)
        return EXIT_FAILURE;

    file = fopen(argv[2], "r");
    if (!file) {
        fprintf(stderr, "Unable to open: %s!\n", argv[2]);
        return EXIT_FAILURE;
    }

    certs = sk_X509_new_null();
    if (!certs)
        goto error;

    for (X509 *x = PEM_read_X509(file, NULL, NULL, NULL); x;
               x = PEM_read_X509(file, NULL, NULL, NULL)) {
        if (sk_X509_unshift(certs, x) <= 0)
            goto error;
    }

    if (sk_X509_num(certs) > 0) {
        jwk = jose_jwk_from_x5c(certs, JOSE_JWK_X5T_SHA1);
    } else {
        EVP_PKEY *pkey = NULL;

        if (fseek(file, 0, SEEK_SET) != 0)
            goto error;

        pkey = import_ec(file);
        if (pkey) {
            jwk = jose_jwk_from_key(pkey, true);
            EVP_PKEY_free(pkey);
        }
    }

    if (!jwk)
        goto error;

    json_dumpf(jwk, stdout, JSON_SORT_KEYS);
    fprintf(stdout, "\n");

    sk_X509_pop_free(certs, X509_free);
    json_decref(jwk);
    fclose(file);
    return EXIT_SUCCESS;

error:
    fprintf(stderr, "Error during import!\n");
    sk_X509_pop_free(certs, X509_free);
    json_decref(jwk);
    fclose(file);
    return EXIT_FAILURE;
}

static int
jose_generate(int argc, char *argv[])
{
    json_t *jwk = NULL;

    jwk = json_loads(argv[2], 0, NULL);
    if (!jwk || !jose_jwk_generate(jwk)) {
        fprintf(stderr, "Invalid template!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    if (json_dumpf(jwk, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWK!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");
    json_decref(jwk);
    return EXIT_SUCCESS;
}

static int
jose_publicize(int argc, char *argv[])
{
    json_t *jwk = NULL;

    jwk = json_loadf(stderr, 0, NULL);
    if (!jwk) {
        fprintf(stderr, "Invalid JWK!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    if (!jose_jwk_publicize(jwk)) {
        fprintf(stderr, "Error removing public keys!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    if (json_dumpf(jwk, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWK!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    json_decref(jwk);
    return EXIT_SUCCESS;
}

static int
jose_sign(int argc, char *argv[])
{
    json_t *jws = NULL;
    uint8_t *b = NULL;
    size_t l = 0;

    if (argc < 4)
        return EXIT_FAILURE;

    jws = json_loads(argv[2], 0, NULL);
    if (!jws) {
        fprintf(stderr, "Invalid template!\n");
        return EXIT_FAILURE;
    }

    for (size_t r = 512; r == 512; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(b, l + 512);
        if (!tmp) {
            fprintf(stderr, "Out of memory!\n");
            json_decref(jws);
            return EXIT_FAILURE;
        }

        b = tmp;
        r = fread(&b[l], 1, 512, stdin);
        l += r;
    }

    if (json_object_set_new(jws, "payload", jose_b64_encode_json(b, l)) < 0) {
        fprintf(stderr, "Error encoding payload!\n");
        json_decref(jws);
        return EXIT_FAILURE;
    }

    for (int i = 3; i < argc; i++) {
        json_t *jwk = NULL;
        FILE *file = NULL;

        file = fopen(argv[i], "r");
        if (!file) {
            fprintf(stderr, "Unable to open: %s!\n", argv[i]);
            json_decref(jws);
            return EXIT_FAILURE;
        }

        jwk = json_loadf(file, 0, NULL);
        fclose(file);
        if (!jwk) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            json_decref(jws);
            return EXIT_FAILURE;
        }

        if (!jose_jws_sign_jwk(jws, jwk, NULL)) {
            fprintf(stderr, "Error creating signature!\n");
            json_decref(jws);
            json_decref(jwk);
            return EXIT_FAILURE;
        }

        json_decref(jwk);
    }

    if (json_dumpf(jws, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWS!\n");
        json_decref(jws);
        return EXIT_FAILURE;
    }

    json_decref(jws);
    return EXIT_SUCCESS;
}

static int
jose_verify(int argc, char *argv[])
{
    json_t *jws = NULL;

    if (argc < 3)
        return EXIT_FAILURE;

    jws = load_jose(stdin, jose_jws_from_compact);
    if (!jws)
        return EXIT_FAILURE;

    for (int i = 2; i < argc; i++) {
        json_t *jwk = NULL;
        FILE *file = NULL;

        file = fopen(argv[i], "r");
        if (!file) {
            fprintf(stderr, "Unable to open: %s!\n", argv[i]);
            json_decref(jws);
            return EXIT_FAILURE;
        }

        jwk = json_loadf(file, 0, NULL);
        fclose(file);
        if (!jwk) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            json_decref(jws);
            return EXIT_FAILURE;
        }

        if (jose_jws_verify_jwk(jws, jwk)) {
            const char *payload = NULL;
            uint8_t *out = NULL;
            size_t len = 0;

            json_decref(jwk);

            if (json_unpack(jws, "{s:s}", "payload", &payload) < 0) {
                json_decref(jws);
                return EXIT_FAILURE;
            }

            len = jose_b64_dlen(strlen(payload));
            out = malloc(len);
            if (!out) {
                json_decref(jws);
                return EXIT_FAILURE;
            }

            if (!jose_b64_decode(payload, out)) {
                json_decref(jws);
                free(out);
                return EXIT_FAILURE;
            }

            fwrite(out, 1, len, stdout);
            json_decref(jws);
            free(out);
            return EXIT_SUCCESS;
        }

        json_decref(jwk);
    }

    fprintf(stderr, "No signatures validated!\n");
    json_decref(jws);
    return EXIT_FAILURE;
}

static int
jose_encrypt(int argc, char *argv[])
{
    EVP_PKEY *cek = NULL;
    json_t *jwe = NULL;
    uint8_t *b = NULL;
    size_t l = 0;

    if (argc < 4)
        return EXIT_FAILURE;

    jwe = json_loads(argv[2], 0, NULL);
    if (!jwe) {
        fprintf(stderr, "Invalid template!\n");
        return EXIT_FAILURE;
    }

    for (size_t r = 512; r == 512; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(b, l + 512);
        if (!tmp) {
            fprintf(stderr, "Out of memory!\n");
            json_decref(jwe);
            return EXIT_FAILURE;
        }

        b = tmp;
        r = fread(&b[l], 1, 512, stdin);
        l += r;
    }

    cek = jose_jwe_generate_cek(jwe);
    if (!cek) {
        fprintf(stderr, "Error generating CEK!\n");
        json_decref(jwe);
        free(b);
        return EXIT_FAILURE;
    }

    if (!jose_jwe_encrypt(jwe, cek, b, l)) {
        fprintf(stderr, "Error encrypting input!\n");
        EVP_PKEY_free(cek);
        json_decref(jwe);
        free(b);
        return EXIT_FAILURE;
    }
    free(b);

    for (int i = 3; i < argc; i++) {
        json_t *jwk = NULL;
        FILE *file = NULL;

        file = fopen(argv[i], "r");
        if (!file) {
            fprintf(stderr, "Unable to open: %s!\n", argv[i]);
            EVP_PKEY_free(cek);
            json_decref(jwe);
            return EXIT_FAILURE;
        }

        jwk = json_loadf(file, 0, NULL);
        fclose(file);
        if (!jwk) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            EVP_PKEY_free(cek);
            json_decref(jwe);
            return EXIT_FAILURE;
        }

        if (!jose_jwe_seal_jwk(jwe, cek, jwk, NULL)) {
            fprintf(stderr, "Error creating seal!\n");
            EVP_PKEY_free(cek);
            json_decref(jwe);
            json_decref(jwk);
            return EXIT_FAILURE;
        }

        json_decref(jwk);
    }

    if (json_dumpf(jwe, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWS!\n");
        EVP_PKEY_free(cek);
        json_decref(jwe);
        return EXIT_FAILURE;
    }

    EVP_PKEY_free(cek);
    json_decref(jwe);
    return EXIT_SUCCESS;
}

static int
jose_decrypt(int argc, char *argv[])
{
    uint8_t *out = NULL;
    json_t *jwe = NULL;
    ssize_t len = 0;

    if (argc < 3)
        return EXIT_FAILURE;

    jwe = load_jose(stdin, jose_jwe_from_compact);
    if (!jwe)
        return EXIT_FAILURE;

    len = json_string_length(json_object_get(jwe, "ciphertext"));
    len = jose_b64_dlen(len);
    out = malloc(len);
    if (!out) {
        fprintf(stderr, "Out of memory!\n");
        goto error;
    }

    for (int i = 2; i < argc; i++) {
        EVP_PKEY *cek = NULL;
        json_t *jwk = NULL;
        FILE *file = NULL;

        file = fopen(argv[i], "r");
        if (!file) {
            fprintf(stderr, "Unable to open: %s!\n", argv[i]);
            goto error;
        }

        jwk = json_loadf(file, 0, NULL);
        fclose(file);
        if (!jwk) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            goto error;
        }

        cek = jose_jwe_unseal_jwk(jwe, jwk);
        if (cek) {
            len = jose_jwe_decrypt(jwe, cek, out);
            if (len < 0) {
                fprintf(stderr, "Error during decryption!\n");
                EVP_PKEY_free(cek);
                json_decref(jwk);
                goto error;
            }

            fwrite(out, 1, len, stdout);
            EVP_PKEY_free(cek);
            json_decref(jwe);
            json_decref(jwk);
            free(out);
            return EXIT_SUCCESS;
        }

        json_decref(jwk);
    }

    fprintf(stderr, "Decryption failed!\n");

error:
    free(out);
    json_decref(jwe);
    return EXIT_FAILURE;
}

int
main(int argc, char *argv[])
{
    if (argc < 2)
        goto usage;

    OpenSSL_add_all_algorithms();
    RAND_poll();

    switch(str_to_enum(argv[1], "import", "export", "generate", "publicize",
                       "sign", "verify", "encrypt", "decrypt", NULL)) {
    case 0: return jose_import(argc, argv);
    case 2: return jose_generate(argc, argv);
    case 3: return jose_publicize(argc, argv);
    case 4: return jose_sign(argc, argv);
    case 5: return jose_verify(argc, argv);
    case 6: return jose_encrypt(argc, argv);
    case 7: return jose_decrypt(argc, argv);
    }

usage:
    fprintf(stderr, "Usage:\n");
    return EXIT_FAILURE;
}
