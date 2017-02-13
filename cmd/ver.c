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

#include <cmd/jose.h>
#include <string.h>

static bool
dump(const char *filename, const json_t *jws)
{
    jose_buf_auto_t *buf = NULL;
    const char *payload = NULL;

    if (json_unpack((json_t *) jws, "{s:s}", "payload", &payload) < 0)
        return false;

    buf = jose_b64_decode(payload);
    if (!buf)
        return false;

    if (!jcmd_dump_data(filename, buf->data, buf->size))
        return false;

    return true;
}

static const struct option opts[] = {
    { "help",     no_argument,       .val = 'h' },

    { "all",      no_argument,       .val = 'a' },
    { "jwk",      required_argument, .val = 'k' },
    { "input",    required_argument, .val = 'i' },
    { "output",   required_argument, .val = 'o' },
    { "detached", required_argument, .val = 'd' },
    {}
};

int
jcmd_ver(int argc, char *argv[])
{
    json_auto_t *jwks = NULL;
    json_auto_t *jws = NULL;
    const char *det = NULL;
    const char *out = NULL;
    bool all = false;

    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "hak:i:o:d:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 'a': all = true; break;
        case 'd': det = optarg; break;

        case 'i':
            json_decref(jws);
            jws = jcmd_load_json(optarg, NULL, jose_from_compact);
            break;

        case 'k':
            if (!jcmd_jwks_extend(jwks, jcmd_load_json(optarg, NULL, NULL))) {
                fprintf(stderr, "Invalid JWK(Set): %s!\n", optarg);
                goto usage;
            }
            break;

        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (json_array_size(jwks) == 0) {
        fprintf(stderr, "MUST specify a JWK(Set)!\n\n");
        goto usage;
    }

    if (!jws) {
        fprintf(stderr, "Invalid JWS!\n");
        return EXIT_FAILURE;
    }

    if (det) {
        uint8_t *py = NULL;
        size_t pyl = 0;
        int r = 0;

        py = jcmd_load_data(det, &pyl);
        if (!py) {
            fprintf(stderr, "Unable to load detatched payload: %s!\n", det);
            return EXIT_FAILURE;
        }

        r = json_object_set_new(jws, "payload", jose_b64_encode_json(py, pyl));
        memset(py, 0, pyl);
        free(py);
        if (r < 0)
            return EXIT_FAILURE;
    }

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        bool valid = false;

        valid = jose_jws_verify(NULL, jws, NULL, json_array_get(jwks, i));
        if (valid && !all) {
            all = true;
            break;
        }

        if (!valid && all) {
            fprintf(stderr, "Signature validation failed!\n");
            return EXIT_FAILURE;
        }
    }

    if (!all)
        fprintf(stderr, "No signatures validated!\n");
    else if ((out || !det) && !dump(out ? out : "-", jws))
        fprintf(stderr, "Error dumping payload!\n");
    else
        return EXIT_SUCCESS;

    return EXIT_FAILURE;

usage:
    fprintf(stderr,
"jose " VER_USE
"\n"
"\nVerifies a JWS using the supplied JWKs and outputs the payload."
"\n"
"\n    -i FILE, --input=FILE       JWS input (file)"
"\n    -i -,    --input=-          JWS input (stdin)"
"\n"
"\n    -d FILE, --detached=FILE    Detached payload input (file)"
"\n    -d -,    --detached=-       Detached payload input (stdin)"
"\n"
"\n    -k FILE, --jwk=FILE         JWK or JWKSet (file)"
"\n    -k -,    --jwk=-            JWK or JWKSet (stdin)"
"\n"
"\n    -a,      --all              Require verification of all JWKs"
"\n"
"\n    -o FILE, --output=FILE      JWS output (file)"
"\n    -o -,    --output=-         JWS output (stdout; default if -d not set)"
"\n"
"\nHere are some examples. First, we create a signature with two keys:"
"\n"
"\n    $ echo hi | jose sig -i- -o /tmp/msg.jws -k rsa.jwk -k ec.jwk"
"\n"
"\nWe can verify this signature using an input file or stdin:"
"\n"
"\n    $ jose ver -i /tmp/msg.jws -k ec.jwk"
"\n    hi"
"\n"
"\n    $ cat /tmp/msg.jws | jose ver -i- -k rsa.jwk"
"\n    hi"
"\n"
"\nWhen we use a different key, validation fails:"
"\n"
"\n    $ jose ver -i /tmp/msg.jws -k oct.jwk"
"\n    No signatures validated!"
"\n"
"\nNormally, we want validation to succeed if any key validates:"
"\n"
"\n    $ jose ver -i /tmp/msg.jws -k rsa.jwk -k oct.jwk"
"\n    hi"
"\n"
"\nHowever, we can also require validation of all specified keys:"
"\n"
"\n    $ jose ver -a -i /tmp/msg.jws -k rsa.jwk -k oct.jwk"
"\n    Signature validation failed!"
"\n\n");
    return EXIT_FAILURE;
}
