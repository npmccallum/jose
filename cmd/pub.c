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

#define START "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
#define PUB "\"x\": \"...\", \"y\": \"...\""
#define END " }"

static const struct option opts[] = {
    { "help",      no_argument,       .val = 'h' },

    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    {}
};

int
jcmd_pub(int argc, char *argv[])
{
    json_auto_t *jwk = NULL;
    const char *out = "-";

    for (int c; (c = getopt_long(argc, argv, "hi:o:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 'i':
            json_decref(jwk);
            jwk = jcmd_load_json(optarg, NULL, NULL);
            break;
        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (!jwk) {
        fprintf(stderr, "Invalid JWK!\n");
        return EXIT_FAILURE;
    }

    if (!jose_jwk_clean(NULL, jwk)) {
        fprintf(stderr, "Error removing public keys!\n");
        return EXIT_FAILURE;
    }

    if (!jcmd_dump_json(jwk, out, NULL)) {
        fprintf(stderr, "Error dumping JWK!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

usage:
    fprintf(stderr,
"jose " PUB_USE
"\n"
"\nCleans private keys from a JWK."
"\n"
"\n    -i FILE, --jwk=FILE       JWK or JWKSet input (file)"
"\n    -i -,    --jwk=-          JWK or JWKSet input (stdin)"
"\n"
"\n    -o FILE, --output=FILE    JWK or JWKSet output (file)"
"\n    -o -,    --output=-       JWK or JWKSet output (stdout; default)"
"\n"
"\nThis command simply takes a JWK(Set) as input and outputs a JWK(Set):"
"\n"
"\n    $ jose pub -i ec.jwk"
"\n    " START PUB END
"\n"
"\n    $ cat ec.jwk | jose pub -i-"
"\n    " START PUB END
"\n\n");
    return EXIT_FAILURE;
}
