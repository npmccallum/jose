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

static bool
load(const char *in, json_t *tmpl)
{
    uint8_t *buf = NULL;
    size_t len = 0;

    buf = jcmd_load_data(in, &len);
    if (!buf) {
        fprintf(stderr, "Error reading payload!\n");
        return false;
    }

    if (json_object_set_new(tmpl, "payload",
                            jose_b64_encode_json(buf, len)) < 0) {
        fprintf(stderr, "Error encoding payload!\n");
        free(buf);
        return false;
    }

    free(buf);
    return true;
}

static const struct option opts[] = {
    { "help",      no_argument,       .val = 'h' },

    { "jwk",       required_argument, .val = 'k' },
    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    { "compact",   no_argument,       .val = 'c' },
    { "detached",  no_argument,       .val = 'd' },
    { "template",  required_argument, .val = 't' },
    { "signature", required_argument, .val = 's' },
    {}
};

int
jcmd_sig(int argc, char *argv[])
{
    json_auto_t *tmpl = NULL;
    json_auto_t *sigs = NULL;
    json_auto_t *jwks = NULL;
    const char *out = "-";
    const char *in = NULL;
    bool compact = false;
    bool detach = false;
    json_t *tmp = NULL;

    tmpl = json_object();
    sigs = json_array();
    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "hk:i:o:cdt:s:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'i': in = optarg; break;
        case 'o': out = optarg; break;
        case 'd': detach = true; break;
        case 'c': compact = true; break;

        case 'k':
            if (!jcmd_jwks_extend(jwks, jcmd_load_json(optarg, NULL, NULL))) {
                fprintf(stderr, "Invalid JWK(Set): %s!\n", optarg);
                goto usage;
            }
            break;

        case 't':
            json_decref(tmpl);
            tmpl = jcmd_load_json(optarg, optarg, jose_from_compact);
            if (!tmpl) {
                fprintf(stderr, "Invalid JWS template: %s!\n", optarg);
                goto usage;
            }

            break;

        case 's':
            tmp = jcmd_load_json(optarg, optarg, NULL);
            if (json_array_append_new(sigs, tmp) == -1) {
                fprintf(stderr, "Invalid JWS signature template: %s!\n",
                        optarg);
                goto usage;
            }

            break;

        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (json_array_size(jwks) == 0) {
        fprintf(stderr, "MUST specify a JWK!\n\n");
        goto usage;
    }

    if (!json_object_get(tmpl, "payload") && !load(in, tmpl))
        return EXIT_FAILURE;

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        if (!jose_jws_sign(NULL, tmpl, json_array_get(jwks, i),
                           json_array_get(sigs, i))) {
            fprintf(stderr, "Error creating signature!\n");
            return EXIT_FAILURE;
        }
    }

    if (detach && json_object_del(tmpl, "payload") == -1)
        return EXIT_FAILURE;

    if (!jcmd_dump_json(tmpl, out, compact ? jose_to_compact : NULL)) {
        fprintf(stderr, "Error dumping JWS!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

usage:
    fprintf(stderr,
"jose " SIG_USE
"\n"
"\nSigns a payload using one or more JWKs and outputs a JWS."
"\n"
"\n    -i FILE, --input=FILE        Payload input (file)"
"\n    -i -,    --input=-           Payload input (stdin)"
"\n"
"\n    -t FILE, --template=FILE     JWS template (file)"
"\n    -t JSON, --template=JSON     JWS template (JSON)"
"\n    -t -,    --template=-        JWS template (stdin)"
"\n"
"\n    -s FILE, --signature=FILE    JWS signature template (file)"
"\n    -s JSON, --signature=JSON    JWS signature template (JSON)"
"\n    -s -,    --signature=-       JWS signature template (stdin)"
"\n"
"\n    -k FILE, --jwk=FILE          JWK or JWKSet (file)"
"\n    -k -,    --jwk=-             JWK or JWKSet (stdin)"
"\n"
"\n    -o FILE, --output=FILE       JWS output (file)"
"\n    -o -,    --output=-          JWS output (stdout; default)"
"\n"
"\n    -c,      --compact           Use JWS compact format"
"\n    -d,      --detatched         Do not embed the payload in the JWS"
"\n"
"\nWhen creating multiple signatures, JWS general format is used:"
"\n"
"\n    $ echo hi | jose sig -i- -k ec.jwk -k rsa.jwk"
"\n    { \"payload\": \"aGkK\", \"signatures\": ["
"\n      { \"protected\": \"...\", \"signature\": \"...\" },"
"\n      { \"protected\": \"...\", \"signature\": \"...\" } ] }"
"\n"
"\nWith a single signature, JWS flattened format is used:"
"\n"
"\n    $ echo hi | jose sig -i- -k ec.jwk"
"\n    { \"payload\": \"aGkK\", \"protected\": \"...\", \"signature\": \"...\" }"
"\n"
"\nAlternatively, JWS compact format may be used:"
"\n"
"\n    $ echo hi | jose sig -i- -c -k ec.jwk"
"\n    eyJhbGciOiJFUzI1NiJ9.aGkK.VauBzVLMesMtTtGfwVOHh9WN1dn6iuEkmebFpJJu..."
"\n"
"\nIf the payload is specified in the template, '-i' is ignored:"
"\n"
"\n    $ jose sig -t '{ \"payload\": \"aGkK\" }' -k rsa.jwk"
"\n    { \"payload\": \"aGkK\", \"protected\": \"...\", \"signature\": \"...\" }"
"\n"
"\n    $ jose sig -i message.txt -k rsa.jwk"
"\n    { \"payload\": \"aGkK\", \"protected\": \"...\", \"signature\": \"...\" }"
"\n\n");
    return EXIT_FAILURE;
}
