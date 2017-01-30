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
#include <unistd.h>

static const char *
prompt(void)
{
    const char *c = NULL;
    char *p = NULL;

    while (!p || !c || strcmp(p, c) != 0) {
        free(p);

        p = strdup(getpass("Please enter a password: "));
        if (!p)
            continue;

        if (strlen(p) < 8) {
            fprintf(stderr, "Password too short!\n");
            continue;
        }

        c = getpass("Please re-enter the previous password: ");
    }

    free(p);
    return c;
}

static const struct option opts[] = {
    { "help",      no_argument,       .val = 'h' },

    { "jwk",       required_argument, .val = 'k' },
    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    { "compact",   no_argument,       .val = 'c' },
    { "template",  required_argument, .val = 't' },
    { "password",  no_argument,       .val = 'p' },
    { "recipient", required_argument, .val = 'r' },
    {}
};

int
jcmd_enc(int argc, char *argv[])
{
    json_auto_t *tmpl = NULL;
    json_auto_t *rcps = NULL;
    json_auto_t *jwks = NULL;
    json_auto_t *cek = NULL;
    int ret = EXIT_FAILURE;
    const char *out = "-";
    bool compact = false;
    uint8_t *buf = NULL;
    size_t len = 0;

    tmpl = json_object();
    rcps = json_array();
    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "hk:i:o:ct:pr:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 'c': compact = true; break;

        case 'i':
            if (buf)
                memset(buf, 0, len);
            free(buf);
            buf = jcmd_load_data(optarg, &len);
            break;

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
                fprintf(stderr, "Invalid JWE template: %s!\n", optarg);
                goto usage;
            }

            break;

        case 'r':
            if (json_array_append_new(rcps,
                        jcmd_load_json(optarg, optarg, NULL)) == -1) {
                fprintf(stderr, "Invalid JWE recipient template: %s!\n", optarg);
                goto usage;
            }

            break;

        case 'p':
            if (json_array_append_new(jwks, json_string(prompt())) == -1) {
                fprintf(stderr, "Error adding password!\n");
                goto usage;
            }

            break;

        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (json_array_size(jwks) == 0) {
        fprintf(stderr, "MUST specify a JWK or password!\n\n");
        goto usage;
    }

    if (!buf) {
        fprintf(stderr, "Error loading the plaintext!\n");
        goto egress;
    }

    cek = json_object();
    if (!cek)
        goto egress;

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        if (!jose_jwe_wrap(NULL, tmpl, cek, json_array_get(jwks, i),
                           json_array_get(rcps, i))) {
            fprintf(stderr, "Wrapping failed!\n");
            goto egress;
        }
    }

    if (compact) {
        json_t *jh = NULL;

        if (json_object_get(tmpl, "recipients")) {
            fprintf(stderr, "Requested compact format with >1 recipient!\n");
            goto egress;
        }

        jh = jose_jwe_merge_header(tmpl, tmpl);
        if (!jh)
            goto egress;

        if (json_object_set_new(tmpl, "protected", jh) == -1)
            goto egress;

        if (json_object_get(tmpl, "unprotected") &&
            json_object_del(tmpl, "unprotected") == -1)
            goto egress;

        if (json_object_get(tmpl, "header") &&
            json_object_del(tmpl, "header") == -1)
            goto egress;
    }

    if (!jose_jwe_encrypt(NULL, tmpl, cek, buf, len)) {
        fprintf(stderr, "Error encrypting input!\n");
        goto egress;
    }

    if (!jcmd_dump_json(tmpl, out, compact ? jose_to_compact : NULL)) {
        fprintf(stderr, "Error dumping JWS!\n");
        goto egress;
    }

    ret = EXIT_SUCCESS;

egress:
    if (buf)
        memset(buf, 0, len);
    free(buf);
    return ret;

usage:
    fprintf(stderr,
"jose " ENC_USE
"\n"
"\nEncrypts plaintext using one or more JWKs and outputs a JWE."
"\n"
"\n    -i FILE, --input=FILE       Plaintext payload (file)"
"\n    -i -,    --input=-          Plaintext payload (stdin)"
"\n"
"\n    -t FILE, --template=FILE    JWE template (file)"
"\n    -t JSON, --template=JSON    JWE template (JSON)"
"\n    -t -,    --template=-       JWE template (stdin)"
"\n"
"\n    -r FILE, --template=FILE    JWE recipient template (file)"
"\n    -r JSON, --template=JSON    JWE recipient template (JSON)"
"\n    -r -,    --template=-       JWE recipient template (stdin)"
"\n"
"\n    -p,      --password         Use a password for encryption"
"\n"
"\n    -k FILE, --jwk=FILE         JWK or JWKSet (file)"
"\n    -k -,    --jwk=-            JWK or JWKSet (stdin)"
"\n"
"\n    -o FILE, --output=FILE      JWE output (file)"
"\n    -o -,    --output=-         JWE output (stdout; default)"
"\n"
"\n    -c,      --compact          Output JWE in compact format"
"\n"
"\nWhen encrypting to multiple recipients, JWE general format is used:"
"\n"
"\n    $ jose enc -i msg.txt -k rsa.jwk -k oct.jwk"
"\n    { \"ciphertext\": \"...\", \"recipients\": [{...}, {...}], ...}"
"\n"
"\nWith a single recipient, JWE flattened format is used:"
"\n"
"\n    $ jose enc -i msg.txt -k rsa.jwk"
"\n    { \"ciphertext\": \"...\", \"encrypted_key\": \"...\", ... }"
"\n"
"\nAlternatively, JWE compact format may be used:"
"\n"
"\n    $ jose enc -c -i msg.txt -k rsa.jwk"
"\n    eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ZBRtX0Z0vaCMMg..."
"\n"
"\nBy tweaking the JWE template, you can choose alternate crypto parameters:"
"\n"
"\n    $ jose enc -i msg.txt -t '{\"unprotected\":{\"enc\":\"A128GCM\"}}' -k rsa.jwk"
"\n    { \"ciphertext\": \"...\", \"unprotected\": { \"enc\": \"A128GCM\" }, ... }"
"\n"
"\nTransparent plaintext compression is also supported:"
"\n"
"\n    $ jose enc -i msg.txt -t '{\"protected\":{\"zip\":\"DEF\"}}' -k rsa.jwk"
"\n    { \"ciphertext\": \"...\", ... }"
"\n"
"\nYou can encrypt to one or more passwords by using the '-p' option. This"
"\ncan even be mixed with JWKs:"
"\n"
"\n    $ jose enc -i msg.txt -p"
"\n    Please enter a password:"
"\n    Please re-enter the previous password:"
"\n    { \"ciphertext\": \"...\", ... }"
"\n"
"\n    $ jose enc -i msg.txt -p -k rsa.jwk -p -k oct.jwk"
"\n    Please enter a password:"
"\n    Please re-enter the previous password:"
"\n    Please enter a password:"
"\n    Please re-enter the previous password:"
"\n    { \"ciphertext\": \"...\", ... }"
"\n\n");
    goto egress;
}
