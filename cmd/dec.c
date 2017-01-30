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
#include <unistd.h>
#include <string.h>

static bool
header_has_pbes2(const json_t *jwe, const json_t *rcp)
{
    json_auto_t *hdr = NULL;
    const char *alg = NULL;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return false;

    json_unpack(hdr, "{s:s}", "alg", &alg);
    return strncmp(alg, "PBES2", strlen("PBES2")) == 0;
}

static bool
jwe_has_pbes2(const json_t *jwe)
{
    json_t *rcps = NULL;

    rcps = json_object_get(jwe, "recipients");
    if (!json_is_array(rcps))
        return header_has_pbes2(jwe, jwe);

    for (size_t i = 0; i < json_array_size(rcps); i++) {
        if (header_has_pbes2(jwe, json_array_get(rcps, i)))
            return true;
    }

    return false;
}

static int
decrypt(const json_t *jwe, const json_t *cek, const char *to)
{
    jose_buf_auto_t *pt = NULL;

    pt = jose_jwe_decrypt(NULL, jwe, cek);
    if (!pt) {
        fprintf(stderr, "Error during decryption!\n");
        return EXIT_FAILURE;
    }

    if (!jcmd_dump_data(to, pt->data, pt->size)) {
        fprintf(stderr, "Error dumping JWE!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static const struct option opts[] = {
    { "help",      no_argument,       .val = 'h' },

    { "jwk",       required_argument, .val = 'k' },
    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    { "no-prompt", no_argument,       .val = 'n' },
    {}
};

int
jcmd_dec(int argc, char *argv[])
{
    json_auto_t *jwks = NULL;
    json_auto_t *jwe = NULL;
    const char *out = "-";
    bool nonint = false;

    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "hk:i:o:n", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 'n': nonint = true; break;

        case 'i':
            json_decref(jwe);
            jwe = jcmd_load_json(optarg, NULL, jose_from_compact);
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

    if (!jwe) {
        fprintf(stderr, "Invalid JWE!\n");
        goto usage;
    }

    if (json_array_size(jwks) == 0 && nonint) {
        fprintf(stderr, "MUST specify a JWK in non-interactive mode!\n\n");
        goto usage;
    }

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        json_auto_t *cek = NULL;

        cek = jose_jwe_unwrap(NULL, jwe, json_array_get(jwks, i), NULL);
        if (cek)
            return decrypt(jwe, cek, out);
    }

    if (jwe_has_pbes2(jwe) && !nonint) {
        const char *pwd = NULL;

        pwd = getpass("Please enter password: ");
        if (pwd) {
            json_auto_t *jwk = json_string(pwd);
            json_auto_t *cek = NULL;

            cek = jose_jwe_unwrap(NULL, jwe, jwk, NULL);
            if (cek)
                return decrypt(jwe, cek, out);
        }
    }

    fprintf(stderr, "Decryption failed!\n");
    return EXIT_FAILURE;

usage:
    fprintf(stderr,
"jose " DEC_USE
"\n"
"\nDecrypts a JWE using the supplied JWK(Set) and outputs the plaintext."
"\n"
"\n    -n,      --no-prompt      Do not prompt for password"
"\n"
"\n    -k FILE, --jwk=FILE       JWK or JWKSet (file)"
"\n    -k -,    --jwk=-          JWK or JWKSet (stdin)"
"\n"
"\n    -i FILE, --input=FILE     JWE input (file)"
"\n    -i -,    --input=-        JWE input (stdin)"
"\n"
"\n    -o FILE, --output=FILE    Plaintext payload (file)"
"\n    -o -,    --output=-       Plaintext payload (stdout; default)"
"\n"
"\nHere are some examples. First, we encrypt a message with three keys:"
"\n"
"\n    $ echo hi | jose enc -i- -o /tmp/msg.jwe -p -k rsa.jwk -k oct.jwk"
"\n    Please enter a password:"
"\n    Please re-enter the previous password:"
"\n"
"\nWe can decrypt this message with any JWK using an input file or stdin:"
"\n"
"\n    $ jose dec -i /tmp/msg.jwe -k oct.jwk"
"\n    hi"
"\n"
"\n    $ cat /tmp/msg.jwe | jose dec -i- -k rsa.jwk"
"\n    hi"
"\n"
"\nWe can also decrypt this message using the password:"
"\n"
"\n    $ jose dec -i /tmp/msg.jwe"
"\n    Please enter password:"
"\n    hi"
"\n"
"\nWhen we use a different key and suppress prompting, decryption fails:"
"\n"
"\n    $ jose dec -n -i /tmp/msg.jwe -k ec.jwk"
"\n    Decryption failed!"
"\n\n");
    return EXIT_FAILURE;
}
