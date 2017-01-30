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

static const struct option opts[] = {
    { "help",   no_argument,       .val = 'h' },

    { "hash",   required_argument, .val = 'H' },
    { "input",  required_argument, .val = 'i' },
    { "output", required_argument, .val = 'o' },
    {}
};

int
jcmd_thp(int argc, char *argv[])
{
    const char *hsh = "sha256";
    json_auto_t *jwk = NULL;
    int ret = EXIT_FAILURE;
    const char *out = "-";
    json_t *arr = NULL;
    char *thp = NULL;
    size_t len = 0;

    for (int c; (c = getopt_long(argc, argv, "hH:i:o:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'H': hsh = optarg; break;
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
        fprintf(stderr, "Invalid JWK(Set)!\n");
        goto usage;
    }

    len = jose_jwk_thumbprint_len(hsh);
    if (len == 0) {
        fprintf(stderr, "Unsupported hash function!\n");
        goto usage;
    }

    if (!json_is_array(json_object_get(jwk, "keys")))
        jwk = json_pack("{s:[o]}", "keys", jwk);

    arr = json_object_get(jwk, "keys");
    if (!arr)
        goto egress;

    thp = calloc(json_array_size(arr), ++len);
    if (!thp)
        goto egress;

    for (size_t i = 0; i < json_array_size(arr); i++) {
        json_t *key = json_array_get(arr, i);

        if (i > 0)
            thp[i * len - 1] = '\n';

        if (!jose_jwk_thumbprint_buf(NULL, key, hsh, &thp[i * len])) {
            fprintf(stderr, "Error making thumbprint!\n");
            goto egress;
        }
    }

    jcmd_dump_data(out, (uint8_t *) thp, strlen(thp));
    ret = EXIT_SUCCESS;

egress:
    free(thp);
    return ret;

usage:
    fprintf(stderr,
"jose " PUB_USE
"\n"
"\nCalculates the JWK thumbprint."
"\n"
"\n    -i FILE,   --jwk=FILE       JWK or JWKSet input (file)"
"\n    -i -,      --jwk=-          JWK or JWKSet input (stdin)"
"\n"
"\n    -H sha1,   --hash=sha1      Use SHA1 as the hash function"
"\n    -H sha224, --hash=sha224    Use SHA224 as the hash function"
"\n    -H sha256, --hash=sha256    Use SHA256 as the hash function"
"\n    -H sha384, --hash=sha384    Use SHA384 as the hash function"
"\n    -H sha512, --hash=sha512    Use SHA512 as the hash function"
"\n"
"\n    -o FILE,   --output=FILE    JWK or JWKSet output (file)"
"\n    -o -,      --output=-       JWK or JWKSet output (stdout; default)"
"\n\n");
    goto egress;
}
