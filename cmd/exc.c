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
    { "help",      no_argument,       .val = 'h' },

    { "local",     required_argument, .val = 'l' },
    { "remote",    required_argument, .val = 'r' },
    { "output",    required_argument, .val = 'o' },
    { "template",  required_argument, .val = 't' },
    {}
};

int
jcmd_exc(int argc, char *argv[])
{
    json_auto_t *tmpl = NULL;
    json_auto_t *lcl = NULL;
    json_auto_t *rem = NULL;
    json_auto_t *key = NULL;
    const char *out = "-";

    tmpl = json_object();

    for (int c; (c = getopt_long(argc, argv, "hl:r:o:t:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 't':
            json_decref(tmpl);
            tmpl = jcmd_load_json(optarg, optarg, NULL);
            if (!tmpl) {
                fprintf(stderr, "Invalid template: %s!\n", optarg);
                goto usage;
            }
            break;
        case 'l':
            json_decref(lcl);
            lcl = jcmd_load_json(optarg, optarg, NULL);
            if (!lcl) {
                fprintf(stderr, "Invalid local JWK: %s!\n", optarg);
                goto usage;
            }
            break;
        case 'r':
            json_decref(rem);
            rem = jcmd_load_json(optarg, optarg, NULL);
            if (!rem) {
                fprintf(stderr, "Invalid remote JWK: %s!\n", optarg);
                goto usage;
            }
            break;
        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (!lcl) {
        fprintf(stderr, "Local JWK not specified!\n");
        goto usage;
    }

    if (!rem) {
        fprintf(stderr, "Remote JWK not specified!\n");
        goto usage;
    }

    key = jose_jwk_exchange(NULL, lcl, rem);
    if (!key) {
        fprintf(stderr, "Error performing exchange!\n");
        return EXIT_FAILURE;
    }

    if (json_object_update(tmpl, key) < 0)
        return EXIT_FAILURE;

    if (!jcmd_dump_json(tmpl, out, NULL)) {
        fprintf(stderr, "Error dumping JWK!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

usage:
    fprintf(stderr,
"jose " EXC_USE
"\n"
"\nPerforms a key exchange using the two input keys."
"\n"
"\n    -t FILE, --template=FILE    JWK template (file)"
"\n    -t JSON, --template=JSON    JWK template (JSON)"
"\n    -t -,    --template=-       JWK template (stdin)"
"\n"
"\n    -l FILE, --local=FILE       JWK local input (file)"
"\n    -l -,    --local=-          JWK local input (stdout; default)"
"\n"
"\n    -r FILE, --remote=FILE      JWK remote input (file)"
"\n    -r -,    --remote=-         JWK remote input (stdout; default)"
"\n"
"\n    -o FILE, --output=FILE      JWK output (file)"
"\n    -o -,    --output=-         JWK output (stdout; default)"
"\n\n");
    return EXIT_FAILURE;
}
