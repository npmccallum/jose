/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2017 Red Hat, Inc.
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

#include <jose/ctx.h>
#include <stdlib.h>
#include <string.h>

struct jose_ctx {
    size_t ref;
};

jose_ctx_t *
jose_ctx(void)
{
    jose_ctx_t *ctx = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->ref++;
    return ctx;
}

jose_ctx_t *
jose_ctx_incref(jose_ctx_t *ctx)
{
    if (ctx)
        ctx->ref++;

    return ctx;
}

void
jose_ctx_decref(jose_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (--ctx->ref == 0)
        free(ctx);
}

void
jose_ctx_auto(jose_ctx_t **ctx)
{
    if (!ctx)
        return;

    jose_ctx_decref(*ctx);
    *ctx = NULL;
}
