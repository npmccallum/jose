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

#include <jose/jwe.h>
#include <jose/hooks.h>
#include <zlib.h>
#include <string.h>

static inline void
swap(jose_buf_t **a, jose_buf_t **b)
{
    jose_buf_t *c = *a;
    *a = *b;
    *b = c;
}

static jose_buf_t *
comp_deflate(jose_ctx_t *ctx, const uint8_t *buf, size_t len)
{
    z_stream __attribute__((cleanup(deflateEnd))) strm = {};
    jose_buf_auto_t *out = NULL;

    strm.next_in = (uint8_t *) buf;
    strm.avail_in = len;

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
                     MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;

    while (strm.avail_in > 0) {
        jose_buf_auto_t *tmp = NULL;

        strm.avail_out = 16 * 1024; /* 16K blocks */

        tmp = jose_buf(strm.total_out + strm.avail_out, JOSE_BUF_FLAG_WIPE);
        if (!tmp)
            return NULL;

        if (out)
            memcpy(tmp->data, out->data, strm.total_out);

        swap(&tmp, &out);

        strm.next_out = &out->data[strm.total_out];

        if (deflate(&strm, Z_FINISH) != Z_STREAM_END)
            return NULL;
    }

    out->size = strm.total_out;
    return jose_buf_incref(out);
}

static jose_buf_t *
comp_inflate(jose_ctx_t *ctx, const uint8_t *buf, size_t len)
{
    z_stream __attribute__((cleanup(inflateEnd))) strm = {};
    jose_buf_auto_t *out = NULL;

    strm.next_in = (uint8_t *) buf;
    strm.avail_in = len;

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK)
        return NULL;

    while (strm.avail_in > 0) {
        jose_buf_auto_t *tmp = NULL;

        strm.avail_out = 16 * 1024; /* 16K blocks */

        tmp = jose_buf(strm.total_out + strm.avail_out, JOSE_BUF_FLAG_WIPE);
        if (!tmp)
            return NULL;

        if (out)
            memcpy(tmp->data, out->data, strm.total_out);

        swap(&tmp, &out);

        strm.next_out = &out->data[strm.total_out];

        if (inflate(&strm, Z_FINISH) != Z_STREAM_END)
            return NULL;
    }

    out->size = strm.total_out;
    return jose_buf_incref(out);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwe_zipper_t zipper = {
        .zip = "DEF",
        .deflate = comp_deflate,
        .inflate = comp_inflate
    };

    jose_jwe_register_zipper(&zipper);
}
