/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Given an encoded length, returns a decoded length.
 *
 * This function is often used to allocate buffers to store a decoded value.
 */
size_t __attribute__((warn_unused_result))
jose_b64_dlen(size_t elen);

/**
 * Given a decoded length, returns an encoded length.
 *
 * This function is often used to allocate buffers to store an encoded value.
 */
size_t __attribute__((warn_unused_result))
jose_b64_elen(size_t dlen);

/**
 * Decodes a Base64 (URL) encoded C string into a byte array.
 *
 * The dec buffer MUST be at least jose_b64_dlen(strlen(enc)) bytes.
 *
 * Returns true on success or false if a decoding error occurs.
 */
bool __attribute__((warn_unused_result))
jose_b64_decode(const char *enc, uint8_t dec[]);

/**
 * Decodes a Base64 (URL) encoded JSON string into a byte array.
 *
 * The dec buffer MUST be at least jose_b64_dlen(json_string_length(enc)) bytes.
 *
 * Returns true on success or false if a decoding error occurs.
 */
bool __attribute__((warn_unused_result))
jose_b64_decode_json(const json_t *enc, uint8_t dec[]);

/**
 * Decodes a Base64 (URL) encoded JSON string and parses the resulting JSON.
 *
 * This function is used to decode values like the JWS Protected Header which
 * occurs in the following format: BASE64URL(UTF8(JWS Protected Header)).
 *
 * The flags are passed to json_loadb() unmodified.
 *
 * Returns a JSON value on success or NULL on error.
 */
json_t * __attribute__((warn_unused_result))
jose_b64_decode_json_load(const json_t *enc);

/**
 * Encodes a byte array to a Base64 (URL) C string.
 *
 * The enc buffer MUST Be at least jose_b64_elen(len) + 1 bytes.
 */
void
jose_b64_encode(const uint8_t dec[], size_t len, char enc[]);

/**
 * Encodes a byte array to a Base64 (URL) JSON string.
 *
 * Returns a JSON string containing the encoding or NULL on failure.
 */
json_t * __attribute__((warn_unused_result))
jose_b64_encode_json(const uint8_t dec[], size_t len);

/**
 * Serializes a JSON value and then encodes it to a Base64 (URL) JSON string.
 *
 * The flags are passed to json_load_callback() unmodified.
 *
 * Returns a JSON string containing the encoding or NULL on failure.
 */
json_t * __attribute__((warn_unused_result))
jose_b64_encode_json_dump(const json_t *dec);
