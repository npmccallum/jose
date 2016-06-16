JSON Web Keys
=============

The core cryptographic object for JOSE is the JSON Web Key (JWK). A JWK object
contains either a symmetric key or an asymmetric key pair. For asymmetric keys,
the JWK can contain either the public key, the private key or both.

Likewise, OpenSSL provides a data type that can represent both symmetric and
asymmetric keys: ``EVP_PKEY``.

Thus, José provides functions to convert between JWK objects and ``EVP_PKEY``.
Once a JWK is converted to the appropriate ``EVP_PKEY`` instance, this key can
be used with OpenSSL's EVP_ interface.

Elliptic curve JWKs are converted to an ``EVP_PKEY`` of type ``EVP_PKEY_EC``.
RSA JWKs are converted to an ``EVP_PKEY`` of type ``EVP_PKEY_RSA``. Symmetric keys
are converted to an ``EVP_PKEY`` of type ``EVP_PKEY_HMAC``.

.. _EVP: https://www.openssl.org/docs/manmaster/crypto/evp.html

.. c:function:: json_t *jose_jwk_from_key(EVP_PKEY *key);

  Converts an ``EVP_PKEY`` into a JWK.

.. c:function:: EVP_PKEY *jose_jwk_to_key(const json_t *jwk);

  Converts a JWK into an ``EVP_PKEY``.

.. DANGER::

  RSA is vulnerable to a timing attack. OpenSSL provides "blinding" to
  protect against this. However, this requires that the OpenSSL PRNG is
  properly seeded before the jose_jwk_to_key() function is called.

Secure Key Duplication
----------------------

Given the critical security nature of private key material, it is essential to
protect this data from exposure. To this end, José implements a function for
the duplication of 
