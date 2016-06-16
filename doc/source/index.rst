.. José documentation master file, created by
   sphinx-quickstart on Thu Jun 16 15:47:57 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to José's documentation!
================================

José is a C language implementation of the Javascript Object Signing and
Encryption (JOSE) Web Standards as they are being developed in the JOSE_
IETF Working Group and related technology. José leans heavily on OpenSSL_
for all cryptographic routines and does not implement any cryptography.

José aims towards implementing the following standards:
  * RFC 7515 - JSON Web Signature (JWS)
  * RFC 7516 - JSON Web Encryption (JWE)
  * RFC 7517 - JSON Web Key (JWK)
  * RFC 7518 - JSON Web Algorithms (JWA)
  * RFC 7519 - JSON Web Token (JWT)
  * RFC 7520 - Examples of ... JOSE

.. _JOSE: https://datatracker.ietf.org/wg/jose/charter/
.. _OpenSSL: https://www.openssl.org

Contents:

.. toctree::
   :maxdepth: 2

   b64
   jwk
   jwkset
   jws

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

