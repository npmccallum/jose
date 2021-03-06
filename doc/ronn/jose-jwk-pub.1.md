jose-jwk-pub(1) -- Cleans private keys from a JWK
=================================================

## SYNOPSIS

`jose jwk pub` -i JWK [-o JWK]

## OVERVIEW

The `jose jwk pub` command removes all private key material from one or more
JWK(Set) inputs. The output will contain only public key material.

If the JWK contains the "key_ops" property, it will be automatically adjusted
to include only operations relevant to public keys.

## OPTIONS

* `-i` _JSON_, `--input`=_JSON_ :
  Parse JWK(Set) from JSON

* `-i` _FILE_, `--input`=_FILE_ :
  Read JWK(Set) from FILE

* `-i` -, `--input`=- :
  Read JWK(Set) from standard input

* `-o` _FILE_, `--output`=_FILE_ :
  Write JWK(Set) to FILE

* `-o` -, `--output`=- :
  Write JWK(Set) to standard input

* `-s`, `--set` :
  Always output a JWKSet

## EXAMPLES

Clean private key material from a JWK:

    $ jose jwk gen -i '{"alg":"ES256"}' -o prv.jwk
    $ cat prv.jwk
    {"alg":"ES256","crv":"P-256","key_ops":["sign","verify"],"kty":"EC", ...}
    $ jose jwk pub -i prv.jwk -o pub.jwk
    $ cat pub.jwk
    {"alg":"ES256","crv":"P-256","key_ops":["verify"],"kty":"EC", ...}

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-alg`(1),
`jose-jwe-enc`(1),
`jose-jwk-exc`(1),
`jose-jwk-gen`(1),
`jose-jwk-thp`(1),
`jose-jwk-use`(1),
`jose-jws-ver`(1)
