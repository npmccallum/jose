AM_CFLAGS = @JOSE_CFLAGS@ @jansson_CFLAGS@
LDFLAGS += -Wl,--no-as-needed
EXTRA_DIST = tests/vectors

incdir = $(includedir)/$(PACKAGE_NAME)
pkgconfigdir = $(libdir)/pkgconfig

TESTS =

inc_HEADERS = jose/buf.h jose/b64.h jose/ctx.h jose/err.h jose/jwk.h jose/jws.h jose/jwe.h jose/jose.h jose/hooks.h
pkgconfig_DATA = jose.pc
lib_LTLIBRARIES = libjose.la
libjose_la_LIBADD = @jansson_LIBS@
libjose_la_LDFLAGS = -export-symbols-regex '^jose_'
libjose_la_SOURCES = \
    lib/misc.c lib/misc.h \
    lib/buf.c \
    lib/b64.c \
    lib/hooks.c \
    lib/ctx.c \
    lib/jwk.c \
    lib/jws.c \
    lib/jwe.c \
    lib/jose.c \
    lib/dir.c

if USE_OPENSSL
inc_HEADERS += jose/openssl.h
pkgconfig_DATA += jose-openssl.pc
lib_LTLIBRARIES += libjose-openssl.la
libjose_openssl_la_CFLAGS = $(AM_CFLAGS) @libcrypto_CFLAGS@ -pthread
libjose_openssl_la_LIBADD = libjose.la @libcrypto_LIBS@ @jansson_LIBS@
libjose_openssl_la_LDFLAGS = -export-symbols-regex '^jose_openssl_' -pthread
libjose_openssl_la_SOURCES = \
    lib/openssl/compat.c lib/openssl/compat.h \
    lib/openssl/misc.c lib/openssl/misc.h \
    lib/openssl/jwk.c \
    lib/openssl/hmac.c \
    lib/openssl/ecdsa.c \
    lib/openssl/ecdhes.c \
    lib/openssl/rsassa.c \
    lib/openssl/aescbch.c \
    lib/openssl/aesgcm.c \
    lib/openssl/rsaes.c \
    lib/openssl/pbes2.c \
    lib/openssl/aeskw.c \
    lib/openssl/oct.c \
    lib/openssl/rsa.c \
    lib/openssl/ec.c \
    lib/openssl/sha.c \
    lib/openssl/lock.c

bin_PROGRAMS = cmd/jose
cmd_jose_CFLAGS = $(AM_CFLAGS) @libcrypto_CFLAGS@
cmd_jose_LDADD = libjose.la libjose-openssl.la @jansson_LIBS@
cmd_jose_SOURCES = \
    cmd/gen.c \
    cmd/pub.c \
    cmd/thp.c \
    cmd/use.c \
    cmd/exc.c \
    cmd/sig.c \
    cmd/ver.c \
    cmd/enc.c \
    cmd/dec.c \
    cmd/sup.c \
    cmd/jose.c \
    cmd/jose.h

TESTS += $(dist_check_SCRIPTS)
dist_check_SCRIPTS = \
    tests/rfc7515_A \
    tests/rfc7520_4 \
    tests/rfc7520_5 \
    tests/rfc7638 \
    tests/jose-use \
    tests/jose
endif

if USE_ZLIB
pkgconfig_DATA += jose-zlib.pc
lib_LTLIBRARIES += libjose-zlib.la
libjose_zlib_la_CFLAGS = $(AM_CFLAGS) @zlib_CFLAGS@
libjose_zlib_la_LIBADD = libjose.la @zlib_LIBS@
libjose_zlib_la_SOURCES = \
    lib/zlib/deflate.c

if USE_OPENSSL
cmd_jose_LDADD += libjose-zlib.la
endif
endif
