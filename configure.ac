AC_PREREQ(2.59)
AC_INIT(jose, 6)
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([jansson], [jansson >= 2.9])

AC_ARG_WITH(
    [openssl],
    [AS_HELP_STRING([--with-openssl], [build openssl library @<:@default=check@:>@])],
    [],
    [with_openssl=check]
)
AS_CASE(
    ["$with_openssl"],
    [yes], [PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.2], [HAVE_OPENSSL=1])],
    [no], [HAVE_OPENSSL=0],
    [PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.2], [HAVE_OPENSSL=1], [HAVE_OPENSSL=0])]
)
AM_CONDITIONAL([USE_OPENSSL], [test "$with_openssl" != no -a "$HAVE_OPENSSL" -eq 1])
AM_COND_IF(
    [USE_OPENSSL],
    [AC_CHECK_LIB([pthread], [pthread_mutex_lock], [], [AC_MSG_ERROR([no pthread])])]
)

AC_ARG_WITH(
    [zlib],
    [AS_HELP_STRING([--with-zlib], [build zlib library @<:@default=check@:>@])],
    [],
    [with_zlib=check]
)
AS_CASE(
    ["$with_zlib"],
    [yes], [PKG_CHECK_MODULES([zlib], [zlib], [HAVE_ZLIB=1])],
    [no], [HAVE_ZLIB=0],
    [PKG_CHECK_MODULES([zlib], [zlib], [HAVE_ZLIB=1], [HAVE_ZLIB=0])]
)
AM_CONDITIONAL([USE_ZLIB], [test "$with_zlib" != no -a "$HAVE_ZLIB" -eq 1])

JOSE_CFLAGS="\
-Wall \
-Wextra \
-Werror \
-Wstrict-aliasing \
-Wchar-subscripts \
-Wformat-security \
-Wmissing-declarations \
-Wmissing-prototypes \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wsign-compare \
-Wstrict-prototypes \
-Wtype-limits \
-Wunused-function \
-Wno-missing-field-initializers \
-Wno-unused-parameter \
"
AC_SUBST([JOSE_CFLAGS])

AC_CONFIG_FILES([jose/jose.h jose.pc jose-openssl.pc jose-zlib.pc Makefile])
AC_OUTPUT
