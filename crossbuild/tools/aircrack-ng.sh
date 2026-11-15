#!/bin/bash
# tool: aircrack-ng suite (autotools, build minimale solo-CLI)
set -e
V=1.7
SRC="$SRCROOT/aircrack-ng-$V"
[ -f "$SRCROOT/aircrack-ng-$V.tar.gz" ] || curl -fSL "https://github.com/aircrack-ng/aircrack-ng/archive/refs/tags/$V.tar.gz" -o "$SRCROOT/aircrack-ng-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/aircrack-ng-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
# tarball git GitHub: configure NON pre-generato → autoreconf
autoreconf -fi 2>&1 | tail -5
make distclean >/dev/null 2>&1 || true
export PKG_CONFIG_PATH="$DEPS/usr/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
# aircrack_ng_mac.m4: su host darwin force ramo Homebrew + AC_CHECK_FILE (morte in cross)
# 1) PATH ridotto → brew invisibile → BREW_FOUND=no, niente iniezione CFLAGS brew
# 2) cache var AC_CHECK_FILE pre-seedate (MacPorts/Xcode check saltati)
export ac_cv_file__usr_local_Homebrew=no
export ac_cv_file__opt_local_include=no
export ac_cv_file__opt_local_lib=no
export ac_cv_file__Applications_Xcode_app_Contents_Developer_Toolchains_XcodeDefault_xctoolchain_usr_lib_swift_migrator_sdk_MacOSX_sdk_usr_include=no
CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" LIBS="-lz" \
env PATH=/usr/bin:/bin \
./configure --prefix="$PREFIX" --host=arm-apple-darwin \
    --disable-libnl --disable-pcre --disable-hwloc \
    --without-sqlite3 --without-gcrypt --without-opt \
    --enable-static --disable-shared \
    --with-openssl="$DEPS/usr"
[ -f Makefile ] && sed -i '' 's/-arch x86_64 -arch arm64//g; s/-arch arm64 -arch x86_64//g' Makefile
make -j8
make DESTDIR="$STAGE" install
$STRIP "$STAGE/var/jb/usr/bin/"* 2>/dev/null || true
