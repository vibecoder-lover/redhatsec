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
CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" \
./configure --prefix="$PREFIX" --host=arm-apple-darwin \
    --disable-libnl --disable-pcre --disable-hwloc \
    --without-sqlite3 --without-gcrypt --without-opt \
    --enable-static --disable-shared
[ -f Makefile ] && sed -i '' 's/-arch x86_64 -arch arm64//g; s/-arch arm64 -arch x86_64//g' Makefile
make -j8
make DESTDIR="$STAGE" install
$STRIP "$STAGE/var/jb/usr/bin/"* 2>/dev/null || true
