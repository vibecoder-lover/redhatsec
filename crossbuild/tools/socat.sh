#!/bin/bash
# tool: socat multipurpose relay (rootless)
set -e
V=1.8.0.1
SRC="$SRCROOT/socat-$V"
[ -f "$SRCROOT/socat-$V.tar.gz" ] || curl -fSL "http://www.dest-unreach.org/socat/download/socat-$V.tar.gz" -o "$SRCROOT/socat-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/socat-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
make distclean >/dev/null 2>&1 || true
CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" \
./configure --prefix="$PREFIX" --disable-openssl --disable-libwrap
make -j8
make DESTDIR="$STAGE" install
$STRIP "$STAGE/var/jb/usr/bin/"* 2>/dev/null || true
