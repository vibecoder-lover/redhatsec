#!/bin/bash
# tool: pixiewps (offline WPS pixie dust) — openssl static
set -e
V=1.4.2
SRC="$SRCROOT/pixiewps-$V"
[ -f "$SRCROOT/pixiewps-$V.tar.gz" ] || curl -fSL "https://github.com/wiire/pixiewps/archive/refs/tags/v$V.tar.gz" -o "$SRCROOT/pixiewps-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/pixiewps-$V.tar.gz" -C "$SRCROOT"
cd "$SRC/src"
make -j8 CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" PREFIX="$PREFIX" \
    CPPFLAGS="$CFLAGS -I$DEPS/usr/include"
mkdir -p "$STAGE/var/jb/usr/bin"
cp pixiewps "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/pixiewps" 2>/dev/null || true
