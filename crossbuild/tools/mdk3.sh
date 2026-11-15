#!/bin/bash
# tool: mdk3 deauth/beacon flood — Makefile raw con osdep incluso
set -e
V=mdk3-v6
SRC="$SRCROOT/mdk3-$V"
[ -f "$SRCROOT/mdk3-$V.tar.gz" ] || curl -fSL "https://github.com/aircrack-ng/mdk3/archive/refs/tags/$V.tar.gz" -o "$SRCROOT/mdk3-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/mdk3-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
make -j8 CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include -Iosdep" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
    osd=BSD
mkdir -p "$STAGE/var/jb/usr/bin"
cp mdk3 "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/mdk3" 2>/dev/null || true
