#!/bin/bash
# tool: aircrack-ng suite (aircrack-ng, aireplay-ng, airodump-ng, …)
set -e
V=1.7.0
SRC="$SRCROOT/aircrack-ng-$V"
[ -f "$SRCROOT/aircrack-ng-$V.tar.gz" ] || curl -fSL "https://download.aircrack-ng.org/aircrack-ng-$V.tar.gz" -o "$SRCROOT/aircrack-ng-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/aircrack-ng-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
make distclean >/dev/null 2>&1 || true
make -j8 sqlite=false libgcrypt=false experimental=false \
    CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
    all
make prefix="$PREFIX" DESTDIR="$STAGE" install
$STRIP "$STAGE/var/jb/usr/bin/"* 2>/dev/null || true
