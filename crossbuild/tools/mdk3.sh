#!/bin/bash
# tool: mdk3 deauth/beacon flood — tarball master (repo senza tag), osdep incluso
set -e
SRC="$SRCROOT/mdk3-master"
[ -f "$SRCROOT/mdk3-master.tar.gz" ] || curl -fSL "https://github.com/aircrack-ng/mdk3/archive/refs/heads/master.tar.gz" -o "$SRCROOT/mdk3-master.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/mdk3-master.tar.gz" -C "$SRCROOT"
cd "$SRC"
make CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" -j8
mkdir -p "$STAGE/var/jb/usr/bin"
cp mdk3 "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/mdk3" 2>/dev/null || true
