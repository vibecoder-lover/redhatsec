#!/bin/bash
# tool: reaver WPS attacker + sqlite3 static
set -e
V=1.6.6
SRC="$SRCROOT/reaver-$V"
[ -f "$SRCROOT/reaver-$V.tar.gz" ] || curl -fSL "https://github.com/t6n/reaver/archive/refs/tags/v$V.tar.gz" -o "$SRCROOT/reaver-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/reaver-$V.tar.gz" -C "$SRCROOT"
cd "$SRC/src"
export PKG_CONFIG_PATH="$DEPS/usr/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export ac_cv_file__usr_local_Homebrew=no ac_cv_file__opt_local_include=no ac_cv_file__opt_local_lib=no
CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
./configure --prefix="$PREFIX" --host=arm-apple-darwin \
    --enable-static --disable-shared \
    --with-openssl="$DEPS/usr"
make -j8
mkdir -p "$STAGE/var/jb/usr/bin"
for b in reaver wash; do cp "$b" "$STAGE/var/jb/usr/bin/"; done
$STRIP "$STAGE/var/jb/usr/bin/"* 2>/dev/null || true
