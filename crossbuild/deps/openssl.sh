#!/bin/bash
# deps: openssl static cross (libssl.a + libcrypto.a) via target ios64-cross
set -e
cd "$ROOT"
[ -f "$DEPS/usr/lib/libssl.a" ] && exit 0
echo "=== DEP openssl ==="
V=3.3.2
[ -f "$SRCROOT/openssl-$V.tar.gz" ] || curl -fSL "https://github.com/openssl/openssl/releases/download/openssl-$V/openssl-$V.tar.gz" -o "$SRCROOT/openssl-$V.tar.gz"
[ -d "$SRCROOT/openssl-$V" ] || tar xzf "$SRCROOT/openssl-$V.tar.gz" -C "$SRCROOT"
cd "$SRCROOT/openssl-$V"
make distclean >/dev/null 2>&1 || true
CROSS_TOP="$(dirname "$SDK")" CROSS_SDK="$(basename "$SDK")" \
./Configure ios64-cross no-asm no-tests no-shared \
    --prefix="$DEPS/usr" --openssldir="$DEPS/etc/ssl"
make -j8 build_libs
make install_sw
echo "=== DEP openssl OK ==="
