#!/bin/bash
# dep: libnet 1.2 — packet injection (yersinia), static in deps-rootless
set -e
[ -f "$DEPS/usr/lib/libnet.a" ] && exit 0
# libnet gira PRIMA di libpcap (ordine alfabetico deps) → serve già lo shim net/bpf.h
bash deps/libpcap.sh >/dev/null 2>&1 || true
SRC="$SRCROOT/libnet-1.2"
[ -f "$SRCROOT/libnet-1.2.tar.gz" ] || curl -fSL "https://github.com/libnet/libnet/archive/refs/tags/v1.2.tar.gz" -o "$SRCROOT/libnet-1.2.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/libnet-1.2.tar.gz" -C "$SRCROOT"
cd "$SRC"
autoreconf -fi 2>&1 | tail -2
CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
./configure --prefix="$DEPS/usr" --host=arm-apple-darwin \
  --with-link-layer=bpf \
  --disable-shared --enable-static
make -j8
make install
