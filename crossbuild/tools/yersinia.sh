#!/bin/bash
# tool: yersinia — core CLI senza gtk/ncurses (configure legacy)
set -e
V=0.8.2
SRC="$SRCROOT/yersinia-$V"
[ -f "$SRCROOT/yersinia-$V.tar.gz" ] || curl -fSL "https://github.com/tomac/yersinia/archive/refs/tags/v$V.tar.gz" -o "$SRCROOT/yersinia-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/yersinia-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
autoreconf -fi 2>&1 | tail -3
make distclean >/dev/null 2>&1 || true
# configure cerca pcap-bpf.h TOP-LEVEL (legacy, non installato da libpcap >=1.9) → alias dir
mkdir -p "$DEPS/usr/include/pcap-legacy"
cp "$DEPS/usr/include/pcap/bpf.h" "$DEPS/usr/include/pcap-legacy/pcap-bpf.h" 2>/dev/null || true
CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
./configure --prefix="$PREFIX" --host=arm-apple-darwin \
  --with-pcap-includes="$DEPS/usr/include/pcap-legacy"
echo "configure done"
make -j1
echo "make done"
mkdir -p "$STAGE/var/jb/usr/bin"
cp yersinia "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/yersinia" 2>/dev/null || true
