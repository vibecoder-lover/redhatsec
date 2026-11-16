#!/bin/bash
# tool: tcpdump — sniffing reale via rootd (/dev/bpf, root)
set -e
V=4.99.4
SRC="$SRCROOT/tcpdump-$V"
# tcpdump cerca pcap-bpf.h top-level (legacy) — libpcap moderna la mette in pcap/
[ -f "$DEPS/usr/include/pcap-bpf.h" ] || cp "$DEPS/usr/include/pcap/bpf.h" "$DEPS/usr/include/pcap-bpf.h"
[ -f "$SRCROOT/tcpdump-$V.tar.gz" ] || curl -fSL "https://www.tcpdump.org/release/tcpdump-$V.tar.gz" -o "$SRCROOT/tcpdump-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/tcpdump-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
./configure --prefix="$PREFIX" --host=arm-apple-darwin \
  --without-smi --without-cryptopp
make -j8
mkdir -p "$STAGE/var/jb/usr/bin"
cp tcpdump "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/tcpdump" 2>/dev/null || true
