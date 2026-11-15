#!/bin/bash
# deps: libpcap static cross (per airodump/aireplay e tool sniffing)
set -e
cd "$ROOT"
if [ -f "$DEPS/usr/lib/libpcap.a" ]; then exit 0; fi
echo "=== DEP libpcap ==="
V=1.10.5
[ -f "$SRCROOT/libpcap-$V.tar.gz" ] || curl -fSL "https://www.tcpdump.org/release/libpcap-$V.tar.gz" -o "$SRCROOT/libpcap-$V.tar.gz"
[ -d "$SRCROOT/libpcap-$V" ] || tar xzf "$SRCROOT/libpcap-$V.tar.gz" -C "$SRCROOT"
cd "$SRCROOT/libpcap-$V"
make distclean >/dev/null 2>&1 || true
CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS -DHAVE_CONFIG_H" LDFLAGS="$LDFLAGS" \
./configure --prefix="$DEPS/usr" --host=arm-apple-darwin --disable-shared --without-libnl --disable-dbus --disable-rdma --disable-snf --disable-tc
make -j8
make install
echo "=== DEP libpcap OK ==="
