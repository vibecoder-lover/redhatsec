#!/bin/bash
# deps: libpcap static cross (per airodump/aireplay e tool sniffing)
set -e
cd "$ROOT"
if [ -f "$DEPS/usr/lib/libpcap.a" ]; then exit 0; fi
echo "=== DEP libpcap ==="
# Xcode 26 SDK non include più net/bpf.h — shim header da xnu
mkdir -p "$DEPS/usr/include/net"
[ -f "$DEPS/usr/include/net/bpf.h" ] || curl -fSL "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/bpf.h" -o "$DEPS/usr/include/net/bpf.h"
V=1.10.5
[ -f "$SRCROOT/libpcap-$V.tar.gz" ] || curl -fSL "https://www.tcpdump.org/release/libpcap-$V.tar.gz" -o "$SRCROOT/libpcap-$V.tar.gz"
[ -d "$SRCROOT/libpcap-$V" ] || tar xzf "$SRCROOT/libpcap-$V.tar.gz" -C "$SRCROOT"
cd "$SRCROOT/libpcap-$V"
make distclean >/dev/null 2>&1 || true
echo "=== PROBE compile via \$CC ==="
printf '#include <sys/types.h>\nint main(void){return 0;}\n' > probe.c
"$CC" $CFLAGS -c probe.c -o probe.o && file probe.o || { echo "PROBE FAIL"; exit 1; }
CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS -DHAVE_CONFIG_H" CPPFLAGS="-I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
./configure --prefix="$DEPS/usr" --host=arm-apple-darwin --with-pcap=bpf --disable-shared --without-libnl --disable-dbus --disable-rdma --disable-snf --disable-tc
make -j1
make install
echo "=== DEP libpcap OK ==="
