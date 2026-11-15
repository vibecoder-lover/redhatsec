#!/bin/bash
# tool: hostapd AP server — userspace-only (driver BSD), openssl static
set -e
V=2.10
SRC="$SRCROOT/hostapd-$V"
[ -f "$SRCROOT/hostapd-$V.tar.gz" ] || curl -fSL "https://w1.fi/releases/hostapd-$V.tar.gz" -o "$SRCROOT/hostapd-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/hostapd-$V.tar.gz" -C "$SRCROOT"
# Xcode 26 SDK ha rimosso net/route.h — shim da xnu (driver_bsd.c lo usa)
mkdir -p "$DEPS/usr/include/net"
[ -f "$DEPS/usr/include/net/route.h" ] || curl -fSL "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/route.h" -o "$DEPS/usr/include/net/route.h"
cd "$SRC/hostapd"
cat > .config <<EOF
CONFIG_DRIVER_BSD=y
CONFIG_L2_PACKET=freebsd
CONFIG_IEEE80211N=y
CONFIG_IEEE80211AC=y
CONFIG_EAP=y
CONFIG_EAP_MD5=y
CONFIG_EAP_TLS=y
CONFIG_EAP_PEAP=y
CONFIG_EAP_TTLS=y
CONFIG_WPS=y
CONFIG_TLS=internal
CONFIG_INTERNAL_LIBTOMMATH=y
CONFIG_NO_LINUX_PACKET_SOCKET=y
CFLAGS += -I$DEPS/usr/include -I../src -I../src/utils -I../src/ap
LIBS += -L$DEPS/usr/lib
EOF
make CC="$CC" -j8
mkdir -p "$STAGE/var/jb/usr/bin"
cp hostapd "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/hostapd" 2>/dev/null || true
