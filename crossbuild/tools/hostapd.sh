#!/bin/bash
# tool: hostapd AP server — openssl static, config minimale
set -e
V=2.10
SRC="$SRCROOT/hostapd-$V"
[ -f "$SRCROOT/hostapd-$V.tar.gz" ] || curl -fSL "https://w1.fi/releases/hostapd-$V.tar.gz" -o "$SRCROOT/hostapd-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/hostapd-$V.tar.gz" -C "$SRCROOT"
cd "$SRC/hostapd"
cat > .config <<EOF
CONFIG_DRIVER_BSD=y
CONFIG_IEEE80211N=y
CONFIG_IEEE80211AC=y
CONFIG_ACS=y
CONFIG_IPV6=y
CONFIG_BACKEND_FILE=y
CFLAGS += -I$DEPS/usr/include
LIBS += -L$DEPS/usr/lib
LIBS_p += -lssl -lcrypto
EOF
make -j8 CC="$CC" CFLAGS="$CFLAGS"
mkdir -p "$STAGE/var/jb/usr/bin"
cp hostapd "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/hostapd" 2>/dev/null || true
