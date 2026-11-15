#!/bin/bash
# tool: mdk3 deauth/beacon flood — tarball master, osdep Darwin nativo
set -e
SRC="$SRCROOT/mdk3-master"
[ -f "$SRCROOT/mdk3-master.tar.gz" ] || curl -fSL "https://github.com/aircrack-ng/mdk3/archive/refs/heads/master.tar.gz" -o "$SRCROOT/mdk3-master.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/mdk3-master.tar.gz" -C "$SRCROOT"
cd "$SRC"
# CFLAGS via ENV; -I$SRC PRIMO: il "pcap.h" quote-include deve risolvere a src/pcap.h
# (header custom con le LINKTYPE_*), NON al pcap.h di libpcap in DEPS
export CFLAGS="-I$SRC $CFLAGS -I$DEPS/usr/include -L$DEPS/usr/lib"
make CC="$CC" -j8
mkdir -p "$STAGE/var/jb/usr/bin"
cp mdk3 "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/mdk3" 2>/dev/null || true
