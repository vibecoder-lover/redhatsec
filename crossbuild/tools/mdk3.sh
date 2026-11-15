#!/bin/bash
# tool: mdk3 deauth/beacon flood — tarball master, osdep Darwin nativo
set -e
SRC="$SRCROOT/mdk3-master"
[ -f "$SRCROOT/mdk3-master.tar.gz" ] || curl -fSL "https://github.com/aircrack-ng/mdk3/archive/refs/heads/master.tar.gz" -o "$SRCROOT/mdk3-master.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/mdk3-master.tar.gz" -C "$SRCROOT"
cd "$SRC"
# file.c usa LINKTYPE_PPI_HDR (costante di libpcap recenti, assente in 1.10.5) → 192 = DLT_PPI
sed -i '' 's/LINKTYPE_PPI_HDR/192/g' src/osdep/file.c
# CFLAGS via ENV (non command-line): il Makefile fa CFLAGS += -I.. e il "pcap.h" custom
# deve risolvere a src/pcap.h (le LINKTYPE_* custom). -L via CFLAGS per l'ordine del linker.
export CFLAGS="-I$SRC/src $CFLAGS -I$DEPS/usr/include -L$DEPS/usr/lib"
make CC="$CC" -j8
mkdir -p "$STAGE/var/jb/usr/bin"
cp mdk3 "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/mdk3" 2>/dev/null || true
