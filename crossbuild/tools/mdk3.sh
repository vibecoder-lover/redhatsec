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
# file.c usa il pcap.h CUSTOM (LINKTYPE_*) → include relativo, ordine -I indifferente
sed -i '' 's|#include "pcap.h"|#include "../pcap.h"|' src/osdep/file.c
export CFLAGS="-std=gnu89 $CFLAGS -Wno-error=implicit-function-declaration -Wno-error=implicit-int -I$DEPS/usr/include -L$DEPS/usr/lib -include $SRCROOT/../endian-shim.h -include stdio.h -include stdlib.h -include unistd.h"
# attacks/Makefile fa CFLAGS = (override) → += per ereditare le -include
sed -i '' 's|^CFLAGS[[:space:]]*= |CFLAGS += |' src/attacks/Makefile
# ghosting/evasion: osdep Darwin non espone i txpower linux → stub onesto
cat > src/ghosting_stub.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
void parse_ghosting(const char *input) { (void)input; fprintf(stderr, "ghosting/evasion: non supportata su iOS (osdep)\n"); exit(1); }
EOF
sed -i '' 's|ghosting.o|ghosting_stub.o|g' src/Makefile
make -j1 CC="$CC"
mkdir -p "$STAGE/var/jb/usr/bin"
cp mdk3 "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/mdk3" 2>/dev/null || true
