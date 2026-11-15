#!/bin/bash
# tool: yersinia — core CLI senza gtk/ncurses (configure legacy)
set -e
V=0.8.2
SRC="$SRCROOT/yersinia-$V"
[ -f "$SRCROOT/yersinia-$V.tar.gz" ] || curl -fSL "https://github.com/tomac/yersinia/archive/refs/tags/v$V.tar.gz" -o "$SRCROOT/yersinia-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/yersinia-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
# AC_TRY_RUN BPF senza action-if-cross → morte in cross; sostituisco con AC_DEFINE
# (PRIMA di autoreconf, altrimenti configure rigenerato resta non patchato)
perl -0pi -e 's/AC_MSG_CHECKING\(for BPF device sending support\).*?else\s+AC_MSG_RESULT\(no\)\s*fi\s*\]\)/AC_DEFINE([HAVE_BPF],[1],[Do we have BPF device support?])\nhave_bpf=yes\nAC_MSG_RESULT(yes)/s' configure.in
# versione libnet: TRY_RUN in cross → sempre "no"; sostituisco con have_libnet=yes
perl -0pi -e 's/AC_TRY_RUN\(\[\n#include<stdio\.h>\n#include<libnet\.h>.*?have_libnet=no\]\)/AC_MSG_RESULT\(yes\)\nhave_libnet=yes/s' configure.in
# vtp.c: aux_short2 è puntatore + memcpy 4 byte → valore + 2 byte (bug upstream)
sed -i '' 's|u_int16_t \*aux_short2;|u_int16_t aux_short2;|' src/vtp.c
sed -i '' 's|memcpy((void \*)&aux_short2, (void \*)aux_short, 4);|memcpy((void *)\&aux_short2, (void *)aux_short, 2);|' src/vtp.c
autoreconf -fi 2>&1 | tail -3
make distclean >/dev/null 2>&1 || true
# configure cerca pcap-bpf.h TOP-LEVEL (legacy, non installato da libpcap >=1.9) → alias dir
mkdir -p "$DEPS/usr/include/pcap-legacy"
cp "$DEPS/usr/include/pcap/bpf.h" "$DEPS/usr/include/pcap-legacy/pcap-bpf.h" 2>/dev/null || true
CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
./configure --prefix="$PREFIX" --host=arm-apple-darwin \
  --disable-gtk --with-ncurses=no \
  --with-pcap-includes="$DEPS/usr/include/pcap-legacy" \
  --with-libnet-includes="$DEPS/usr/include"
echo "configure done"
make -j1
echo "make done"
mkdir -p "$STAGE/var/jb/usr/bin"
cp yersinia "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/yersinia" 2>/dev/null || true
