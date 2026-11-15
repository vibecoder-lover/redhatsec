#!/bin/bash
# tool: reaver + wash (WPS attacker) — crypto internal, pcap static
set -e
V=1.6.6
SRC="$SRCROOT/reaver-wps-fork-t6x-$V"
[ -f "$SRCROOT/reaver-$V.tar.gz" ] || curl -fSL "https://github.com/t6x/reaver-wps-fork-t6x/archive/refs/tags/v$V.tar.gz" -o "$SRCROOT/reaver-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/reaver-$V.tar.gz" -C "$SRCROOT"
cd "$SRC/src"
trap 'echo "### FAILED line $BASH_LINENO"; tail -20 config.log 2>/dev/null || echo "(no config.log)"' ERR
make distclean >/dev/null 2>&1 || true
# configure antepone "-lm -lpcap" a LDFLAGS → -lpcap prima del nostro -L → post-fix config.mak
CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="-L$DEPS/usr/lib" \
./configure --prefix="$PREFIX" --host=arm-apple-darwin
echo "configure done"
# delimiter | (la DEPS contiene / → s/// con / rompe)
sed -i '' "s|-lpcap|-L$DEPS/usr/lib -lpcap|g" config.mak
echo "sed done"
grep LDFLAGS config.mak || true
make -j1
echo "make done"
mkdir -p "$STAGE/var/jb/usr/bin"
cp reaver "$STAGE/var/jb/usr/bin/"
cp wash "$STAGE/var/jb/usr/bin/" 2>/dev/null || cp -R reaver "$STAGE/var/jb/usr/bin/wash"
$STRIP "$STAGE/var/jb/usr/bin/reaver" 2>/dev/null || true
