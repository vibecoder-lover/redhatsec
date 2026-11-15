#!/bin/bash
# deps: ncurses static cross (wide-char, terminfo in DEPS) — per yersinia/ettercap
set -e
cd "$ROOT"
if [ -f "$DEPS/usr/lib/libncursesw.a" ]; then exit 0; fi
echo "=== DEP ncurses ==="
# Xcode 26 SDK ha rimosso sys/ttydev.h — shim da xnu
mkdir -p "$DEPS/usr/include/sys"
[ -f "$DEPS/usr/include/sys/ttydev.h" ] || curl -fSL "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/ttydev.h" -o "$DEPS/usr/include/sys/ttydev.h"
V=6.5
[ -f "$SRCROOT/ncurses-$V.tar.gz" ] || curl -fSL "https://invisible-mirror.net/archives/ncurses/ncurses-$V.tar.gz" -o "$SRCROOT/ncurses-$V.tar.gz"
[ -d "$SRCROOT/ncurses-$V" ] || tar xzf "$SRCROOT/ncurses-$V.tar.gz" -C "$SRCROOT"
cd "$SRCROOT/ncurses-$V"
make distclean >/dev/null 2>&1 || true
CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" \
./configure --prefix="$DEPS/usr" --host=arm-apple-darwin \
    --enable-widec --enable-termcap --with-termlib \
    --disable-shared --enable-static \
    --without-progs --without-tack --without-tests \
    --with-default-terminfo-dir="$PREFIX/share/terminfo" \
    --disable-database --with-fallbacks=""
make -j8
make install
# strip multiarch se iniettato
sed -i '' 's/-arch x86_64 -arch arm64//g' "$DEPS/usr/lib/pkgconfig/ncursesw.pc" 2>/dev/null || true
echo "=== DEP ncurses OK ==="
