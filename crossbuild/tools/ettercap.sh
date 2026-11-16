#!/bin/bash
# tool: ettercap — MITM suite, curses UI (GTK off), cmake toolchain iOS nativa
set -e
V=0.8.3.1
SRC="$SRCROOT/ettercap"
[ -f "$SRCROOT/ettercap.tar.gz" ] || curl -fSL "https://github.com/Ettercap/ettercap/archive/refs/tags/v$V.tar.gz" -o "$SRCROOT/ettercap.tar.gz"
[ -d "$SRC" ] || { mkdir -p "$SRC" && tar xzf "$SRCROOT/ettercap.tar.gz" -C "$SRC" --strip-components 1; }
cd "$SRC"

# CMake 4 (runner 2026): respinge cmake_minimum_required(VERSION 2.8)
sed -i '' 's|cmake_minimum_required(VERSION 2.8)|cmake_minimum_required(VERSION 3.10)|' CMakeLists.txt
grep -n "cmake_minimum_required" CMakeLists.txt | head -2
mkdir -p "$DEPS/usr/include/net" "$DEPS/usr/include/netinet"
for h in net/if_arp.h net/ethernet.h net/route.h net/bpf.h netinet/if_ether.h netinet/ip_var.h; do
  [ -f "$DEPS/usr/include/$h" ] || curl -fSL "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/$h" -o "$DEPS/usr/include/$h"
done

B="$SRC/build-ios"
rm -rf "$B"
mkdir -p "$B"
cd "$B"
# CMAKE_SYSTEM_NAME=iOS: toolchain nativa cmake (niente file custom)
cmake .. \
  -DCMAKE_SYSTEM_NAME=Darwin \
  -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCMAKE_FIND_ROOT_PATH="$DEPS/usr" \
  -DCMAKE_INSTALL_PREFIX=/var/jb \
  -DCMAKE_C_FLAGS="-I$DEPS/usr/include -I$DEPS/usr/include/ncursesw -DBYTE_ORDER_LITTLE_ENDIAN" \
  -DCMAKE_EXE_LINKER_FLAGS="-L$DEPS/usr/lib" \
  -DENABLE_GTK=OFF \
  -DENABLE_CURSES=ON \
  -DENABLE_SSL=ON \
  -DENABLE_TESTS=OFF \
  -DENABLE_PLUGINS=OFF \
  -DSYSTEM_CURL=OFF \
  -DBUNDLED_CURL=OFF \
  -DENABLE_GEOIP=OFF \
  -DENABLE_PCRE=OFF \
  -DPCAP_LIBRARY="$DEPS/usr/lib/libpcap.a" \
  -DNETLIB_LIBRARY="$DEPS/usr/lib/libnet.a" \
  -DOPENSSL_ROOT_DIR="$DEPS/usr" \
  -DOPENSSL_SSL_LIBRARY="$DEPS/usr/lib/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$DEPS/usr/lib/libcrypto.a" \
  -DCURSES_LIBRARY="$DEPS/usr/lib/libncursesw.a" \
  -DCURSES_INCLUDE_PATH="$DEPS/usr/include" \
  || { echo "=== CMAKE FALLITA ==="; tail -40 "$B/CMakeFiles/CMakeError.log" 2>/dev/null || true; exit 1; }
make -j8
echo "make ok"

mkdir -p "$STAGE/var/jb/usr/bin" "$STAGE/var/jb/etc"
cp "$B/src/ettercap" "$STAGE/var/jb/usr/bin/"
# etterfilter/etterlog (utility openssl) — path variabile tra versioni: find
find "$B" -maxdepth 4 \( -name "etterfilter" -o -name "etterlog" \) -type f | while IFS= read -r f; do
  cp "$f" "$STAGE/var/jb/usr/bin/"
done
cp "$SRC/etter.conf" "$STAGE/var/jb/etc/" 2>/dev/null || true
find "$STAGE/var/jb" -type f -name "etter*" | while IFS= read -r f; do echo "staged: $f"; done
$STRIP "$STAGE/var/jb/usr/bin/"etter* 2>/dev/null || true
