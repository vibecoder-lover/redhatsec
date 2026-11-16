#!/bin/bash
# tool: hping3 — packet crafting raw TCP/UDP/ICMP/scan via rootd (raw socket, root)
set -e
SRC="$SRCROOT/hping3-master"
[ -f "$SRCROOT/hping3.tar.gz" ] || curl -fSL "https://github.com/NullHypothesis/hping3/archive/refs/heads/master.tar.gz" -o "$SRCROOT/hping3.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/hping3.tar.gz" -C "$SRCROOT"
cd "$SRC"

# shim header rimosse dall'SDK 26 (xnu): bpf/route/ip_var/in_systm — if_arp/if_ether/ethernet già da reaver
mkdir -p "$DEPS/usr/include/net" "$DEPS/usr/include/netinet"
for h in net/bpf.h net/route.h netinet/ip_var.h netinet/in_systm.h; do
  [ -f "$DEPS/usr/include/$h" ] || curl -fSL "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/$h" -o "$DEPS/usr/include/$h"
done

make distclean >/dev/null 2>&1 || true
rm -f byteorder.h byteorder systype.h Makefile .depend
# configure con HOST cc: compila+rune byteorder (runner arm64 = stesso byteorder del target iOS)
# -I$DEPS serve a -MM per trovare pcap.h
CC="cc -I$DEPS/usr/include" ./configure --no-tcl
# fix makefile: gcc hardcoded, -L/usr/local/lib, -ltcl (bug configure: [ -n $USE_TCL ] con vuoto),
# ./hping3 -v nel target (binario iOS non eseguibile sul runner)
sed -i '' 's/^CC= gcc/CC= cc/' Makefile
sed -i '' "s|-L/usr/local/lib|-L$DEPS/usr/lib|g" Makefile
sed -i '' 's/-ltcl[^ ]*//g' Makefile
sed -i '' '/\.\/hping3 -v/d' Makefile
make -j8 CC="$CC" CCOPT="-I$DEPS/usr/include -O2 -DBYTE_ORDER_LITTLE_ENDIAN"
echo "make done"
mkdir -p "$STAGE/var/jb/usr/bin"
cp hping3 "$STAGE/var/jb/usr/bin/"
$STRIP "$STAGE/var/jb/usr/bin/hping3" 2>/dev/null || true
