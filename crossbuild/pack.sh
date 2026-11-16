#!/bin/bash
# pack.sh <tool> — .deb rootless via manual-ar (formato dpkg provato su Sileo con rhs-sudoers)
set -e
cd "$(dirname "$0")"
source ./env.sh
TOOL="$1"
[ -d "$STAGE/var/jb" ] || { echo "staging vuoto: $STAGE/var/jb"; exit 1; }

VER="1.0.$(date +%Y%m%d)"
SIZE=$(du -sk "$STAGE" | awk '{print $1}')
T="$ROOT/.pack-$TOOL"
rm -rf "$T"; mkdir -p "$T/control" "$T/data" "$ROOT/deb"

cat > "$T/control/control" <<EOF
Package: rhs-$TOOL
Version: $VER
Architecture: iphoneos-arm64
Installed-Size: $SIZE
Origin: RedHatSec
Maintainer: He <he@redhatsec.local>
Section: Security
Description: RedHatSec cross-compiled tool ($TOOL) for iphoneos-arm64 rootless
EOF
printf '2.0\n' > "$T/debian-binary"

tar czf "$T/control.tar.gz" -C "$T/control" control
cp -a "$STAGE/." "$T/data/"
tar czf "$T/data.tar.gz"    -C "$T/data" var

C_SIZE=$(stat -f %z "$T/control.tar.gz")
D_SIZE=$(stat -f %z "$T/data.tar.gz")
B_SIZE=$(stat -f %z "$T/debian-binary")
OUT="$ROOT/deb/${TOOL}_iphoneos-arm64.deb"
{
  printf '!<arch>\n'
  m() {
    printf '%-16s%-12s%-6s%-6s%-8s%-10s\140\n' "$1" '0' '0' '0' '644' "$2"
    cat "$3"
    if [ $(($4 % 2)) -eq 1 ]; then printf '\n'; fi
  }
  m 'debian-binary'  "$B_SIZE" "$T/debian-binary"  "$B_SIZE"
  m 'control.tar.gz' "$C_SIZE" "$T/control.tar.gz" "$C_SIZE"
  m 'data.tar.gz'    "$D_SIZE" "$T/data.tar.gz"    "$D_SIZE"
} > "$OUT"
echo "packed: ${TOOL}_iphoneos-arm64.deb ($(du -k "$OUT" | awk '{print $1}') KB)"
