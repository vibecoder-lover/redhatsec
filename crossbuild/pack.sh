#!/bin/bash
# pack.sh <tool> — pacchetto .deb rootless (ar llvm, formato Procursus-compatible)
set -e
cd "$(dirname "$0")"
source ./env.sh
TOOL="$1"
[ -d "$STAGE/var/jb" ] || { echo "staging vuoto: $STAGE/var/jb"; exit 1; }

VER="1.0.$(date +%Y%m%d)"
SIZE=$(du -sk "$STAGE" | awk '{print $1}')
T="$ROOT/.pack-$TOOL"
rm -rf "$T"; mkdir -p "$T/control" "$T/data"

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

tar czf "$T/control.tar.gz" -C "$T/control" control
tar czf "$T/data.tar.gz"    -C "$T/data" var
printf '2.0\n' > "$T/debian-binary"

OUT="$ROOT/deb/${TOOL}_iphoneos-arm64.deb"
rm -f "$OUT"
( cd "$T" && ar rc "$OUT" debian-binary control.tar.gz data.tar.gz )
echo "packed: ${TOOL}_iphoneos-arm64.deb ($(du -k "$OUT" | awk '{print $1}') KB)"
