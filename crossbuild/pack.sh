#!/bin/bash
# pack.sh <tool> — pacchetto .deb rootless (ar 60-byte, formato dpkg iOS)
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

tar czf "$T/control.tar.gz" -C "$T/control" .
tar czf "$T/data.tar.gz"    -C "$T/data" var

# ar members: header 60 byte (name16 mtime12 uid6 gid6 mode8 size10 + "\`\n")
C_SIZE=$(stat -f %z "$T/control.tar.gz")
D_SIZE=$(stat -f %z "$T/data.tar.gz")
OUT="deb/${TOOL}_iphoneos-arm64.deb"
{
    printf '!<arch>\n'
    printf '%-16s%-12s%-6s%-6s%-8s%-10s\`\n' 'debian-binary' '0' '0' '0' '644' '4'
    printf '2.0\n'
    printf '%-16s%-12s%-6s%-6s%-8s%-10s\`\n' 'control.tar.gz' '0' '0' '0' '644' "$C_SIZE"
    cat "$T/control.tar.gz"
    [ $((C_SIZE % 2)) -eq 1 ] && printf '\n'
    printf '%-16s%-12s%-6s%-6s%-8s%-10s\`\n' 'data.tar.gz' '0' '0' '0' '644' "$D_SIZE"
    cat "$T/data.tar.gz"
    [ $((D_SIZE % 2)) -eq 1 ] && printf '\n'
} > "$OUT"

echo "packed: $OUT ($(du -k "$OUT" | awk '{print $1}') KB)"
