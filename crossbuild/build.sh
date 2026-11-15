#!/bin/bash
# uso: ./build.sh <tool>        — compila tools/<tool>.sh e produce deb/<tool>_iphoneos-arm64.deb
#      ./build.sh --all        — compila tutte le ricette
# le dipendenze (deps/*.sh) vengono costruite una volta sola in deps-rootless/
set -e
cd "$(dirname "$0")"
source ./env.sh

if [ "$1" = "--all" ]; then
    TOOLS=$(for f in tools/*.sh; do basename "$f" .sh; done)
else
    [ -n "$1" ] || { echo "uso: $0 <tool>|--all"; exit 1; }
    [ -f "tools/$1.sh" ] || { echo "ricetta mancante: tools/$1.sh"; exit 1; }
    TOOLS="$1"
fi

for dep in deps/*.sh; do
    bash "$dep" || echo "=== DEP $(basename "$dep" .sh) FAILED (tolerata, tool che la usa fara SKIP) ==="
done

# smoke: il wrapper produce arm64-ios?
echo 'int main(void){return 0;}' > "$ROOT/smoke.c"
echo "SMOKE: $CC $CFLAGS"
"$CC" $CFLAGS -c "$ROOT/smoke.c" -o "$ROOT/smoke.o" || { echo "SMOKE COMPILE FAIL"; exit 1; }
file "$ROOT/smoke.o" || true
echo "$CC -v:"; "$CC" -v 2>&1 | tail -2 || true

mkdir -p deb
for t in $TOOLS; do
    echo "=== BUILD $t ==="
    rm -rf "$STAGE"; mkdir -p "$STAGE"
    bash ${XTR:+-x} "tools/$t.sh"
    bash ./pack.sh "$t"
    echo "=== OK $t → deb/${t}_iphoneos-arm64.deb ==="
done
