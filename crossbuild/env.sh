#!/bin/bash
# RedHatSec universal cross-compiler — iphoneos-arm64 (rootless)
# wrapper clang single-word: TUTTI i comandi che invocano $CC hanno il target baked in
set -e
export SDK="$(xcrun -sdk iphoneos --show-sdk-path)"
export TARGET=arm64-apple-ios14.0
ROOT="$(cd "$(dirname "$0")" && pwd)"
export ROOT
export STAGE="$ROOT/stage"          # staging del tool corrente
export DEPS="$ROOT/deps-rootless"   # librerie cross installate qui (usr/lib, usr/include)
export SRCROOT="$ROOT/src"          # sorgenti scaricati
export PREFIX=/var/jb
mkdir -p "$DEPS" "$SRCROOT" "$ROOT/bin"

# wrapper compilatore/linker (target+sysroot sempre presenti, anche senza CFLAGS)
mkwrap() {
    local f="$ROOT/bin/$1"; shift
    printf '#!/bin/bash\nexec xcrun -sdk iphoneos %s %s "$@"\n' "$1" "$2" > "$f"
    chmod +x "$f"
}
mkwrap clang64    clang "-target $TARGET -isysroot $SDK"
mkwrap clangxx64  clang++ "-target $TARGET -isysroot $SDK -stdlib=libc++"
mkwrap cc64       clang "-target $TARGET -isysroot $SDK"

export CC="$ROOT/bin/clang64"
export CXX="$ROOT/bin/clangxx64"
export CFLAGS="-I$DEPS/usr/include -O2"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-L$DEPS/usr/lib"
export AR="xcrun -sdk iphoneos ar"
export RANLIB="xcrun -sdk iphoneos ranlib"
export STRIP="xcrun -sdk iphoneos strip"
