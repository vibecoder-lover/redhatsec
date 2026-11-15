#!/bin/bash
# RedHatSec universal cross-compiler — iphoneos-arm64 (rootless)
# export: CC/CXX/CFLAGS/LDFLAGS/PREFIX/STAGE/DEPS per tutte le ricette
set -e
export SDK="$(xcrun -sdk iphoneos --show-sdk-path)"
export MIN_IOS=14.0
export CC="xcrun -sdk iphoneos clang"
export CXX="xcrun -sdk iphoneos clang++"
export AR="xcrun -sdk iphoneos ar"
export RANLIB="xcrun -sdk iphoneos ranlib"
export STRIP="xcrun -sdk iphoneos strip"
export CFLAGS="-arch arm64 -isysroot $SDK -miphoneos-version-min=$MIN_IOS -O2"
export CXXFLAGS="$CFLAGS -stdlib=libc++"
export LDFLAGS="-arch arm64 -isysroot $SDK -miphoneos-version-min=$MIN_IOS"
export PREFIX=/var/jb
ROOT="$(cd "$(dirname "$0")" && pwd)"
export ROOT
export STAGE="$ROOT/stage"          # staging del tool corrente (svuotato a ogni build)
export DEPS="$ROOT/deps-rootless"   # librerie cross installate qui (usr/lib, usr/include)
export SRCROOT="$ROOT/src"          # sorgenti scaricati
mkdir -p "$DEPS" "$SRCROOT"
