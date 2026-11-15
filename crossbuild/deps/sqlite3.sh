#!/bin/bash
# deps: sqlite3 static cross (amalgamation → libsqlite3.a)
set -e
cd "$ROOT"
if [ -f "$DEPS/usr/lib/libsqlite3.a" ]; then exit 0; fi
echo "=== DEP sqlite3 ==="
V=3450100   # 3.45.1
[ -f "$SRCROOT/sqlite-amalgamation-$V.zip" ] || curl -fSL "https://www.sqlite.org/2024/sqlite-amalgamation-$V.zip" -o "$SRCROOT/sqlite-amalgamation-$V.zip"
[ -d "$SRCROOT/sqlite-amalgamation-$V" ] || { rm -rf "$SRCROOT/sqlite-amalgamation-$V"; unzip -q "$SRCROOT/sqlite-amalgamation-$V.zip" -d "$SRCROOT"; }
cd "$SRCROOT/sqlite-amalgamation-$V"
"$CC" $CFLAGS -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE -DSQLITE_THREADSAFE=0 \
    -DSQLITE_ENABLE_COLUMN_METADATA -c sqlite3.c -o sqlite3.o
xcrun -sdk iphoneos ar rcs "$DEPS/usr/lib/libsqlite3.a" sqlite3.o
mkdir -p "$DEPS/usr/include" "$DEPS/usr/lib/pkgconfig"
cp sqlite3.h "$DEPS/usr/include/"
cat > "$DEPS/usr/lib/pkgconfig/sqlite3.pc" <<EOF
prefix=$DEPS/usr
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: sqlite3
Version: 3.45.1
Description: SQLite
Libs: -L\${libdir} -lsqlite3
Cflags: -I\${includedir}
EOF
echo "=== DEP sqlite3 OK ==="
