# RedHatSec Universal Cross-Compiler

Compila **qualsiasi tool** per `iphoneos-arm64` (rootless Dopamine) e produce `.deb` installabili direttamente dall'app (PATH `debURL` → `dpkg -i` via rootd).

## Quickstart
```bash
cd crossbuild
./build.sh aircrack-ng        # un tool
./build.sh --all              # tutte le ricette
ls deb/                       # <tool>_iphoneos-arm64.deb
```

## Architettura
| File | Ruolo |
|---|---|
| `env.sh` | toolchain: clang SDK iphoneos, `-arch arm64`, sysroot, min iOS 14, prefix `/var/jb` |
| `deps/*.sh` | librerie cross **statiche** in `deps-rootless/usr` (libpcap, openssl) — idempotenti |
| `tools/*.sh` | una ricetta per tool: scarica sorgente, configura, `make`, `DESTDIR=stage install` |
| `pack.sh` | staging → `.deb` rootless (ar 60-byte, `Package: rhs-<tool>`) |

Il runner CI è **Apple Silicon** → i test di configure girano nativi: nessun `--host` da passare.

## Aggiungere un tool (ricetta universale)
```bash
cat > tools/<tool>.sh <<'EOF'
#!/bin/bash
set -e
V=<version>
SRC="$SRCROOT/<tool>-$V"
[ -f "$SRCROOT/<tool>-$V.tar.gz" ] || curl -fSL "<url-tarball>" -o "$SRCROOT/<tool>-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/<tool>-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
make distclean >/dev/null 2>&1 || true
CC="$CC" CFLAGS="$CFLAGS -I$DEPS/usr/include" LDFLAGS="$LDFLAGS -L$DEPS/usr/lib" \
./configure --prefix="$PREFIX" --disable-<opt>
make -j8
make DESTDIR="$STAGE" install
$STRIP "$STAGE/var/jb/usr/bin/"* 2>/dev/null || true
EOF
./build.sh <tool>
```
Autotools/CMake/Makefile-raw vanno bene: l'universale sono le env `CC/CFLAGS/LDFLAGS/PREFIX/DEPS`.
Per autotools passa **sempre** `--host=arm-apple-darwin` (cross-mode: configure non esegue conftest iOS sul runner).

## Deploy
Il workflow `debs.yml` compila la matrice e pubblica i `.deb` nella release tag `debs` — l'app li installa con `curl + dpkg -i` via rootd.
Trigger: il workflow parte su push di crossbuild/** — failure stampa primo errore (multi-pattern), comando e tail del log. brew: flex bison autoconf automake libtool. socat: patch call-site system() (fork/exec/waitpid) + pre-seed cache sc_cv_type_*. Ricetta aircrack-ng: autotools minimale (libnl/pcre/hwloc/sqlite/gcrypt/opt OFF, openssl da DEPS statico).
- rerun trigger: 2026-11-16 (2132b1d cancellata dal runner)
- trigger bpf ioctl + curl off
