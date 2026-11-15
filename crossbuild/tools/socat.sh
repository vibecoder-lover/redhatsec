#!/bin/bash
# tool: socat multipurpose relay (rootless)
set -e
V=1.8.0.1
SRC="$SRCROOT/socat-$V"
[ -f "$SRCROOT/socat-$V.tar.gz" ] || curl -fSL "http://www.dest-unreach.org/socat/download/socat-$V.tar.gz" -o "$SRCROOT/socat-$V.tar.gz"
[ -d "$SRC" ] || tar xzf "$SRCROOT/socat-$V.tar.gz" -C "$SRCROOT"
cd "$SRC"
make distclean >/dev/null 2>&1 || true
# socat usa macro custom che A VOLTE (CHANCE=0) fanno try_run → morte in cross.
# Pre-seedo le cache con i valori arm64-iOS (rilevati via GCC method, validati in CI):
# 1 short, 2 u-short, 3 int, 4 u-int, 5 long, 6 u-long, 7 long long, 8 u-long-long, 0 default
export ac_cv_file__dev_ptmx=yes
export sc_cv_type_uint16_basic=2 sc_cv_type_uint32_basic=4 sc_cv_type_uint64_basic=8
export sc_cv_type_int16_basic=1 sc_cv_type_int32_basic=3 sc_cv_type_int64_basic=7
export sc_cv_type_sizet_basic=6 sc_cv_type_modet_basic=2 sc_cv_type_pidt_basic=3
export sc_cv_type_uidt_basic=4 sc_cv_type_gidt_basic=4 sc_cv_type_timet_basic=5
export sc_cv_type_socklent_basic=4 sc_cv_type_off_basic=7 sc_cv_type_off64_basic=0
export sc_cv_type_dev_basic=3 sc_cv_type_spee_t=6
export sc_cv_type_stat_stino_basic=8 sc_cv_type_stat_stnlink_basic=2
export sc_cv_type_stat_stsize_basic=7 sc_cv_type_stat_stblksize_basic=3
export sc_cv_type_stat_stblocks_basic=7
export sc_cv_type_stat64_stdev_basic=0 sc_cv_type_stat64_stino_basic=0
export sc_cv_type_stat64_stnlink_basic=0 sc_cv_type_stat64_stsize_basic=0
export sc_cv_type_stat64_stblksize_basic=0 sc_cv_type_stat64_stblocks_basic=0
export sc_cv_type_struct_timeval_tv_usec=3 sc_cv_type_struct_timespec_tv_nsec=5
export sc_cv_type_rlimit_rlimmax_basic=8 sc_cv_typeof_struct_cmsghdr_cmsg_len=4
CC="$CC" CFLAGS="$CFLAGS -include $ROOT/api-shim.h" LDFLAGS="$LDFLAGS" \
./configure --prefix="$PREFIX" --host=arm-apple-darwin --disable-openssl --disable-libwrap
make -j8
make DESTDIR="$STAGE" install
$STRIP "$STAGE/var/jb/usr/bin/"* 2>/dev/null || true
