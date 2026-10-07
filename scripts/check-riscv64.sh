#!/bin/sh
# Build and run the crown unit tests for riscv64 on this x86_64 host through
# QEMU user emulation.
#
# Requirements (Debian/Ubuntu names):
#   rustup target add riscv64gc-unknown-linux-gnu
#   apt install gcc-riscv64-linux-gnu qemu-user-static
#
# Usage:
#   scripts/check-riscv64.sh [cargo test args...]
#                                                          # defaults: qemu
#                                                          # `max` and the
#                                                          # full ISA string
#   CPU=rv64 CAPS= scripts/check-riscv64.sh                # portable paths
#                                                          # and T-table AES
#   CPU=rv64,zbb=true,zbc=true,zknd=true,zkne=true,zknh=true,zksed=true,zksh=true \
#       CAPS=rv64gc_zbb_zbc_zknd_zkne_zknh_zksed_zksh \
#       scripts/check-riscv64.sh                           # Zkn AES and Zbc
#                                                          # GHASH tiers
#   CAPS=rv64gc_v_zvbb_zvbc CPU=rv64,v=true,zvbb=true,zvbc=true \
#       scripts/check-riscv64.sh                           # Zvkb+Zvbc GHASH
#                                                          # tier
#
# Two knobs describe the emulated CPU:
#
#   CPU   the qemu -cpu model and its extensions. The extensions must be
#         enabled here for the instructions to *run*.
#   CAPS  the OPENSSL_riscvcap ISA string, which is how crown learns what the
#         CPU has: qemu-user's riscv_hwprobe (as of qemu 8.2) reports only
#         the baseline bits, not Zbc/Zk*/Zvk*, so without the override no
#         tier above Zbb would ever be selected. An empty CAPS leaves the
#         probe alone, which is what a baseline run wants.
#
# A vector extension in CAPS needs `_v` in the same string (the parser only
# sets the bits it is given, like OpenSSL's crypto/riscvcap.c).
set -eu

TARGET=riscv64gc-unknown-linux-gnu
SYSROOT=${SYSROOT:-/usr/riscv64-linux-gnu}
CPU=${CPU:-max}
CAPS=${CAPS-rv64gc_v_zba_zbb_zbc_zbs_zbkb_zbkc_zbkx_zknd_zkne_zknh_zksed_zksh_zvbb_zvbc_zvkb_zvkg_zvkned_zvknha_zvknhb_zvksed_zvksh}
# The defaults above are the full vector-crypto configuration; the CI job also
# runs the scalar (Zkn/Zbc), Zvbc and baseline (probe-only) ones, see
# docs/algorithms-status.md §1c.

export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER:-riscv64-linux-gnu-gcc}
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64-static -L $SYSROOT -cpu $CPU"
if [ -n "$CAPS" ]; then
    export OPENSSL_riscvcap="$CAPS"
else
    unset OPENSSL_riscvcap
fi

exec cargo test -p crown --features asm --target "$TARGET" "$@"
