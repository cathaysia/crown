#!/bin/sh
# Build and run the crown unit tests for aarch64 on this x86_64 host through
# QEMU user emulation.
#
# Requirements (Debian/Ubuntu names):
#   rustup target add aarch64-unknown-linux-gnu
#   apt install gcc-aarch64-linux-gnu qemu-user-static
#
# Usage:
#   scripts/check-aarch64.sh [cargo test args...]
#   CPU=max scripts/check-aarch64.sh              # default: every feature the
#                                                 # emulated CPU can expose
#   CPU=cortex-a72 scripts/check-aarch64.sh       # no SHA3/SM4/SVE: exercises
#                                                 # the scalar/NEON fallbacks
set -eu

TARGET=aarch64-unknown-linux-gnu
SYSROOT=${SYSROOT:-/usr/aarch64-linux-gnu}
CPU=${CPU:-max}

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64-static -L $SYSROOT -cpu $CPU"

exec cargo test -p crown --features asm --target "$TARGET" "$@"
