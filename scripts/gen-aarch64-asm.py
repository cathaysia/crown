#!/usr/bin/env python3
"""Generate the crown aarch64 assembly modules (`*/aarch64.ts`) from OpenSSL.

Each module is the frozen output of one aarch64 perlasm script, generated for
the `linux64` flavour and run through the C preprocessor the way OpenSSL's
build does (`-I crypto`, `-D__ASSEMBLER__` from gcc's own aarch64 defines).
The preprocessed text is embedded verbatim in a TypeScript file that exports
it as a string; `crown_derive::jsasm_file!` then hands it to
`core::arch::global_asm!`, whose LLVM integrated assembler consumes exactly
what a stock aarch64 build assembles.

The C preprocessor step resolves `#include "arm_arch.h"`, the `#if
__ARM_MAX_ARCH__>=7` guards and the `AARCH64_*` support macros. It is run once,
here, because `global_asm!` does not go through cpp.

Usage:
    scripts/gen-aarch64-asm.py [module ...]     # regenerate (all by default)
    scripts/gen-aarch64-asm.py --check          # verify the committed files
    scripts/gen-aarch64-asm.py --lint           # assemble every module
    scripts/gen-aarch64-asm.py --list

Environment:
    OPENSSL_SRC   OpenSSL source tree, default ../crown-ref/openssl
    AARCH64_CPP   preprocessor command, default aarch64-linux-gnu-gcc
    AARCH64_AS    assembler for --lint, default clang -target aarch64-linux-gnu
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OPENSSL_SRC = REPO.parent / "crown-ref" / "openssl"


@dataclass(frozen=True)
class Module:
    key: str
    perl: str  # path under the OpenSSL source tree
    out: str  # output basename handed to the perl (picks the variant)
    ts: str  # crown path of the generated TypeScript file
    title: str
    wired: bool = True


MODULES: tuple[Module, ...] = (
    Module(
        "sha1",
        "crypto/sha/asm/sha1-armv8.pl",
        "sha1-armv8",
        "crown/src/hash/sha1/block/aarch64.ts",
        "SHA-1 block transform (ARMv8 crypto extensions + NEON fallback)",
    ),
    Module(
        "sha256",
        "crypto/sha/asm/sha512-armv8.pl",
        "sha256-armv8",
        "crown/src/hash/sha256/block/aarch64.ts",
        "SHA-256 block transform (ARMv8 crypto extensions + NEON fallback)",
    ),
    Module(
        "sha512",
        "crypto/sha/asm/sha512-armv8.pl",
        "sha512-armv8",
        "crown/src/hash/sha512/block/aarch64.ts",
        "SHA-512 block transform (ARMv8.2 crypto extensions + NEON fallback)",
    ),
    Module(
        "md5",
        "crypto/md5/asm/md5-aarch64.pl",
        "md5-aarch64",
        "crown/src/hash/md5/block/aarch64.ts",
        "MD5 block transform (ARMv8 NEON)",
    ),
    Module(
        "sm3",
        "crypto/sm3/asm/sm3-armv8.pl",
        "sm3-armv8",
        "crown/src/hash/sm3/aarch64.ts",
        "SM3 block transform (ARMv8.2 SM3 crypto extensions)",
    ),
    Module(
        "keccak",
        "crypto/sha/asm/keccak1600-armv8.pl",
        "keccak1600-armv8",
        "crown/src/hash/sha3/aarch64.ts",
        "Keccak-f[1600] absorb/squeeze (NEON + ARMv8.2 SHA3 crypto extensions)",
    ),
    Module(
        "aesv8",
        "crypto/aes/asm/aesv8-armx.pl",
        "aesv8-armx",
        "crown/src/block/aes/aesv8/aarch64.ts",
        "AES key schedule, ECB and CBC (ARMv8 AES crypto extensions)",
    ),
    Module(
        "vpaes",
        "crypto/aes/asm/vpaes-armv8.pl",
        "vpaes-armv8",
        "crown/src/block/aes/vpaes/aarch64.ts",
        "AES bitsliced constant-time implementation (ARMv8 NEON)",
    ),
    Module(
        "bsaes",
        "crypto/aes/asm/bsaes-armv8.pl",
        "bsaes-armv8",
        "crown/src/block/aes/bsaes/aarch64.ts",
        "AES bit-sliced bulk CBC/CTR/ECB (ARMv8 NEON)",
    ),
    Module(
        "ghash",
        "crypto/modes/asm/ghashv8-armx.pl",
        "ghashv8-armx",
        "crown/src/block/aes/gcm/aarch64.ts",
        "GHASH (ARMv8 PMULL crypto extensions)",
    ),
    Module(
        "gcm",
        "crypto/modes/asm/aes-gcm-armv8_64.pl",
        "aes-gcm-armv8_64",
        "crown/src/aead/gcm/aarch64.ts",
        "AES-GCM stitched implementation (ARMv8 PMULL + AES)",
    ),
    Module(
        "gcm-unroll8",
        "crypto/modes/asm/aes-gcm-armv8-unroll8_64.pl",
        "aes-gcm-armv8-unroll8_64",
        "crown/src/aead/gcm/aarch64_unroll8.ts",
        "AES-GCM stitched implementation, unrolled by 8 (fused AES+EOR3)",
    ),
    Module(
        "chacha",
        "crypto/chacha/asm/chacha-armv8.pl",
        "chacha-armv8",
        "crown/src/stream/chacha20/aarch64.ts",
        "ChaCha20 stream cipher (ARMv8 NEON)",
    ),
    Module(
        "chacha-sve",
        "crypto/chacha/asm/chacha-armv8-sve.pl",
        "chacha-armv8-sve",
        "crown/src/stream/chacha20/aarch64_sve.ts",
        "ChaCha20 stream cipher (ARMv8 SVE2)",
        wired=False,
    ),
    Module(
        "poly1305",
        "crypto/poly1305/asm/poly1305-armv8.pl",
        "poly1305-armv8",
        "crown/src/mac/poly1305/aarch64.ts",
        "Poly1305 one-shot MAC (ARMv8 NEON)",
    ),
    Module(
        "mont",
        "crypto/bn/asm/armv8-mont.pl",
        "armv8-mont",
        "crown/src/bn/aarch64.ts",
        "Montgomery multiplication (ARMv8)",
    ),
    Module(
        "nistz256",
        "crypto/ec/asm/ecp_nistz256-armv8.pl",
        "ecp_nistz256-armv8",
        "crown/src/ec/nistz256/aarch64.ts",
        "P-256 field arithmetic and scalar multiplication (ARMv8)",
    ),
    Module(
        "sm2p256",
        "crypto/ec/asm/ecp_sm2p256-armv8.pl",
        "ecp_sm2p256-armv8",
        "crown/src/ec/sm2p256_aarch64.ts",
        "SM2 P-256 field arithmetic and scalar multiplication (ARMv8)",
        wired=False,
    ),
    Module(
        "sm4",
        "crypto/sm4/asm/sm4-armv8.pl",
        "sm4-armv8",
        "crown/src/block/sm4/aarch64.ts",
        "SM4 block cipher (ARMv8 NEON)",
    ),
    Module(
        "vpsm4",
        "crypto/sm4/asm/vpsm4-armv8.pl",
        "vpsm4-armv8",
        "crown/src/block/sm4/vpsm4_aarch64.ts",
        "SM4 bulk ECB/CBC/CTR/CFB/OFB (vector permute, ARMv8.2 SM4)",
    ),
    Module(
        "vpsm4-ex",
        "crypto/sm4/asm/vpsm4_ex-armv8.pl",
        "vpsm4_ex-armv8",
        "crown/src/block/sm4/vpsm4_ex_aarch64.ts",
        "SM4 bulk CBC/CTR/ECB, extended (vector permute with fused rounds)",
        wired=False,
    ),
)



def copyright_line(perl_path: Path) -> str:
    text = perl_path.read_text(errors="replace")
    for line in text.splitlines()[:20]:
        line = line.strip().lstrip("#!*/ ").strip()
        if line.lower().startswith("copyright"):
            return re.sub(r"\s+", " ", line)
    return "Copyright 2014-2026 The OpenSSL Project Authors. All Rights Reserved."


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def generate(mod: Module, openssl: Path, cpp: str) -> str:
    script = openssl / mod.perl
    if not script.exists():
        raise SystemExit(f"{mod.key}: missing perl script {script}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        raw = tmp / f"{mod.out}.S"
        res = run(["perl", str(script), "linux64", str(raw)])
        if res.returncode != 0:
            raise SystemExit(f"{mod.key}: perl failed:\n{res.stderr}")
        if not raw.exists() or raw.stat().st_size == 0:
            raise SystemExit(f"{mod.key}: perl produced no output")

        # `gcc -E` on a .S file defines __ASSEMBLER__ and the target macros
        # exactly like OpenSSL's build does; -P drops the line markers. The
        # include path carries the source root and `crypto/` because some
        # scripts include "arm_arch.h" and others "crypto/arm_arch.h".
        pre = tmp / "pre.s"
        res = run([cpp, "-E", "-P", "-I", str(openssl / "crypto"), "-I", str(openssl),
                   "-x", "assembler-with-cpp", str(raw), "-o", str(pre)])
        if res.returncode != 0:
            raise SystemExit(f"{mod.key}: cpp failed:\n{res.stderr}")

        asm = pre.read_text()
        if not asm.endswith("\n"):
            asm += "\n"

    # A normal template literal: escape the three characters that would
    # otherwise terminate or interpolate, and keep everything else byte-exact.
    body = asm.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")

    globals_ = re.findall(r"^\.globl\s+(\S+)$", asm, re.M)

    header = [
        "/**\n",
        f" * {mod.title} for aarch64.\n",
        " *\n",
        f" * Frozen assembly output of OpenSSL {mod.perl} (linux64 flavour),\n",
        " * preprocessed with the C preprocessor the way the OpenSSL build does\n",
        " * (arm_arch.h is included and the ARMv8 support macros are expanded),\n",
        " * then embedded verbatim. Regenerate with:\n",
        " *\n",
        f" *   scripts/gen-aarch64-asm.py {mod.key}\n",
        " *\n",
        f" * {copyright_line(openssl / mod.perl)}\n",
        " * Licensed under the Apache License 2.0 (https://www.openssl.org/source/license.html).\n",
        " */\n",
        "\n",
    ]
    doc = [
        f"// Exported entry points: {', '.join(globals_)}\n" if globals_ else "",
        "\nconst asm = `",
        body,
        "`;\n",
        "\n",
        "export default asm;\n",
    ]
    return "".join(header) + "".join(doc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("modules", nargs="*", help="module keys (default: all)")
    parser.add_argument("--check", action="store_true",
                        help="verify the committed files match the generators")
    parser.add_argument("--lint", action="store_true",
                        help="assemble every generated module (LLVM MC by default)")
    parser.add_argument("--list", action="store_true", help="list module keys")
    parser.add_argument("--openssl", type=Path,
                        default=Path(os.environ.get("OPENSSL_SRC", DEFAULT_OPENSSL_SRC)))
    parser.add_argument("--cpp", default=os.environ.get("AARCH64_CPP", "aarch64-linux-gnu-gcc"))
    args = parser.parse_args()

    if args.list:
        for mod in MODULES:
            state = "" if mod.wired else "  (not wired yet)"
            print(f"{mod.key:12} {mod.perl}{state}")
        return 0

    wanted = args.modules or [mod.key for mod in MODULES]
    by_key = {mod.key: mod for mod in MODULES}
    unknown = [key for key in wanted if key not in by_key]
    if unknown:
        raise SystemExit(f"unknown module(s): {', '.join(unknown)}")

    failed = False
    as_cmd = os.environ.get("AARCH64_AS", "clang -target aarch64-linux-gnu").split()
    for key in wanted:
        mod = by_key[key]
        text = generate(mod, args.openssl, args.cpp)
        path = REPO / mod.ts
        if args.lint:
            # `core::arch::global_asm!` goes through LLVM's integrated
            # assembler, so that is what --lint runs (each module on its own:
            # crown-derive tags the`.L` labels when it merges them).
            body = text.split("const asm = `", 1)[1].rsplit("`;", 1)[0]
            body = body.replace("\\\\", "\\").replace("\\`", "`").replace("\\${", "${")
            with tempfile.TemporaryDirectory() as tmp:
                src = Path(tmp) / "mod.s"
                src.write_text(body)
                res = run([*as_cmd, "-c", str(src), "-o", str(Path(tmp) / "mod.o")])
            if res.returncode != 0:
                print(f"{mod.key}: does not assemble:\n{res.stderr}", file=sys.stderr)
                failed = True
            else:
                print(f"{mod.key}: assembles")
            continue
        if args.check:
            if not path.exists() or path.read_text() != text:
                print(f"{mod.ts}: out of date", file=sys.stderr)
                failed = True
            else:
                print(f"{mod.ts}: ok")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            print(f"wrote {mod.ts} ({len(text)} bytes)")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
