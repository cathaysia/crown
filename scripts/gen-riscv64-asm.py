#!/usr/bin/env python3
"""Generate the crown riscv64 assembly modules (`*/riscv64.ts`) from OpenSSL.

Each module is the frozen output of one riscv64 perlasm script, generated for
the `linux64` flavour, embedded verbatim in a TypeScript file that exports it
as a string; `crown_derive::jsasm_file!` then hands it to
`core::arch::global_asm!`, whose LLVM integrated assembler consumes it (with
`options(raw)`: some modules carry `{`/`}` in their comments).

Unlike the x86_64 ports (which re-run the x86_64-xlate emulation at build
time) and the aarch64 ones (which need a C preprocessor pass for
`#include "arm_arch.h"` and the `__ARM_MAX_ARCH__` guards), a riscv64 module
is already plain GAS syntax with no preprocessor directives: OpenSSL's own
build generates most of them as lowercase `.s` (no cpp) and assembles them
with `as`. The SHA-256, SHA-512 and SM3 ones are named `.S` upstream, but
none of the three carries a `#include` or a `#if` either, so preprocessing
them would only reflow blank lines and `#` comments -- the raw perl text is
what gets embedded, exactly as emitted, with one exception:

  Some riscv64 scripts emit comment lines that *look* like a preprocessor
  conditional (`    # if bits == 128`). GNU as reads `#` as a line comment,
  and so does the LLVM of the pinned toolchain, but older LLVM MC releases
  (e.g. clang 18) parse `# if` as a hash-conditional directive and then fail
  with "unterminated conditional directive". The generator therefore prefixes
  those lines with one extra `#`, which is still a comment to every assembler
  and removes the ambiguity. The affected modules and line counts are printed
  (and recorded in the generated header) so the divergence from upstream is
  visible, never silent.

Usage:
    scripts/gen-riscv64-asm.py [module ...]     # regenerate (all by default)
    scripts/gen-riscv64-asm.py --check          # verify the committed files
    scripts/gen-riscv64-asm.py --lint           # assemble every module (GNU as)
    scripts/gen-riscv64-asm.py --lint-llvm      # assemble via rustc/LLVM global_asm!
    scripts/gen-riscv64-asm.py --list

Environment:
    OPENSSL_SRC   OpenSSL source tree, default ../crown-ref/openssl
    RISCV64_AS    assembler for --lint, default riscv64-linux-gnu-gcc
    RISCV64_RUST_TARGET  rust target for --lint-llvm,
                  default riscv64gc-unknown-linux-gnu
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
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
    # The flavour argument. None of the riscv64 scripts reads it as an ABI
    # selector (OpenSSL itself runs them without one); chacha-riscv64-v-zbb.pl
    # is the exception, taking `zvkb` there to emit the Zvkb variant, which is
    # how `GENERATE[chacha-riscv64-v-zbb-zvkb.s]=asm/chacha-riscv64-v-zbb.pl
    # zvkb` drives it upstream.
    flavour: str = "linux64"


MODULES: tuple[Module, ...] = (
    Module(
        "aes",
        "crypto/aes/asm/aes-riscv64.pl",
        "aes-riscv64",
        "crown/src/block/aes/riscv64/aes_ttable.ts",
        "AES T-table implementation (RV64I scalar)",
    ),
    Module(
        "aes-zkn",
        "crypto/aes/asm/aes-riscv64-zkn.pl",
        "aes-riscv64-zkn",
        "crown/src/block/aes/riscv64/zkn.ts",
        "AES key schedule and block cipher (Zknd/Zkne scalar crypto)",
    ),
    Module(
        "aes-zvkned",
        "crypto/aes/asm/aes-riscv64-zvkned.pl",
        "aes-riscv64-zvkned",
        "crown/src/block/aes/riscv64/zvkned.ts",
        "AES key schedule, single block, ECB and CBC (Zvkned vector crypto)",
    ),
    Module(
        "aes-ctr-zvkb-zvkned",
        "crypto/aes/asm/aes-riscv64-zvkb-zvkned.pl",
        "aes-riscv64-zvkb-zvkned",
        "crown/src/block/aes/riscv64/zvkb_zvkned_ctr32.ts",
        "AES-CTR32 bulk (Zvkb + Zvkned vector crypto)",
    ),
    Module(
        "aes-xts-zvbb-zvkg-zvkned",
        "crypto/aes/asm/aes-riscv64-zvbb-zvkg-zvkned.pl",
        "aes-riscv64-zvbb-zvkg-zvkned",
        "crown/src/block/aes/riscv64/zvbb_zvkg_zvkned_xts.ts",
        "AES-XTS over one data unit, ciphertext stealing included "
        "(Zvbb + Zvkg + Zvkned vector crypto)",
    ),
    Module(
        "aes-rv32-zkn",
        "crypto/aes/asm/aes-riscv32-zkn.pl",
        "aes-riscv32-zkn",
        "crown/src/block/aes/riscv64/aes_rv32_zkn.ts",
        "AES key schedule and block cipher (RV32 Zknd/Zkne scalar crypto)",
        wired=False,
    ),
    Module(
        "chacha",
        "crypto/chacha/asm/chacha-riscv64-v-zbb.pl",
        "chacha-riscv64-v-zbb",
        "crown/src/stream/chacha20/riscv64.ts",
        "ChaCha20 stream cipher (RV64 V + Zbb)",
    ),
    Module(
        "chacha-zvkb",
        "crypto/chacha/asm/chacha-riscv64-v-zbb.pl",
        "chacha-riscv64-v-zbb-zvkb",
        "crown/src/stream/chacha20/riscv64_zvkb.ts",
        "ChaCha20 stream cipher (RV64 V + Zbb + Zvkb)",
        flavour="zvkb",
    ),
    Module(
        "ghash-zbc",
        "crypto/modes/asm/ghash-riscv64.pl",
        "ghash-riscv64",
        "crown/src/block/aes/gcm/riscv64_zbc.ts",
        "GHASH (Zbc scalar bit-manipulation, with Zbb/Zbkb variants)",
    ),
    Module(
        "ghash-zvkb-zvbc",
        "crypto/modes/asm/ghash-riscv64-zvkb-zvbc.pl",
        "ghash-riscv64-zvkb-zvbc",
        "crown/src/block/aes/gcm/riscv64_zvkb_zvbc.ts",
        "GHASH (Zvkb + Zvbc carry-less-multiply vector crypto)",
    ),
    Module(
        "ghash-zvkg",
        "crypto/modes/asm/ghash-riscv64-zvkg.pl",
        "ghash-riscv64-zvkg",
        "crown/src/block/aes/gcm/riscv64_zvkg.ts",
        "GHASH (Zvkg vector GCM extension, with Zvkb variant)",
    ),
    Module(
        "aes-gcm",
        "crypto/modes/asm/aes-gcm-riscv64-zvkb-zvkg-zvkned.pl",
        "aes-gcm-riscv64-zvkb-zvkg-zvkned",
        "crown/src/aead/gcm/riscv64.ts",
        "AES-GCM stitched implementation (Zvkb + Zvkg + Zvkned)",
    ),
    Module(
        "sha256",
        "crypto/sha/asm/sha256-riscv64-zvkb-zvknha_or_zvknhb.pl",
        "sha256-riscv64-zvkb-zvknha_or_zvknhb",
        "crown/src/hash/sha256/block/riscv64.ts",
        "SHA-256 block transform (Zvkb + Zvknha/Zvknhb vector crypto)",
    ),
    Module(
        "sha512",
        "crypto/sha/asm/sha512-riscv64-zvkb-zvknhb.pl",
        "sha512-riscv64-zvkb-zvknhb",
        "crown/src/hash/sha512/block/riscv64.ts",
        "SHA-512 block transform (Zvkb + Zvknhb vector crypto)",
    ),
    Module(
        "sm3",
        "crypto/sm3/asm/sm3-riscv64-zvksh.pl",
        "sm3-riscv64-zvksh",
        "crown/src/hash/sm3/riscv64.ts",
        "SM3 block transform (Zvkb + Zvksh vector crypto)",
    ),
    Module(
        "sm4",
        "crypto/sm4/asm/sm4-riscv64-zvksed.pl",
        "sm4-riscv64-zvksed",
        "crown/src/block/sm4/riscv64.ts",
        "SM4 key schedule and block cipher (Zvksed vector crypto)",
    ),
    Module(
        "cpuid",
        "crypto/riscv64cpuid.pl",
        "riscv64cpuid",
        "crown/src/utils/cpuid/riscv64.ts",
        "CRYPTO_memcmp, OPENSSL_cleanse and riscv_vlen_asm (RV64I)",
        wired=False,
    ),
)

# Comment lines that older LLVM MC releases read as hash-conditional
# directives instead of comments (see the module docstring).
HASH_DIRECTIVE = re.compile(
    r"^([ \t]*)#(\s*)(if|ifdef|ifndef|else|elif|endif|define|undef|include|error|warning|line)\b",
    re.M,
)


def copyright_line(perl_path: Path) -> str:
    text = perl_path.read_text(errors="replace")
    for line in text.splitlines()[:20]:
        line = line.strip().lstrip("#!*/ ").strip()
        if line.lower().startswith("copyright"):
            return re.sub(r"\s+", " ", line)
    return "Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved."


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def generate(mod: Module, openssl: Path) -> str:
    script = openssl / mod.perl
    if not script.exists():
        raise SystemExit(f"{mod.key}: missing perl script {script}")

    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / f"{mod.out}.S"
        res = run(["perl", str(script), mod.flavour, str(raw)])
        if res.returncode != 0:
            raise SystemExit(f"{mod.key}: perl failed:\n{res.stderr}")
        if not raw.exists() or raw.stat().st_size == 0:
            raise SystemExit(f"{mod.key}: perl produced no output")

        asm = raw.read_text()

    escaped = len(HASH_DIRECTIVE.findall(asm))
    asm = HASH_DIRECTIVE.sub(lambda m: f"{m.group(1)}##{m.group(2)}{m.group(3)}", asm)
    if not asm.endswith("\n"):
        asm += "\n"

    # A normal template literal: escape the three characters that would
    # otherwise terminate or interpolate, and keep everything else byte-exact.
    body = asm.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")

    globals_ = re.findall(r"^\.globl\s+(\S+)$", asm, re.M)

    header = [
        "/**\n",
        f" * {mod.title} for riscv64.\n",
        " *\n",
        f" * Frozen assembly output of OpenSSL {mod.perl} ({mod.flavour} flavour),\n",
        " * embedded verbatim: the riscv64 scripts emit GNU-as syntax directly and\n",
        " * carry no preprocessor directives, so there is no cpp step (compare\n",
        " * scripts/gen-aarch64-asm.py). Regenerate with:\n",
        " *\n",
        f" *   scripts/gen-riscv64-asm.py {mod.key}\n",
        " *\n",
    ]
    if escaped:
        header += [
            f" * {escaped} comment line(s) that look like a preprocessor\n",
            " * conditional (`# if ...`) carry an extra `#` so that LLVM MC reads\n",
            " * them as comments; see the generator docstring.\n",
            " *\n",
        ]
    header += [
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


def module_body(text: str) -> str:
    """The assembly text of a generated .ts file."""
    body = text.split("const asm = `", 1)[1].rsplit("`;", 1)[0]
    return body.replace("\\\\", "\\").replace("\\`", "`").replace("\\${", "${")


def lint_gas(text: str, as_cmd: list[str], tmp: Path) -> str | None:
    src = tmp / "mod.s"
    src.write_text(module_body(text))
    res = run([*as_cmd, "-c", str(src), "-o", str(tmp / "mod.o")])
    return None if res.returncode == 0 else res.stderr


def lint_llvm(texts: dict[str, str], target: str) -> dict[str, str]:
    """Assemble every module through `core::arch::global_asm!` (the LLVM path
    `crown_derive::jsasm_file!` ends up on) and return the failures by key.

    Each module is assembled on its own: `crown-derive` tags the `.L` labels
    when it merges the modules into one `global_asm!`, so a combined input
    would report duplicate-label errors that do not exist in the real build.
    """
    toolchain = os.environ.get("RISCV64_RUST_TOOLCHAIN", "").strip()
    if not toolchain:
        pinned = REPO / "rust-toolchain.toml"
        if pinned.exists():
            m = re.search(r'^channel\s*=\s*"([^"]+)"', pinned.read_text(), re.M)
            toolchain = m.group(1) if m else ""
    rustc = ["rustup", "run", toolchain, "rustc"] if toolchain else ["rustc"]
    if shutil.which(rustc[0]) is None:
        raise SystemExit(f"--lint-llvm: {rustc[0]} not found")

    failures: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # `options(raw)`: the modules carry `{`/`}` (at least in comments),
        # which the macro would otherwise read as operand placeholders.
        src = tmp / "mod.rs"
        for key, text in texts.items():
            src.write_text(f'#![no_std]\ncore::arch::global_asm!(r##"{module_body(text)}"##, '
                           "options(raw));\n")
            res = run([*rustc, "--target", target, "--crate-type", "lib",
                       "--edition", "2021", "--emit=metadata",
                       "-o", str(tmp / "mod.rmeta"), str(src)])
            if res.returncode != 0:
                failures[key] = res.stderr.strip()
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("modules", nargs="*", help="module keys (default: all)")
    parser.add_argument("--check", action="store_true",
                        help="verify the committed files match the generators")
    parser.add_argument("--lint", action="store_true",
                        help="assemble every generated module (GNU as by default)")
    parser.add_argument("--lint-llvm", action="store_true",
                        help="assemble every generated module through rustc's global_asm!")
    parser.add_argument("--list", action="store_true", help="list module keys")
    parser.add_argument("--openssl", type=Path,
                        default=Path(os.environ.get("OPENSSL_SRC", DEFAULT_OPENSSL_SRC)))
    parser.add_argument("--as", dest="as_cmd",
                        default=os.environ.get("RISCV64_AS", "riscv64-linux-gnu-gcc"),
                        help="assembler command for --lint")
    parser.add_argument("--rust-target",
                        default=os.environ.get("RISCV64_RUST_TARGET",
                                               "riscv64gc-unknown-linux-gnu"))
    args = parser.parse_args()

    if args.list:
        for mod in MODULES:
            state = "" if mod.wired else "  (not wired yet)"
            print(f"{mod.key:24} {mod.perl}{state}")
        return 0

    wanted = args.modules or [mod.key for mod in MODULES]
    by_key = {mod.key: mod for mod in MODULES}
    unknown = [key for key in wanted if key not in by_key]
    if unknown:
        raise SystemExit(f"unknown module(s): {', '.join(unknown)}")

    texts = {key: generate(by_key[key], args.openssl) for key in wanted}

    if args.lint or args.lint_llvm:
        failed = False
        if args.lint:
            with tempfile.TemporaryDirectory() as tmpdir:
                for key in wanted:
                    err = lint_gas(texts[key], args.as_cmd.split(), Path(tmpdir))
                    if err:
                        print(f"{key}: does not assemble:\n{err}", file=sys.stderr)
                        failed = True
                    else:
                        print(f"{key}: assembles (GNU as)")
        if args.lint_llvm:
            failures = lint_llvm(texts, args.rust_target)
            for key in wanted:
                if key in failures:
                    print(f"{key}: does not assemble through global_asm!:\n{failures[key]}",
                          file=sys.stderr)
                    failed = True
                else:
                    print(f"{key}: assembles (LLVM global_asm!)")
        return 1 if failed else 0

    failed = False
    for key in wanted:
        mod = by_key[key]
        text = texts[key]
        path = REPO / mod.ts
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
