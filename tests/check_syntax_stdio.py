#!/usr/bin/env python3
"""--stdio refuses a content or model size that does not fit a buffer."""

import json
import subprocess
from pathlib import Path


repo = Path(__file__).resolve().parents[1]
grammar = repo.parent / "MySyntaxEngine/tests/fixtures/grammars/mylang_lsp.grammar"
table = repo / "mylang-syntax-check.table"
checker = repo / "mylang-syntax-check"

# Enough bytes after the header to run far past a zero-sized buffer.
FILLER = b"x" * (256 * 1024)


def fail(message):
    raise SystemExit(f"syntax-check stdio: {message}")


def run(data):
    return subprocess.run(
        [checker, "--stdio", grammar, table],
        cwd=repo,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )


def check_valid():
    source = b"i32 main() { return 0; }"
    result = run(f"content {len(source)}\n".encode("ascii") + source + b"\n")
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) != 2 or lines[0] != b"ready":
        fail(f"a valid request failed: rc={result.returncode} out={result.stdout[:200]!r}")
    if json.loads(lines[1]).get("status") != "ok":
        fail(f"a valid request was not ok: {lines[1][:200]!r}")


def check_refused(header):
    result = run(header.encode("ascii") + b"\n" + FILLER)
    if result.returncode != 1:
        fail(f"{header!r} gave rc={result.returncode}, expected 1: {result.stderr[-300:]!r}")


def main():
    check_valid()
    for kind in ("content", "model"):
        check_refused(f"{kind} 18446744073709551615")
        check_refused(f"{kind} 99999999999999999999999")
        check_refused(f"{kind} -1")
        check_refused(f"{kind}  -1")
    print("syntax-check stdio refuses sizes that overflow")


if __name__ == "__main__":
    main()
