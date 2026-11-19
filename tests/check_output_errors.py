#!/usr/bin/env python3
"""A compile whose assembly cannot be written must fail."""

import os
import subprocess
import tempfile
from pathlib import Path


repo = Path(__file__).resolve().parents[1]
compiler = repo / "mlc"


def fail(message):
    raise SystemExit(f"output errors: {message}")


def compile_to(source, output):
    return subprocess.run(
        [compiler, source, output],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )


def expect_failure(source, output, why):
    result = compile_to(source, output)
    if result.returncode == 0:
        fail(f"{why}: exit 0 although {output} could not be written")
    if b"Output saved" in result.stdout:
        fail(f"{why}: still reported the output as saved")


def main():
    with tempfile.TemporaryDirectory(prefix="mylang-output-") as temporary:
        temporary = Path(temporary)
        source = temporary / "ok.mln"
        source.write_text("i32 main() { return 0; }\n", encoding="utf-8")

        written = compile_to(source, temporary / "ok.masm")
        if written.returncode != 0 or not (temporary / "ok.masm").is_file():
            fail(f"a writable output failed: {written.stderr[-300:]!r}")

        # A regular file where a directory should be: fopen fails (ENOTDIR).
        blocker = temporary / "blocker"
        blocker.write_text("", encoding="utf-8")
        expect_failure(source, blocker / "x.masm", "output under a file")

        # A full device: the write fails only when the buffer is flushed.
        if os.path.exists("/dev/full"):
            expect_failure(source, "/dev/full", "full device")
    print("unwritable output fails the compile")


if __name__ == "__main__":
    main()
