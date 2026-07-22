#!/usr/bin/env python3
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MLC_PATH = REPO_ROOT / "mlc"
TESTS_DIR = REPO_ROOT / "tests"

PASS_CASES = {
    "namedCallArgs": TESTS_DIR / "succeed/function/namedCallArgs.mln",
}

FAIL_CASES = {
    "namedCallUnknown": (
        TESTS_DIR / "fail/semantic/namedCallUnknown_fail.mln",
        "unknown named argument 'nope'",
    ),
    "namedCallDuplicate": (
        TESTS_DIR / "fail/semantic/namedCallDuplicate_fail.mln",
        "duplicate named argument 'a'",
    ),
    "namedCallMissing": (
        TESTS_DIR / "fail/semantic/namedCallMissing_fail.mln",
        "missing argument 'b'",
    ),
    "namedCallPositionalAfterNamed": (
        TESTS_DIR / "fail/semantic/namedCallPositionalAfterNamed_fail.mln",
        "positional argument cannot follow a named argument",
    ),
}


def compile_source(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(MLC_PATH), str(source), str(output)],
        cwd=output.parent,
        text=True,
        capture_output=True,
    )


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory(prefix="mylang-named-arg-blackbox-") as tmp:
        out_dir = Path(tmp)

        for name, source in PASS_CASES.items():
            result = compile_source(source, out_dir / f"{name}.masm")
            if result.returncode != 0:
                failures.append(
                    f"{name}: compiler failed\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
                )
            else:
                print(f"[PASS] {name}")

        for name, (source, expected) in FAIL_CASES.items():
            result = compile_source(source, out_dir / f"{name}.masm")
            if result.returncode == 0:
                failures.append(f"{name}: compiler unexpectedly succeeded")
            elif expected not in result.stderr:
                failures.append(
                    f"{name}: missing diagnostic {expected!r}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
                )
            else:
                print(f"[PASS] {name}")

    for failure in failures:
        print(f"[FAIL] {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
