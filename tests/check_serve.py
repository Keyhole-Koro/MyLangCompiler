#!/usr/bin/env python3
"""A serving mlc (mlc --serve) keeps the modules one unit loads for the units
after it (src/frontend/module/module_cache.c). Whatever it kept, each unit has
to come out as it does from an mlc of its own: compile every fixture both
ways, the served ones in two orders, and compare whether each compiled and
every file each wrote."""

import subprocess
import tempfile
from pathlib import Path


repo = Path(__file__).resolve().parents[1]
mlc = repo / "mlc"
sources = sorted(repo.glob("tests/succeed/**/*.mln")) + sorted(repo.glob("tests/fail/**/*.mln"))


def unit_args(source: Path, out: Path) -> list:
    target = out / source.relative_to(repo).with_suffix(".masm")
    target.parent.mkdir(parents=True, exist_ok=True)
    return ["--line-info", "--depfile", f"{target}.deps", str(source), str(target)]


def one_by_one(out: Path) -> dict:
    return {
        source: "0" if subprocess.run(
            [mlc, *unit_args(source, out)], cwd=repo,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0 else "1"
        for source in sources
    }


def start_server():
    proc = subprocess.Popen([mlc, "--serve"], cwd=repo, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, errors="replace")
    if proc.stdout.readline() != "\x1eserving\n":
        raise SystemExit("mlc --serve did not start")
    return proc


def served(out: Path, order: list) -> dict:
    """Each unit's status: "0", "1", "2", or "ended" where the compile ended
    the server, which a compile error does; another one takes the next unit."""
    proc = start_server()
    statuses = {}
    for source in order:
        proc.stdin.write("\t".join(unit_args(source, out)) + "\n")
        proc.stdin.flush()
        statuses[source] = "ended"
        for line in proc.stdout:
            if line.startswith("\x1e"):
                statuses[source] = line[1:].strip()
                break
        if statuses[source] == "ended":
            proc.wait()
            proc = start_server()
    proc.stdin.close()
    proc.wait()
    return statuses


def files(out: Path) -> dict:
    return {path.relative_to(out): path.read_bytes() for path in out.rglob("*") if path.is_file()}


def unit_files(source: Path) -> set:
    """What a compile of source writes, relative to its output directory."""
    stem = str(source.relative_to(repo).with_suffix(""))
    return {Path(stem + suffix) for suffix in (".masm", ".masm.deps", "_tokens.txt", "_ast.txt")}


with tempfile.TemporaryDirectory(prefix="mylang-serve-") as temporary:
    temporary = Path(temporary)
    expected_status = one_by_one(temporary / "one")
    expected_files = files(temporary / "one")
    failures = []
    for name, order in (("in order", sources), ("reversed", list(reversed(sources)))):
        out = temporary / name.replace(" ", "-")
        status = served(out, order)
        # A unit the server could not give a kept module to (status 2), or
        # that ended it, is one the build compiles again by itself: what the
        # server wrote for it does not count. Only a failing unit may end it.
        skipped = set()
        for source in sources:
            if status[source] == "2" or (status[source] == "ended" and expected_status[source] == "1"):
                skipped |= unit_files(source)
            elif status[source] != expected_status[source]:
                failures.append(f"{name}: {source.relative_to(repo)} status {status[source]}, "
                                f"alone {expected_status[source]}")
        actual_files = files(out)
        for path in sorted(set(expected_files) | set(actual_files)):
            if path not in skipped and expected_files.get(path) != actual_files.get(path):
                failures.append(f"{name}: {path} differs from the one-process compile")
    if failures:
        raise SystemExit("mlc --serve does not match single compiles:\n  " + "\n  ".join(failures[:20]))
print(f"mlc --serve matches single compiles of {len(sources)} fixtures in two orders")
