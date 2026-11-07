#!/usr/bin/env python3
"""An import means the file next to its importer, however often the name recurs."""

import subprocess
import sys
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
compiler = Path(sys.argv[1]) if len(sys.argv) > 1 else repo / "mlc"

with tempfile.TemporaryDirectory(prefix="mylang-imports-") as temporary:
    root = Path(temporary).resolve()
    (root / "a").mkdir()
    (root / "b").mkdir()
    (root / "a" / "util.mln").write_text("i32 from_a() { return 1; }\n")
    (root / "b" / "util.unsafe.mln").write_text("i32 from_b() { return 2; }\n")
    (root / "a" / "left.mln").write_text(
        'import from_a from "util.mln";\ni32 left() { return from_a(); }\n')
    (root / "b" / "right.mln").write_text(
        'import from_b from "util.mln";\ni32 right() { return from_b(); }\n')
    (root / "main.mln").write_text(
        'import left from "a/left.mln";\n'
        'import right from "b/right.mln";\n'
        'import from_a from "b/../a/util.mln";\n'
        'i32 main() { return left() + right() + from_a(); }\n')

    def imports(source: str) -> list[str]:
        depfile = root / "imports.deps"
        subprocess.run([compiler, "--depfile", depfile, root / source, root / "out.masm"],
                       cwd=root, check=True, stdout=subprocess.DEVNULL)
        return sorted(depfile.read_text(encoding="utf-8").splitlines()[1:])

    def expect(source: str, names: list[str]) -> None:
        expected = sorted(f"mln\t{root / name}" for name in names)
        actual = imports(source)
        if actual != expected:
            raise SystemExit(f"{source}:\nexpected={expected!r}\nactual={actual!r}")

    # Compiling main needs from_a and from_b, so each `util.mln` must have been
    # the one next to its importer.
    expect("main.mln", ["a/left.mln", "a/util.mln", "b/right.mln"])
    expect("a/left.mln", ["a/util.mln"])
    expect("b/right.mln", ["b/util.unsafe.mln"])

    # A failed import is said each time, not remembered as resolved.
    (root / "bad.mln").write_text(
        'import nothing from "missing.mln";\ni32 main() { return nothing(); }\n')
    failed = subprocess.run([compiler, root / "bad.mln", root / "bad.masm"],
                            cwd=root, capture_output=True, text=True)
    if failed.returncode == 0 or "missing.mln" not in failed.stdout + failed.stderr:
        raise SystemExit(f"a missing import was not reported:\n{failed.stdout}{failed.stderr}")

print("import paths resolve per importer")
