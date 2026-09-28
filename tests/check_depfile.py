#!/usr/bin/env python3

import subprocess
import tempfile
from pathlib import Path


repo = Path(__file__).resolve().parents[1]
source = repo / "tests/succeed/package/importFrom_main.mln"
expected = (source.parent / "importFrom_helper.mln").resolve()

with tempfile.TemporaryDirectory(prefix="mylang-depfile-") as temporary:
    temporary = Path(temporary)
    output = temporary / "main.masm"
    depfile = temporary / "main.deps"
    subprocess.run(
        [repo / "mlc", "--depfile", depfile, source, output],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    lines = depfile.read_text(encoding="utf-8").splitlines()
    expected_lines = ["MYDEPS 1", f"mln\t{expected}"]
    if lines != expected_lines:
        raise SystemExit(
            f"unexpected dependency manifest:\nexpected={expected_lines!r}\nactual={lines!r}"
        )

    foreign_dir = temporary / "foreign"
    foreign_dir.mkdir()
    foreign = foreign_dir / "runtime.masm"
    foreign.write_text("runtime:\n  ret\n", encoding="utf-8")
    alias_source = temporary / "alias_dep.mln"
    alias_source.write_text(
        'import { runtime } from "@foreign/runtime.masm";\n'
        "i32 main() { return 0; }\n",
        encoding="utf-8",
    )
    alias_depfile = temporary / "alias_dep.deps"
    subprocess.run(
        [
            repo / "mlc",
            "--alias",
            f"@foreign={foreign_dir}",
            "--depfile",
            alias_depfile,
            alias_source,
            temporary / "alias_dep.masm",
        ],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    alias_lines = alias_depfile.read_text(encoding="utf-8").splitlines()
    expected_alias_lines = ["MYDEPS 1", f"masm\t{foreign.resolve()}"]
    if alias_lines != expected_alias_lines:
        raise SystemExit(
            "unexpected alias dependency manifest:\n"
            f"expected={expected_alias_lines!r}\nactual={alias_lines!r}"
        )

print("[PASS] compiler dependency manifest")
