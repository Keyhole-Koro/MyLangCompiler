#!/usr/bin/env python3
"""`@safe` vouches for the declaration after it, and for nothing else.

Written before an import, it once marked every function of the imported module
safe, as long as that import was the first to load the module, so a checked file
could call an `.unsafe.mln` function nobody had marked; later it was accepted and
did nothing. An import takes no attribute: the grammar the language server parses
with has none there, and mlc rejects one. The source is written here rather than
kept as a fixture so that the error itself is checked, both by the full check and
by the parse alone, which is what lsp-check asks mlc for.
"""

import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]

LIBRARY = """package rawlib;

export i32 raw() {
    i32 *p = (i32 *)4096;
    return *p;
}
"""

MAIN = """@safe
import rawlib from "rawlib.mln";

i32 main() { return rawlib.raw(); }
"""

with tempfile.TemporaryDirectory(prefix="mylang-safe-scope-") as temporary:
    directory = Path(temporary)
    (directory / "rawlib.unsafe.mln").write_text(LIBRARY, encoding="utf-8")
    (directory / "main.mln").write_text(MAIN, encoding="utf-8")
    for stage in ("--check", "--parse-only"):
        result = subprocess.run([str(repo / "mlc"), stage, "main.mln"], cwd=directory,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert result.returncode != 0, result.stdout
        assert "main.mln:1:1: error: @safe cannot precede an import" in result.stdout, result.stdout
print("check safe scope: ok")
