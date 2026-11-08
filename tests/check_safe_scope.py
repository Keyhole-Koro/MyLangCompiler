#!/usr/bin/env python3
"""`@safe` vouches for the declaration after it, and for nothing else.

Written before an import, it once marked every function of the imported module
safe, as long as that import was the first to load the module, so a checked file
could call an `.unsafe.mln` function nobody had marked. The source is written
here rather than kept as a fixture: the grammar has no attribute before an
import, so the language server rejects the line the compiler still accepts.
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
    result = subprocess.run([str(repo / "mlc"), "--check", "main.mln"], cwd=directory,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert result.returncode != 0, result.stdout
    assert "calling 'rawlib_raw', which is not @safe" in result.stdout, result.stdout
print("check safe scope: ok")
