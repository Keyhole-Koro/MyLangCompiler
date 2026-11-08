#!/usr/bin/env python3
"""free_ast releases everything ast_clone allocates.

tests/support/ast_free_check.c is linked with the AST and free_ast sources
alone, with malloc and free wrapped to count live blocks. It clones and frees a
node of every kind that owns strings or arrays, so a field the clone copies but
free_ast forgets -- a function's link name was one -- is a block left behind.
"""

import os
import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
compiler = os.environ.get("CC", "gcc")
wrapped = "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free"

with tempfile.TemporaryDirectory(prefix="mylang-ast-free-") as temporary:
    binary = Path(temporary) / "ast_free_check"
    build = subprocess.run(
        [compiler, "-Wall", "-Wextra", "-I", str(repo / "inc"), "-o", str(binary),
         str(repo / "tests/support/ast_free_check.c"),
         str(repo / "src/ast/AST.c"),
         str(repo / "src/frontend/parser/parser_free.c"),
         wrapped],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert build.returncode == 0, build.stdout
    result = subprocess.run([str(binary)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    assert result.returncode == 0, "free_ast leaves cloned blocks behind"
