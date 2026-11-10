#!/usr/bin/env python3
"""`mlc --check` and `--parse-only` report errors, print nothing else and write nothing.
`--check` runs the code generator too, for the errors only it finds."""

import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
mlc = repo / "mlc"

SOURCES = {
    "clean.mln": "i32 main() { return 0; }\n",
    "semantic.mln": "i32 main() { return nope; }\n",
    "syntax.mln": "i32 main( {\n}\n",
    # Only the code generator refuses this: a struct passed by value has to
    # come from a variable, a field or a dereference.
    "codegen.mln": "struct Pair { i32 a; i32 b; };\n"
                   "Pair make() { return Pair { a: 1, b: 2 }; }\n"
                   "i32 take(Pair p) { return p.a; }\n"
                   "i32 main() { bool c = true; return take(c ? make() : make()); }\n",
}

# source -> what each flag returns and the diagnostic it prints.
EXPECTED = {
    ("--check", "clean.mln"): (0, None),
    ("--parse-only", "clean.mln"): (0, None),
    ("--check", "semantic.mln"): (1, "undefined identifier 'nope'"),
    ("--parse-only", "semantic.mln"): (0, None),
    ("--check", "syntax.mln"): (1, "syntax.mln:1:"),
    ("--parse-only", "syntax.mln"): (1, "syntax.mln:1:"),
    ("--check", "codegen.mln"): (1, "bind it to one first"),
    ("--parse-only", "codegen.mln"): (0, None),
}


def run(*arguments, cwd):
    return subprocess.run([str(mlc), *arguments], cwd=cwd, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


with tempfile.TemporaryDirectory() as work:
    directory = Path(work)
    for name, text in SOURCES.items():
        (directory / name).write_text(text, encoding="utf-8")
    written = sorted(path.name for path in directory.iterdir())

    for (flag, name), (code, message) in EXPECTED.items():
        result = run(flag, name, cwd=directory)
        assert result.returncode == code, (flag, name, result.returncode, result.stderr)
        assert result.stdout == "", (flag, name, result.stdout)
        if message:
            assert message in result.stderr, (flag, name, result.stderr)
        else:
            assert result.stderr == "", (flag, name, result.stderr)

    # Nothing to write, so anything that names an output is a mistake.
    for extra in (["out.masm"], ["--depfile", "out.d"], ["--emit-symbols", "out.sym"]):
        result = run("--check", "clean.mln", *extra, cwd=directory)
        assert result.returncode == 1 and "write nothing" in result.stderr, (extra, result.stderr)

    result = run("--check", ".", cwd=directory)
    assert result.returncode == 1 and "not a directory" in result.stderr, result.stderr

    assert sorted(path.name for path in directory.iterdir()) == written

print("check stages: ok")
