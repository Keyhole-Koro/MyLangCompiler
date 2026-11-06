#!/usr/bin/env python3
"""A model trace must describe the text the compiler really reads."""

import json
import os
import subprocess
import tempfile
from pathlib import Path


repo = Path(__file__).resolve().parents[1]
grammars = repo.parent / "MySyntaxEngine/tests/fixtures/grammars"
grammar = f"{grammars / 'mylang_lsp.grammar'},{grammars / 'mlx.grammar'}"
table = repo / "mylang-syntax-check-lsp.table"
checker = repo / "mylang-syntax-check"


def fail(message):
    raise SystemExit(f"model trace: {message}")


def query(process, source):
    data = source.encode("utf-8")
    process.stdin.write(f"model {len(data)}\n".encode("ascii") + data + b"\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline()), json.loads(process.stdout.readline())


def expansion_of(path):
    with tempfile.TemporaryDirectory(prefix="mylang-model-") as temporary:
        dump = Path(temporary) / "expansion.mln"
        subprocess.run(
            [checker, path, grammar, table],
            cwd=repo,
            check=True,
            stdout=subprocess.DEVNULL,
            env={**os.environ, "MLC_DUMP_MODEL": str(dump)},
        )
        return dump.read_text(encoding="utf-8")


def generated_from(trace, source, needle):
    """The source word behind the generated line that contains `needle`."""
    lines = trace["generated"].split("\n")
    index = next(i for i, line in enumerate(lines) if needle in line)
    line, column, length = trace["origins"][index]
    return line, source.split("\n")[line][column:column + length]


def check_valid(process):
    for name in ("ui", "more"):
        path = repo / f"tests/succeed/model/{name}.model.mln"
        source = path.read_text(encoding="utf-8")
        trace, parsed = query(process, source)
        if trace["errors"] or parsed["status"] != "ok":
            fail(f"{name}: a valid model did not check: {trace['errors']} {parsed['diagnostics']}")
        if not expansion_of(path).endswith(trace["generated"]):
            fail(f"{name}: the trace generated other code than the compiler reads")
        if len(trace["origins"]) != trace["generated"].count("\n"):
            fail(f"{name}: not one origin per generated line")
        if trace["generatedLine"] != source.count("\n"):
            fail(f"{name}: the generated code does not start after the file")
        for line, column, length in trace["origins"]:
            word = source.split("\n")[line][column:column + length]
            if length and not word.isidentifier():
                fail(f"{name}: an origin is not a word: {word!r}")

    source = (repo / "tests/succeed/model/ui.model.mln").read_text(encoding="utf-8")
    trace, _parsed = query(process, source)
    relation = source.split("\n").index("Node   has   many Node as children / parent, ordered;")
    column = next(
        i for i, line in enumerate(source.split("\n")) if line.startswith("    i32 owner;")
    )
    for needle, expected in [
        ("new_node()", (source.split("\n").index("entity Node   max 64 {"), "Node")),
        ("children_add(Node member)", (relation, "children")),
        ("(Node member) parent()", (relation, "parent")),
        ("set_focus(Node target)", (relation + 1, "focus")),
        ("(Node x) owner()", (column, "owner")),
        ("node_by_owner(i32 value)", (column, "owner")),
    ]:
        if generated_from(trace, source, needle) != expected:
            fail(f"{needle}: came from {generated_from(trace, source, needle)}, not {expected}")


def check_errors(process):
    source = (
        "package p;\n"
        "entity A max 4 {\n"
        "    i32 x;\n"
        "    ;\n"
        "}\n"
        "entity B max 4 { i32 y; }\n"
        "B has many C as cs;\n"
        "B knows one B as next;\n"
    )
    trace, _parsed = query(process, source)
    found = [(line, message) for line, _column, _length, message in trace["errors"]]
    expected = [(3, "malformed column in entity 'A'"), (6, "unknown entity 'C'")]
    if found != expected:
        fail(f"errors: {found}")
    if "next" in trace["generated"]:
        fail("a model with an error still generated code")
    if process.poll() is not None:
        fail("an error stopped the checker")


def main():
    process = subprocess.Popen(
        [checker, "--stdio", grammar, table],
        cwd=repo,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        if process.stdout.readline().strip() != b"ready":
            fail("the checker did not start")
        check_valid(process)
        check_errors(process)
    finally:
        process.terminate()
        process.wait()


if __name__ == "__main__":
    main()
