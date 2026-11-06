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


# --error-trace calls into @std/debug/error_trace.mln without the source
# importing it: the manifest must name the module so the build links it. A
# build without the flag emits no trace calls at all.
with tempfile.TemporaryDirectory(prefix="mylang-trace-depfile-") as temporary:
    temporary = Path(temporary)
    traced = temporary / "traced.mln"
    traced.write_text(
        'import { Result } from "@std/core/result.mln";\n'
        "Result<i32, i32> fail() { return Err(1); }\n"
        "i32 main() { return 0; }\n",
        encoding="utf-8",
    )
    trace_module = (repo.parent / "MyStdLib/debug/error_trace.unsafe.mln").resolve()
    for flags, wants_trace in (([], False), (["--error-trace"], True)):
        output = temporary / "traced.masm"
        depfile = temporary / "traced.deps"
        subprocess.run(
            [repo / "mlc", *flags, "--alias", f"@std={repo.parent / 'MyStdLib'}",
             "--depfile", depfile, traced, output],
            cwd=repo,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        lists_module = f"mln\t{trace_module}" in depfile.read_text(encoding="utf-8").splitlines()
        calls_trace = "error_trace_note" in output.read_text(encoding="utf-8")
        if lists_module != wants_trace or calls_trace != wants_trace:
            raise SystemExit(
                f"error trace flags={flags!r}: manifest lists module={lists_module}, "
                f"code calls error_trace_note={calls_trace}; expected {wants_trace}"
            )

print("[PASS] compiler dependency manifest")
