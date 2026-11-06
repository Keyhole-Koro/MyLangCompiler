#!/usr/bin/env python3
"""A generic's body is checked under the file it was written in.

An instance of an imported generic must report its diagnostics against the
template's own file and line, and follow that file's safety profile: raw
pointer indexing in a checked library is an error at the library's line, and
the same code in an `.unsafe.mln` library compiles.
"""

import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]

LIBRARY = """export struct Buf<T> {
    T *data;
    i32 len;
};

@safe
export T (Buf<T> *b) first() {
    T *data = b->data;
    return data[0];
}
"""

# `storage` is a global: keeping `&storage[0]` in the struct is not itself a
# raw-pointer operation, so every W0003 left comes from the template's body.
MAIN = """import {{ Buf }} from "{lib}";

i32 storage[2];

i32 main() {{
    storage[0] = 5;
    Buf<i32> b = Buf<i32> {{ data: &storage[0], len: 2 }};
    return b.first();
}}
"""


def compile_with(directory: Path, library_name: str) -> str:
    library = directory / library_name
    library.write_text(LIBRARY, encoding="utf-8")
    main = directory / f"main_{library.stem.replace('.', '_')}.mln"
    main.write_text(MAIN.format(lib=library_name), encoding="utf-8")
    result = subprocess.run(
        [repo / "mlc", main, directory / f"{main.stem}.masm"],
        cwd=directory,
        capture_output=True,
        text=True,
    )
    return result.stderr


with tempfile.TemporaryDirectory(prefix="mylang-generic-origin-") as temporary:
    directory = Path(temporary)

    checked = compile_with(directory, "buf.mln")
    errors = [line for line in checked.splitlines() if "E0701" in line]
    expected_prefix = f"{(directory / 'buf.mln').resolve()}:"
    if not errors or not all(line.startswith(expected_prefix) for line in errors):
        raise SystemExit(
            "expected every E0701 to name buf.mln, got:\n" + checked
        )

    unsafe = compile_with(directory, "buf.unsafe.mln")
    if "E0701" in unsafe:
        raise SystemExit(
            "an instance of a generic from an .unsafe.mln file must compile:\n" + unsafe
        )

print("[PASS] generic instances report against their template's file")
