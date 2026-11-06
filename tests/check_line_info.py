#!/usr/bin/env python3
"""`--line-info` says where code came from without changing the code.

The directives must be the only difference from a plain compile. A statement
gets a `.loc`, a function its `.func`, and a generic instance names the file
its template was written in, not the file that instantiated it.
"""

import re
import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]

LIBRARY = """export struct Box<T> {
    T value;
};

@safe
export T (Box<T> *b) get() {
    return b->value;
}
"""

MAIN = """import {{ Box }} from "{lib}";

i32 scale(i32 a, i32 b) {{
    i32 r = a * b;
    return r;
}}

i32 main() {{
    Box<i32> box = Box<i32> {{ value: 6 }};
    return scale(box.get(), 7);
}}
"""


def compile_with(directory: Path, name: str, *flags: str) -> list[str]:
    output = directory / name
    subprocess.run(
        [repo / "mlc", *flags, directory / "main.mln", output],
        cwd=directory,
        check=True,
        capture_output=True,
        text=True,
    )
    return output.read_text(encoding="utf-8").splitlines()


def is_directive(line: str) -> bool:
    return re.match(r"\s*\.(func|loc|cost)\b", line) is not None


with tempfile.TemporaryDirectory(prefix="mylang-line-info-") as temporary:
    directory = Path(temporary)
    (directory / "box.unsafe.mln").write_text(LIBRARY, encoding="utf-8")
    (directory / "main.mln").write_text(MAIN.format(lib="box.unsafe.mln"), encoding="utf-8")

    plain = compile_with(directory, "plain.masm")
    marked = compile_with(directory, "marked.masm", "--line-info")

    if [line for line in marked if not is_directive(line)] != plain:
        raise SystemExit("--line-info changed something besides its directives")
    if any(is_directive(line) for line in plain):
        raise SystemExit("a plain compile emitted debug directives")

    text = "\n".join(marked)
    main_path = (directory / "main.mln").resolve()
    if f'.func "scale" "{main_path}"' not in text:
        raise SystemExit("expected a .func for `scale` naming main.mln:\n" + text)
    if not re.search(r"\.loc 4\n(.*\n)*?\s*\.cost \"arith\"", text):
        raise SystemExit("expected the multiply on line 4 inside an arith region:\n" + text)
    instances = [line for line in marked if ".func" in line and "get" in line]
    if not instances or not all("box.unsafe.mln" in line for line in instances):
        raise SystemExit("a generic instance must name its template's file:\n" + "\n".join(instances))

print("line info: ok")
