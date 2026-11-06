#!/usr/bin/env python3
"""`mlc --emit-symbols` lists exports with their place and the symbols used.

A use is read from the assembly, so it sees a call the source never spells: an
instance of a generic, and the `eq` behind `==`.
"""

import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]

LIBRARY = """package lib;

import { Eq } from "@std/core/cmp.mln";

export i32 g_value = 1;
i32 g_hidden = 2;

export i32 plain() { return g_hidden; }
i32 hidden() { return 3; }

// Codegen writes `; init array 'lib_plain'` here: a comment, not a use.
i32 commented() { i32 lib_plain[2] = {1, 2}; return lib_plain[0]; }

export T same<T>(T value) { return value; }

export struct Box<T> { T value; };
export T (Box<T> self) get() { return self.value; }
T (Box<T> self) unexported() { return self.value; }

export struct Key { i32 value; };
export i32 (Key self) raw() { return self.value; }
export impl Eq for Key {
    bool (Key self) eq(Key other) { return self.value == other.value; }
}

// Exported from the object for instances elsewhere, but not an export.
i32 reached() { return 4; }
export i32 through<T>(T value) { return reached(); }
"""

MAIN = """import lib from "lib.mln";
import { same, Box, Key } from "lib.mln";

i32 main() {
    Box<i32> box;
    Key a;
    Key b;
    if (a == b) { return 1; }
    return lib.plain() + lib.g_value + same<i32>(1) + box.get();
}
"""

with tempfile.TemporaryDirectory(prefix="mylang-symbols-") as temporary:
    temporary = Path(temporary).resolve()
    library = temporary / "lib.mln"
    main = temporary / "main.mln"
    library.write_text(LIBRARY, encoding="utf-8")
    main.write_text(MAIN, encoding="utf-8")

    def symbols(source):
        path = temporary / (source.stem + ".symbols")
        subprocess.run(
            [repo / "mlc", "--alias", f"@std={repo.parent / 'MyStdLib'}",
             "--emit-symbols", path, source, temporary / (source.stem + ".masm")],
            cwd=temporary, check=True, stdout=subprocess.DEVNULL)
        return path.read_text(encoding="utf-8").splitlines()

    lines = symbols(library)
    if lines[0] != "MYSYMBOLS 1":
        raise SystemExit(f"unexpected header: {lines[0]!r}")
    exports = {line for line in lines if not line.startswith("use\t")}
    expected_exports = {
        "MYSYMBOLS 1",
        f"global\tlib_g_value\t{library}\t5",
        f"function\tlib_plain\t{library}\t8",
        f"template\tsame\t{library}\t14",
        f"template\tBox__get\t{library}\t17",
        f"method\tKey__raw\t{library}\t21",
        f"impl\tKey__eq\t{library}\t23",
        f"template\tthrough\t{library}\t28",
    }
    if exports != expected_exports:
        raise SystemExit(f"unexpected exports:\nexpected={sorted(expected_exports)!r}\n"
                         f"actual={sorted(exports)!r}")
    if "use\tlib_plain\tg_hidden" not in lines:
        raise SystemExit(f"a use of a global is missing: {lines!r}")
    if "use\tcommented\tlib_plain" in lines:
        raise SystemExit(f"a comment counted as a use: {lines!r}")

    lines = symbols(main)
    expected_lines = {
        f"instance\t__mlg_f_4_same_p0_r0_m0_n3_i32\t{library}\t14",
        f"instance\t__mlg_s_3_Box_p0_r0_m0_n3_i32__get\t{library}\t17",
        "use\t__START__\tKey__eq",
        "use\t__START__\tlib_plain",
        "use\t__START__\tlib_g_value",
        "use\t__START__\t__mlg_f_4_same_p0_r0_m0_n3_i32",
        "use\t__START__\t__mlg_s_3_Box_p0_r0_m0_n3_i32__get",
    }
    missing = expected_lines - set(lines)
    if missing:
        raise SystemExit(f"missing from the symbol file: {sorted(missing)!r}\n"
                         f"actual={lines!r}")

    rejected = subprocess.run(
        [repo / "mlc", "--emit-symbols", temporary / "tree.symbols", temporary, temporary / "out"],
        cwd=temporary, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if rejected.returncode == 0 or "single-file" not in rejected.stderr:
        raise SystemExit(f"directory mode should refuse --emit-symbols: {rejected.stderr!r}")

print("[PASS] compiler symbol file")
