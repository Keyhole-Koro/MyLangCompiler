#!/usr/bin/env python3
"""What mlc says about a namespace line and about files that share a namespace.

The fail/namespace fixtures only have to be rejected; this checks that each is
rejected for its own reason, and that an ambiguous name names both files.
"""

import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
tests = repo / "tests"

expected = {
    "fail/namespace/ambiguousImport_fail.mln": [
        "'../../succeed/namespace/clash_a.mln' and '../../succeed/namespace/clash_b.mln' "
        "both export 'value' in namespace 'clash', so 'clash.value' is ambiguous",
    ],
    "fail/namespace/ambiguousOwnExport_fail.mln": [
        "this file and '../../succeed/namespace/clash_b.mln' both export 'value' "
        "in namespace 'clash'",
    ],
    "fail/namespace/nested_fail.mln": ["namespaces do not nest"],
    "fail/namespace/twoNamespaces_fail.mln": ["a file declares one namespace"],
    "fail/package/importUnknownName_fail.mln": [
        "declares namespace 'lib' and nothing named 'other_name'; "
        "a namespace is imported by its own name",
    ],
}

with tempfile.TemporaryDirectory(prefix="mylang-namespaces-") as temporary:
    output = Path(temporary) / "out.masm"
    for fixture, texts in expected.items():
        result = subprocess.run([repo / "mlc", tests / fixture, output],
                                capture_output=True, text=True)
        said = result.stdout + result.stderr
        if result.returncode == 0:
            raise SystemExit(f"{fixture}: compiled, expected a rejection")
        for text in texts:
            if text not in said:
                raise SystemExit(f"{fixture}: expected {text!r} in:\n{said}")

print("namespace lines and shared namespaces are diagnosed")
