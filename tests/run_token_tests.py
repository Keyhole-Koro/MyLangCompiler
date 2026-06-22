#!/usr/bin/env python3
"""Golden tests for the token/role stream emitted by `mylang-syntax-check`.

Guards the data contract the language server depends on:
  - source-width fidelity: a token's [col, col+length] slices to the exact
    source lexeme (hex->dec, escapes and quotes do not corrupt the span);
  - grammar-derived roles: identifiers get function/type/struct/namespace/
    parameter/property from the LR1 parse.

Mirrors run_syntax_check_tests.py: drives the binary over --stdio and asserts
the JSON it returns. Uses the default grammar (mylang_lsp.grammar), same as the
language server.
"""
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SYNTAX_CHECK_PATH = REPO_ROOT / "mylang-syntax-check"


@dataclass
class TokenCase:
    name: str
    source: str
    # text -> required role for some token slicing to that text
    roles: dict = field(default_factory=dict)
    # literal lexemes that must each appear as exactly one full token slice
    # (verifies source-width, e.g. "0xFF" stays 4 wide even though value is 255)
    widths: list = field(default_factory=list)
    status: str | None = None       # required parse status, if set
    min_tokens: int = 0             # require at least this many tokens emitted


CASES = [
    TokenCase(
        name="function_def_and_params",
        source="i32 add(i32 a, Point b) { return a + b; }\n",
        roles={"add": "function", "a": "parameter", "b": "parameter", "Point": "type"},
    ),
    TokenCase(
        name="simple_call_is_function",
        source="i32 main() { return foo(b); }\n",
        roles={"main": "function", "foo": "function"},
    ),
    TokenCase(
        name="member_access_is_property_not_call",
        source="i32 main() { return a.x + obj.bar(); }\n",
        roles={"x": "property", "bar": "property"},
    ),
    TokenCase(
        name="package_is_namespace",
        source="package gfx;\n",
        roles={"gfx": "namespace"},
    ),
    TokenCase(
        name="struct_and_typedef",
        source="struct Point { i32 x; };\ntypedef i32 MyInt;\n",
        roles={"Point": "struct", "MyInt": "type"},
    ),
    TokenCase(
        name="enum_name_is_struct",
        source="enum Color { RED, GREEN };\n",
        roles={"Color": "struct"},
    ),
    TokenCase(
        name="import_is_namespace",
        source='import math from "m";\n',
        roles={"math": "namespace"},
    ),
    TokenCase(
        name="func_proto_is_function",
        source="extern i32 puts(i32 c);\n",
        roles={"puts": "function", "c": "parameter"},
    ),
    TokenCase(
        name="typedef_struct_alias_is_struct",
        source="typedef struct { i32 x; } Vec;\n",
        roles={"Vec": "struct"},
    ),
    TokenCase(
        name="mut_param_is_parameter",
        source="i32 f(mut i32 a) { return a; }\n",
        roles={"a": "parameter"},
    ),
    TokenCase(
        # i8 is not a lexer keyword; it gets `type` from the grammar (baseType).
        name="user_and_alias_types_via_grammar",
        source="i8 a = 0; Point p = mk();\n",
        roles={"i8": "type", "Point": "type", "mk": "function"},
    ),
    TokenCase(
        name="hex_number_source_width",
        source="i32 x = 0xFF;\n",
        widths=["0xFF"],
    ),
    TokenCase(
        name="string_escape_source_width",
        source='char s = "hi\\n";\n',
        widths=['"hi\\n"'],
    ),
    TokenCase(
        name="binary_and_char_source_width",
        source="i32 m() { i32 x = 0b1010; char c = 'x'; }\n",
        widths=["0b1010", "'x'"],
    ),
    TokenCase(
        name="char_escape_source_width",
        source="char c = '\\n';\n",
        widths=["'\\n'"],
    ),
    TokenCase(
        # tokens must still be emitted when the parse fails (LSP needs the
        # lexical layer mid-edit).
        name="tokens_present_on_error",
        source="i32 add(i32 a) { i32 x = ; }\n",
        status="error",
        min_tokens=5,
    ),
]


def ensure_built() -> None:
    if os.environ.get("MYLANG_SKIP_SYNTAX_CHECK_BUILD") == "1":
        return
    result = subprocess.run(
        ["make", "-C", str(REPO_ROOT), "syntax-check"],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(1)


def run_cases() -> list[dict]:
    proc = subprocess.Popen(
        [str(SYNTAX_CHECK_PATH), "--stdio"],
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None

    ready = proc.stdout.readline().decode("utf-8").strip()
    if ready != "ready":
        stderr = proc.stderr.read().decode("utf-8") if proc.stderr else ""
        proc.kill()
        raise RuntimeError(f"syntax-check did not become ready: {ready}\n{stderr}")

    results = []
    for case in CASES:
        data = case.source.encode("utf-8")
        proc.stdin.write(f"content {len(data)}\n".encode("ascii"))
        proc.stdin.write(data)
        proc.stdin.write(b"\n")
        proc.stdin.flush()
        results.append(json.loads(proc.stdout.readline().decode("utf-8")))

    proc.stdin.close()
    proc.wait(timeout=5)
    return results


def sliced_tokens(case: TokenCase, result: dict) -> list[tuple[str, str | None]]:
    """Return (sliced_text, role) for every token in the result."""
    lines = case.source.splitlines()
    out = []
    for tok in result.get("tokens", []):
        line, col, length = tok[0], tok[1], tok[2]
        role = tok[4] if len(tok) > 4 else None
        text = lines[line][col:col + length] if 0 <= line < len(lines) else ""
        out.append((text, role))
    return out


def check_case(case: TokenCase, result: dict) -> tuple[bool, str]:
    tokens = sliced_tokens(case, result)

    if case.status is not None and result.get("status") != case.status:
        return False, f"{case.name}: status {result.get('status')!r}, expected {case.status!r}"
    if len(tokens) < case.min_tokens:
        return False, f"{case.name}: {len(tokens)} tokens, expected >= {case.min_tokens}"

    for text, want_role in case.roles.items():
        got = [r for (t, r) in tokens if t == text]
        if not got:
            return False, f"{case.name}: no token slices to {text!r}"
        if want_role not in got:
            return False, f"{case.name}: {text!r} role {got!r}, expected {want_role!r}"

    for literal in case.widths:
        if literal not in [t for (t, _) in tokens]:
            return False, (
                f"{case.name}: {literal!r} did not appear as a full token slice "
                f"(width regression?); tokens={[t for (t, _) in tokens]!r}"
            )

    return True, f"{case.name}: ok"


if __name__ == "__main__":
    ensure_built()
    results = run_cases()
    failed = []
    for case, result in zip(CASES, results):
        ok, message = check_case(case, result)
        print(f"[{'PASS' if ok else 'FAIL'}] {message}")
        if not ok:
            failed.append(case.name)
    raise SystemExit(1 if failed else 0)
