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
CASES_DIR = REPO_ROOT / "tests" / "token"


@dataclass
class TokenCase:
    name: str
    # text -> required role for some token slicing to that text
    roles: dict = field(default_factory=dict)
    # literal lexemes that must each appear as exactly one full token slice
    # (verifies source-width, e.g. "0xFF" stays 4 wide even though value is 255)
    widths: list = field(default_factory=list)
    status: str | None = None       # required parse status, if set
    min_tokens: int = 0             # require at least this many tokens emitted
    symbols: dict = field(default_factory=dict)   # text -> required outline kind
    not_symbols: list = field(default_factory=list)  # texts that must NOT be symbols

    @property
    def source(self) -> str:
        """The .mln fixture this case feeds to the tool, from tests/token/<name>.mln."""
        return (CASES_DIR / f"{self.name}.mln").read_text()


CASES = [
    TokenCase(
        name="function_def_and_params",
        roles={"add": "function", "a": "parameter", "b": "parameter", "Point": "type"},
    ),
    TokenCase(
        name="simple_call_is_function",
        roles={"main": "function", "foo": "function"},
    ),
    TokenCase(
        name="member_access_is_property_not_call",
        roles={"x": "property", "bar": "property"},
    ),
    TokenCase(
        name="qualified_call_on_import_is_namespace_and_function",
        roles={"mmu": "namespace", "map_page": "function"},
    ),
    TokenCase(
        name="package_is_namespace",
        roles={"gfx": "namespace"},
    ),
    TokenCase(
        name="struct_and_typedef",
        roles={"Point": "struct", "MyInt": "type"},
    ),
    TokenCase(
        name="enum_name_is_enum",
        roles={"Color": "enum"},
    ),
    TokenCase(
        name="result_generic_qualified_case",
        roles={
            "Result": "result", "MmuError": "enum", "Ok": "resultVariant",
            "Err": "resultVariant", "AllocFailed": "enumMember",
        },
        status="ok",
    ),
    TokenCase(
        name="case_statement_expression",
        status="ok",
    ),
    TokenCase(
        name="nested_qualified_payload_pattern",
        status="ok",
    ),
    TokenCase(
        name="import_is_namespace",
        roles={"math": "namespace"},
    ),
    TokenCase(
        name="func_proto_is_function",
        roles={"puts": "function", "c": "parameter"},
    ),
    TokenCase(
        name="typedef_struct_alias_is_struct",
        roles={"Vec": "struct"},
    ),
    TokenCase(
        name="mut_param_is_parameter",
        roles={"a": "parameter"},
    ),
    TokenCase(
        # i8 is not a lexer keyword; it gets `type` from the grammar (baseType).
        name="user_and_alias_types_via_grammar",
        roles={"i8": "type", "Point": "type", "mk": "function"},
    ),
    TokenCase(
        name="hex_number_source_width",
        widths=["0xFF"],
    ),
    TokenCase(
        name="string_escape_source_width",
        widths=['"hi\\n"'],
    ),
    TokenCase(
        name="binary_and_char_source_width",
        widths=["0b1010", "'x'"],
    ),
    TokenCase(
        name="char_escape_source_width",
        widths=["'\\n'"],
    ),
    TokenCase(
        # tokens must still be emitted when the parse fails (LSP needs the
        # lexical layer mid-edit).
        name="tokens_present_on_error",
        status="error",
        min_tokens=5,
    ),
    TokenCase(
        # outline = top-level decls only; locals, struct fields and call sites
        # must not appear.
        name="symbols_top_level_only",
        symbols={"g": "variable", "Point": "struct", "Color": "enum",
                 "MyInt": "type", "add": "function"},
        not_symbols=["fx", "local", "foo", "p", "RED"],
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

    if case.symbols or case.not_symbols:
        lines = case.source.splitlines()
        syms = {}
        for s in result.get("symbols", []):
            text = lines[s[0]][s[1]:s[1] + s[2]] if 0 <= s[0] < len(lines) else ""
            syms.setdefault(text, set()).add(s[3])
        for text, want in case.symbols.items():
            if want not in syms.get(text, set()):
                return False, f"{case.name}: symbol {text!r} -> {syms.get(text)!r}, expected {want!r}"
        for text in case.not_symbols:
            if text in syms:
                return False, f"{case.name}: {text!r} must not be an outline symbol, got {syms[text]!r}"

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
