#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SYNTAX_CHECK_PATH = REPO_ROOT / "mylang-syntax-check"
CASES_DIR = REPO_ROOT / "tests" / "syntax_check"


@dataclass
class SyntaxCase:
    name: str
    status: str
    message: str | None = None
    line: int | None = None
    character: int | None = None
    token_roles: dict[int, str] | None = None

    @property
    def source(self) -> str:
        """The .mln fixture this case feeds to the tool, from tests/syntax_check/<name>.mln."""
        return (CASES_DIR / f"{self.name}.mln").read_text()


CASES = [
    SyntaxCase(
        name="missing_initializer_expression",
        status="error",
        message="Expected expression before ';'.",
        line=0,
        character=21,
    ),
    SyntaxCase(
        name="missing_if_condition",
        status="error",
        message="Expected expression before ')'.",
        line=0,
        character=17,
    ),
    SyntaxCase(
        name="expression_precedence_ok",
        status="ok",
    ),
    SyntaxCase(
        name="parenthesized_binary_after_identifier_star_ok",
        status="ok",
    ),
    SyntaxCase(
        name="nested_if_else_ok",
        status="ok",
    ),
    SyntaxCase(
        name="primitive_cast_ok",
        status="ok",
    ),
    SyntaxCase(
        name="hex_number_ok",
        status="ok",
    ),
    SyntaxCase(
        name="binary_number_ok",
        status="ok",
    ),
    SyntaxCase(
        name="deref_assignment_ok",
        status="ok",
    ),
    SyntaxCase(
        name="named_pointer_cast_ok",
        status="ok",
    ),
    SyntaxCase(
        name="named_struct_literal_ok",
        status="ok",
    ),
    SyntaxCase(
        name="postfix_increment_identifier_role",
        status="ok",
        token_roles={1: "function", 7: "variable", 11: "variable"},
    ),
    SyntaxCase(
        name="function_call_identifier_role",
        status="ok",
        token_roles={1: "function", 5: "function"},
    ),
    SyntaxCase(
        name="arrow_function_literal_ok",
        status="ok",
    ),
    SyntaxCase(
        name="empty_arrow_function_literal_ok",
        status="ok",
    ),
    SyntaxCase(
        name="export_function_ok",
        status="ok",
    ),
    SyntaxCase(
        name="export_mut_global_ok",
        status="ok",
    ),
    SyntaxCase(
        name="export_typedef_struct_ok",
        status="ok",
    ),
    SyntaxCase(
        name="enum_without_semicolon_ok",
        status="ok",
    ),
    SyntaxCase(
        name="generic_declarations_and_call_ok",
        status="ok",
        token_roles={0: "type", 1: "function", 23: "function"},
    ),
    SyntaxCase(
        name="nested_generic_type_ok",
        status="ok",
    ),
    SyntaxCase(
        name="imported_generic_containers_ok",
        status="ok",
        token_roles={12: "function", 22: "type", 28: "function"},
    ),
    SyntaxCase(
        name="generic_angles_preserve_relational_and_shift_ok",
        status="ok",
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
    command = [str(SYNTAX_CHECK_PATH), "--stdio"]
    grammar_path = os.environ.get("MYLANG_SYNTAX_GRAMMAR")
    cache_path = os.environ.get("MYLANG_SYNTAX_CACHE")
    if grammar_path:
        command.append(grammar_path)
        if cache_path:
            command.append(cache_path)
    proc = subprocess.Popen(
        command,
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

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
        line = proc.stdout.readline().decode("utf-8")
        results.append(json.loads(line))

    proc.stdin.close()
    proc.wait(timeout=5)
    return results


def check_case(case: SyntaxCase, result: dict) -> tuple[bool, str]:
    if result.get("status") != case.status:
        return False, f"{case.name}: status {result.get('status')!r}, expected {case.status!r}"

    diagnostics = result.get("diagnostics", [])
    if case.status == "ok":
        if diagnostics:
            return False, f"{case.name}: expected no diagnostics, got {diagnostics!r}"
        if case.token_roles is not None:
            tokens = result.get("tokens", [])
            for index, role in case.token_roles.items():
                if index >= len(tokens):
                    return False, f"{case.name}: missing token at index {index}"
                token = tokens[index]
                actual = token[4] if len(token) > 4 else None
                if actual != role:
                    return False, (
                        f"{case.name}: token {index} role {actual!r}, "
                        f"expected {role!r}"
                    )
        return True, f"{case.name}: ok"

    if not diagnostics:
        return False, f"{case.name}: expected diagnostic"

    diagnostic = diagnostics[0]
    if case.message is not None and diagnostic.get("message") != case.message:
        return False, (
            f"{case.name}: message {diagnostic.get('message')!r}, "
            f"expected {case.message!r}"
        )
    if case.line is not None and diagnostic.get("line") != case.line:
        return False, f"{case.name}: line {diagnostic.get('line')!r}, expected {case.line!r}"
    if case.character is not None and diagnostic.get("character") != case.character:
        return False, (
            f"{case.name}: character {diagnostic.get('character')!r}, "
            f"expected {case.character!r}"
        )

    return True, f"{case.name}: diagnostic matched"


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
