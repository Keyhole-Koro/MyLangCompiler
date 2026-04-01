#!/usr/bin/env python3
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"
INPUT_DIR = TESTS_DIR / "inputs"
MLC_PATH = REPO_ROOT / "mlc"

CASES = [
    "phase1_simpleFunc",
    "phase1_simpleStruct",
    "phase1_testTernary",
    "phase1_testStmtExpr",
]


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def ensure_built() -> None:
    result = run(["make", "-C", str(REPO_ROOT), "all"])
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(1)


def check_case(case_name: str, out_root: Path) -> tuple[bool, str]:
    src = INPUT_DIR / f"{case_name}.mln"
    case_dir = out_root / case_name
    case_dir.mkdir(parents=True, exist_ok=True)
    asm = case_dir / f"{case_name}.masm"
    result = run([str(MLC_PATH), str(src), str(asm)], cwd=case_dir)

    if result.returncode != 0:
        return False, (
            f"{case_name}: compiler failed\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    expected_markers = [
        "AST parsing completed.",
        "Semantic analysis completed.",
        "Code generation completed.",
    ]
    for marker in expected_markers:
        if marker not in result.stdout:
            return False, (
                f"{case_name}: missing marker '{marker}'\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            )

    token_sidecar = case_dir / f"{case_name}_tokens.txt"
    ast_sidecar = case_dir / f"{case_name}_ast.txt"
    expected_files = [asm, token_sidecar, ast_sidecar]
    missing = [str(path) for path in expected_files if not path.exists()]
    if missing:
        return False, f"{case_name}: missing output files: {', '.join(missing)}"

    return True, f"{case_name}: semantic phase smoke test passed"


if __name__ == "__main__":
    ensure_built()

    requested = sys.argv[1:]
    cases = requested if requested else CASES
    unknown = [case for case in cases if case not in CASES]
    if unknown:
        sys.stderr.write(f"Unknown semantic test case(s): {', '.join(unknown)}\n")
        raise SystemExit(2)

    temp_root = Path(tempfile.mkdtemp(prefix="mylang-semantic-tests-"))
    failed = []
    try:
        for case_name in cases:
            ok, message = check_case(case_name, temp_root)
            prefix = "PASS" if ok else "FAIL"
            print(f"[{prefix}] {message}")
            if not ok:
                failed.append(case_name)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    raise SystemExit(1 if failed else 0)
