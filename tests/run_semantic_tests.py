#!/usr/bin/env python3
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"
MLC_PATH = REPO_ROOT / "mlc"

PASS_CASES = {
    "genericInstantiation": "succeed/generic/instantiation.mln",
    "genericNestedStruct": "succeed/generic/nestedStruct.mln",
    "genericRecursive": "succeed/generic/recursive.mln",
    "genericDeclarations": "succeed/semantic/genericDeclarations.mln",
    "phase1_simpleFunc": "succeed/semantic/phase1_simpleFunc.mln",
    "phase1_simpleStruct": "succeed/semantic/phase1_simpleStruct.mln",
    "namedStructLiteral": "succeed/struct/namedStructLiteral.mln",
    "phase1_testTernary": "succeed/semantic/phase1_testTernary.mln",
    "phase1_testStmtExpr": "succeed/semantic/phase1_testStmtExpr.mln",
    "phase2_refBorrow": "succeed/semantic/phase2_refBorrow.mln",
    "phase2_refMut": "succeed/semantic/phase2_refMut.mln",
    "phase2_unchecked": "succeed/semantic/phase2_unchecked.mln",
    "phase2_refParam": "succeed/semantic/phase2_refParam.mln",
    "phase2_refMutParam": "succeed/semantic/phase2_refMutParam.mln",
    "phase2_uncheckedNested": "succeed/semantic/phase2_uncheckedNested.mln",
    "phase2_doWhileControl": "succeed/semantic/phase2_doWhileControl.mln",
    "phase3_branchMoveIsolation": "succeed/semantic/phase3_branchMoveIsolation.mln",
    "phase_restParam": "succeed/semantic/phase_restParam.mln",
    "phase_printfRestBuiltin": "succeed/semantic/phase_printfRestBuiltin.mln",
    "phase_enumBasic": "succeed/semantic/phase_enumBasic.mln",
    "phase_enumAutoValues": "succeed/semantic/phase_enumAutoValues.mln",
    "phase_enumExplicitBase": "succeed/semantic/phase_enumExplicitBase.mln",
    "phase_enumMultipleTypes": "succeed/semantic/phase_enumMultipleTypes.mln",
    "dom_localFunctionWins": "succeed/dom/localFunctionWins.dom.mln",
}

WARN_CASES = {
    "phase_unreachableAfterReturn_warn": (
        "warn/semantic/phase_unreachableAfterReturn_warn.mln",
        [
            ":3:5: warning[W0001]: unreachable statement",
            "[range 3:5-3:14]",
        ],
    ),
}

FAIL_CASES = {
    "byvalArgNonAddressable_fail": (
        "fail/struct/byvalArgNonAddressable_fail.mln",
        "takes a struct or array by value, and only a variable, a field of one, or a dereference can be passed that way",
        None,
    ),
    "byvalReturnNonAddressable_fail": (
        "fail/struct/byvalReturnNonAddressable_fail.mln",
        "returning a struct or array from a non-lvalue is not supported yet",
        None,
    ),
    "byvalVariadicReturn_fail": (
        "fail/struct/byvalVariadicReturn_fail.mln",
        "cannot both be variadic and return a struct or array by value",
        None,
    ),
    "payloadEnumNonExhaustive_fail": (
        "fail/semantic/payloadEnumNonExhaustive_fail.mln",
        "does not cover one variant of 'Result': Err",
        None,
    ),
    "payloadEnumWrongEnum_fail": (
        "fail/semantic/payloadEnumWrongEnum_fail.mln",
        "'Some' is a variant of 'Opt', not of 'Result'",
        None,
    ),
    "payloadEnumDuplicateArm_fail": (
        "fail/semantic/payloadEnumDuplicateArm_fail.mln",
        "'Ok' is matched more than once",
        None,
    ),
    "structUnknownMember_fail": (
        "fail/semantic/structUnknownMember_fail.mln",
        "'P' has no member named 'zzz'",
        None,
    ),
    "structMemberTypeMismatch_fail": (
        "fail/semantic/structMemberTypeMismatch_fail.mln",
        "assignment type mismatch: expected i32",
        None,
    ),
    "structLiteralUnknownField_fail": (
        "fail/semantic/structLiteralUnknownField_fail.mln",
        "'Point' has no member named 'y'",
        None,
    ),
    "structLiteralFieldType_fail": (
        "fail/semantic/structLiteralFieldType_fail.mln",
        "struct literal field type mismatch: expected i32",
        None,
    ),
    "payloadEnumBadPosition_fail": (
        "fail/semantic/payloadEnumBadPosition_fail.mln",
        "constructs a payload enum, which can only appear as the whole right-hand side",
        None,
    ),
    "payloadEnumArity_fail": (
        "fail/semantic/payloadEnumArity_fail.mln",
        "carries one payload, but 2 were given",
        None,
    ),
    "payloadEnumTarget_fail": (
        "fail/semantic/payloadEnumTarget_fail.mln",
        "can only be matched on a variable or a field of one",
        None,
    ),
    "genericTypeArgCountMismatch_fail": (
        "fail/semantic/genericTypeArgCountMismatch_fail.mln",
        "error[E0501]: generic type 'Box' expects 1 type argument but got 2",
        None,
    ),
    "genericFunctionArgsRequired_fail": (
        "fail/semantic/genericFunctionArgsRequired_fail.mln",
        "error[E0502]: generic function 'identity' requires type arguments",
        None,
    ),
    "genericDuplicateTypeParam_fail": (
        "fail/semantic/genericDuplicateTypeParam_fail.mln",
        "duplicate type parameter",
        None,
    ),
    "genericEmptyTypeParams_fail": (
        "fail/semantic/genericEmptyTypeParams_fail.mln",
        "generic declaration requires at least one type parameter",
        None,
    ),
    "genericTrailingTypeParamComma_fail": (
        "fail/semantic/genericTrailingTypeParamComma_fail.mln",
        "trailing comma in type parameter list",
        None,
    ),
    "genericTrailingTypeArgComma_fail": (
        "fail/semantic/genericTrailingTypeArgComma_fail.mln",
        "trailing comma in type argument list",
        None,
    ),
    "genericArgsRequired_fail": (
        "fail/semantic/genericArgsRequired_fail.mln",
        "error[E0502]: generic type 'Box' requires type arguments",
        None,
    ),
    "genericArgCountMismatch_fail": (
        "fail/semantic/genericArgCountMismatch_fail.mln",
        "error[E0501]: generic function 'identity' expects 1 type argument but got 2",
        None,
    ),
    "phase3_useAfterMove_fail": (
        "fail/semantic/phase3_useAfterMove_fail.mln",
        "use of moved value 'a'",
    ),
    "phase3_useAfterCallMove_fail": (
        "fail/semantic/phase3_useAfterCallMove_fail.mln",
        "use of moved value 'a'",
    ),
    "phase3_branchMoveMerge_fail": (
        "fail/semantic/phase3_branchMoveMerge_fail.mln",
        "use of moved value 'a'",
    ),
    "phase3_branchElseMoveMerge_fail": (
        "fail/semantic/phase3_branchElseMoveMerge_fail.mln",
        "use of moved value 'a'",
    ),
    "phase3_moveWhileBorrowed_fail": (
        "fail/semantic/phase3_moveWhileBorrowed_fail.mln",
        "cannot move 'a' while it is borrowed",
    ),
    "phase3_sharedThenMutBorrow_fail": (
        "fail/semantic/phase3_sharedThenMutBorrow_fail.mln",
        "cannot mutably borrow 'x' while it is already borrowed",
    ),
    "phase3_mutThenSharedBorrow_fail": (
        "fail/semantic/phase3_mutThenSharedBorrow_fail.mln",
        "cannot borrow 'x' while it is mutably borrowed",
    ),
    "phase3_returnLocalBorrow_fail": (
        "fail/semantic/phase3_returnLocalBorrow_fail.mln",
        "cannot return reference to local 'x'",
    ),
    "phase3_returnLocalRefBinding_fail": (
        "fail/semantic/phase3_returnLocalRefBinding_fail.mln",
        "cannot return reference to local 'x'",
    ),
    "phase_restNotLast_fail": (
        "fail/semantic/phase_restNotLast_fail.mln",
        "rest parameter must be the final parameter",
        None,
    ),
    "phase_enumNonLiteral_fail": (
        "fail/semantic/phase_enumNonLiteral_fail.mln",
        "enum member value must be a number literal",
        None,
    ),
    "phase_undefinedIdentifier_fail": (
        "fail/semantic/phase_undefinedIdentifier_fail.mln",
        [
            ":2:13: error[E0001]: undefined identifier 'missing'",
            "[range 2:13-2:20]",
        ],
    ),
    "phase_undefinedFunction_fail": (
        "fail/semantic/phase_undefinedFunction_fail.mln",
        ":2:12: error[E0002]: undefined function 'missing_func'",
    ),
    "phase_callArgCount_fail": (
        "fail/semantic/phase_callArgCount_fail.mln",
        ":6:12: error[E0101]: function 'add' expects 2 arguments but got 1",
    ),
    "phase_callArgTypeMismatch_fail": (
        "fail/semantic/phase_callArgTypeMismatch_fail.mln",
        ":7:16: error[E0102]: function argument type mismatch: parameter 1 of 'add' expected i32, got char*",
    ),
    "phase_callReturnTypePropagation_fail": (
        "fail/semantic/phase_callReturnTypePropagation_fail.mln",
        ":10:19: error[E0301]: initializer type mismatch: expected char*, got i32",
    ),
    "phase_returnMissingValue_fail": (
        "fail/semantic/phase_returnMissingValue_fail.mln",
        ":2:5: error[E0201]: function 'value' must return a value",
    ),
    "phase_voidReturnValue_fail": (
        "fail/semantic/phase_voidReturnValue_fail.mln",
        ":2:5: error[E0201]: void function 'log' should not return a value",
    ),
    "phase_returnTypeMismatch_fail": (
        "fail/semantic/phase_returnTypeMismatch_fail.mln",
        ":2:12: error[E0201]: return type mismatch: expected i32, got char[]",
    ),
    "phase_typeInitMismatch_fail": (
        "fail/semantic/phase_typeInitMismatch_fail.mln",
        ":2:13: error[E0301]: initializer type mismatch: expected i32, got char[]",
    ),
    "phase_typeAssignMismatch_fail": (
        "fail/semantic/phase_typeAssignMismatch_fail.mln",
        ":3:9: error[E0301]: assignment type mismatch: expected i32, got char[]",
    ),
    "phase_typeBinaryMismatch_fail": (
        "fail/semantic/phase_typeBinaryMismatch_fail.mln",
        ":3:12: error[E0302]: invalid operands to '+': char* and char*",
    ),
    "phase_typeConditionMismatch_fail": (
        "fail/semantic/phase_typeConditionMismatch_fail.mln",
        ":3:9: error[E0303]: condition must be integer-like, pointer, or reference, got char[3]",
    ),
    "phase_multipleDiagnostics_fail": (
        "fail/semantic/phase_multipleDiagnostics_fail.mln",
        [
            ":2:13: error[E0001]: undefined identifier 'first_missing'",
            ":2:29: error[E0001]: undefined identifier 'second_missing'",
        ],
    ),
    # DOM lowering: a tag is a function, a property is that function's
    # parameter of the same name, a child is an append_child call. What the
    # lowering produces when it succeeds is covered end to end by
    # system/MyKernel/tests/dom/dom_lowering.dom.test.mln in MyComputer.
    "dom_unknownTag_fail": (
        "fail/dom/unknownTag_fail.dom.mln",
        "no function named 'Column' is in scope",
        None,  # rejected while lowering, before semantic analysis runs
    ),
    "dom_unknownProperty_fail": (
        "fail/dom/unknownProperty_fail.dom.mln",
        "has no property 'foo'",
        None,  # rejected while lowering, before semantic analysis runs
    ),
    "dom_missingProperty_fail": (
        "fail/dom/missingProperty_fail.dom.mln",
        "is missing property 'y'",
        None,  # rejected while lowering, before semantic analysis runs
    ),
    "dom_duplicateProperty_fail": (
        "fail/dom/duplicateProperty_fail.dom.mln",
        "sets 'text' twice",
        None,  # rejected while lowering, before semantic analysis runs
    ),
    "dom_childNeedsAppendChild_fail": (
        "fail/dom/childNeedsAppendChild_fail.dom.mln",
        "function named 'append_child'",
        None,  # rejected while lowering, before semantic analysis runs
    ),
}


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def ensure_built() -> None:
    result = run(["make", "-C", str(REPO_ROOT), "all"])
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(1)


def case_source(rel_path: str) -> Path:
    return TESTS_DIR / rel_path


def check_case(case_name: str, rel_path: str, out_root: Path) -> tuple[bool, str]:
    src = case_source(rel_path)
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


def check_fail_case(case_name: str, rel_path: str, expected: str, failure_marker: str | None, out_root: Path) -> tuple[bool, str]:
    src = case_source(rel_path)
    case_dir = out_root / case_name
    case_dir.mkdir(parents=True, exist_ok=True)
    asm = case_dir / f"{case_name}.masm"
    result = run([str(MLC_PATH), str(src), str(asm)], cwd=case_dir)

    if result.returncode == 0:
        return False, (
            f"{case_name}: compiler unexpectedly succeeded\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    expected_items = expected if isinstance(expected, list) else [expected]
    missing_expected = [item for item in expected_items if item not in result.stderr]
    if missing_expected:
        return False, (
            f"{case_name}: missing expected semantic error(s) {missing_expected!r}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    if failure_marker and failure_marker not in result.stderr:
        return False, (
            f"{case_name}: missing failure marker '{failure_marker}'\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    return True, f"{case_name}: semantic failure test passed"


def check_warn_case(case_name: str, rel_path: str, expected: str, out_root: Path) -> tuple[bool, str]:
    src = case_source(rel_path)
    case_dir = out_root / case_name
    case_dir.mkdir(parents=True, exist_ok=True)
    asm = case_dir / f"{case_name}.masm"
    result = run([str(MLC_PATH), str(src), str(asm)], cwd=case_dir)

    if result.returncode != 0:
        return False, (
            f"{case_name}: compiler failed without --Werror\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    expected_items = expected if isinstance(expected, list) else [expected]
    missing_expected = [item for item in expected_items if item not in result.stderr]
    if missing_expected:
        return False, (
            f"{case_name}: missing expected warning(s) {missing_expected!r}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    werror_asm = case_dir / f"{case_name}.werror.masm"
    werror = run([str(MLC_PATH), "--Werror", str(src), str(werror_asm)], cwd=case_dir)
    if werror.returncode == 0:
        return False, (
            f"{case_name}: compiler unexpectedly succeeded with --Werror\n"
            f"STDOUT:\n{werror.stdout}\n"
            f"STDERR:\n{werror.stderr}"
        )

    missing_werror = [item for item in expected_items if item not in werror.stderr]
    if missing_werror:
        return False, (
            f"{case_name}: missing expected --Werror warning(s) {missing_werror!r}\n"
            f"STDOUT:\n{werror.stdout}\n"
            f"STDERR:\n{werror.stderr}"
        )

    return True, f"{case_name}: semantic warning test passed"


if __name__ == "__main__":
    ensure_built()

    all_cases = list(PASS_CASES.keys()) + list(WARN_CASES.keys()) + list(FAIL_CASES.keys())
    requested = sys.argv[1:]
    cases = requested if requested else all_cases
    unknown = [case for case in cases if case not in all_cases]
    if unknown:
        sys.stderr.write(f"Unknown semantic test case(s): {', '.join(unknown)}\n")
        raise SystemExit(2)

    temp_root = Path(tempfile.mkdtemp(prefix="mylang-semantic-tests-"))
    failed = []
    try:
        for case_name in cases:
            if case_name in WARN_CASES:
                rel_path, expected = WARN_CASES[case_name]
                ok, message = check_warn_case(case_name, rel_path, expected, temp_root)
            elif case_name in FAIL_CASES:
                data = FAIL_CASES[case_name]
                if len(data) == 2:
                    rel_path, expected = data
                    failure_marker = "Semantic analysis failed."
                else:
                    rel_path, expected, failure_marker = data
                ok, message = check_fail_case(case_name, rel_path, expected, failure_marker, temp_root)
            else:
                ok, message = check_case(case_name, PASS_CASES[case_name], temp_root)
            prefix = "PASS" if ok else "FAIL"
            print(f"[{prefix}] {message}")
            if not ok:
                failed.append(case_name)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    raise SystemExit(1 if failed else 0)
