#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = REPO_ROOT.parents[1]
TESTS_DIR = REPO_ROOT / "tests"

CC_PATH = REPO_ROOT / "mlc"
ASM_PATH = PROJECT_ROOT / "toolchain" / "MyAssembler" / "build" / "myas"
LINKER_PATH = PROJECT_ROOT / "toolchain" / "MyLinker" / "mllinker"
EMU_PATH = PROJECT_ROOT / "runtime" / "MyEmulator" / "target" / "release" / "myemu"
EMU_TIMEOUT_SEC = float(os.environ.get("EMU_TIMEOUT_SEC", "8"))

TESTCASES = [
    ("genericInstantiation", ["succeed/generic/instantiation.mln"], "R1", 45),
    ("genericNestedStruct", ["succeed/generic/nestedStruct.mln"], "R1", 57),
    ("genericRecursive", ["succeed/generic/recursive.mln"], "R1", 15),
    ("genericImportedTemplates", ["succeed/generic/imported_templates_main.mln", "succeed/generic/imported_templates_lib.mln"], "R1", 13),
    ("genericKernelContainers", ["succeed/generic/kernel_containers.mln"], "R1", 63),
    ("genericModuleIsolation", ["succeed/generic/modules_main.mln", "succeed/generic/modules_one.mln", "succeed/generic/modules_two.mln"], "R1", 33),
    ("simpleFunc", ["succeed/function/simpleFunc.mln"], "R1", 15),
    ("simpleCondition", ["succeed/control/simpleCondition.mln"], "R1", 328),
    ("simpleFor", ["succeed/control/simpleFor.mln"], "R1", 5),
    ("simplePointer", ["succeed/pointer/simplePointer.mln"], "R1", 14),
    ("simpleBinop", ["succeed/expr/simpleBinop.mln"], "R1", 3),
    ("simpleWhile", ["succeed/control/simpleWhile.mln"], "R1", 15),
    ("complexWhile", ["succeed/control/complexWhile.mln"], "R1", 16),
    ("simpleChar", ["succeed/expr/simpleChar.mln"], "R1", 72),
    ("stringEscape", ["succeed/expr/stringEscape.mln"], "R1", 10),
    ("intWidth32", ["succeed/expr/intWidth32.mln"], "R1", 20),
    ("uintWidthSmall", ["succeed/expr/uintWidthSmall.mln"], "R1", 69),
    ("simpleStruct", ["succeed/struct/simpleStruct.mln"], "R1", 10),
    ("arrayInit", ["succeed/array/arrayInit.mln"], "R1", 106),
    ("multiArray", ["succeed/array/multiArray.mln"], "R1", 6),
    ("arraySizeof", ["succeed/array/arraySizeof.mln"], "R1", 24),
    ("testDoWhile", ["succeed/control/testDoWhile.mln"], "R1", 10),
    ("testBitwise", ["succeed/expr/testBitwise.mln"], "R1", 29),
    ("testOps", ["succeed/expr/testOps.mln"], "R1", 10),
    ("testTernary", ["succeed/expr/testTernary.mln"], "R1", 8),
    ("testTypedef", ["succeed/expr/testTypedef.mln"], "R1", 1),
    ("longProgram", ["succeed/struct/longProgram.mln"], "R1", 77),
    ("enum_basic", ["succeed/expr/enum_basic.mln"], "R1", 60),
    ("complex_ops", ["succeed/expr/complex_ops.mln"], "R1", 188),
    ("condGlobalSum", ["succeed/expr/condGlobalSum.mln"], "R1", 88),
    ("hexBinLiteral", ["succeed/expr/hexBinLiteral.mln"], "R1", 541),
    ("largeImmediate", ["succeed/expr/largeImmediate.mln"], "R1", 42),
    ("structAssign", ["succeed/struct/structAssign.mln"], "R1", 381),
    ("payloadResult", ["succeed/enum/payloadResult.mln"], "R1", 172),
    ("payloadOption", ["succeed/enum/payloadOption.mln"], "R1", 137),
    ("byvalParamAndReturn", ["succeed/struct/byval/paramAndReturn.mln"], "R1", 140),
    ("argNestedCall", ["succeed/function/argNestedCall.mln"], "R1", 706),
    ("multiInclude", ["succeed/package/multiInclude.mln", "succeed/package/multiInclude_part1.mln", "succeed/package/multiInclude_part2.mln"], "R1", 11),
    ("multiInclude_complex", ["succeed/package/multiInclude_complex.mln", "succeed/package/multiInclude_midA.mln", "succeed/package/multiInclude_midB.mln", "succeed/package/multiInclude_shared.mln"], "R1", 21),
    ("importFrom", ["succeed/package/importFrom_main.mln", "succeed/package/importFrom_helper.mln"], "R1", 11),
    ("testStmtExpr", ["succeed/expr/testStmtExpr.mln"], "R1", 5),
    ("testCaseExpr", ["succeed/case/testCaseExpr.mln"], "R1", 30),
    ("testCaseStructArrow", ["succeed/case/testCaseStructArrow.mln"], "R1", 42),
    ("testCaseComplex", ["succeed/case/testCaseComplex.mln"], "R1", 400),
    ("testCaseExprRef", ["succeed/case/testCaseExprRef.mln"], "R1", 100),
    ("nestedCaseArrow", ["succeed/case/nestedCaseArrow.mln"], "R1", 10),
    ("packageSample", ["succeed/package/pkg_main.mln", "succeed/package/pkg_math.mln"], "R1", 20),
    ("pkgVariadic", ["succeed/package/pkgVariadic_main.mln", "succeed/package/pkgVariadic_lib.mln"], "R1", 133),
    ("functionLiteral", ["succeed/function/functionLiteral.mln"], "R1", 10),
    ("arrowFunctionLiteral", ["succeed/function/arrowFunctionLiteral.mln"], "R1", 13),
    ("localFunctionLiteral", ["succeed/function/localFunctionLiteral.mln"], "R1", 10),
    ("nestedFunctionLiteral", ["succeed/function/nestedFunctionLiteral.mln"], "R1", 6),
    ("globalInit", ["succeed/global/globalInit.mln"], "R1", 42),
    ("testGlobalScalar", ["succeed/global/testGlobalScalar.mln"], "R1", 105),
    ("globalUninit", ["succeed/global/globalUninit.mln"], "R1", 83),
    ("phase2_refBorrow", ["succeed/semantic/phase2_refBorrow.mln"], "R1", 7),
    ("phase2_refMut", ["succeed/semantic/phase2_refMut.mln"], "R1", 9),
    ("phase2_unchecked", ["succeed/semantic/phase2_unchecked.mln"], "R1", 9),
    ("phase2_refParam", ["succeed/semantic/phase2_refParam.mln"], "R1", 11),
    ("phase2_refMutParam", ["succeed/semantic/phase2_refMutParam.mln"], "R1", 9),
    ("phase2_uncheckedNested", ["succeed/semantic/phase2_uncheckedNested.mln"], "R1", 12),
    ("refImportLongLocals", ["succeed/semantic/refImportLongLocals_main.mln", "succeed/semantic/refImportLongLocals_helper.mln"], "R1", 49),
    ("phase_restParam", ["succeed/semantic/phase_restParam.mln"], "R1", 0),
]

VERBOSE = False
results = {}


def colored(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"


def status_line(label, message, color="36"):
    print(colored(f"[{label}]", color), message)


def fmt_hex(v: int) -> str:
    return f"0x{v:x}"


def has_failure(outcomes):
    return any(msg.startswith("FAIL:") for msg in outcomes)


def run_step(command, description, base, timeout=None, out_dir=None, outcomes=None, cwd=None):
    log_root = out_dir if out_dir else Path.cwd()
    log_root.mkdir(parents=True, exist_ok=True)
    log_file_path = log_root / f"{base}.log"
    if outcomes is None:
        outcomes = results.setdefault(base, [])
    try:
        if VERBOSE:
            status_line("RUN", description)
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"\n--- {description} ---\nCommand: {' '.join(command)}\n")
            result = subprocess.run(
                command, check=True, capture_output=True, text=True, timeout=timeout, cwd=cwd
            )
            log_file.write(f"STDOUT:\n{result.stdout}\n")
            log_file.write(f"STDERR:\n{result.stderr}\n")
        return result.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"\n[TIMEOUT] {description}\n")
            log_file.write(f"Partial STDOUT:\n{exc.stdout}\n")
            log_file.write(f"Partial STDERR:\n{exc.stderr}\n")
        outcomes.append(f"FAIL: {description} timed out ({timeout}s)")
        outcomes.append(f"LOG: {log_file_path}")
        return None
    except subprocess.CalledProcessError as exc:
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"\n[FAILED] {description}\n")
            log_file.write(f"Return Code: {exc.returncode}\n")
            log_file.write(f"STDOUT:\n{exc.stdout}\n")
            log_file.write(f"STDERR:\n{exc.stderr}\n")
        outcomes.append(f"FAIL: {description}")
        outcomes.append(f"LOG: {log_file_path}")
        return None


def build_all():
    status_line("SETUP", "build toolchain")
    build_commands = [
        (["make", "-C", str(REPO_ROOT), "all"], "Build MyLangCompiler"),
        (["make", "-C", str(PROJECT_ROOT / 'toolchain' / 'MyAssembler'), "all"], "Build MyAssembler"),
        (["make", "-C", str(PROJECT_ROOT / 'toolchain' / 'MyLinker'), "all"], "Build MyLinker"),
        (["make", "-C", str(PROJECT_ROOT / 'runtime' / 'MyEmulator'), "all"], "Build MyEmulator"),
    ]
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(subprocess.run, cmd, check=False, capture_output=True, text=True) for cmd, _ in build_commands]
        for (cmd, desc), future in zip(build_commands, futures):
            result = future.result()
            if result.returncode != 0:
                if desc == "Build MyEmulator" and "cargo: not found" in result.stderr and EMU_PATH.exists():
                    status_line("INFO", f"cargo not found; using existing emulator: {EMU_PATH}", "33")
                    continue
                sys.stderr.write(result.stdout)
                sys.stderr.write(result.stderr)
                status_line("FATAL", f"{desc} failed", "31")
                raise SystemExit(1)


def run_test(basename, sources, reg, expected, temp_root):
    test_dir = temp_root / basename
    test_dir.mkdir(parents=True, exist_ok=True)
    obj_paths = []
    bin_path = test_dir / f"{basename}.mbin"
    outcomes = []

    for src in sources:
        src_path = TESTS_DIR / src
        stem = src_path.stem
        asm_path = test_dir / f"{basename}__{stem}.masm"
        bin_prelink_path = test_dir / f"{basename}__{stem}.prelink.mbin"
        obj_path = test_dir / f"{basename}__{stem}.mobj"

        if run_step([str(CC_PATH), str(src_path), str(asm_path)], f"MLN to MASM: {src}", basename, out_dir=test_dir, outcomes=outcomes, cwd=test_dir) is None:
            return basename, outcomes
        if run_step([str(ASM_PATH), str(asm_path), str(bin_prelink_path), "--obj", str(obj_path)], f"MASM to MOBJ: {src}", basename, out_dir=test_dir, outcomes=outcomes, cwd=test_dir) is None:
            return basename, outcomes
        obj_paths.append(str(obj_path))

    if run_step([str(LINKER_PATH), str(bin_path)] + obj_paths, f"Link MOBJ to MBIN: {basename}", basename, out_dir=test_dir, outcomes=outcomes, cwd=test_dir) is None:
        return basename, outcomes

    output = run_step([str(EMU_PATH), "-i", str(bin_path), "--headless", "--reg", reg], f"Run Emulator: {basename}.mbin", basename, timeout=EMU_TIMEOUT_SEC, out_dir=test_dir, outcomes=outcomes, cwd=test_dir)
    if output is None:
        outcomes.append("FAIL: Emulator execution failed")
        return basename, outcomes

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        outcomes.append("FAIL: No output from emulator")
        return basename, outcomes

    try:
        actual = int(lines[-1], 0)
        if actual == expected:
            outcomes.append(f"PASS: {reg} = {fmt_hex(actual)} (expected)")
        else:
            outcomes.append(f"FAIL: {reg} = {fmt_hex(actual)}, expected {fmt_hex(expected)}")
    except Exception as exc:
        outcomes.append(f"FAIL: Failed to parse reg value '{lines[-1]}' ({exc})")
    return basename, outcomes


def run_tests(selected=None):
    global results
    results = {}
    to_run = TESTCASES
    if selected:
        to_run = [t for t in TESTCASES if t[0] == selected]
        if not to_run:
            print(f"[ERROR] Test case '{selected}' not found.")
            raise SystemExit(1)
    status_line("RUN", f"{len(to_run)} case(s)")

    temp_root = Path(tempfile.mkdtemp(prefix="mylang-integration-tests-"))
    try:
        max_workers = min(len(to_run), max(1, os.cpu_count() or 4), 8)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(run_test, *t, temp_root): t[0] for t in to_run}
            for future in as_completed(future_map):
                name, outcomes = future.result()
                results[name] = outcomes
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    passed = 0
    failed = 0
    failures = []
    for name in sorted(results):
        if has_failure(results[name]):
            failed += 1
            failures.append((name, results[name]))
        else:
            passed += 1
            summary = next((x for x in results[name] if x.startswith("PASS:")), "PASS")
            status_line("PASS", f"{name} {summary.removeprefix('PASS: ').strip()}", "32")
    for name, outcomes in failures:
        summary = next((x for x in outcomes if x.startswith("FAIL:")), "FAIL")
        status_line("FAIL", f"{name} {summary.removeprefix('FAIL: ').strip()}", "31")
        if not VERBOSE:
            for outcome in outcomes:
                if outcome.startswith("PASS:"):
                    continue
                print(f"  {outcome}")
    status_line("DONE", f"Summary: {passed} passed, {failed} failed", "32" if failed == 0 else "33")
    if failures:
        print("Failed cases:", ", ".join(name for name, _ in failures))
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MyLangCompiler integration tests.")
    parser.add_argument("test", nargs="?", help="Optional test case name or source filename")
    parser.add_argument("--verbose", action="store_true", help="Show step-by-step command progress")
    args = parser.parse_args()
    VERBOSE = args.verbose
    selected = None
    if args.test:
        base, ext = os.path.splitext(args.test)
        selected = base if ext else args.test
    build_all()
    run_tests(selected)
