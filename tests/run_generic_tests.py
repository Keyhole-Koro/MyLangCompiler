#!/usr/bin/env python3
"""Exercise specialization through the compiler's public CLI, without toolchain dependencies."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "tests" / "generic_cases"

# (case name -> tests/generic_cases/<name>.mln, expected compile error substring
# or None for an expected-successful compile)
CASES = [
    ("wrong_call_type", "argument type mismatch"),
    ("wrong_body_type", "return type mismatch"),
    ("wrong_call_arity", "error[E0101]"),
    ("prototype_only", "requires a definition in this module"),
    ("ordinary_type_arguments", "generic declaration is not available"),
    ("recursive_value", "infinite size"),
    ("recursive_value_array", "infinite size"),
    ("expanding_function", "instantiation limit exceeded"),
    ("expanding_type", "instantiation limit exceeded"),
    ("reference_wrapping", "cannot wrap a reference type argument"),
    ("reserved_symbol", "prefix is reserved"),
    ("unused_invalid_body", None),
    ("concrete_return_lookahead", None),
    ("array_and_cast", None),
    ("literal_lowering", None),
    ("generic_case", None),
    ("global_struct", None),
    ("enum_payload", None),
    ("alias_of_nested_generic", None),
    ("generic_receiver_method", None),
    ("generic_receiver_method_importer", None),
]


def run():
    with tempfile.TemporaryDirectory(prefix="mylang-generics-") as directory:
        temp = Path(directory)
        for name, error in CASES:
            source = CASES_DIR / f"{name}.mln"
            result = subprocess.run([str(ROOT / "mlc"), str(source), str(temp / "out.s")],
                                    capture_output=True, text=True, timeout=10)
            if error is None:
                assert result.returncode == 0, (name, result.stderr)
            else:
                assert result.returncode > 0 and error in result.stderr, (name, result.stderr)
            print(f"[PASS] {name}")

        # Repeated requests share code; qualifiers and type/value namespaces do not collide.
        source = CASES_DIR / "cache.mln"
        assembly = temp / "cache.s"
        command = [str(ROOT / "mlc"), str(source), str(assembly)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        first = assembly.read_text()
        assert "export __mlg_" not in first, "specializations must remain object-local"
        labels = re.findall(r"^__mlg_f_[^:\n]+:", first, re.M)
        assert len(labels) == len(set(labels)) == 4, labels
        subprocess.run(command, capture_output=True, check=True, timeout=10)
        assert assembly.read_text() == first, "specialization names changed between compilations"
        print("[PASS] cache, qualifiers, namespaces, deterministic code generation")

        # Imported exported templates are instantiated by the importing module.
        # generic_importer.mln imports generic_library.mln by its own relative
        # path, so both have to stay siblings under CASES_DIR -- not copied
        # into `temp` -- for that import to resolve.
        importer = CASES_DIR / "generic_importer.mln"
        assembly = temp / "generic_importer.s"
        result = subprocess.run([str(ROOT / "mlc"), str(importer), str(assembly)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        generated = assembly.read_text()
        assert "__mlg_f_" in generated, generated
        assert "import twice" not in generated, generated
        print("[PASS] imported exported generic templates")

        imported_method = CASES_DIR / "generic_receiver_method_importer.mln"
        assembly = temp / "generic_receiver_method_importer.s"
        result = subprocess.run([str(ROOT / "mlc"), str(imported_method), str(assembly)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert "__get:" in assembly.read_text(), "imported generic method was not specialized"
        print("[PASS] imported generic receiver methods")


if __name__ == "__main__":
    run()
