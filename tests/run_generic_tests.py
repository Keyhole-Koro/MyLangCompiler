#!/usr/bin/env python3
"""Exercise specialization through the compiler's public CLI, without toolchain dependencies."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

CASES = [
    ("wrong_call_type", 'T id<T>(T x) { return x; } i32 main() { return id<i32>("bad"); }', "argument type mismatch"),
    ("wrong_body_type", 'T bad<T>(T x) { return "bad"; } i32 main() { return bad<i32>(1); }', "return type mismatch"),
    ("wrong_call_arity", 'T id<T>(T x) { return x; } i32 main() { return id<i32>(); }', "error[E0101]"),
    ("prototype_only", 'T id<T>(T x); i32 main() { return id<i32>(1); }', "requires a definition in this module"),
    ("ordinary_type_arguments", 'struct Box { i32 x; }; i32 main() { Box<i32> x; return 0; }', "generic declaration is not available"),
    ("recursive_value", 'struct Box<T> { Box<T> x; }; i32 main() { Box<i32> x; return 0; }', "infinite size"),
    ("recursive_value_array", 'struct Box<T> { Box<T> x[2]; }; i32 main() { Box<i32> x; return 0; }', "infinite size"),
    ("expanding_function", 'i32 grow<T>(i32 n) { return grow<T *>(n); } i32 main() { return grow<i32>(0); }', "instantiation limit exceeded"),
    ("expanding_type", 'struct Box<T> { Box<T *> *next; }; i32 main() { Box<i32> x; return 0; }', "instantiation limit exceeded"),
    ("reference_wrapping", 'T *id<T>(T *p) { return p; } i32 main() { return id<ref i32>(0); }', "cannot wrap a reference type argument"),
    ("reserved_symbol", 'T id<T>(T x) { return x; } i32 __mlg_user() { return 0; }', "prefix is reserved"),
    ("unused_invalid_body", 'T unused<T>(T x) { return unknown(x); } i32 main() { return 0; }', None),
    ("concrete_return_lookahead", 'struct Box<T> { T x; }; Box<i32> *pass(Box<i32> *p) { return p; } i32 main() { Box<i32> x; return 0; }', None),
    ("array_and_cast", 'T first<T>(T a[2]) { T copy[2]; copy[0] = (T)a[0]; return copy[0]; } i32 main() { i32 a[2] = {4, 5}; return first<i32>(a); }', None),
    ("literal_lowering", 'T run<T>(T x) { T f = (i32 y) => { return y + 1; }; return f(x); } i32 main() { return run<i32>(4); }', None),
    ("generic_case", 'T choose<T>(T x) { return case x of { 0 -> (T)1; _ -> x; }; } i32 main() { return choose<i32>(0); }', None),
    ("global_struct", 'struct Box<T> { T x; }; Box<i32> box; i32 main() { box.x = 7; return box.x; }', None),
    ("enum_payload", 'enum Color { RED, GREEN }; struct Box<T> { T x; }; i32 main() { Box<Color> box; box.x = GREEN; return box.x; }', None),
    ("alias_of_nested_generic", 'struct Box<T> { T x; }; typedef Box<i32> IntBox; struct Wrapper<T> { T x; }; i32 main() { Wrapper<IntBox> box; box.x.x = 7; return box.x.x; }', None),
]


def run():
    with tempfile.TemporaryDirectory(prefix="mylang-generics-") as directory:
        temp = Path(directory)
        for name, source, error in CASES:
            path = temp / f"{name}.mln"
            path.write_text(source)
            result = subprocess.run([str(ROOT / "mlc"), str(path), str(temp / "out.s")],
                                    capture_output=True, text=True, timeout=10)
            if error is None:
                assert result.returncode == 0, (name, result.stderr)
            else:
                assert result.returncode > 0 and error in result.stderr, (name, result.stderr)
            print(f"[PASS] {name}")

        # Repeated requests share code; qualifiers and type/value namespaces do not collide.
        path = temp / "cache.mln"
        path.write_text('struct Same<T> { T x; }; T Same<T>(T x) { return x; } '
                        'i32 main() { Same<i32> box; i32 a = 3; '
                        'i32 *p = Same<i32 *>(&a); const i32 *q = Same<const i32 *>(&a); '
                        'return Same<i32>(1) + Same<i32>(2) + Same<char>((char)3); }')
        assembly = temp / "cache.s"
        command = [str(ROOT / "mlc"), str(path), str(assembly)]
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
        library = temp / "generic_library.mln"
        library.write_text('export T twice<T>(T value) { return value + value; } '
                           'export struct Pair<T> { T first; T second; };')
        importer = temp / "generic_importer.mln"
        importer.write_text('import { twice, Pair } from "generic_library.mln"; '
                            'i32 main() { Pair<i32> pair; pair.first = twice<i32>(6); '
                            'pair.second = 1; return pair.first + pair.second; }')
        assembly = temp / "generic_importer.s"
        result = subprocess.run([str(ROOT / "mlc"), str(importer), str(assembly)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        generated = assembly.read_text()
        assert "__mlg_f_" in generated, generated
        assert "import twice" not in generated, generated
        print("[PASS] imported exported generic templates")


if __name__ == "__main__":
    run()
