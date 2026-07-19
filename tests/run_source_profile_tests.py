#!/usr/bin/env python3
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MLC = ROOT / "mlc"


def run_case(name: str, source: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        input_path = tmp_path / name
        output_path = tmp_path / "out.masm"
        input_path.write_text(source, encoding="utf-8")
        return subprocess.run(
            [str(MLC), str(input_path), str(output_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


def expect_success(name: str, expected_profile: str) -> None:
    result = run_case(name, "i32 main() { return 0; }\n")
    assert result.returncode == 0, (name, result.stdout, result.stderr)
    assert expected_profile in result.stdout, (name, result.stdout)


def expect_failure(name: str, expected_error: str, source: str = "i32 main() { return 0; }\n") -> None:
    result = run_case(name, source)
    assert result.returncode != 0, (name, result.stdout, result.stderr)
    combined = result.stdout + result.stderr
    assert expected_error in combined, (name, expected_error, combined)


def main() -> None:
    expect_success("main.mln", "syntax=core, safety=default")
    expect_success("main.safe.mln", "syntax=core, safety=safe")
    expect_success("page.dom.mln", "syntax=dom, safety=default")
    expect_success("page.dom.safe.mln", "syntax=dom, safety=safe")

    expect_failure("page.mlx", "expected a canonical .mln filename")
    expect_failure("page.web.mln", "unknown source modifier 'web'")
    expect_failure("page.dom.dom.mln", "duplicate source modifier 'dom'")
    expect_failure("page.safe.safe.mln", "duplicate source modifier 'safe'")
    expect_failure("page.safe.dom.mln", "must precede semantic policy modifiers")
    expect_failure("page..mln", "empty modifier")
    expect_failure(
        "page.mln",
        "DOM syntax requires a canonical .dom.mln filename",
        "DomNode* build() { return <Window/>; }\n",
    )

    print("source profile tests passed")


if __name__ == "__main__":
    main()
