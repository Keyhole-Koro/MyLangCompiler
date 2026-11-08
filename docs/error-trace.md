# Error return trace

`?` returns an error to the caller and keeps only the value. With
`mlc --error-trace`, the compiler also records where the error was created
and every `?` it went through, so the receiver can show its path:

```
error trace:
  ssd.mln:52 ssd_wait_for_completion (created)
  ssd.mln:88 ssd_write_block
  fs.mln:977 fs_write (SsdError -> FsError)
```

Without the flag nothing is inserted and the generated code is unchanged.

## What is recorded

| site | recorded as |
| --- | --- |
| `return Err(...)` written in the source | origin: starts a new trace |
| the return a `?` expands to | one more hop, with `(Source -> Target)` when it converted through `From` |

Each site is a static string `file.mln:line function`, where `function` is
the emitted symbol name. The call happens after the returned value is
stored, just before deferred blocks run and the function returns.

An error handled with `case` instead of propagated ends nothing explicitly:
its trace stays readable until the next origin replaces it.

## Reading the trace

The recording calls go to `error_trace.note` in MyStdLib's
`debug/error_trace.mln`, which keeps the last trace (32 sites; later hops are
counted as dropped):

```mylang
import error_trace from "@std/debug/error_trace.mln";

char text[512];
error_trace.format(&text[0], 512);   // "error trace:\n  site (created)\n  ..."
i32 n = error_trace.depth();          // site(0) is the origin
```

A source compiled with the flag does not need to import the module: when
codegen emits a recording call, the dependency manifest (`--depfile`) lists
`@std/debug/error_trace.mln`, so the build links it.

There is one trace per image. A MyOS user process has its own; the kernel's
tasks share one.

## Building MyComputer with traces

`qa/runners/build_toolchain.py --error-trace` or `MYLANG_ERROR_TRACE=1`
(`MYLANG_ERROR_TRACE=1 make build`) compiles every source with the flag.
MyOS's filesystem syscall boundary then prints the trace of an error it
returns to user space into the guest log.

## Implementation

| stage | file | work |
| --- | --- | --- |
| parse | `parser_stmt.c` | marks `return Err(...)` as an origin |
| parse | `parser_expr_postfix.c` | marks the return of a `?` expansion as a hop |
| lower | `parser_payload_try.c` | names the From conversion |
| lower | `parser_payload_enum.c` | keeps the marks when a return is rebuilt |
| codegen | `codegen_stmt.c` | `emit_error_trace_note` when the flag is on |
| driver | `driver_compile.c` | adds the trace module to the manifest |

Tests: `tests/succeed/trace/errorTrace.mln` (e2e, built with the flag) and
`tests/check_depfile.py` (manifest, and no recording without the flag).
