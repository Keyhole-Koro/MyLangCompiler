# MyLang Debugger Design

## Status

This document proposes a debugger for programs produced by MyLangCompiler and MyAssembler. The debugger is intentionally designed as a separate runtime component instead of embedding execution logic into either compiler or assembler.

## Goals

The first usable version should support:

- loading a MyLang machine-code image;
- running and single-stepping the virtual CPU;
- setting breakpoints by address and symbol;
- inspecting registers and memory;
- disassembling instructions around the current program counter;
- mapping machine-code addresses back to MyLang source locations.

Later versions may add source-level stepping, stack traces, and local-variable inspection.

## Non-goals for the first version

- reverse execution;
- optimized-code variable reconstruction;
- compatibility with GDB remote serial protocol;
- a full DWARF implementation;
- self-modifying software breakpoints.

## Architecture

```text
program.my
    |
    v
MyLangCompiler
    |  emits assembly plus source directives
    v
program.asm
    |
    v
MyAssembler
    |  emits machine code plus debug metadata
    +--------------------+
    |                    |
    v                    v
program.bin          program.mdbg
    |                    |
    +---------+----------+
              |
              v
        MyDebugger / MyVM
```

The debugger controls a virtual CPU. MyLangCompiler and MyAssembler only provide enough metadata for the debugger to recover source-level information.

## Component responsibilities

### MyLangCompiler

MyLangCompiler should emit source-position directives alongside generated assembly.

Suggested directives:

```asm
.file 1 "examples/sample.my"
.func main
.loc 1 10 1
main:

.loc 1 11 5
    MOV r1, 10

.loc 1 12 5
    CALL add
.endfunc
```

The compiler already tracks the active source path through `codegen_set_source_path()`. The next step is to preserve line and column information on AST nodes and emit `.file`, `.loc`, `.func`, and `.endfunc` directives during code generation.

### MyAssembler

MyAssembler should parse debug directives without emitting bytes for them. Instead, it should associate each directive with the current output address.

The assembler should produce:

- normal machine code;
- symbol information;
- relocations;
- address-to-source mappings;
- function ranges;
- later, variable-location records.

Initially, debug metadata may be written to a separate `.mdbg` file. A later object-file revision can store the same records in dedicated sections.

### MyDebugger / MyVM

The debugger owns execution state:

```c
typedef struct {
    uint32_t regs[16];
    uint32_t pc;
    uint32_t sp;
    uint32_t flags;
    uint8_t *memory;
    size_t memory_size;
    bool halted;
} MyCpu;
```

The core execution API should be small and testable:

```c
typedef enum {
    CPU_STEP_OK,
    CPU_STEP_HALTED,
    CPU_STEP_FAULT
} CpuStepResult;

CpuStepResult mycpu_step(MyCpu *cpu);
```

## Shared instruction definition

The assembler, disassembler, and emulator must not maintain separate opcode tables. Instruction definitions should be moved into a shared library or repository, tentatively named `MyArchitecture`.

```text
MyArchitecture/
  include/myarch/
    opcode.h
    instruction.h
    register.h
  src/
    decode.c
    instruction_table.c
```

Consumers:

```text
MyAssembler  ----+
MyDebugger  -----+---- MyArchitecture
MyEmulator  -----+
```

This avoids silent drift between encoding and execution behavior.

## Debug information format

The first implementation may use JSON for ease of inspection and testing.

```json
{
  "format": "mdbg",
  "version": 1,
  "architecture": "mylang32",
  "files": [
    {"id": 1, "path": "examples/sample.my"}
  ],
  "symbols": [
    {"name": "main", "address": 288, "kind": "function"}
  ],
  "lines": [
    {"address": 288, "file": 1, "line": 10, "column": 1},
    {"address": 292, "file": 1, "line": 11, "column": 5}
  ],
  "functions": [
    {"name": "main", "start": 288, "end": 352}
  ]
}
```

Required compatibility rules:

- `format` must be `mdbg`;
- readers must reject unsupported major versions;
- unknown fields must be ignored;
- addresses are byte addresses in the final linked image;
- line mappings remain valid until the next mapping entry.

A later binary format should preserve the same logical schema.

## Command-line interface

Proposed executable name: `mydb`.

```console
$ mydb program.bin --debug program.mdbg
(mydb) break main
(mydb) run
Breakpoint 1, main at examples/test.my:12

12 | let result = add(a, b);
             ^

(mydb) regs
(mydb) x 0x1000 16
(mydb) step
(mydb) next
(mydb) disassemble
(mydb) continue
```

MVP commands:

| Command | Purpose |
| --- | --- |
| `run` | reset and start execution |
| `continue`, `c` | continue until halt, fault, or breakpoint |
| `step`, `s` | execute one machine instruction |
| `break <address\|symbol>` | add a breakpoint |
| `delete <id>` | remove a breakpoint |
| `regs` | show registers, flags, PC, and SP |
| `x <address> [count]` | examine memory |
| `disassemble` | decode instructions near PC |
| `info breakpoints` | list breakpoints |
| `quit` | leave the debugger |

Breakpoints should initially be implemented by comparing the current PC against an in-memory breakpoint table. Binary patching is unnecessary for a virtual CPU.

## Source-level stepping

Machine-level `step` executes exactly one instruction.

Source-level `next` can initially run until the mapped source line changes:

```c
SourceLocation initial = debug_lookup(cpu.pc);

while (!cpu.halted) {
    CpuStepResult result = mycpu_step(&cpu);
    if (result != CPU_STEP_OK) break;

    SourceLocation current = debug_lookup(cpu.pc);
    if (!same_source_line(initial, current)) break;
}
```

A later implementation should distinguish stepping into a call from stepping over it by using temporary breakpoints at the return address.

## Local variables

Variable inspection should be postponed until source mapping and function ranges are stable.

An initial unoptimized-only representation may be:

```c
typedef enum {
    DBG_VAR_REGISTER,
    DBG_VAR_STACK,
    DBG_VAR_GLOBAL
} DebugVariableLocationKind;

typedef struct {
    const char *name;
    const char *function;
    uint32_t scope_start;
    uint32_t scope_end;
    DebugVariableLocationKind kind;
    int32_t location;
} DebugVariable;
```

This is sufficient for simple `print <name>` and `info locals` commands when compiling without optimization.

## Implementation plan

### Phase 1: machine-level debugger

1. Extract shared instruction descriptions.
2. Implement instruction decoding.
3. Implement `MyCpu` and one-instruction execution.
4. Add `run`, `continue`, `step`, and `regs`.
5. Add address breakpoints and memory inspection.
6. Add disassembly.

### Phase 2: symbols

1. Export assembler symbols into `.mdbg`.
2. Add symbol lookup.
3. Support `break main` and `disassemble add`.

### Phase 3: source mapping

1. Preserve source locations on AST nodes.
2. Emit `.file` and `.loc` directives.
3. Record address-to-source mappings in MyAssembler.
4. Add source display and `break file:line`.
5. Add source-level stepping.

### Phase 4: functions and variables

1. Emit function ranges.
2. Add stack traces.
3. Emit variable locations for unoptimized builds.
4. Add `print` and `info locals`.

## Testing strategy

- table-driven decode tests for every opcode;
- CPU-step tests for every instruction;
- breakpoint tests at the first instruction, middle of a function, and halt;
- malformed `.mdbg` rejection tests;
- compiler-to-assembler integration tests checking expected address/line pairs;
- source-level stepping tests over straight-line code, branches, loops, and calls.

## Open questions

- whether execution belongs in a dedicated `MyVM` repository or in `MyDebugger`;
- whether `.mdbg` remains a sidecar or becomes an object-file section immediately;
- the authoritative register count and calling convention exposed to the debugger;
- whether instruction definitions should be a new repository or a vendored library shared by both existing repositories;
- how linking adjusts debug addresses when multiple object files are combined.

## Recommended first PRs after this design

1. **MyAssembler:** extract the instruction table and decoder into a reusable module.
2. **MyDebugger/MyVM:** implement the CPU state, loader, `step`, `run`, and register display.
3. **MyAssembler:** emit symbol and line metadata in `.mdbg` version 1.
4. **MyLangCompiler:** emit `.file` and `.loc` directives from AST source positions.
