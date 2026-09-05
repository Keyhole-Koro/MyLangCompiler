# Gemini 実装指示書: module loading / symbol resolution の整理

## 目的

MyLangCompiler に後付けされてきた import 処理を整理し、同じ `.mln` ファイルを parser、generic、DOM lowering、semantic、codegen が個別に読み直す構造をやめる。

今回の作業範囲は、共有の `ModuleLoader` / `ModuleGraph` と、import 先の宣言を問い合わせる最小限の `Resolver` を導入し、既存の import 利用箇所をそこへ移すところまでとする。

これは将来の payload enum、`Result<T, E>`、`case value of { Ok(x) -> ...; Err(e) -> ...; }`、semantic が生成する `TypeMap` の前提整理である。ただし、この作業で `Result<T, E>` や tagged union 自体は実装しない。

## リポジトリと現在地

- 作業ディレクトリ: `/home/kiho/Workspaces/MyComputer/toolchain/MyLangCompiler`
- 現在のブランチ: `feat/tagged-result-patterns`
- 既存 Draft PR: <https://github.com/Keyhole-Koro/MyLangCompiler/pull/21>
- この指示書作成時点の先頭コミット: `d599d10 Share type representation across frontend phases`
- Git author / committer は必ず次を使う:
  - `Keyhole-Koro`
  - `korokorornthird@gmail.com`
- ユーザー由来の変更や、親 workspace の別 submodule の変更には触れない。
- force push、reset、checkout による変更破棄は禁止。

作業開始時に必ず `git status --short --branch` と `git log -5 --oneline` を確認すること。この文書の先頭コミットより作業が進んでいた場合は、現在のコードを正として適応すること。

## 現在の問題

同じ import 元を複数箇所が別々に lex / scan / parse しており、各フェーズが独自の不完全な symbol resolution を持っている。

主な重複箇所:

- `src/frontend/parser/parser_toplevel.c`
  - import path の相対解決
  - import 先の package 宣言確認
- `src/frontend/parser/parser_import_generics.c`
  - import 元を再 lex / parse して generic template を clone
- `src/frontend/parser/parser_dom_sig.c`
  - import 元を再 lex し、token 列から関数名と parameter 名を推測
  - package 名も別途再走査
- `src/backend/codegen/codegen_toplevel.c`
  - import 元を再 lex し、exported function signature を token scan
- `src/semantic/semantic_walk.c`
  - `parser_name_has_imported_package_prefix()` を通して parser の default context に依存
- `src/backend/codegen/codegen_type_infer.c`
  - semantic とは別に式の型を再推論している。ただしこれは今回すべて直さず、次段階の `TypeMap` 作業として残す。

このため、package/import の解釈、variadic signature、DOM parameter、generic template の扱いがフェーズごとにずれる危険がある。また compiler phase が parser の mutable global/default context に逆依存している。

## 目標構造

概念上、frontend session が module graph を所有する。

```text
FrontendSession
  ├── ModuleLoader
  │     └── ModuleGraph
  │           └── Module[]
  │                 ├── canonical_path
  │                 ├── package_name
  │                 ├── syntax AST
  │                 ├── declarations / exports
  │                 └── load state
  └── root ParserContext

Resolver
  └── ModuleGraph を参照し、import の可視性を適用して宣言を返す
```

最小データモデルの目安:

```c
typedef enum ModuleLoadState {
    MODULE_LOADING,
    MODULE_LOADED,
    MODULE_FAILED,
} ModuleLoadState;

typedef enum SymbolKind {
    SYMBOL_FUNCTION,
    SYMBOL_STRUCT,
    SYMBOL_TYPEDEF,
    SYMBOL_ENUM,
    SYMBOL_GLOBAL,
    SYMBOL_GENERIC_FUNCTION,
    SYMBOL_GENERIC_STRUCT,
} SymbolKind;

typedef struct ModuleSymbol {
    SymbolKind kind;
    const char *source_name;
    const char *link_name;
    ASTNode *declaration;
    int is_exported;
} ModuleSymbol;

typedef struct Module {
    char *canonical_path;
    char *package_name;
    ASTNode *program;
    ModuleSymbol *symbols;
    int symbol_count;
    ModuleLoadState state;
} Module;

typedef struct ModuleGraph {
    Module **modules;
    int module_count;
} ModuleGraph;
```

名前やファイル分割は既存の命名規則に合わせて調整してよい。ただし以下は必須:

- cache key は import 文字列ではなく canonical path。
- 同じ canonical path は一度だけ lex / parse する。
- import cycle は `MODULE_LOADING` の検出で無限再帰させない。
- `.masm` など MyLang 以外の import は source module として parse しない。linker-visible import として従来どおり残す。
- ModuleGraph が AST と symbol metadata の寿命を所有する。borrowed pointer と owned pointer をコメントで明確にする。
- parser の一時 context を reset した結果、Module 内の AST pointer が dangling にならないこと。
- AST を clone する場合は必要な境界だけに限定し、誰が free するかを明示する。

## 実装順序

### 1. ModuleLoader / ModuleGraph を追加する

frontend 内に module loading 専用ディレクトリと internal header を作る。`makefile` は `find src -name '*.c'` なので、通常は source list の手修正は不要。

最低限必要な操作:

- graph/session の init と destroy
- importer の source path を基準にした path resolve
- canonicalize
- path による cache lookup
- `.mln` module の load
- package name と top-level declaration/export metadata の取得
- cycle / load failure の扱い

path resolve のロジックは `parser_toplevel.c`、`parser_dom_sig.c`、`codegen_toplevel.c` に重複させず一か所へ移す。

エラー方針:

- 明示された `.mln` が存在するのに load/parse できない場合は、黙って linker symbol 扱いに落とさず診断する。
- `.masm` 等は graph に無理に載せず従来の linker import として扱う。
- cycle 自体を許可するか拒否するかは現行仕様に明記がない。少なくとも無限再帰を防ぎ、未解決 symbol が必要になった地点で分かる診断を出す。

### 2. 最小 Resolver を追加する

今回の Resolver は完全な name-resolution pass でなくてよい。以下を共通 API で答えられればよい。

- import 先の package name
- source name に対応する exported declaration
- function の link name（package mangling 後の名前）
- function parameter の名前、型、個数、variadic 情報
- exported generic struct/function template
- import 形式に応じてその symbol が可視か

import の意味を維持する:

- `import { foo } from "x.mln";`: 指定 symbol だけを直接参照可能
- `import foo from "x.mln";`: target が `package foo;` なら package import。そうでなければ単一 symbol import
- package import: exported symbol を `foo.bar()` 形式で参照し、既存規約に従って link name を `foo_bar` にする
- `import foo;`: path のない linker/package import として既存挙動を壊さない

### 3. 既存の再走査を Resolver に移す

次を実施する。

1. `parser_import_generics.c`
   - `lexer_from_file()` と独自 parse を削除する。
   - cached Module から requested + exported generic template を取得する。
   - importing module で specialization/lowering するための clone が必要なら、ここだけで clone する。
   - generic symbol を import list から外して linker import を出さない現行挙動は維持する。
2. `parser_dom_sig.c`
   - token scan、`package_name_of()`、独自 path resolver を削除する。
   - local function 優先、その後 import の順序を維持する。
   - `DomSignature` は Resolver が返す parsed function declaration から parameter name を組み立てる。
   - token heuristic ではなく AST の parameter metadata を使う。
3. `codegen_toplevel.c`
   - `append_import_sigs_from_source()` の lex/token scan を削除する。
   - Resolver/Module metadata から function signature と variadic 情報を登録する。
4. `parser_toplevel.c`
   - `import_path_declares_package()` と独自 path resolver を削除する。
   - loader/resolver の package metadata を使う。
5. `semantic_walk.c`
   - semantic が `parser_name_has_imported_package_prefix()` で default parser context を読む依存を削除する。
   - package-import 情報または解決済み symbol 情報を明示的に SemanticContext へ渡す。

単に helper 関数を別ファイルへ移すだけでは完了ではない。lex/parse/cache の責務と symbol visibility の責務を分離すること。

## frontend API とライフタイム

既存 public API を一度に壊さない。必要なら互換 wrapper を残してよい。

理想的には driver の一コンパイルが session を所有する:

```text
frontend_session_init
  -> root module load / parse
  -> resolve imports
  -> generic specialization
  -> DOM lowering
  -> function literal lowering
  -> name rewrite
  -> semantic
  -> codegen
frontend_session_destroy
```

現在の `parse_program(Token **cur)`、`semantic_check(ASTNode *)`、`codegen(ASTNode *)` を即座に全面変更すると影響が大きい。最初は context/session-aware な内部 API を追加し、public wrapper が default session を使う構成でもよい。ただし semantic/codegen が parser singleton を直接参照する構造は残さない。

特に注意する点:

- 現在 `parser_context_reset()` は `generic_templates.declarations` 内の AST を free する。
- 通常の syntax AST は caller が `free_ast(root)` する。
- `ParserSymbolState.functions` と struct table の一部は AST を借用している。
- imported module の一時 ParserContext を reset する前に、その Module が所有する情報を確保する必要がある。
- `ParserModuleState.filename` は現在 borrowed `const char *`。canonical path の owner と混同しない。

所有権をテストだけでなく header のコメントにも残すこと。

## 今回やらないこと

変更をレビュー可能な大きさに保つため、次は別コミット/別段階にする。

- payload enum / tagged union
- `Result<T, E>` 本体
- `case ... of` の constructor pattern binding
- aggregate return ABI
- 全 AST node の型注釈
- codegen の `infer_expr_type()` 全削除
- parser 全体の CST 化や parser generator への置換
- Go 風 struct method

ただし、新しい API は次段階で以下を実装できる形にする:

```c
typedef struct TypedNode {
    ASTNode *node;
    MylangType type;
    ModuleSymbol *resolved_symbol;
} TypedNode;

typedef struct TypeMap {
    TypedNode *entries;
    int count;
} TypeMap;
```

次段階では semantic が `TypeMap` を一度生成し、codegen がそれを読む。そこで初めて `src/backend/codegen/codegen_type_infer.c` を削除する。

## テスト要件

最低限、次の component/white-box テストを追加する。

- 同じ `.mln` を複数回 import しても module instance/load が一つ
- 異なる相対表現が同じ canonical path なら同一 module
- 2 module 間の循環 import で無限再帰しない
- package import の package 名、export visibility、mangled link name
- symbol-list import で未指定 symbol が見えない
- exported generic template を cached AST から取得できる
- 非 export generic template は取得できない
- DOM signature が AST parameter names と variadic metadata を使う
- `.masm` import を MyLang parser に渡さない
- session を破棄したとき ASan 上で double free / use-after-free がない
- 独立した二つの frontend session 間で module/symbol state が漏れない

既存 regression として少なくとも次を通す:

```bash
make test-component
make test-e2e
```

余力があれば sanitizer build も実行する:

```bash
make clean
make CFLAGS='-Wall -Wextra -Iinc -g -fsanitize=address,undefined' test
```

既存の重要ケース:

- `tests/succeed/generic/imported_templates_main.mln`
- `tests/succeed/generic/modules_main.mln`
- `tests/succeed/generic/kernel_containers.mln`
- `tests/succeed/package/importFrom_main.mln`
- `tests/succeed/package/multiInclude.mln`
- `tests/succeed/package/pkgVariadic_main.mln`
- `tests/succeed/dom/localFunctionWins.dom.mln`
- DOM support fixture を使う既存 integration cases

テスト失敗を期待値変更だけで隠さない。既存言語挙動を変える必要が出た場合は、先に理由と影響範囲を報告すること。

## 完了条件

以下をすべて満たしたら今回の作業は完了。

- `.mln` import source の lex/parse は canonical path ごとに一回
- parser generic import、DOM signature、codegen import signature が同じ Module/Resolver metadata を使う
- DOM/codegen の import token scan が削除されている
- semantic から parser default context への依存が削除されている
- `.masm` import を含む既存挙動が維持される
- module/session の所有権が明記され、cycle と cleanup のテストがある
- `make test-component` と `make test-e2e` が成功する
- 警告を新規追加しない
- 実装に合わせて `docs/compiler-architecture.md` を更新する

## Git workflow

作業は小さな意味単位でコミットする。推奨分割:

1. `Add cached frontend module graph`
2. `Resolve imported declarations through module graph`
3. `Remove per-phase import source scans`
4. `Document frontend module ownership`

コミット前に identity を確認する:

```bash
git config user.name
git config user.email
```

異なる場合はこの repository local config を `Keyhole-Koro <korokorornthird@gmail.com>` に合わせる。commit author と committer の両方がユーザー本人になるようにする。

各コミット後に関連テストを実行し、最後に全テストを実行する。既存 branch を push し、Draft PR #21 を更新する。PR 本文には以下を追記する。

- 導入した ownership model
- 削除できた再走査箇所
- cycle の扱い
- 実行した test command と結果
- `TypeMap` と tagged `Result` は後続作業であること

不明点があっても推測で巨大な redesign を始めず、まず既存の構文とテストを読み、最小の互換 migration を選ぶこと。
