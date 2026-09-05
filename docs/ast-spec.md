# MyLang AST Specification

This document describes the internal structure of the Abstract Syntax Tree (AST) used in `MyLangCompiler`.

## Base Structure

Every AST node shares a common header:

- `type`: `ASTNodeType` (Enumeration)
- `line`: Line number in the source file
- `col`: Column number in the source file

Nodes are represented by the `ASTNode` struct, which contains a union of specific data for each node type.

---

## 1. Literals and Identifiers

### AST_NUMBER
- `number.value`: `char*` (String representation of the numeric literal)

### AST_STRING_LITERAL
- `string_literal.value`: `char*` (The string content)

### AST_CHAR_LITERAL
- `char_literal.value`: `char*` (The character content)

### AST_IDENTIFIER
- `identifier.name`: `char*` (The name of the identifier)

---

## 2. Expressions

### AST_BINARY
- `binary.op`: `TokenKind` (Operator, e.g., `ADD`, `SUB`, `LTE`)
- `binary.left`: `ASTNode*`
- `binary.right`: `ASTNode*`

### AST_UNARY
- `unary.op`: `TokenKind` (Operator, e.g., `NOT`, `BITNOT`, `INC`, `SUB`)
- `unary.operand`: `ASTNode*`

### AST_TERNARY
- `ternary.cond`: `ASTNode*`
- `ternary.then_expr`: `ASTNode*`
- `ternary.else_expr`: `ASTNode*`

### AST_CALL
- `call.name`: `char*` (Function name)
- `call.args`: `ASTNode**` (Array of arguments)
- `call.arg_count`: `int`

### AST_CAST
- `cast.type`: `ASTNode*` (Target type node)
- `cast.expr`: `ASTNode*` (Expression to cast)

### AST_SIZEOF
- `sizeof_expr.expr`: `ASTNode*`

### AST_MEMBER_ACCESS (`.`)
- `member_access.lhs`: `ASTNode*`
- `member_access.member`: `char*` (Member name)

### AST_ARROW_ACCESS (`->`)
- `arrow_access.lhs`: `ASTNode*`
- `arrow_access.member`: `char*` (Member name)

### AST_BORROW (`&`) / AST_BORROW_MUT (`&mut`)
- `borrow.expr`: `ASTNode*`

### AST_ASSIGN (`=`)
- `assign.left`: `ASTNode*`
- `assign.right`: `ASTNode*`

### AST_INIT_LIST (`{ ... }`)
- `init_list.elements`: `ASTNode**`
- `init_list.count`: `int`

### AST_CASE
- `case_expr.target`: `ASTNode*`
- `case_expr.cases`: `CaseItem*` (Array of pattern-expression pairs)
- `case_expr.case_count`: `int`

A wildcard pattern is represented as a normal `CaseItem`; there is no separate
default-expression field in the pattern-based form.

### CasePattern
- `kind`: wildcard, literal, zero-payload variant, or single-payload variant
- `variant_name`: Variant name for variant patterns
- `binding_name`: Arm-local binding name for `Variant(identifier)` patterns
- `literal`: Literal value for literal patterns

### AST_STMT_EXPR (`( { ... } )`)
- `stmt_expr.block`: `ASTNode*` (A block node)

---

## 3. Statements

### AST_BLOCK
- `block.stmts`: `ASTNode**`
- `block.count`: `int`

### AST_IF
- `if_stmt.cond`: `ASTNode*`
- `if_stmt.then_stmt`: `ASTNode*`
- `if_stmt.else_stmt`: `ASTNode*` (Optional)

### AST_WHILE / AST_DO_WHILE
- `while_stmt.cond`: `ASTNode*`
- `while_stmt.body`: `ASTNode*`

### AST_FOR
- `for_stmt.init`: `ASTNode*` (Expression or VarDecl)
- `for_stmt.cond`: `ASTNode*`
- `for_stmt.inc`: `ASTNode*`
- `for_stmt.body`: `ASTNode*`

### AST_RETURN
- `ret.expr`: `ASTNode*` (Optional)

### AST_BREAK / AST_CONTINUE
- (No specific fields beyond the common header)

### AST_YIELD
- `yield_stmt.expr`: `ASTNode*`

### AST_EXPR_STMT
- `expr_stmt.expr`: `ASTNode*`

### AST_UNCHECKED
- `unchecked_block.body`: `ASTNode*` (A block node)

---

## 4. Declarations

### AST_FUNDEF
- `fundef.ret_type`: `ASTNode*`
- `fundef.name`: `char*`
- `fundef.params`: `ASTNode**` (Array of `AST_PARAM` nodes)
- `fundef.param_count`: `int`
- `fundef.body`: `ASTNode*` (Optional for declarations)
- `fundef.is_exported`: `int`
- `fundef.package`: `char*`
- `fundef.is_variadic`: `bool`

### AST_FUN_LITERAL (Lambda)
- `fun_literal.params`: `ASTNode**`
- `fun_literal.param_count`: `int`
- `fun_literal.body`: `ASTNode*`
- `fun_literal.is_variadic`: `bool`

### AST_VAR_DECL
- `var_decl.var_type`: `ASTNode*`
- `var_decl.name`: `char*`
- `var_decl.init`: `ASTNode*` (Optional)
- `var_decl.is_mut`: `int`
- `var_decl.is_exported`: `int`
- `var_decl.package`: `char*`

### AST_PARAM
- `param.type`: `ASTNode*`
- `param.name`: `char*`
- `param.is_mut`: `int`
- `param.is_rest`: `int` (For `rest` parameters)

### AST_TYPEDEF
- `typedef_stmt.src_type`: `ASTNode*`
- `typedef_stmt.alias`: `char*`

### AST_STRUCT
- `struct_stmt.name`: `char*`
- `struct_stmt.members`: `ASTNode**` (Array of `AST_VAR_DECL` nodes)
- `struct_stmt.member_count`: `int`

### AST_TYPEDEF_STRUCT
- `typedef_struct.struct_name`: `char*`
- `typedef_struct.members`: `ASTNode**`
- `typedef_struct.member_count`: `int`
- `typedef_struct.typedef_name`: `char*`

### AST_ENUM
- `enum_stmt.name`: `char*`
- `enum_stmt.members`: `ASTNode**` (Array of `AST_ENUM_MEMBER` nodes)
- `enum_stmt.member_count`: `int`

### AST_ENUM_MEMBER
- `enum_member.name`: `char*`
- `enum_member.value`: `ASTNode*` (Optional explicit value expression)
- `enum_member.resolved_value`: `long` (Resolved numeric value)

---

## 5. Types

### AST_TYPE
- `type_node.base_type`: `ASTNode*` (Identifier or nested type)
- `type_node.pointer_level`: `int`
- `type_node.type_modifiers`: `int` (Bitmask of `TYPEMOD_CONST`, etc.)
- `type_node.ref_kind`: `RefKind` (`NONE`, `SHARED`, `MUT`)

### AST_TYPE_ARRAY
- `type_array.element_type`: `ASTNode*`
- `type_array.array_size`: `int`

---

## 6. Modules

### AST_IMPORT
- `import_stmt.path`: `char*`
- `import_stmt.symbols`: `char**` (Array of symbol names)
- `import_stmt.symbol_count`: `int`
