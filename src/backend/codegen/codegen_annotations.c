#include "mylang/backend/codegen_internal.h"
#include "mylang/frontend/parser.h"

/* Emits the annotation rows the frontend recorded (parser_lower_annot.c) as
 * static data in the `annotations` collected section:
 *
 *     .section annotations
 *     __annotations_rows:
 *       .word s_0, Terminal__poll, s_1, 24, 1, 100, 0, 0
 *
 * Eight words per row: name (char*), the annotated function, receiver type
 * name (char*, "" for a plain function), sizeof that type (0 for a plain
 * function), the argument count, then three arguments -- a number, a bool
 * as 0/1, or a string as a char*. Symbol operands are filled in by the
 * linker (RELOC_WORD32); the linker also gathers every object's chunk into
 * an index between __annotations_start and __annotations_end, which is how
 * the framework finds the rows of every module (ObjectFormat.h,
 * CollectEntry). The label is local: the assembler makes it unique per
 * object. */
void emit_annotation_rows(CompilerContext *cc, StringBuilder *sb) {
    int count = annotation_row_count();
    if (count == 0) return;

    sb_append(sb, "\n; annotation rows: name, fn, type, size, argc, arg0, arg1, arg2\n");
    sb_append(sb, ".section annotations\n__annotations_rows:\n");
    for (int i = 0; i < count; i++) {
        const AnnotationRow *row = annotation_row(i);
        const char *name_label = intern_string_literal(cc, row->name);
        const char *type_label = intern_string_literal(cc, row->type ? row->type : "");
        int size = 0;
        if (row->type) {
            const StructInfo *si = find_struct(cc, row->type);
            size = si ? si->size_bytes : 0;
        }
        sb_append(sb, "  .word %s, %s, %s, %d, %d", name_label, row->fn, type_label, size, row->argc);
        for (int k = 0; k < ANNOTATION_MAX_ARGS; k++) {
            const AnnotationArg *arg = &row->args[k];
            if (k >= row->argc) sb_append(sb, ", 0");
            else if (arg->is_string) sb_append(sb, ", %s", intern_string_literal(cc, arg->text));
            else sb_append(sb, ", %ld", arg->value);
        }
        sb_append(sb, "\n");
    }
}
