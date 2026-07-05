#ifndef MYLANG_SEMANTIC_DIAGNOSTIC_CODES_H
#define MYLANG_SEMANTIC_DIAGNOSTIC_CODES_H

/*
 * Diagnostic code registry.
 *
 * Codes are stable identifiers attached to semantic diagnostics. The prefix
 * selects severity (E = error, W = warning) and the leading two digits select
 * a category:
 *
 *   E00xx  name resolution        (undefined identifier / function)
 *   E01xx  function call          (argument count / type)
 *   E02xx  return                 (return type)
 *   E03xx  expression type        (assignment / binary / condition)
 *   E04xx  package / import       (reserved for package symbol resolution)
 *   W00xx  warnings               (unreachable statement, ...)
 *
 * When adding a code, keep it inside its category band and update
 * docs/diagnostic-codes.md so the documentation stays the single source of
 * truth. Existing code values must not change.
 */

/* E00xx: name resolution */
#define SEMCODE_UNDEFINED_IDENTIFIER "E0001"
#define SEMCODE_UNDEFINED_FUNCTION "E0002"

/* E01xx: function call */
#define SEMCODE_ARG_COUNT_MISMATCH "E0101"

/* E02xx: return */
#define SEMCODE_RETURN_TYPE_MISMATCH "E0201"

/* E03xx: expression type */
#define SEMCODE_ASSIGNMENT_TYPE_MISMATCH "E0301"
#define SEMCODE_INVALID_BINARY_OPERANDS "E0302"
#define SEMCODE_INVALID_CONDITION_TYPE "E0303"

/* W00xx: warnings */
#define SEMCODE_UNREACHABLE_STATEMENT "W0001"

#endif
