#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>

// Reads a source file verbatim (no include expansion).
// Caller owns the returned NUL-terminated buffer.
char *readSampleInput(const char *filePath);

// Saves content to filePath, creating parent directories as needed.
// Returns 1 on success and 0, after reporting why, when the file could not
// be written.
int saveOutput(const char *filePath, const char *content);

#endif
