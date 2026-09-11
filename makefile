CC = gcc
CFLAGS = -Wall -Wextra -Iinc
SYNTAX_ENGINE_DIR = ../MySyntaxEngine
SYNTAX_ENGINE_INC = -I$(SYNTAX_ENGINE_DIR)/inc
SYNTAX_ENGINE_SRC = $(shell find $(SYNTAX_ENGINE_DIR)/src/lr1 -name '*.c' | sort)
SRC = $(shell find src -name '*.c' | sort)
MYCC = mlc
SYNTAX_CHECK = mylang-syntax-check

.PHONY: all syntax-check test test-component test-all test-e2e test-integration test-semantic test-generics \
	test-source-profiles test-syntax-check test-tokens debug-mycc clean

all: mlc

mlc: $(SRC)
	$(CC) $(CFLAGS) -o $(MYCC) $(SRC)

syntax-check: tools/syntax_check.c src/frontend/lexer/lexer.c src/support/utils.c $(SYNTAX_ENGINE_SRC)
	$(CC) $(CFLAGS) $(SYNTAX_ENGINE_INC) -o $(SYNTAX_CHECK) $^

# Compiler-local C/Python test suites were retired in favor of MyLangTestKit
# and the repository-level system suites.  Keep the historical entry points
# as build checks so callers (including qa/tests/test-all.py) remain valid.
test: mlc syntax-check

test-component: test

test-e2e: mlc

test-integration: test-e2e
test-semantic test-generics test-source-profiles test-syntax-check test-tokens: test-component
test-all: test-component test-e2e

debug-mycc: $(SRC)
	$(CC) $(CFLAGS) -g -o $(MYCC) $(SRC)
	gdb --args ./$(MYCC) $(IN) $(OUT)

clean:
	rm -f $(MYCC) $(SYNTAX_CHECK)
