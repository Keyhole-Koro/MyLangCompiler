CC = gcc
CFLAGS = -Wall -Wextra -Iinc
SYNTAX_ENGINE_DIR = ../MySyntaxEngine
SYNTAX_ENGINE_INC = -I$(SYNTAX_ENGINE_DIR)/inc
SYNTAX_ENGINE_SRC = $(shell find $(SYNTAX_ENGINE_DIR)/src/lr1 -name '*.c' | sort)
SRC = $(shell find src -name '*.c' | sort)
MYCC = mlc
SYNTAX_CHECK = mylang-syntax-check
MYTEST = ../MyLangTester/build/mytest

# Test runs keep scratch files out of /tmp, which is memory on some machines.
export TMPDIR ?= $(CURDIR)/build/tmp
$(shell mkdir -p $(TMPDIR))

.PHONY: all syntax-check test test-component test-all test-e2e test-integration test-semantic test-generics \
	test-source-profiles test-syntax-check test-tokens debug-mycc clean

all: mlc

mlc: $(SRC)
	$(CC) $(CFLAGS) -o $(MYCC) $(SRC)

syntax-check: tools/syntax_check.c src/frontend/lexer/lexer.c src/frontend/model/model_expand.c src/support/utils.c $(SYNTAX_ENGINE_SRC)
	$(CC) $(CFLAGS) $(SYNTAX_ENGINE_INC) -o $(SYNTAX_CHECK) $^

# Compiler fixtures are executed by MyLangTester. They remain here as .mln
# inputs, while the test protocol lives in the shared Java runner.
test: test-component

test-component: mlc syntax-check
	$(MAKE) -C ../MyLangTester all
	$(MYTEST) --compiler tests
	python3 tests/check_depfile.py
	python3 tests/check_import_paths.py
	python3 tests/check_generic_origin.py
	python3 tests/check_line_info.py
	python3 tests/check_emit_symbols.py
	python3 tests/check_model_trace.py

test-e2e: mlc
	$(MAKE) -C ../MyLangTester all
	$(MYTEST) --compiler-e2e tests

test-integration: test-e2e
test-semantic test-generics test-source-profiles test-syntax-check test-tokens: test-component
test-all: test-component test-e2e

debug-mycc: $(SRC)
	$(CC) $(CFLAGS) -g -o $(MYCC) $(SRC)
	gdb --args ./$(MYCC) $(IN) $(OUT)

clean:
	rm -f $(MYCC) $(SYNTAX_CHECK)
