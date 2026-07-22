CC = gcc
CFLAGS = -Wall -Wextra -Iinc
SYNTAX_ENGINE_DIR = ../MySyntaxEngine
SYNTAX_ENGINE_INC = -I$(SYNTAX_ENGINE_DIR)/inc
SYNTAX_ENGINE_SRC = $(shell find $(SYNTAX_ENGINE_DIR)/src/lr1 -name '*.c' | sort)
SRC = $(shell find src -name '*.c' | sort)
TESTS = $(wildcard tests/*.c)
SRC_NO_MAIN = $(filter-out src/driver/main.c, $(SRC))
OUT = test
MYCC = mlc
SYNTAX_CHECK = mylang-syntax-check

.PHONY: all syntax-check test test-component test-all test-e2e test-integration test-semantic \
	test-source-profiles test-syntax-check test-tokens debug debug-mycc clean

all: mlc

mlc: $(SRC)
	$(CC) $(CFLAGS) -o $(MYCC) $(SRC)

syntax-check: tools/syntax_check.c src/frontend/lexer/lexer.c src/support/utils.c $(SYNTAX_ENGINE_SRC)
	$(CC) $(CFLAGS) $(SYNTAX_ENGINE_INC) -o $(SYNTAX_CHECK) $^

test-semantic: mlc
	python3 tests/run_semantic_tests.py

test-e2e: mlc
	python3 tests/run_integration_tests.py

# Backward-compatible alias. This suite crosses component boundaries.
test-integration: test-e2e

test-source-profiles: mlc
	python3 tests/run_source_profile_tests.py

test-syntax-check: syntax-check
	MYLANG_SKIP_SYNTAX_CHECK_BUILD=1 python3 tests/run_syntax_check_tests.py

test-tokens: syntax-check
	MYLANG_SKIP_SYNTAX_CHECK_BUILD=1 python3 tests/run_token_tests.py

test: $(SRC_NO_MAIN) $(TESTS)
	$(CC) $(CFLAGS) -g $(SRC_NO_MAIN) $(TESTS) -o $(OUT)
	./$(OUT)

# Tests owned by and executable within the compiler repository.
test-component: test test-semantic test-source-profiles test-syntax-check test-tokens

# Developer convenience aggregate. Repository CI runs test-component;
# MyComputer runs test-e2e against its pinned toolchain revisions.
test-all: test-component test-e2e

debug: $(SRC_NO_MAIN) $(TESTS)
	$(CC) $(CFLAGS) -g $(SRC_NO_MAIN) $(TESTS) -o $(OUT)
	gdb ./$(OUT)

debug-mycc: $(SRC)
	$(CC) $(CFLAGS) -g -o $(MYCC) $(SRC)
	gdb --args ./$(MYCC) $(IN) $(OUT)

clean:
	rm -f $(OUT) $(MYCC) $(SYNTAX_CHECK)
