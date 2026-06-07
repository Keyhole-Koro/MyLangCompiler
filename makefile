CC = gcc
CFLAGS = -Wall -Wextra -Iinc
SYNTAX_ENGINE_DIR = ../MyLangSyntaxEngine
SYNTAX_ENGINE_INC = -I$(SYNTAX_ENGINE_DIR)/include
SYNTAX_ENGINE_SRC = $(SYNTAX_ENGINE_DIR)/src/lr1/syntax_engine.c
SRC = $(shell find src -name '*.c' | sort)
TESTS = $(wildcard tests/*.c)
SRC_NO_MAIN = $(filter-out src/driver/main.c, $(SRC))
OUT = test
MYCC = mlc
SYNTAX_CHECK = mylang-syntax-check

all: mlc

mlc: $(SRC)
	$(CC) $(CFLAGS) -o $(MYCC) $(SRC)

syntax-check: tools/syntax_check.c src/frontend/lexer/lexer.c src/support/utils.c $(SYNTAX_ENGINE_SRC)
	$(CC) $(CFLAGS) $(SYNTAX_ENGINE_INC) -o $(SYNTAX_CHECK) $^

test-semantic: mlc
	python3 tests/run_semantic_tests.py

test-integration: mlc
	python3 tests/run_integration_tests.py

test: $(SRC_NO_MAIN) $(TESTS)
	$(CC) $(CFLAGS) -g $(SRC_NO_MAIN) $(TESTS) -o $(OUT)
	./$(OUT)

debug: $(SRC_NO_MAIN) $(TESTS)
	$(CC) $(CFLAGS) -g $(SRC_NO_MAIN) $(TESTS) -o $(OUT)
	gdb ./$(OUT)

debug-mycc: $(SRC)
	$(CC) $(CFLAGS) -g -o $(MYCC) $(SRC)
	gdb --args ./$(MYCC) $(IN) $(OUT)

clean:
	rm -f $(OUT) $(MYCC) $(SYNTAX_CHECK)
