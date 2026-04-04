CC = gcc
CFLAGS = -Wall -Wextra -Iinc
SRC = $(shell find src -name '*.c' | sort)
TESTS = $(wildcard tests/*.c)
SRC_NO_MAIN = $(filter-out src/driver/main.c, $(SRC))
OUT = test
MYCC = mlc

all: mlc

mlc: $(SRC)
	$(CC) $(CFLAGS) -o $(MYCC) $(SRC)

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
	rm -f $(OUT) $(MYCC)
