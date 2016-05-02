# ==========================================
# cdbd-vpn  COSC 534 Project
# Clayton Davis, Brandon Denton
# ==========================================

CLEANUP = rm -rf
MKDIR = mkdir -p

UNITY_ROOT=contrib/unity
C_COMPILER=gcc

CFLAGS=-std=gnu11
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Werror 
CFLAGS += -Wpointer-arith
CFLAGS += -Wcast-align
CFLAGS += -Wwrite-strings
CFLAGS += -Wswitch-default
CFLAGS += -Wunreachable-code
CFLAGS += -Winit-self
CFLAGS += -Wmissing-field-initializers
CFLAGS += -Wno-unknown-pragmas
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wundef
CFLAGS += -Wold-style-definition

TEST_TARGET = all_tests.o
DEBUG_TARGET = 
TEST_SRC_FILES=\
$(UNITY_ROOT)/src/unity.c \
$(UNITY_ROOT)/extras/fixture/src/unity_fixture.c \
src/*.c \
test/*.c \
test/test_runners/*.c
DEBUG_SRC_FILES=
TEST_INC_DIRS=-Isrc -Iinclude -I$(UNITY_ROOT)/src -I$(UNITY_ROOT)/extras/fixture/src
DEBUG_INC_DIRS=-Isrc -Iinclude 
TEST_LDFLAGS = 
TEST_SYMBOLS=-DUNITY_FIXTURES

.PHONY: clean test

default:
	mkdir -p build
	$(C_COMPILER) -O2 -std=gnu11 $(DEBUG_INC_DIRS) $(DEBUG_SRC_FILES) -o build/cdbd-vpn -lm

all: debug test

	
test:
	$(C_COMPILER) -g -O0 $(CFLAGS) $(TEST_INC_DIRS) $(TEST_LDFLAGS) $(TEST_SYMBOLS) $(TEST_SRC_FILES)  -o test/$(TEST_TARGET) -lm
	./test/$(TEST_TARGET)

clean:
	$(CLEANUP) *.o build/cdbd-vpn