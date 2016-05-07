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


TARGET = build/cdbd-vpn
SRC_FILES = $(filter-out src/vpnctl.c, $(wildcard src/*.c))
INC_DIRS=-Isrc -Iinclude 
LDFLAGS = -lssl -lcrypto -lpthread -lrt
SYMBOLS = 

TEST_TARGET = all_tests.o
TEST_SRC_FILES=\
$(UNITY_ROOT)/src/unity.c \
$(UNITY_ROOT)/extras/fixture/src/unity_fixture.c \
$(filter-out src/vpnctl.c, $(wildcard src/*.c)) \
test/*.c \
test/test_runners/*.c
TEST_INC_DIRS=-Isrc -Iinclude -I$(UNITY_ROOT)/src -I$(UNITY_ROOT)/extras/fixture/src
TEST_LDFLAGS = -lssl -lcrypto -lpthread -lrt
TEST_SYMBOLS=-DUNITY_FIXTURES

.PHONY: clean test

default:
	mkdir -p build
	$(C_COMPILER) -O2 -DNDEBUG $(CFLAGS) $(INC_DIRS) $(SRC_FILES) -o $(TARGET) $(LDFLAGS)
	$(C_COMPILER) -O2 -DNDEBUG $(CFLAGS) $(INC_DIRS) src/vpnctl.c src/debug.c -o build/vpnctl -lrt

all: test default 

debug:
	mkdir -p build
	$(C_COMPILER) -g -O0 $(CFLAGS) $(INC_DIRS) $(SRC_FILES) -o $(TARGET) $(LDFLAGS)
	$(C_COMPILER) -g -O0 $(CFLAGS) $(INC_DIRS) src/vpnctl.c src/debug.c -o build/vpnctl -lrt
	
test:
	$(C_COMPILER) -g -O0 $(CFLAGS) $(TEST_INC_DIRS) $(TEST_SYMBOLS) $(TEST_SRC_FILES)  -o test/$(TEST_TARGET) $(TEST_LDFLAGS)
	./test/$(TEST_TARGET)

clean:
	$(CLEANUP) *.o build/cdbd-vpn build/vpnctl