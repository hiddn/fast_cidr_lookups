# Variables
CC := gcc
CFLAGS := -Wall -Wextra -Werror -g -ggdb -O0
SRC_DIR := src
TEST_DIR := tests
OBJ_DIR := obj
BIN_DIR := .
TARGET := $(BIN_DIR)/cidr

EXAMPLE_SRC := example.c
EXAMPLE_OBJ := $(OBJ_DIR)/example.o

# Source and Object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Targets
.PHONY: all test clean

all: $(TARGET) $(BIN_DIR)/example

$(TARGET): $(OBJS) $(TEST_DIR)/tests.c
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(TEST_DIR)/tests.c

$(BIN_DIR)/example: $(EXAMPLE_OBJ) $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/example.o: example.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

test: CFLAGS += -DCIDR_DEBUG_ENABLED
test: $(TARGET)
	$(TARGET)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
CC := gcc
