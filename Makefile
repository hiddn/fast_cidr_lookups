# Variables
CC := gcc
CFLAGS := -Wall -Wextra -Werror -g -ggdb -O0
SRC_DIR := src
TEST_DIR := tests
OBJ_DIR := obj
BIN_DIR := .
TARGET := $(BIN_DIR)/cidr

# Source and Object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Targets
.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(OBJS) $(TEST_DIR)/tests.c
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(TEST_DIR)/tests.c

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

test: CFLAGS += -DCIDR_DEBUG_ENABLED
test: $(TARGET)
	$(TARGET)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
CC := gcc
