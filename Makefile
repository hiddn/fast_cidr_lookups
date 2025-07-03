# Variables
CC := gcc
CFLAGS := -Wall -Wextra -Werror -g -ggdb -O0
SRC_DIR := src
TEST_DIR := tests
OBJ_DIR := obj
BIN_DIR := bin
TARGET := $(BIN_DIR)/cidr

# Source and Object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Targets
.PHONY: all test clean

all: $(TARGET) $(BIN_DIR)/example $(BIN_DIR)/bench-cidr-lookups

$(TARGET): $(OBJS) $(TEST_DIR)/tests.c
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(TEST_DIR)/tests.c

$(BIN_DIR)/example: $(OBJS) $(OBJ_DIR)/example.o
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR)/bench-cidr-lookups: $(OBJS) $(OBJ_DIR)/bench-cidr-lookups.o
	$(CC) $(CFLAGS) -o $@ $^ -lm

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/example.o: example.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/bench-cidr-lookups.o: tests/bench-cidr.c
	$(CC) $(CFLAGS) -DCIDR_LOOKUPS_API -c -o $@ $<

test: CFLAGS += -DCIDR_DEBUG_ENABLED
test: $(TARGET)
	$(TARGET)
tests: test

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/*
