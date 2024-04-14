#   Project:        IPK Project 1 - Client for Chat Servers
#   File Name:      Makefile
#   Author:         Tomas Dolak
#   Date:           13.04.2024
#   Description:    Makefile for Packet Sniffer.

# Program Name
TARGET = ipk-sniffer
# Program Name For Debug Configuration
DEBUG_TARGET = ipk-sniffer_debug
# Test Program Name
TEST_TARGET = ipk-sniffer_test

# Compiler
CC = clang++
# Compiler Flags
CFLAGS = -std=c++17 -Wall -Wextra -Werror -Wshadow -Wnon-virtual-dtor -pedantic -Iinclude
DEBUG_CFLAGS = -fsanitize=address -g -std=c++17 -Wall -Wextra -Werror -Wshadow -Wnon-virtual-dtor -pedantic

# Header Files
HEADERS = include/SnifferConfig.hpp include/NetworkInterfacePrinter.hpp include/PrintIPv4Packet.hpp include/IPv4PacketSniffer.hpp
# Libraries
LIBS = -lpcap

# Source Files
SOURCES = src/SnifferConfig.cpp src/NetworkInterfacePrinter.cpp src/PrintIPv4Packet.cpp src/IPv4PacketSniffer.cpp src/main.cpp
# Object Files 
OBJECTS = $(SOURCES:.cpp=.o)

# Test Source Files
TEST_SOURCES = tests/SnifferConfigTest.cpp
# Test Object Files (Derived from TEST_SOURCES)
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)
# Google Test Flags
GTEST_FLAGS = -lgtest -lgtest_main -pthread
# Default build target
all: $(TARGET)

# Main target
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	rm -f $(OBJECTS)

# Object compilation
%.o: %.cpp $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_OBJECTS) $(TEST_TARGET)

# Tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Test executable
$(TEST_TARGET): $(OBJECTS) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(GTEST_FLAGS)

# Debug build
debug: $(SOURCES)
	$(CC) $(DEBUG_CFLAGS) -o $(DEBUG_TARGET) $^
	rm -f $(OBJECTS)